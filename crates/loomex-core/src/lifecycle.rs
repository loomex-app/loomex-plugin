use std::collections::BTreeMap;
use std::time::Duration;

use crate::{CoreError, CoreResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerLifecycleState {
    NotAuthenticated,
    Authenticated,
    ProjectNotSelected,
    ProjectBound,
    Connecting,
    Connected,
    Running,
    Paused,
    ApprovalRequired,
    Disconnected,
    Error,
    Updating,
}

impl RunnerLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAuthenticated => "not_authenticated",
            Self::Authenticated => "authenticated",
            Self::ProjectNotSelected => "project_not_selected",
            Self::ProjectBound => "project_bound",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::ApprovalRequired => "approval_required",
            Self::Disconnected => "disconnected",
            Self::Error => "error",
            Self::Updating => "updating",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerLifecycleEvent {
    Authenticated,
    ProjectRequired,
    ProjectBound,
    ConnectStarted,
    Connected,
    ToolCallStarted,
    ToolCallCompleted,
    ApprovalRequired,
    ApprovalResolved,
    Disconnected,
    Error,
    Pause,
    Resume,
    Updating,
    ResetAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerStateSnapshot {
    pub state: RunnerLifecycleState,
    pub display_state: &'static str,
    pub inflight_tool_calls: usize,
    pub pending_approvals: usize,
    pub reconnect_attempt: u32,
    pub emergency_stopped: bool,
    pub draining: bool,
    pub last_error_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerStateMachine {
    state: RunnerLifecycleState,
    last_error_code: Option<&'static str>,
}

impl RunnerStateMachine {
    pub fn new() -> Self {
        Self {
            state: RunnerLifecycleState::NotAuthenticated,
            last_error_code: None,
        }
    }

    pub fn state(&self) -> RunnerLifecycleState {
        self.state
    }

    pub fn transition(&mut self, event: RunnerLifecycleEvent) -> CoreResult<RunnerLifecycleState> {
        let next = match (self.state, event) {
            (_, RunnerLifecycleEvent::ResetAuth) => RunnerLifecycleState::NotAuthenticated,
            (_, RunnerLifecycleEvent::Error) => RunnerLifecycleState::Error,
            (RunnerLifecycleState::NotAuthenticated, RunnerLifecycleEvent::Authenticated) => {
                RunnerLifecycleState::Authenticated
            }
            (RunnerLifecycleState::Authenticated, RunnerLifecycleEvent::ProjectRequired) => {
                RunnerLifecycleState::ProjectNotSelected
            }
            (
                RunnerLifecycleState::Authenticated | RunnerLifecycleState::ProjectNotSelected,
                RunnerLifecycleEvent::ProjectBound,
            ) => RunnerLifecycleState::ProjectBound,
            (
                RunnerLifecycleState::ProjectBound
                | RunnerLifecycleState::Disconnected
                | RunnerLifecycleState::Connected,
                RunnerLifecycleEvent::ConnectStarted,
            ) => RunnerLifecycleState::Connecting,
            (RunnerLifecycleState::Connecting, RunnerLifecycleEvent::Connected) => {
                RunnerLifecycleState::Connected
            }
            (
                RunnerLifecycleState::Connected
                | RunnerLifecycleState::Running
                | RunnerLifecycleState::ApprovalRequired,
                RunnerLifecycleEvent::ToolCallStarted,
            ) => RunnerLifecycleState::Running,
            (
                RunnerLifecycleState::Running | RunnerLifecycleState::ApprovalRequired,
                RunnerLifecycleEvent::ToolCallCompleted,
            ) => RunnerLifecycleState::Connected,
            (
                RunnerLifecycleState::Connected | RunnerLifecycleState::Running,
                RunnerLifecycleEvent::ApprovalRequired,
            ) => RunnerLifecycleState::ApprovalRequired,
            (RunnerLifecycleState::ApprovalRequired, RunnerLifecycleEvent::ApprovalResolved) => {
                RunnerLifecycleState::Running
            }
            (
                RunnerLifecycleState::Running | RunnerLifecycleState::ApprovalRequired,
                RunnerLifecycleEvent::Disconnected,
            ) => RunnerLifecycleState::Disconnected,
            (RunnerLifecycleState::Connected, RunnerLifecycleEvent::Disconnected) => {
                RunnerLifecycleState::Disconnected
            }
            (
                RunnerLifecycleState::Connected | RunnerLifecycleState::Running,
                RunnerLifecycleEvent::Pause,
            ) => RunnerLifecycleState::Paused,
            (RunnerLifecycleState::Paused, RunnerLifecycleEvent::Resume) => {
                RunnerLifecycleState::Connected
            }
            (_, RunnerLifecycleEvent::Updating) => RunnerLifecycleState::Updating,
            _ => {
                return Err(CoreError::new(
                    "RUNNER_STATE_TRANSITION_INVALID",
                    format!("cannot apply {:?} while {}", event, self.state.as_str()),
                ));
            }
        };

        self.state = next;
        if next != RunnerLifecycleState::Error {
            self.last_error_code = None;
        }
        Ok(next)
    }

    pub fn set_error(&mut self, code: &'static str) {
        self.state = RunnerLifecycleState::Error;
        self.last_error_code = Some(code);
    }

    pub fn snapshot(
        &self,
        inflight_tool_calls: usize,
        pending_approvals: usize,
        reconnect_attempt: u32,
        emergency_stopped: bool,
        draining: bool,
    ) -> RunnerStateSnapshot {
        RunnerStateSnapshot {
            state: self.state,
            display_state: self.state.as_str(),
            inflight_tool_calls,
            pending_approvals,
            reconnect_attempt,
            emergency_stopped,
            draining,
            last_error_code: self.last_error_code,
        }
    }
}

impl Default for RunnerStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_attempts: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectState {
    policy: ReconnectPolicy,
    attempt: u32,
    resume_after_server_sequence: u64,
    last_received_runner_sequence: u64,
}

impl ReconnectState {
    pub fn new(policy: ReconnectPolicy) -> Self {
        Self {
            policy,
            attempt: 0,
            resume_after_server_sequence: 0,
            last_received_runner_sequence: 0,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn record_disconnect(
        &mut self,
        resume_after_server_sequence: u64,
        last_received_runner_sequence: u64,
    ) {
        self.resume_after_server_sequence = resume_after_server_sequence;
        self.last_received_runner_sequence = last_received_runner_sequence;
    }

    pub fn next_attempt(&mut self) -> CoreResult<ReconnectAttempt> {
        if self.attempt >= self.policy.max_attempts {
            return Err(CoreError::new(
                "RECONNECT_ATTEMPTS_EXHAUSTED",
                "maximum reconnect attempts exhausted",
            ));
        }

        self.attempt += 1;
        Ok(ReconnectAttempt {
            attempt: self.attempt,
            delay: reconnect_delay(
                self.policy.initial_backoff,
                self.policy.max_backoff,
                self.attempt,
            ),
            resume_after_server_sequence: self.resume_after_server_sequence,
            last_received_runner_sequence: self.last_received_runner_sequence,
        })
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectAttempt {
    pub attempt: u32,
    pub delay: Duration,
    pub resume_after_server_sequence: u64,
    pub last_received_runner_sequence: u64,
}

fn reconnect_delay(initial: Duration, max: Duration, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(31);
    let multiplier = 1_u128 << shift;
    let millis = initial.as_millis().saturating_mul(multiplier);
    let capped = millis.min(max.as_millis());
    Duration::from_millis(capped as u64)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ToolCallRuntimeState {
    Accepted,
    WaitingForApproval,
    Running,
    Cancelling,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationToken {
    cancelled: bool,
    reason: Option<String>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: false,
            reason: None,
        }
    }

    pub fn cancel(&mut self, reason: impl Into<String>) {
        self.cancelled = true;
        self.reason = Some(reason.into());
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflightToolCallRuntime {
    pub tool_call_id: String,
    pub workflow_run_id: String,
    pub attempt: u32,
    pub state: ToolCallRuntimeState,
    pub cancellation_token: CancellationToken,
    pub cancellation_idempotency_key: Option<String>,
    pub cancellation_grace_period: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    Accepted,
    IgnoredUnknown,
    IgnoredTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflightToolCallRegistry {
    calls: BTreeMap<String, InflightToolCallRuntime>,
}

impl InflightToolCallRegistry {
    pub fn new() -> Self {
        Self {
            calls: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        tool_call_id: String,
        workflow_run_id: String,
        attempt: u32,
        state: ToolCallRuntimeState,
    ) -> CoreResult<()> {
        if self.calls.contains_key(&tool_call_id) {
            return Err(CoreError::new("INFLIGHT_DUPLICATE", tool_call_id));
        }

        self.calls.insert(
            tool_call_id.clone(),
            InflightToolCallRuntime {
                tool_call_id,
                workflow_run_id,
                attempt,
                state,
                cancellation_token: CancellationToken::new(),
                cancellation_idempotency_key: None,
                cancellation_grace_period: None,
            },
        );
        Ok(())
    }

    pub fn mark_state(
        &mut self,
        tool_call_id: &str,
        state: ToolCallRuntimeState,
    ) -> CoreResult<()> {
        let call = self
            .calls
            .get_mut(tool_call_id)
            .ok_or_else(|| CoreError::new("INFLIGHT_NOT_FOUND", tool_call_id))?;
        call.state = state;
        Ok(())
    }

    pub fn cancel(
        &mut self,
        tool_call_id: &str,
        reason: impl Into<String>,
        idempotency_key: impl Into<String>,
        grace_period: Duration,
    ) -> CancelOutcome {
        let Some(call) = self.calls.get_mut(tool_call_id) else {
            return CancelOutcome::IgnoredUnknown;
        };
        if call.state == ToolCallRuntimeState::Terminal {
            return CancelOutcome::IgnoredTerminal;
        }

        call.state = ToolCallRuntimeState::Cancelling;
        call.cancellation_token.cancel(reason);
        call.cancellation_idempotency_key = Some(idempotency_key.into());
        call.cancellation_grace_period = Some(grace_period);
        CancelOutcome::Accepted
    }

    pub fn mark_terminal(&mut self, tool_call_id: &str) -> CoreResult<()> {
        self.mark_state(tool_call_id, ToolCallRuntimeState::Terminal)
    }

    pub fn can_emit_output(&self, tool_call_id: &str) -> bool {
        self.calls
            .get(tool_call_id)
            .map(|call| {
                matches!(
                    call.state,
                    ToolCallRuntimeState::Accepted
                        | ToolCallRuntimeState::WaitingForApproval
                        | ToolCallRuntimeState::Running
                ) && !call.cancellation_token.is_cancelled()
            })
            .unwrap_or(false)
    }

    pub fn pending_approval_count(&self) -> usize {
        self.calls
            .values()
            .filter(|call| call.state == ToolCallRuntimeState::WaitingForApproval)
            .count()
    }

    pub fn active_count(&self) -> usize {
        self.calls
            .values()
            .filter(|call| call.state != ToolCallRuntimeState::Terminal)
            .count()
    }

    pub fn has_active(&self) -> bool {
        self.active_count() > 0
    }

    pub fn active_tool_call_ids(&self) -> Vec<String> {
        self.calls
            .values()
            .filter(|call| call.state != ToolCallRuntimeState::Terminal)
            .map(|call| call.tool_call_id.clone())
            .collect()
    }
}

impl Default for InflightToolCallRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownMode {
    Graceful,
    Emergency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownCoordinator {
    mode: Option<ShutdownMode>,
    safe_cleanup_complete: bool,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        Self {
            mode: None,
            safe_cleanup_complete: false,
        }
    }

    pub fn graceful_shutdown(&mut self, inflight: &InflightToolCallRegistry) -> bool {
        self.mode = Some(ShutdownMode::Graceful);
        self.safe_cleanup_complete = !inflight.has_active();
        self.safe_cleanup_complete
    }

    pub fn mark_safe_cleanup_complete(&mut self) {
        self.safe_cleanup_complete = true;
    }

    pub fn emergency_stop(&mut self) {
        self.mode = Some(ShutdownMode::Emergency);
        self.safe_cleanup_complete = true;
    }

    pub fn blocks_new_calls(&self) -> bool {
        self.mode.is_some()
    }

    pub fn is_draining(&self) -> bool {
        matches!(self.mode, Some(ShutdownMode::Graceful)) && !self.safe_cleanup_complete
    }

    pub fn is_emergency_stopped(&self) -> bool {
        matches!(self.mode, Some(ShutdownMode::Emergency))
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transition_table_covers_required_states() {
        let mut machine = RunnerStateMachine::new();
        assert_eq!("not_authenticated", machine.state().as_str());
        machine
            .transition(RunnerLifecycleEvent::Authenticated)
            .unwrap();
        machine
            .transition(RunnerLifecycleEvent::ProjectBound)
            .unwrap();
        machine
            .transition(RunnerLifecycleEvent::ConnectStarted)
            .unwrap();
        machine.transition(RunnerLifecycleEvent::Connected).unwrap();
        machine
            .transition(RunnerLifecycleEvent::ToolCallStarted)
            .unwrap();
        machine
            .transition(RunnerLifecycleEvent::ApprovalRequired)
            .unwrap();
        assert_eq!(RunnerLifecycleState::ApprovalRequired, machine.state());
        machine
            .transition(RunnerLifecycleEvent::Disconnected)
            .unwrap();
        assert_eq!(RunnerLifecycleState::Disconnected, machine.state());
    }

    #[test]
    fn invalid_state_transition_is_rejected() {
        let mut machine = RunnerStateMachine::new();
        assert_eq!(
            "RUNNER_STATE_TRANSITION_INVALID",
            machine
                .transition(RunnerLifecycleEvent::Connected)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn reconnect_after_server_restart_uses_resume_positions_and_backoff() {
        let mut reconnect = ReconnectState::new(ReconnectPolicy {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            max_attempts: 3,
        });
        reconnect.record_disconnect(42, 7);

        let first = reconnect.next_attempt().unwrap();
        let second = reconnect.next_attempt().unwrap();
        let third = reconnect.next_attempt().unwrap();

        assert_eq!(1, first.attempt);
        assert_eq!(Duration::from_secs(1), first.delay);
        assert_eq!(Duration::from_secs(2), second.delay);
        assert_eq!(Duration::from_secs(4), third.delay);
        assert_eq!(42, first.resume_after_server_sequence);
        assert_eq!(7, first.last_received_runner_sequence);
    }

    #[test]
    fn cancel_shell_command_sets_token_and_blocks_output() {
        let mut registry = InflightToolCallRegistry::new();
        registry
            .insert(
                "tool_123".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::Running,
            )
            .unwrap();

        let outcome = registry.cancel(
            "tool_123",
            "user requested cancel",
            "cancel_123",
            Duration::from_secs(2),
        );

        assert_eq!(CancelOutcome::Accepted, outcome);
        assert!(!registry.can_emit_output("tool_123"));
    }

    #[test]
    fn cancel_during_approval_is_deterministic() {
        let mut registry = InflightToolCallRegistry::new();
        registry
            .insert(
                "tool_123".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::WaitingForApproval,
            )
            .unwrap();

        assert_eq!(
            CancelOutcome::Accepted,
            registry.cancel(
                "tool_123",
                "cancel during approval",
                "cancel_approval_123",
                Duration::from_secs(1),
            )
        );
        assert_eq!(0, registry.pending_approval_count());
    }

    #[test]
    fn cancel_after_completed_call_is_ignored() {
        let mut registry = InflightToolCallRegistry::new();
        registry
            .insert(
                "tool_123".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::Terminal,
            )
            .unwrap();

        assert_eq!(
            CancelOutcome::IgnoredTerminal,
            registry.cancel(
                "tool_123",
                "late cancel",
                "cancel_late",
                Duration::from_secs(1)
            )
        );
    }

    #[test]
    fn graceful_shutdown_waits_for_safe_cleanup() {
        let mut registry = InflightToolCallRegistry::new();
        registry
            .insert(
                "tool_123".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::Running,
            )
            .unwrap();
        let mut shutdown = ShutdownCoordinator::new();

        assert!(!shutdown.graceful_shutdown(&registry));
        assert!(shutdown.is_draining());
        registry.mark_terminal("tool_123").unwrap();
        shutdown.mark_safe_cleanup_complete();
        assert!(!shutdown.is_draining());
    }

    #[test]
    fn active_tool_call_ids_exclude_terminal_calls() {
        let mut registry = InflightToolCallRegistry::new();
        registry
            .insert(
                "tool_123".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::Running,
            )
            .unwrap();
        registry
            .insert(
                "tool_done".to_string(),
                "run_123".to_string(),
                1,
                ToolCallRuntimeState::Terminal,
            )
            .unwrap();

        assert_eq!(
            vec!["tool_123".to_string()],
            registry.active_tool_call_ids()
        );
    }

    #[test]
    fn emergency_stop_blocks_new_calls() {
        let mut shutdown = ShutdownCoordinator::new();
        shutdown.emergency_stop();
        assert!(shutdown.blocks_new_calls());
        assert!(shutdown.is_emergency_stopped());
    }
}
