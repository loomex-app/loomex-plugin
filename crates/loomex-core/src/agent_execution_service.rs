//! Shared, synchronous orchestration for authoritative plugin-agent tasks.
//!
//! Transport callers own threading/async scheduling. This service owns the safety-critical order:
//! exact binding validation, durable claim, progress journaling, local runtime invocation,
//! immediate session checkpointing, and one typed execution outcome.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use loomex_protocol::agent_runtime_v2::{
    AgentAttemptRetryV2, AgentAttemptState, AgentAttemptV2, AgentDeliveryRouteV2, AgentErrorCode,
    AgentExecutionBindingV2, AgentExecutionState, AgentExecutionV2, AgentProcessDeliveryV2,
    AgentProcessDispatchV2, AgentProcessRetryKindV2, AgentProvider, AgentRetryDisposition,
    AgentRuntimeErrorEnvelopeV2, AgentSessionCheckpointV2, AgentSessionState, AgentTaskRequestV2,
    ExecutorKind, ModelSelectionMode, AGENT_EXECUTION_SCHEMA_V2, AGENT_PROCESS_DISPATCH_SCHEMA_V2,
    AGENT_SESSION_SCHEMA_V2,
};
use loomex_protocol::{validate_agent_terminal_execution, validate_agent_terminal_output};

use crate::execution::agent_journal::{AgentPendingDeliveryKind, PersistedAgentAttempt};
use crate::{
    agent_runtime::{
        runtime_error, AgentRuntimeObserver, CancellationToken, LocalAgentRuntime, RuntimeConfig,
        RuntimeErrorContext, RuntimeExecutionResult, SessionDiscovery,
    },
    execution::{
        sha256_payload_digest, AgentDeliveryRoute, AgentExecutionClaim, AgentExecutionClaimOutcome,
        AgentExecutionJournal, AgentExecutionJournalEntry, AgentExecutionReplay, AgentProcessLoss,
        AgentResumeExpectation, CancelRequestOutcome,
    },
    CoreError, CoreResult,
};

const MAX_ACTIVE_AGENT_EXECUTIONS: usize = 8;
// Backend currently caps the complete runner-job terminal request at 8,000,000 bytes. Keep the
// serialized output comfortably below that wire ceiling for the execution envelope and wrapper.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentExecutionServiceOutcome {
    /// This invocation advanced the durable execution and returns its complete current envelope.
    Executed(AgentExecutionV2),
    /// The identical request was already claimed. No process was spawned by this invocation.
    ///
    /// The journal deliberately does not persist prompt/output content, so cross-restart replay
    /// returns durable metadata rather than inventing an `AgentOutput`.
    Replay(AgentExecutionReplay),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCancellationResult {
    pub outcome: CancelRequestOutcome,
    pub execution: AgentExecutionReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentExecutionIdentity {
    pub execution_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub retry_kind: AgentProcessRetryKindV2,
    pub from_attempt_id: Option<String>,
    pub delivery: AgentProcessDeliveryV2,
    /// Per-process immutable task key from AgentProcessDispatchV2.
    pub task_idempotency_key: String,
    /// Per-process terminal delivery key from AgentProcessDispatchV2.
    pub delivery_idempotency_key: String,
    /// Backend-authoritative lowercase SHA-256 over the complete canonical task JSON.
    pub payload_digest: String,
    /// Locally recomputed digest over the raw task JSON with only `continuation` removed.
    pub task_intent_digest: String,
}

impl AgentExecutionIdentity {
    pub fn validate(&self) -> CoreResult<()> {
        validate_authoritative_identity("execution id", &self.execution_id)?;
        validate_authoritative_identity("attempt id", &self.attempt_id)?;
        if let Some(from_attempt_id) = &self.from_attempt_id {
            validate_authoritative_identity("predecessor attempt id", from_attempt_id)?;
        }
        if self.attempt_number == 0 {
            return Err(CoreError::new(
                "AGENT_EXECUTION_ATTEMPT_NUMBER_INVALID",
                "authoritative process attempt number must be positive",
            ));
        }
        loomex_protocol::agent_runtime_v2::validate_agent_attempt_task_idempotency_key(
            &self.task_idempotency_key,
        )
        .map_err(|_| {
            CoreError::new(
                "AGENT_EXECUTION_TASK_IDEMPOTENCY_KEY_INVALID",
                "authoritative process task idempotency key is invalid",
            )
        })?;
        loomex_protocol::agent_runtime_v2::validate_agent_attempt_delivery_idempotency_key(
            &self.delivery_idempotency_key,
        )
        .map_err(|_| {
            CoreError::new(
                "AGENT_EXECUTION_DELIVERY_IDEMPOTENCY_KEY_INVALID",
                "authoritative process delivery idempotency key is invalid",
            )
        })?;
        if loomex_protocol::agent_runtime_v2::validate_agent_payload_digest(&self.payload_digest)
            .is_err()
        {
            return Err(CoreError::new(
                "AGENT_EXECUTION_PAYLOAD_DIGEST_INVALID",
                "authoritative payload digest must use the agent-payload-v1 SHA-256 domain",
            ));
        }
        if self.task_intent_digest.len() != 64
            || !self
                .task_intent_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CoreError::new(
                "AGENT_EXECUTION_TASK_INTENT_DIGEST_INVALID",
                "task intent digest must be a bare lowercase SHA-256 hexadecimal digest",
            ));
        }
        Ok(())
    }
}

pub enum AgentExecutionPreparation {
    /// Durable claim and active cancellation reservation are held by this background-safe handle.
    Ready(AgentClaimedExecution),
    /// An identical active/terminal operation already exists and no process may be spawned.
    Replay(AgentExecutionReplay),
    /// Startup reconciliation advanced a stale running journal entry to indeterminate.
    Reconciled(AgentExecutionV2),
}

pub struct AgentClaimedExecution {
    service: AgentExecutionService,
    request: AgentTaskRequestV2,
    identity: AgentExecutionIdentity,
    sink: Arc<dyn AgentExecutionProgressSink>,
    config: RuntimeConfig,
    workspace: PathBuf,
    token: CancellationToken,
    replay: Option<AgentExecutionReplay>,
    receipt: AgentExecutionReplay,
    reservation: Option<ActiveExecutionReservation>,
}

impl AgentClaimedExecution {
    pub fn receipt(&self) -> &AgentExecutionReplay {
        &self.receipt
    }

    /// Runs synchronously on the caller-selected thread/task. The durable claim is not repeated.
    pub fn execute(self) -> CoreResult<AgentExecutionServiceOutcome> {
        let service = self.service.clone();
        service.execute_claimed(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExecutionProgressPhase {
    Queued,
    Probing,
    Running,
    SessionCheckpointed,
    Blocked,
    Completed,
    Failed,
    Cancelled,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentExecutionProgressPayload {
    Execution(AgentExecutionV2),
    SessionCheckpoint(AgentSessionCheckpointV2),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentExecutionProgress {
    pub request_id: String,
    pub sequence: u64,
    pub phase: AgentExecutionProgressPhase,
    pub payload: AgentExecutionProgressPayload,
}

/// Receives only protocol-owned, pathless execution/checkpoint envelopes after durable commit.
pub trait AgentExecutionProgressSink: Send + Sync {
    fn on_progress(&self, progress: AgentExecutionProgress) -> CoreResult<()>;

    /// Durable transport owner for this logical execution. The route is committed
    /// atomically with the pre-spawn claim and cannot change on replay.
    fn delivery_route(&self) -> AgentDeliveryRoute {
        AgentDeliveryRoute::DirectHuman
    }

    /// Whether `on_progress` returned only after the authoritative Backend acknowledged this
    /// exact sequence. A sink may durably transfer a terminal payload to another local outbox and
    /// return `false`; the job complete/fail path then owns the final journal acknowledgement.
    fn backend_acknowledged(&self, _phase: AgentExecutionProgressPhase) -> bool {
        true
    }
}

#[derive(Debug, Default)]
struct NoopProgressSink;

impl AgentExecutionProgressSink for NoopProgressSink {
    fn on_progress(&self, _progress: AgentExecutionProgress) -> CoreResult<()> {
        Ok(())
    }
}

/// Process-local registry used to deliver cancellation concurrently with synchronous execution.
#[derive(Debug, Default)]
pub struct AgentCancellationRegistry {
    active: Mutex<BTreeMap<String, ActiveAgentExecution>>,
}

impl AgentCancellationRegistry {
    pub fn is_active(&self, request_id: &str) -> CoreResult<bool> {
        Ok(lock(&self.active, "AGENT_CANCELLATION_REGISTRY_POISONED")?.contains_key(request_id))
    }
}

#[derive(Debug, Clone)]
struct ActiveAgentExecution {
    identity: AgentExecutionIdentity,
    token: CancellationToken,
}

#[derive(Clone)]
pub struct AgentExecutionService {
    runtime: Arc<LocalAgentRuntime>,
    config: Arc<Mutex<RuntimeConfig>>,
    workspace: Arc<Mutex<PathBuf>>,
    binding: Arc<Mutex<AgentExecutionBindingV2>>,
    journal: Arc<Mutex<AgentExecutionJournal>>,
    cancellations: Arc<AgentCancellationRegistry>,
}

impl AgentExecutionService {
    pub fn new(
        runtime: Arc<LocalAgentRuntime>,
        config: Arc<Mutex<RuntimeConfig>>,
        workspace: Arc<Mutex<PathBuf>>,
        binding: Arc<Mutex<AgentExecutionBindingV2>>,
        journal: Arc<Mutex<AgentExecutionJournal>>,
    ) -> Self {
        Self::with_cancellation_registry(
            runtime,
            config,
            workspace,
            binding,
            journal,
            Arc::new(AgentCancellationRegistry::default()),
        )
    }

    pub fn with_cancellation_registry(
        runtime: Arc<LocalAgentRuntime>,
        config: Arc<Mutex<RuntimeConfig>>,
        workspace: Arc<Mutex<PathBuf>>,
        binding: Arc<Mutex<AgentExecutionBindingV2>>,
        journal: Arc<Mutex<AgentExecutionJournal>>,
        cancellations: Arc<AgentCancellationRegistry>,
    ) -> Self {
        Self {
            runtime,
            config,
            workspace,
            binding,
            journal,
            cancellations,
        }
    }

    pub fn cancellation_registry(&self) -> Arc<AgentCancellationRegistry> {
        Arc::clone(&self.cancellations)
    }

    /// Stops the locally owned provider process after transport/lease ownership loss
    /// without recording a user cancellation. The worker converges the interruption to
    /// `indeterminate`, preserving the distinction from an explicit user cancel.
    pub fn interrupt_for_lease_loss(&self, request_id: &str) -> CoreResult<()> {
        let active = lock(
            &self.cancellations.active,
            "AGENT_CANCELLATION_REGISTRY_POISONED",
        )?;
        let execution = active.get(request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTION_NOT_ACTIVE",
                "agent execution has no active local process to interrupt",
            )
        })?;
        execution.token.cancel();
        Ok(())
    }

    /// Durably fences any unacknowledged local outcome after runner lease ownership is lost.
    ///
    /// A completion that raced the lease fence is not authoritative until Backend accepts it, so
    /// this replaces both an active process and an unacknowledged local terminal with
    /// `indeterminate`.
    pub fn reconcile_lease_loss(&self, request_id: &str) -> CoreResult<AgentExecutionV2> {
        let timestamp = now();
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found during lease-loss reconciliation",
            )
        })?;
        if entry.state == AgentExecutionState::Indeterminate {
            return Ok(entry.execution_snapshot());
        }
        let sequence = next_sequence(entry)?;
        journal.mark_process_lost(
            request_id,
            sequence,
            AgentProcessLoss::Crash,
            timestamp.timestamp,
            timestamp.epoch_ms,
        )?;
        journal
            .entry(request_id)
            .map(AgentExecutionJournalEntry::execution_snapshot)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                    "lease-loss reconciliation did not preserve its journal entry",
                )
            })
    }

    /// Converges an acknowledged Backend cancellation after the local worker stopped or exceeded
    /// its bounded shutdown budget. The exact durable directive is required; local success is
    /// never released after Backend cancellation wins.
    pub fn converge_acknowledged_runner_cancellation(
        &self,
        request_id: &str,
        cancellation_id: &str,
        loss: AgentProcessLoss,
    ) -> CoreResult<Option<AgentExecutionV2>> {
        let timestamp = now();
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found during cancellation convergence",
            )
        })?;
        let acknowledged = entry
            .cancellation
            .as_ref()
            .and_then(|cancellation| cancellation.runner_directive.as_ref())
            .is_some_and(|directive| {
                directive.cancellation_id == cancellation_id && directive.acknowledged
            });
        if !acknowledged {
            return Err(CoreError::new(
                "AGENT_JOURNAL_CANCEL_ACK_REQUIRED",
                "runner cancellation convergence requires its exact durable acknowledgement",
            ));
        }
        if entry.state.is_terminal() || entry.state == AgentExecutionState::Blocked {
            return journal.reconcile_runner_cancellation_race(
                request_id,
                cancellation_id,
                timestamp.timestamp,
                timestamp.epoch_ms,
            );
        }
        let sequence = next_sequence(entry)?;
        journal.mark_process_lost(
            request_id,
            sequence,
            loss,
            timestamp.timestamp,
            timestamp.epoch_ms,
        )?;
        Ok(journal
            .entry(request_id)
            .map(AgentExecutionJournalEntry::execution_snapshot))
    }

    /// Executes one authoritative v2 task synchronously.
    ///
    /// No prompt, argv, or executable override is accepted outside `AgentTaskRequestV2` and the
    /// injected runtime configuration.
    pub fn execute(
        &self,
        request: &AgentTaskRequestV2,
        identity: AgentExecutionIdentity,
    ) -> CoreResult<AgentExecutionServiceOutcome> {
        self.execute_with_sink(request, identity, Arc::new(NoopProgressSink))
    }

    pub fn execute_with_sink(
        &self,
        request: &AgentTaskRequestV2,
        identity: AgentExecutionIdentity,
        sink: Arc<dyn AgentExecutionProgressSink>,
    ) -> CoreResult<AgentExecutionServiceOutcome> {
        match self.prepare_with_sink(request.clone(), identity, sink)? {
            AgentExecutionPreparation::Ready(claimed) => claimed.execute(),
            AgentExecutionPreparation::Replay(replay) => {
                Ok(AgentExecutionServiceOutcome::Replay(replay))
            }
            AgentExecutionPreparation::Reconciled(execution) => {
                Ok(AgentExecutionServiceOutcome::Executed(execution))
            }
        }
    }

    /// Validates and durably claims a task before returning a receipt to a fast async caller.
    ///
    /// The returned [`AgentClaimedExecution`] owns the active cancellation reservation. The caller
    /// may move it to a background thread and invoke `execute`; dropping it releases only the
    /// process-local reservation while the queued durable claim remains replay-safe.
    pub fn prepare_with_sink(
        &self,
        request: AgentTaskRequestV2,
        identity: AgentExecutionIdentity,
        sink: Arc<dyn AgentExecutionProgressSink>,
    ) -> CoreResult<AgentExecutionPreparation> {
        identity.validate()?;
        request.validate().map_err(|_| {
            CoreError::new(
                "AGENT_TASK_INVALID",
                "plugin agent task v2 failed protocol validation",
            )
        })?;
        if request.continuation.is_some() && !request.requirements.session_resume {
            return Err(CoreError::new(
                "AGENT_SESSION_RESUME_UNSUPPORTED",
                "the authoritative task does not allow session continuation",
            ));
        }
        let current_binding = lock(&self.binding, "AGENT_BINDING_POISONED")?.clone();
        if !request.is_for_binding(&current_binding) {
            return Err(CoreError::new(
                "AGENT_EXECUTION_BINDING_MISMATCH",
                "agent task binding does not exactly match this runner workspace binding",
            ));
        }
        let workspace = lock(&self.workspace, "AGENT_WORKSPACE_POISONED")?.clone();
        if !workspace.is_absolute() || !workspace.is_dir() {
            return Err(CoreError::new(
                "AGENT_WORKSPACE_INVALID",
                "bound agent workspace must be an existing absolute directory",
            ));
        }
        let config = lock(&self.config, "AGENT_RUNTIME_CONFIG_POISONED")?.clone();
        let current_time = now();
        let queued = queued_execution(&request, &identity, &current_time.timestamp);
        validate_process_dispatch(&request, &identity)?;
        let delivery_route = sink.delivery_route();
        let route_matches = match (&identity.delivery.route, &delivery_route) {
            (AgentDeliveryRouteV2::DirectControl, AgentDeliveryRoute::DirectHuman) => true,
            (AgentDeliveryRouteV2::RunnerJob, AgentDeliveryRoute::RunnerJob { job_id, .. }) => {
                identity.delivery.runner_job_id.as_deref() == Some(job_id.as_str())
            }
            _ => false,
        };
        if !route_matches {
            return Err(CoreError::new(
                "AGENT_PROCESS_DELIVERY_ROUTE_MISMATCH",
                "agent process dispatch delivery ownership does not match its local transport",
            ));
        }

        // Reservation, claim, and token registration share one lock order with cancel():
        // cancellation registry -> journal. This closes the claim/register race.
        let mut active = lock(
            &self.cancellations.active,
            "AGENT_CANCELLATION_REGISTRY_POISONED",
        )?;
        let active_duplicate = if let Some(existing) = active.get(&request.request_id) {
            if existing.identity.execution_id != identity.execution_id
                || existing.identity.attempt_id != identity.attempt_id
            {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_IDENTITY_CONFLICT",
                    "active agent execution has different authoritative execution or attempt identity",
                ));
            }
            true
        } else {
            if active.len() >= MAX_ACTIVE_AGENT_EXECUTIONS {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_CAPACITY_EXHAUSTED",
                    "the local agent execution capacity is exhausted",
                ));
            }
            false
        };
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        if request.continuation.is_some() && journal.entry(&request.request_id).is_none() {
            return Err(CoreError::new(
                "AGENT_SESSION_NOT_FOUND",
                "resume requires an existing durable execution checkpoint",
            ));
        }
        if let Some(entry) = journal.entry(&request.request_id) {
            validate_replay_identity(entry, &identity, request.continuation.is_some())?;
            if let Some(continuation) = request.continuation.as_ref() {
                if !matches!(
                    entry.state,
                    AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
                ) {
                    return Err(CoreError::new(
                        "AGENT_SESSION_RESUME_NOT_ALLOWED",
                        "continuation is valid only for a blocked or indeterminate durable execution",
                    ));
                }
                journal.validate_resume(
                    &request.request_id,
                    continuation,
                    &AgentResumeExpectation {
                        binding: request.binding.clone(),
                        executor: continuation.executor,
                        provider: continuation.provider,
                        model_key: continuation.model_key.clone(),
                        provider_model_id: continuation.provider_model_id.clone(),
                    },
                )?;
            }
        }
        let claim = journal.claim_before_spawn(AgentExecutionClaim {
            request_id: request.request_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            attempt_id: identity.attempt_id.clone(),
            attempt_number: identity.attempt_number,
            retry_kind: identity.retry_kind,
            from_attempt_id: identity.from_attempt_id.clone(),
            delivery: identity.delivery.clone(),
            task_idempotency_key: identity.task_idempotency_key.clone(),
            delivery_idempotency_key: identity.delivery_idempotency_key.clone(),
            task_intent_digest: identity.task_intent_digest.clone(),
            payload_digest: identity.payload_digest.clone(),
            binding: request.binding.clone(),
            delivery_route,
            execution: queued.clone(),
            claimed_at_epoch_ms: current_time.epoch_ms,
        })?;

        let (receipt, replay) = match claim {
            AgentExecutionClaimOutcome::Claimed(receipt) => (receipt, None),
            AgentExecutionClaimOutcome::Replay(replay) => (replay.clone(), Some(replay)),
        };
        let mut delivered_pending = false;
        if active_duplicate {
            if replay.is_none() {
                return Err(CoreError::new(
                    "AGENT_CANCELLATION_REGISTRY_INCONSISTENT",
                    "active agent reservation has no matching durable claim",
                ));
            }
            // The live owner is responsible for the exact in-flight delivery. A duplicate must
            // not race its acknowledgement and turn a healthy checkpoint into DELIVERY_NOT_FOUND.
            return Ok(AgentExecutionPreparation::Replay(receipt));
        }
        if let Some(pending) = journal.pending_delivery(&request.request_id)?.cloned() {
            delivered_pending = true;
            let (progress, terminal_execution) =
                progress_from_pending_delivery(&request.request_id, &pending)?;
            let phase = progress.phase;
            drop(journal);
            drop(active);
            sink.on_progress(progress)?;
            if sink.backend_acknowledged(phase) {
                let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
                if journal
                    .pending_delivery(&request.request_id)?
                    .is_some_and(|delivery| delivery.sequence == pending.sequence)
                {
                    journal.acknowledge_delivery(&request.request_id, pending.sequence)?;
                }
            }
            if let Some(execution) = terminal_execution {
                return Ok(AgentExecutionPreparation::Reconciled(execution));
            }
            active = lock(
                &self.cancellations.active,
                "AGENT_CANCELLATION_REGISTRY_POISONED",
            )?;
            journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        }
        if let Some(replay) = &replay {
            let Some(replay_entry) = journal.entry(&request.request_id) else {
                if journal.tombstone(&request.request_id)?.is_some() {
                    return Ok(AgentExecutionPreparation::Replay(replay.clone()));
                }
                return Err(CoreError::new(
                    "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                    "durable claim replay did not preserve its journal entry or tombstone",
                ));
            };
            validate_replay_identity(replay_entry, &identity, request.continuation.is_some())?;
            let claimed_but_not_started = replay_entry.attempt_claims.iter().any(|claim| {
                claim.attempt_id == identity.attempt_id
                    && claim.attempt_number == identity.attempt_number
            }) && !replay_entry.attempts.iter().any(|attempt| {
                attempt.attempt_id == identity.attempt_id
                    || attempt.attempt_number == identity.attempt_number
            });
            if matches!(
                replay.state,
                AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
            ) && !claimed_but_not_started
            {
                return Ok(AgentExecutionPreparation::Replay(replay.clone()));
            }
            if replay.state.is_terminal() && replay.state != AgentExecutionState::Indeterminate {
                return Ok(AgentExecutionPreparation::Replay(replay.clone()));
            }
            if replay.state == AgentExecutionState::Indeterminate && request.continuation.is_none()
            {
                return Ok(AgentExecutionPreparation::Replay(replay.clone()));
            }
            if replay.state == AgentExecutionState::Running {
                let sequence = replay
                    .last_progress_sequence
                    .checked_add(1)
                    .ok_or_else(|| {
                        CoreError::new(
                            "AGENT_JOURNAL_SEQUENCE_EXHAUSTED",
                            "agent progress sequence is exhausted",
                        )
                    })?;
                let timestamp = now();
                journal.mark_process_lost(
                    &request.request_id,
                    sequence,
                    AgentProcessLoss::Crash,
                    timestamp.timestamp,
                    timestamp.epoch_ms,
                )?;
                let execution =
                    execution_from_entry(journal.entry(&request.request_id).ok_or_else(|| {
                        CoreError::new(
                            "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                            "process-loss transition did not preserve its journal entry",
                        )
                    })?);
                drop(journal);
                drop(active);
                emit_execution_progress(
                    &self.journal,
                    sink.as_ref(),
                    AgentExecutionProgressPhase::Indeterminate,
                    execution.clone(),
                )?;
                return Ok(AgentExecutionPreparation::Reconciled(execution));
            }
        }
        let token = CancellationToken::default();
        active.insert(
            request.request_id.clone(),
            ActiveAgentExecution {
                identity: identity.clone(),
                token: token.clone(),
            },
        );
        drop(journal);
        drop(active);
        let reservation = ActiveExecutionReservation {
            request_id: request.request_id.clone(),
            registry: Arc::clone(&self.cancellations),
        };
        if replay.is_none() && !delivered_pending && identity.attempt_number == 1 {
            emit_execution_progress(
                &self.journal,
                sink.as_ref(),
                AgentExecutionProgressPhase::Queued,
                queued,
            )?;
        }

        Ok(AgentExecutionPreparation::Ready(AgentClaimedExecution {
            service: self.clone(),
            request,
            identity,
            sink,
            config,
            workspace,
            token,
            replay,
            receipt,
            reservation: Some(reservation),
        }))
    }

    fn execute_claimed(
        &self,
        mut claimed: AgentClaimedExecution,
    ) -> CoreResult<AgentExecutionServiceOutcome> {
        let _reservation = claimed.reservation.take().ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTION_RESERVATION_MISSING",
                "prepared agent execution does not own an active reservation",
            )
        })?;
        let request = &claimed.request;
        let identity = claimed.identity;
        let sink = claimed.sink;
        let config = claimed.config;
        let workspace = claimed.workspace;
        let token = claimed.token;
        let replay = claimed.replay;
        let dispatch = process_dispatch(request, &identity);
        let mut execution = self.prepare_execution(request, &identity, replay.as_ref())?;
        emit_execution_progress(
            &self.journal,
            sink.as_ref(),
            if request.continuation.is_some() {
                AgentExecutionProgressPhase::Running
            } else {
                AgentExecutionProgressPhase::Probing
            },
            execution.clone(),
        )?;
        if self.cancel_is_durable(&request.request_id)? {
            let cancelled = self.finish_cancelled(request, execution)?;
            emit_execution_progress(
                &self.journal,
                sink.as_ref(),
                AgentExecutionProgressPhase::Cancelled,
                cancelled.clone(),
            )?;
            return Ok(AgentExecutionServiceOutcome::Executed(cancelled));
        }

        let primary_executor = primary_executor(request);
        // Readiness is force-refreshed immediately before every execution. Heartbeats may use
        // cached probes, but an authoritative task must not start from stale capability state.
        let _ = self
            .runtime
            .probe_executor(primary_executor, &config, &workspace, &token, true);
        if self.cancel_is_durable(&request.request_id)? {
            let cancelled = self.finish_cancelled(request, execution)?;
            emit_execution_progress(
                &self.journal,
                sink.as_ref(),
                AgentExecutionProgressPhase::Cancelled,
                cancelled.clone(),
            )?;
            return Ok(AgentExecutionServiceOutcome::Executed(cancelled));
        }

        self.mark_running(&mut execution)?;
        emit_execution_progress(
            &self.journal,
            sink.as_ref(),
            AgentExecutionProgressPhase::Running,
            execution.clone(),
        )?;
        let shared_execution = Arc::new(Mutex::new(execution));
        let observer = Arc::new(JournalSessionObserver {
            journal: Arc::clone(&self.journal),
            execution: Arc::clone(&shared_execution),
            resumed: request.continuation.is_some(),
            sink: Arc::clone(&sink),
        });
        let runtime_result =
            self.runtime
                .execute_observed(&dispatch, &config, &workspace, &token, observer.clone());
        let mut execution = lock(&shared_execution, "AGENT_EXECUTION_STATE_POISONED")?.clone();

        // Runtime observers also use the process token to stop on checkpoint/sink failure. Only
        // the durable cancellation record identifies a user cancellation at this boundary.
        if self.cancel_is_durable(&request.request_id)? {
            let cancelled = self.finish_cancelled(request, execution)?;
            emit_execution_progress(
                &self.journal,
                sink.as_ref(),
                AgentExecutionProgressPhase::Cancelled,
                cancelled.clone(),
            )?;
            return Ok(AgentExecutionServiceOutcome::Executed(cancelled));
        }

        let final_execution = match runtime_result {
            Ok(result) => {
                if let Some(provider_session_id) = &result.provider_session_id {
                    let (model_key, provider_model_id) = result_model_identity(&result);
                    observer
                        .on_session_initialized(SessionDiscovery {
                            request_id: request.request_id.clone(),
                            provider_session_id: provider_session_id.clone(),
                            selection_index: result.selection_index,
                            executor: result.executor,
                            provider: result.provider,
                            model_key,
                            provider_model_id,
                        })
                        .map_err(|_| {
                            CoreError::new(
                                "AGENT_SESSION_CHECKPOINT_FAILED",
                                "provider session could not be durably checkpointed",
                            )
                        })?;
                    execution = lock(&shared_execution, "AGENT_EXECUTION_STATE_POISONED")?.clone();
                }
                if validate_agent_terminal_output(&result.output).is_err() {
                    self.finish_error(
                        request,
                        execution,
                        runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The agent output exceeded the bounded durable-delivery limit.",
                            RuntimeErrorContext::default(),
                        ),
                    )?
                } else {
                    self.finish_completed(request, execution, result)?
                }
            }
            Err(error) => self.finish_error(request, execution, error)?,
        };
        emit_execution_progress(
            &self.journal,
            sink.as_ref(),
            progress_phase_for_execution(final_execution.state),
            final_execution.clone(),
        )?;
        Ok(AgentExecutionServiceOutcome::Executed(final_execution))
    }

    /// Durably requests cancellation and signals an active local process, if present.
    pub fn cancel(
        &self,
        request_id: &str,
        cancellation_idempotency_key: &str,
    ) -> CoreResult<AgentCancellationResult> {
        let active = lock(
            &self.cancellations.active,
            "AGENT_CANCELLATION_REGISTRY_POISONED",
        )?;
        let token = active.get(request_id).map(|active| active.token.clone());
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        if journal.entry(request_id).is_none() {
            if let Some(tombstone) = journal.tombstone(request_id)? {
                if tombstone.cancellation_idempotency_key.as_deref()
                    == Some(cancellation_idempotency_key)
                {
                    return Ok(AgentCancellationResult {
                        outcome: CancelRequestOutcome::Replay,
                        execution: tombstone.replay_metadata(),
                    });
                }
                return Err(CoreError::new(
                    "AGENT_JOURNAL_ALREADY_TERMINAL",
                    "archived terminal execution cannot accept a cancellation request",
                ));
            }
        }
        let sequence = next_sequence(journal.entry(request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?)?;
        let timestamp = now();
        let outcome = journal.request_cancel(
            request_id,
            sequence,
            cancellation_idempotency_key,
            timestamp.epoch_ms,
        )?;
        if let Some(token) = token {
            token.cancel();
        }
        let execution = journal
            .entry(request_id)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                    "cancel transition did not preserve its journal entry",
                )
            })?
            .replay_metadata();
        drop(journal);
        drop(active);
        Ok(AgentCancellationResult { outcome, execution })
    }

    /// Durably records an authoritative Backend runner-job cancellation without signalling the
    /// process. The caller must signal the active worker and only then acknowledge the directive
    /// to Backend.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_runner_cancellation(
        &self,
        request_id: &str,
        cancellation_idempotency_key: &str,
        cancellation_id: &str,
        job_id: &str,
        process_attempt_id: &str,
        lease_version: u64,
        binding_generation: u64,
        requested_at: &str,
    ) -> CoreResult<CancelRequestOutcome> {
        let timestamp = now();
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        journal.request_runner_cancel(
            request_id,
            cancellation_idempotency_key,
            cancellation_id,
            job_id,
            process_attempt_id,
            lease_version,
            binding_generation,
            requested_at,
            timestamp.epoch_ms,
        )
    }

    /// Signals a locally owned process only when the exact authoritative directive is already
    /// durable. Absence of an active worker is safe: the durable cancellation still fences a
    /// concurrent terminal transition and restart reconciliation can re-ack the directive.
    pub fn signal_reserved_runner_cancellation(
        &self,
        request_id: &str,
        cancellation_id: &str,
    ) -> CoreResult<()> {
        let active = lock(
            &self.cancellations.active,
            "AGENT_CANCELLATION_REGISTRY_POISONED",
        )?;
        let token = active.get(request_id).map(|active| active.token.clone());
        let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?;
        let reserved = entry
            .cancellation
            .as_ref()
            .and_then(|cancellation| cancellation.runner_directive.as_ref())
            .is_some_and(|directive| directive.cancellation_id == cancellation_id);
        if !reserved {
            return Err(CoreError::new(
                "AGENT_CANCELLATION_DIRECTIVE_REQUIRED",
                "runner cancellation was not durably reserved",
            ));
        }
        drop(journal);
        if let Some(token) = token {
            token.cancel();
        }
        Ok(())
    }

    pub fn acknowledge_runner_cancellation(
        &self,
        request_id: &str,
        cancellation_id: &str,
    ) -> CoreResult<()> {
        lock(&self.journal, "AGENT_JOURNAL_POISONED")?
            .acknowledge_runner_cancel(request_id, cancellation_id)
    }

    /// Converges a durable cancellation when no live worker owns the request.
    ///
    /// Callers must reconcile any older pending progress first so the cancelled terminal keeps
    /// the externally visible sequence contiguous.
    pub fn converge_inactive_cancellation(
        &self,
        request: &AgentTaskRequestV2,
        sink: Arc<dyn AgentExecutionProgressSink>,
    ) -> CoreResult<Option<AgentExecutionV2>> {
        let request_id = &request.request_id;
        let active = lock(
            &self.cancellations.active,
            "AGENT_CANCELLATION_REGISTRY_POISONED",
        )?;
        if active.contains_key(request_id) {
            return Ok(None);
        }
        let execution = {
            let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            let entry = journal.entry(request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?;
            if entry.pending_delivery.is_some() {
                return Err(CoreError::new(
                    "AGENT_JOURNAL_DELIVERY_PENDING",
                    "older agent progress must be acknowledged before cancellation converges",
                ));
            }
            if entry.state.is_terminal() {
                return Ok(Some(execution_from_entry(entry)));
            }
            if entry.cancellation.is_none() {
                return Err(CoreError::new(
                    "AGENT_CANCELLATION_NOT_REQUESTED",
                    "inactive cancellation convergence requires durable cancellation intent",
                ));
            }
            let mut execution = execution_from_entry(entry);
            if execution.attempts.is_empty() {
                let claim = entry.attempt_claims.last().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_EXECUTION_ATTEMPT_MISSING",
                        "queued cancellation has no authoritative attempt claim",
                    )
                })?;
                let (executor, provider, model_key, provider_model_id) =
                    requested_attempt_identity(request);
                let timestamp = now().timestamp;
                execution.started_at = Some(timestamp.clone());
                execution.updated_at = timestamp.clone();
                execution.active_attempt_id = Some(claim.attempt_id.clone());
                execution.attempts.push(AgentAttemptV2 {
                    attempt_id: claim.attempt_id.clone(),
                    attempt_number: claim.attempt_number,
                    task_idempotency_key: claim.task_idempotency_key.clone(),
                    delivery_idempotency_key: claim.delivery_idempotency_key.clone(),
                    payload_digest: claim.payload_digest.clone(),
                    state: AgentAttemptState::Starting,
                    started_sequence: execution.sequence,
                    finished_sequence: None,
                    selection_index: request
                        .continuation
                        .as_ref()
                        .map_or(0, |continuation| continuation.selection_index),
                    executor,
                    provider,
                    requested_model_key: model_key.clone(),
                    requested_provider_model_id: provider_model_id.clone(),
                    resolved_model_key: model_key,
                    resolved_provider_model_id: provider_model_id,
                    started_at: timestamp,
                    finished_at: None,
                    session: None,
                    retry: match claim.retry_kind {
                        AgentProcessRetryKindV2::Initial => None,
                        retry_kind => Some(AgentAttemptRetryV2 {
                            retry_kind,
                            from_attempt_id: claim.from_attempt_id.clone().ok_or_else(|| {
                                CoreError::new(
                                    "AGENT_PROCESS_RETRY_SOURCE_INVALID",
                                    "retry process attempt is missing its predecessor attempt",
                                )
                            })?,
                            continuation: request.continuation.clone(),
                        }),
                    },
                    delivery: claim.delivery.clone(),
                    error: None,
                });
            }
            execution
        };
        drop(active);
        let cancelled = self.finish_cancelled_without_request(execution)?;
        emit_execution_progress(
            &self.journal,
            sink.as_ref(),
            AgentExecutionProgressPhase::Cancelled,
            cancelled.clone(),
        )?;
        Ok(Some(cancelled))
    }

    pub fn replay(&self, request_id: &str) -> CoreResult<AgentExecutionReplay> {
        journal_replay(&self.journal, request_id)
    }

    fn prepare_execution(
        &self,
        request: &AgentTaskRequestV2,
        identity: &AgentExecutionIdentity,
        replay: Option<&AgentExecutionReplay>,
    ) -> CoreResult<AgentExecutionV2> {
        let timestamp = now();
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal
            .entry(&request.request_id)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?
            .clone();

        if matches!(
            entry.state,
            AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
        ) && request.continuation.is_some()
        {
            let continuation = request.continuation.as_ref().ok_or_else(|| {
                CoreError::new(
                    "AGENT_SESSION_RESUME_REQUIRED",
                    "indeterminate execution requires its exact durable continuation",
                )
            })?;
            let expected = AgentResumeExpectation {
                binding: request.binding.clone(),
                executor: continuation.executor,
                provider: continuation.provider,
                model_key: continuation.model_key.clone(),
                provider_model_id: continuation.provider_model_id.clone(),
            };
            journal.validate_resume(&request.request_id, continuation, &expected)?;
            let mut execution = execution_from_entry(&entry);
            execution.state = AgentExecutionState::Running;
            execution.active_attempt_id = None;
            execution.output = None;
            execution.error = None;
            execution.finished_at = None;
            execution.updated_at = timestamp.timestamp.clone();
            let sequence = next_sequence(&entry)?;
            execution.sequence = sequence;
            let attempt_number = next_attempt_number(&execution)?;
            if attempt_number != identity.attempt_number {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_IDENTITY_CONFLICT",
                    "authoritative process attempt number is not the next logical attempt",
                ));
            }
            let attempt_id = identity.attempt_id.clone();
            let from_attempt_id = execution
                .attempts
                .iter()
                .max_by_key(|attempt| attempt.attempt_number)
                .map(|attempt| attempt.attempt_id.clone())
                .ok_or_else(|| {
                    CoreError::new(
                        "AGENT_SESSION_RESUME_MISMATCH",
                        "resume requires a durable predecessor attempt",
                    )
                })?;
            if identity.retry_kind != AgentProcessRetryKindV2::ResumeFromCheckpoint
                || identity.from_attempt_id.as_deref() != Some(from_attempt_id.as_str())
            {
                return Err(CoreError::new(
                    "AGENT_PROCESS_RETRY_SOURCE_INVALID",
                    "resume dispatch does not name the exact durable predecessor attempt",
                ));
            }
            execution.active_attempt_id = Some(attempt_id.clone());
            execution.attempts.push(AgentAttemptV2 {
                attempt_id,
                attempt_number,
                task_idempotency_key: identity.task_idempotency_key.clone(),
                delivery_idempotency_key: identity.delivery_idempotency_key.clone(),
                payload_digest: identity.payload_digest.clone(),
                state: AgentAttemptState::Starting,
                started_sequence: sequence,
                finished_sequence: None,
                selection_index: continuation.selection_index,
                executor: continuation.executor,
                provider: continuation.provider,
                requested_model_key: continuation.model_key.clone(),
                requested_provider_model_id: continuation.provider_model_id.clone(),
                resolved_model_key: continuation.model_key.clone(),
                resolved_provider_model_id: continuation.provider_model_id.clone(),
                started_at: timestamp.timestamp.clone(),
                finished_at: None,
                session: None,
                retry: Some(AgentAttemptRetryV2 {
                    retry_kind: identity.retry_kind,
                    from_attempt_id,
                    continuation: Some(continuation.clone()),
                }),
                delivery: identity.delivery.clone(),
                error: None,
            });
            journal.reopen_indeterminate_for_resume(
                &request.request_id,
                sequence,
                &execution,
                timestamp.epoch_ms,
            )?;
            return Ok(execution);
        }
        if request.continuation.is_some() {
            return Err(CoreError::new(
                "AGENT_SESSION_RESUME_NOT_ALLOWED",
                "continuation is valid only for a blocked or indeterminate durable execution",
            ));
        }

        let mut execution = execution_from_entry(&entry);
        match entry.state {
            AgentExecutionState::Queued | AgentExecutionState::Blocked => {
                execution.state = AgentExecutionState::Probing;
                execution.output = None;
                execution.error = None;
                execution.finished_at = None;
                execution
                    .started_at
                    .get_or_insert_with(|| timestamp.timestamp.clone());
                execution.updated_at = timestamp.timestamp.clone();
                let sequence = next_sequence(&entry)?;
                execution.sequence = sequence;
                let attempt_number = next_attempt_number(&execution)?;
                if attempt_number != identity.attempt_number {
                    return Err(CoreError::new(
                        "AGENT_EXECUTION_IDENTITY_CONFLICT",
                        "authoritative process attempt number is not the next logical attempt",
                    ));
                }
                let attempt_id = identity.attempt_id.clone();
                let (executor, provider, model_key, provider_model_id) =
                    requested_attempt_identity(request);
                let retry = match entry.state {
                    AgentExecutionState::Queued
                        if identity.retry_kind == AgentProcessRetryKindV2::Initial
                            && identity.from_attempt_id.is_none() =>
                    {
                        None
                    }
                    AgentExecutionState::Blocked
                        if identity.retry_kind
                            == AgentProcessRetryKindV2::FreshAfterRemediation =>
                    {
                        let predecessor = execution
                            .attempts
                            .iter()
                            .max_by_key(|attempt| attempt.attempt_number)
                            .map(|attempt| attempt.attempt_id.clone())
                            .ok_or_else(|| {
                                CoreError::new(
                                    "AGENT_PROCESS_RETRY_SOURCE_INVALID",
                                    "fresh remediation retry has no durable predecessor attempt",
                                )
                            })?;
                        if identity.from_attempt_id.as_deref() != Some(predecessor.as_str()) {
                            return Err(CoreError::new(
                                "AGENT_PROCESS_RETRY_SOURCE_INVALID",
                                "fresh remediation retry does not name the exact predecessor attempt",
                            ));
                        }
                        Some(AgentAttemptRetryV2 {
                            retry_kind: identity.retry_kind,
                            from_attempt_id: predecessor,
                            continuation: None,
                        })
                    }
                    _ => {
                        return Err(CoreError::new(
                            "AGENT_PROCESS_RETRY_SOURCE_INVALID",
                            "process retry kind is invalid for the durable execution state",
                        ))
                    }
                };
                execution.active_attempt_id = Some(attempt_id.clone());
                execution.attempts.push(AgentAttemptV2 {
                    attempt_id,
                    attempt_number,
                    task_idempotency_key: identity.task_idempotency_key.clone(),
                    delivery_idempotency_key: identity.delivery_idempotency_key.clone(),
                    payload_digest: identity.payload_digest.clone(),
                    state: AgentAttemptState::Probing,
                    started_sequence: sequence,
                    finished_sequence: None,
                    selection_index: request
                        .continuation
                        .as_ref()
                        .map_or(0, |continuation| continuation.selection_index),
                    executor,
                    provider,
                    requested_model_key: model_key.clone(),
                    requested_provider_model_id: provider_model_id.clone(),
                    resolved_model_key: model_key,
                    resolved_provider_model_id: provider_model_id,
                    started_at: timestamp.timestamp.clone(),
                    finished_at: None,
                    session: None,
                    retry,
                    delivery: identity.delivery.clone(),
                    error: None,
                });
                journal.record_execution_with_delivery(
                    &request.request_id,
                    sequence,
                    &execution,
                    serde_json::to_value(&execution).map_err(|_| {
                        CoreError::new(
                            "AGENT_PROGRESS_SERIALIZATION_FAILED",
                            "probing agent execution could not be serialized",
                        )
                    })?,
                    timestamp.epoch_ms,
                )?;
            }
            AgentExecutionState::Probing => {
                // A stale probing state is safe to repeat: no agent invocation was recorded.
            }
            AgentExecutionState::Completed
            | AgentExecutionState::Failed
            | AgentExecutionState::Cancelled => {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_ALREADY_TERMINAL",
                    "terminal execution cannot be started again",
                ))
            }
            AgentExecutionState::Running => {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_INDETERMINATE",
                    "running execution without an active token must be reconciled",
                ))
            }
            AgentExecutionState::Indeterminate => {
                return Err(CoreError::new(
                    "AGENT_EXECUTION_INDETERMINATE",
                    "indeterminate execution must be resumed through its exact durable checkpoint",
                ))
            }
        }
        let _ = replay;
        Ok(execution)
    }

    fn mark_running(&self, execution: &mut AgentExecutionV2) -> CoreResult<()> {
        let timestamp = now();
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let sequence = next_sequence(journal.entry(&execution.request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?)?;
        execution.sequence = sequence;
        execution.state = AgentExecutionState::Running;
        execution.error = None;
        execution.finished_at = None;
        execution.updated_at = timestamp.timestamp.clone();
        let attempt = active_attempt_mut(execution)?;
        attempt.state = AgentAttemptState::Running;
        attempt.error = None;
        attempt.finished_at = None;
        journal.record_execution_with_delivery(
            &execution.request_id,
            sequence,
            execution,
            serde_json::to_value(&*execution).map_err(|_| {
                CoreError::new(
                    "AGENT_PROGRESS_SERIALIZATION_FAILED",
                    "running agent execution could not be serialized",
                )
            })?,
            timestamp.epoch_ms,
        )
    }

    fn finish_completed(
        &self,
        request: &AgentTaskRequestV2,
        mut execution: AgentExecutionV2,
        result: RuntimeExecutionResult,
    ) -> CoreResult<AgentExecutionV2> {
        let running_execution = execution.clone();
        let timestamp = now();
        let sequence = {
            let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            next_sequence(journal.entry(&execution.request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?)?
        };
        execution.sequence = sequence;
        execution.state = AgentExecutionState::Completed;
        execution.active_attempt_id = None;
        execution.output = Some(result.output);
        execution.error = None;
        execution.finished_at = Some(timestamp.timestamp.clone());
        execution.updated_at = timestamp.timestamp.clone();
        let attempt = latest_attempt_mut(&mut execution)?;
        attempt.state = AgentAttemptState::Completed;
        attempt.finished_sequence = Some(sequence);
        attempt.selection_index = result.selection_index;
        attempt.executor = result.executor;
        attempt.provider = result.provider;
        if let Some(model) = result.model {
            attempt.requested_model_key = Some(model.model_key.clone());
            attempt.requested_provider_model_id = Some(model.provider_model_id.clone());
            attempt.resolved_model_key = Some(model.model_key);
            attempt.resolved_provider_model_id = Some(model.provider_model_id);
        }
        attempt.finished_at = Some(timestamp.timestamp.clone());
        attempt.error = None;
        attach_current_checkpoint(&self.journal, &mut execution)?;
        execution.validate().map_err(|error| {
            CoreError::new(
                "AGENT_EXECUTION_INVALID",
                format!("completed agent execution envelope failed validation: {error:?}"),
            )
        })?;
        if validate_agent_terminal_execution(&execution).is_err() {
            return self.finish_error(
                request,
                running_execution,
                runtime_error(
                    AgentErrorCode::OutputInvalid,
                    "The complete agent execution exceeded the bounded durable-delivery limit.",
                    RuntimeErrorContext::default(),
                ),
            );
        }

        if self.record_terminal_respecting_cancel(&execution, timestamp.epoch_ms)? {
            return self.finish_cancelled_without_request(execution);
        }
        Ok(execution)
    }

    fn finish_error(
        &self,
        request: &AgentTaskRequestV2,
        mut execution: AgentExecutionV2,
        mut error: AgentRuntimeErrorEnvelopeV2,
    ) -> CoreResult<AgentExecutionV2> {
        if self.cancel_is_durable(&request.request_id)? {
            return self.finish_cancelled(request, execution);
        }
        if error.code == AgentErrorCode::Cancelled {
            let mut lease_error = runtime_error(
                AgentErrorCode::ExecutionIndeterminate,
                "The local provider process stopped after runner lease ownership was lost.",
                RuntimeErrorContext::default(),
            );
            lease_error
                .context
                .safe_details
                .insert("processLoss".to_string(), "lease_lost".to_string());
            error = lease_error;
        }
        enrich_error(&mut error, &execution);
        if error.code == AgentErrorCode::ExecutionIndeterminate {
            let process_loss = if error
                .context
                .safe_details
                .get("processLoss")
                .is_some_and(|reason| reason == "timeout")
            {
                AgentProcessLoss::Timeout
            } else {
                AgentProcessLoss::Crash
            };
            let timestamp = now();
            let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            let sequence = next_sequence(journal.entry(&request.request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?)?;
            journal.mark_process_lost(
                &request.request_id,
                sequence,
                process_loss,
                timestamp.timestamp,
                timestamp.epoch_ms,
            )?;
            return Ok(execution_from_entry(
                journal.entry(&request.request_id).ok_or_else(|| {
                    CoreError::new(
                        "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                        "process-loss transition did not preserve its journal entry",
                    )
                })?,
            ));
        }

        let timestamp = now();
        let blocked = error.retry == AgentRetryDisposition::UserActionRequired;
        let sequence = {
            let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            next_sequence(journal.entry(&execution.request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?)?
        };
        execution.sequence = sequence;
        execution.state = if blocked {
            AgentExecutionState::Blocked
        } else {
            AgentExecutionState::Failed
        };
        execution.error = Some(error.clone());
        execution.output = None;
        execution.updated_at = timestamp.timestamp.clone();
        execution.active_attempt_id = None;
        if blocked {
            execution.finished_at = None;
        } else {
            execution.finished_at = Some(timestamp.timestamp.clone());
        }
        let attempt = latest_attempt_mut(&mut execution)?;
        attempt.state = if blocked {
            AgentAttemptState::Blocked
        } else {
            AgentAttemptState::Failed
        };
        attempt.finished_sequence = Some(sequence);
        attempt.error = Some(error);
        attempt.finished_at = Some(timestamp.timestamp.clone());
        attach_current_checkpoint(&self.journal, &mut execution)?;
        execution.validate().map_err(|_| {
            CoreError::new(
                "AGENT_EXECUTION_INVALID",
                "failed agent execution envelope failed validation",
            )
        })?;
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let expected_sequence =
            next_sequence(journal.entry(&request.request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?)?;
        if expected_sequence != sequence {
            return Err(CoreError::new(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "agent execution sequence changed before durable commit",
            ));
        }
        let delivery = serde_json::to_value(&execution).map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_SERIALIZATION_FAILED",
                "agent execution could not be serialized for durable delivery",
            )
        })?;
        journal.record_execution_with_delivery(
            &request.request_id,
            sequence,
            &execution,
            delivery,
            timestamp.epoch_ms,
        )?;
        Ok(execution)
    }

    fn finish_cancelled(
        &self,
        request: &AgentTaskRequestV2,
        execution: AgentExecutionV2,
    ) -> CoreResult<AgentExecutionV2> {
        let _ = request;
        self.finish_cancelled_without_request(execution)
    }

    fn finish_cancelled_without_request(
        &self,
        mut execution: AgentExecutionV2,
    ) -> CoreResult<AgentExecutionV2> {
        let timestamp = now();
        let sequence = {
            let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            let entry = journal.entry(&execution.request_id).ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?;
            if entry.state == AgentExecutionState::Cancelled {
                return Ok(execution_from_entry(entry));
            }
            next_sequence(entry)?
        };
        let mut error = runtime_error(
            AgentErrorCode::Cancelled,
            "The local agent execution was cancelled.",
            RuntimeErrorContext::default(),
        );
        enrich_error(&mut error, &execution);
        execution.sequence = sequence;
        execution.state = AgentExecutionState::Cancelled;
        execution.active_attempt_id = None;
        execution.output = None;
        execution.error = Some(error.clone());
        execution.finished_at = Some(timestamp.timestamp.clone());
        execution.updated_at = timestamp.timestamp.clone();
        ensure_cancel_attempt(&mut execution, Some(error), &timestamp.timestamp, sequence);
        attach_current_checkpoint(&self.journal, &mut execution)?;
        execution.validate().map_err(|_| {
            CoreError::new(
                "AGENT_EXECUTION_INVALID",
                "cancelled agent execution envelope failed validation",
            )
        })?;
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(&execution.request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?;
        if next_sequence(entry)? != sequence {
            return Err(CoreError::new(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "agent cancellation sequence changed before durable commit",
            ));
        }
        let delivery = serde_json::to_value(&execution).map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_SERIALIZATION_FAILED",
                "cancelled agent execution could not be serialized for durable delivery",
            )
        })?;
        journal.record_execution_with_delivery(
            &execution.request_id,
            sequence,
            &execution,
            delivery,
            timestamp.epoch_ms,
        )?;
        Ok(execution)
    }

    fn cancel_is_durable(&self, request_id: &str) -> CoreResult<bool> {
        let journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        Ok(journal
            .entry(request_id)
            .is_some_and(|entry| entry.cancellation.is_some()))
    }

    /// Returns true when a durable cancellation won the race and no terminal was recorded.
    fn record_terminal_respecting_cancel(
        &self,
        execution: &AgentExecutionV2,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<bool> {
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(&execution.request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?;
        if entry.cancellation.is_some() {
            return Ok(true);
        }
        let sequence = next_sequence(entry)?;
        if execution.sequence != sequence {
            return Err(CoreError::new(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "terminal agent execution sequence changed before durable commit",
            ));
        }
        let delivery = serde_json::to_value(execution).map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_SERIALIZATION_FAILED",
                "terminal agent execution could not be serialized for durable delivery",
            )
        })?;
        journal.record_execution_with_delivery(
            &execution.request_id,
            sequence,
            execution,
            delivery,
            recorded_at_epoch_ms,
        )?;
        Ok(false)
    }
}

struct ActiveExecutionReservation {
    request_id: String,
    registry: Arc<AgentCancellationRegistry>,
}

impl Drop for ActiveExecutionReservation {
    fn drop(&mut self) {
        if let Ok(mut active) = self.registry.active.lock() {
            active.remove(&self.request_id);
        }
    }
}

struct JournalSessionObserver {
    journal: Arc<Mutex<AgentExecutionJournal>>,
    execution: Arc<Mutex<AgentExecutionV2>>,
    resumed: bool,
    sink: Arc<dyn AgentExecutionProgressSink>,
}

impl AgentRuntimeObserver for JournalSessionObserver {
    fn on_session_initialized(
        &self,
        session: SessionDiscovery,
    ) -> Result<(), AgentRuntimeErrorEnvelopeV2> {
        self.checkpoint(session).map_err(|_| {
            runtime_error(
                AgentErrorCode::ExecutionIndeterminate,
                "The provider session started but its durable checkpoint could not be committed.",
                RuntimeErrorContext::default(),
            )
        })
    }
}

impl JournalSessionObserver {
    fn checkpoint(&self, session: SessionDiscovery) -> CoreResult<()> {
        let timestamp = now();
        let mut execution = lock(&self.execution, "AGENT_EXECUTION_STATE_POISONED")?;
        let attempt = active_attempt_mut(&mut execution)?;
        if attempt.executor != session.executor
            || attempt.provider != session.provider
            || attempt.selection_index != session.selection_index
            || attempt.resolved_model_key != session.model_key
            || attempt.resolved_provider_model_id != session.provider_model_id
        {
            attempt.executor = session.executor;
            attempt.provider = session.provider;
            attempt.selection_index = session.selection_index;
            attempt.resolved_model_key = session.model_key.clone();
            attempt.resolved_provider_model_id = session.provider_model_id.clone();
            execution.updated_at = timestamp.timestamp.clone();
        }

        let attempt_id = execution.active_attempt_id.clone().ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTION_ATTEMPT_MISSING",
                "session checkpoint requires an active attempt",
            )
        })?;
        let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
        let entry = journal.entry(&session.request_id).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?;
        if let Some(existing) = &entry.session_checkpoint {
            if existing.provider_session_id == session.provider_session_id
                && existing.attempt_id == attempt_id
            {
                if let Some(attempt) = execution
                    .attempts
                    .iter_mut()
                    .find(|attempt| attempt.attempt_id == attempt_id)
                {
                    attempt.session = Some(existing.clone());
                }
                return Ok(());
            }
        }
        let sequence = next_sequence(entry)?;
        execution.sequence = sequence;
        let stable_session_id = entry
            .session_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.session_id.clone())
            .unwrap_or_else(|| {
                stable_id(
                    "session",
                    &format!("{}:{}", execution.execution_id, session.provider_session_id),
                )
            });
        let checkpoint = AgentSessionCheckpointV2 {
            schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: stable_id(
                "checkpoint",
                &format!("{}:{attempt_id}", execution.execution_id),
            ),
            sequence,
            session_id: stable_session_id,
            provider_session_id: session.provider_session_id,
            binding: execution.binding.clone(),
            execution_id: execution.execution_id.clone(),
            attempt_id: attempt_id.clone(),
            selection_index: session.selection_index,
            executor: session.executor,
            provider: session.provider,
            model_key: session.model_key,
            provider_model_id: session.provider_model_id,
            state: AgentSessionState::Active,
            recorded_at: timestamp.timestamp,
        };
        let delivery = serde_json::to_value(&checkpoint).map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_SERIALIZATION_FAILED",
                "agent checkpoint could not be serialized for durable delivery",
            )
        })?;
        if self.resumed && entry.session_checkpoint.is_some() {
            journal.checkpoint_resumed_session_with_delivery(
                &session.request_id,
                sequence,
                checkpoint.clone(),
                delivery,
                timestamp.epoch_ms,
            )?;
        } else {
            journal.checkpoint_initialized_session_with_delivery(
                &session.request_id,
                sequence,
                checkpoint.clone(),
                delivery,
                timestamp.epoch_ms,
            )?;
        }
        if let Some(attempt) = execution
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == attempt_id)
        {
            attempt.session = Some(checkpoint);
        }
        let persisted_checkpoint = execution
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == attempt_id)
            .and_then(|attempt| attempt.session.clone())
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_SESSION_CHECKPOINT_INCONSISTENT",
                    "durable checkpoint was not attached to the active attempt",
                )
            })?;
        let request_id = session.request_id;
        let progress = AgentExecutionProgress {
            request_id: request_id.clone(),
            sequence,
            phase: AgentExecutionProgressPhase::SessionCheckpointed,
            payload: AgentExecutionProgressPayload::SessionCheckpoint(persisted_checkpoint),
        };
        drop(journal);
        drop(execution);
        self.sink.on_progress(progress)?;
        if self
            .sink
            .backend_acknowledged(AgentExecutionProgressPhase::SessionCheckpointed)
        {
            let mut journal = lock(&self.journal, "AGENT_JOURNAL_POISONED")?;
            if journal
                .pending_delivery(&request_id)?
                .is_some_and(|delivery| delivery.sequence == sequence)
            {
                journal.acknowledge_delivery(&request_id, sequence)?;
            }
        }
        Ok(())
    }
}

fn queued_execution(
    request: &AgentTaskRequestV2,
    identity: &AgentExecutionIdentity,
    timestamp: &str,
) -> AgentExecutionV2 {
    AgentExecutionV2 {
        schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
        execution_id: identity.execution_id.clone(),
        request_id: request.request_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        sequence: 1,
        binding: request.binding.clone(),
        state: AgentExecutionState::Queued,
        active_attempt_id: None,
        attempts: Vec::new(),
        output: None,
        error: None,
        created_at: timestamp.to_string(),
        started_at: None,
        finished_at: None,
        updated_at: timestamp.to_string(),
    }
}

fn process_dispatch(
    request: &AgentTaskRequestV2,
    identity: &AgentExecutionIdentity,
) -> AgentProcessDispatchV2 {
    AgentProcessDispatchV2 {
        schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
        execution_id: identity.execution_id.clone(),
        attempt_id: identity.attempt_id.clone(),
        attempt_number: identity.attempt_number,
        retry_kind: identity.retry_kind,
        from_attempt_id: identity.from_attempt_id.clone(),
        delivery: identity.delivery.clone(),
        task_idempotency_key: identity.task_idempotency_key.clone(),
        delivery_idempotency_key: identity.delivery_idempotency_key.clone(),
        payload_digest: identity.payload_digest.clone(),
        task: request.clone(),
    }
}

fn validate_process_dispatch(
    request: &AgentTaskRequestV2,
    identity: &AgentExecutionIdentity,
) -> CoreResult<()> {
    let dispatch = process_dispatch(request, identity);
    dispatch.validate().map_err(|_| {
        CoreError::new(
            "AGENT_PROCESS_DISPATCH_INVALID",
            "authoritative agent process dispatch failed protocol validation",
        )
    })?;
    let mut value = serde_json::to_value(&dispatch).map_err(|_| {
        CoreError::new(
            "AGENT_PROCESS_DISPATCH_INVALID",
            "authoritative agent process dispatch could not be canonicalized",
        )
    })?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_PROCESS_DISPATCH_INVALID",
                "authoritative agent process dispatch must be an object",
            )
        })?
        .remove("payloadDigest");
    let digest = crate::execution::canonical_json_payload_digest(&value)?;
    if !crate::execution::constant_time_digest_eq(&digest, &identity.payload_digest) {
        return Err(CoreError::new(
            "AGENT_PROCESS_DISPATCH_DIGEST_MISMATCH",
            "authoritative agent process dispatch changed after Backend digesting",
        ));
    }
    Ok(())
}

fn validate_replay_identity(
    entry: &AgentExecutionJournalEntry,
    identity: &AgentExecutionIdentity,
    is_resume: bool,
) -> CoreResult<()> {
    if entry.execution_id != identity.execution_id {
        return Err(CoreError::new(
            "AGENT_EXECUTION_IDENTITY_CONFLICT",
            "durable execution id differs from the authoritative Backend execution id",
        ));
    }
    let latest = latest_persisted_attempt(entry);
    let attempt_is_valid = match entry.state {
        AgentExecutionState::Queued => true,
        AgentExecutionState::Blocked => latest.is_none_or(|attempt| {
            attempt.attempt_id == identity.attempt_id
                || !entry
                    .attempts
                    .iter()
                    .any(|existing| existing.attempt_id == identity.attempt_id)
        }),
        AgentExecutionState::Indeterminate if is_resume => !entry
            .attempts
            .iter()
            .any(|existing| existing.attempt_id == identity.attempt_id),
        AgentExecutionState::Indeterminate => true,
        AgentExecutionState::Probing
        | AgentExecutionState::Running
        | AgentExecutionState::Completed
        | AgentExecutionState::Failed
        | AgentExecutionState::Cancelled => {
            latest.is_some_and(|attempt| attempt.attempt_id == identity.attempt_id)
        }
    };
    if !attempt_is_valid {
        return Err(CoreError::new(
            "AGENT_EXECUTION_IDENTITY_CONFLICT",
            "durable attempt history differs from the authoritative Backend attempt id",
        ));
    }
    Ok(())
}

fn latest_persisted_attempt(entry: &AgentExecutionJournalEntry) -> Option<&PersistedAgentAttempt> {
    entry
        .attempts
        .iter()
        .max_by_key(|attempt| attempt.attempt_number)
}

fn validate_authoritative_identity(label: &str, value: &str) -> CoreResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        });
    if valid {
        Ok(())
    } else {
        Err(CoreError::new(
            "AGENT_EXECUTION_IDENTITY_INVALID",
            format!("{label} is not a valid authoritative non-secret identifier"),
        ))
    }
}

fn execution_from_entry(entry: &AgentExecutionJournalEntry) -> AgentExecutionV2 {
    let checkpoint = entry.session_checkpoint.as_ref();
    AgentExecutionV2 {
        schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
        execution_id: entry.execution_id.clone(),
        request_id: entry.request_id.clone(),
        idempotency_key: entry.idempotency_key.clone(),
        sequence: entry.last_progress_sequence,
        binding: entry.binding.clone(),
        state: entry.state,
        active_attempt_id: entry.active_attempt_id.clone(),
        attempts: entry
            .attempts
            .iter()
            .map(|attempt| attempt_from_persisted(attempt, checkpoint))
            .collect(),
        output: None,
        error: entry.error.clone(),
        created_at: entry.created_at.clone(),
        started_at: entry.started_at.clone(),
        finished_at: entry.finished_at.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

fn attempt_from_persisted(
    attempt: &PersistedAgentAttempt,
    checkpoint: Option<&AgentSessionCheckpointV2>,
) -> AgentAttemptV2 {
    AgentAttemptV2 {
        attempt_id: attempt.attempt_id.clone(),
        attempt_number: attempt.attempt_number,
        task_idempotency_key: attempt.task_idempotency_key.clone(),
        delivery_idempotency_key: attempt.delivery_idempotency_key.clone(),
        payload_digest: attempt.payload_digest.clone(),
        state: attempt.state,
        started_sequence: attempt.started_sequence,
        finished_sequence: attempt.finished_sequence,
        selection_index: attempt.selection_index,
        executor: attempt.executor,
        provider: attempt.provider,
        requested_model_key: attempt.requested_model_key.clone(),
        requested_provider_model_id: attempt.requested_provider_model_id.clone(),
        resolved_model_key: attempt.resolved_model_key.clone(),
        resolved_provider_model_id: attempt.resolved_provider_model_id.clone(),
        started_at: attempt.started_at.clone(),
        finished_at: attempt.finished_at.clone(),
        session: attempt.session.clone().or_else(|| {
            checkpoint
                .filter(|checkpoint| checkpoint.attempt_id == attempt.attempt_id)
                .cloned()
        }),
        retry: attempt.retry.clone(),
        delivery: attempt.delivery.clone(),
        error: attempt.error.clone(),
    }
}

fn requested_attempt_identity(
    request: &AgentTaskRequestV2,
) -> (ExecutorKind, AgentProvider, Option<String>, Option<String>) {
    match &request.selection.primary {
        ModelSelectionMode::Exact { target } => (
            target.executor,
            target.provider,
            Some(target.model_key.clone()),
            Some(target.provider_model_id.clone()),
        ),
        ModelSelectionMode::Auto { executor, provider } => (*executor, *provider, None, None),
    }
}

fn primary_executor(request: &AgentTaskRequestV2) -> ExecutorKind {
    match &request.selection.primary {
        ModelSelectionMode::Exact { target } => target.executor,
        ModelSelectionMode::Auto { executor, .. } => *executor,
    }
}

fn result_model_identity(result: &RuntimeExecutionResult) -> (Option<String>, Option<String>) {
    result
        .model
        .as_ref()
        .map(|model| {
            (
                Some(model.model_key.clone()),
                Some(model.provider_model_id.clone()),
            )
        })
        .unwrap_or((None, None))
}

fn next_attempt_number(execution: &AgentExecutionV2) -> CoreResult<u32> {
    execution
        .attempts
        .iter()
        .map(|attempt| attempt.attempt_number)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_ATTEMPT_EXHAUSTED",
                "agent attempt number is exhausted",
            )
        })
}

fn active_attempt_mut(execution: &mut AgentExecutionV2) -> CoreResult<&mut AgentAttemptV2> {
    let active_id = execution.active_attempt_id.clone().ok_or_else(|| {
        CoreError::new(
            "AGENT_EXECUTION_ATTEMPT_MISSING",
            "agent execution has no active attempt",
        )
    })?;
    execution
        .attempts
        .iter_mut()
        .find(|attempt| attempt.attempt_id == active_id)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTION_ATTEMPT_MISSING",
                "active agent attempt is not present",
            )
        })
}

fn latest_attempt_mut(execution: &mut AgentExecutionV2) -> CoreResult<&mut AgentAttemptV2> {
    execution
        .attempts
        .iter_mut()
        .max_by_key(|attempt| attempt.attempt_number)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTION_ATTEMPT_MISSING",
                "agent execution has no attempt",
            )
        })
}

fn ensure_cancel_attempt(
    execution: &mut AgentExecutionV2,
    error: Option<AgentRuntimeErrorEnvelopeV2>,
    timestamp: &str,
    sequence: u64,
) {
    if let Some(attempt) = execution
        .attempts
        .iter_mut()
        .max_by_key(|attempt| attempt.attempt_number)
    {
        attempt.state = AgentAttemptState::Cancelled;
        attempt.finished_sequence = Some(sequence);
        attempt.finished_at = Some(timestamp.to_string());
        attempt.error = error;
    }
}

fn enrich_error(error: &mut AgentRuntimeErrorEnvelopeV2, execution: &AgentExecutionV2) {
    error.context.execution_id = Some(execution.execution_id.clone());
    error.context.attempt_id = execution
        .attempts
        .iter()
        .max_by_key(|attempt| attempt.attempt_number)
        .map(|attempt| attempt.attempt_id.clone());
}

fn attach_current_checkpoint(
    journal: &Arc<Mutex<AgentExecutionJournal>>,
    execution: &mut AgentExecutionV2,
) -> CoreResult<()> {
    let checkpoint = lock(journal, "AGENT_JOURNAL_POISONED")?
        .entry(&execution.request_id)
        .and_then(|entry| entry.session_checkpoint.clone());
    if let Some(checkpoint) = checkpoint {
        if let Some(attempt) = execution
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
        {
            attempt.session = Some(checkpoint);
        }
    }
    Ok(())
}

fn next_sequence(entry: &AgentExecutionJournalEntry) -> CoreResult<u64> {
    entry.last_progress_sequence.checked_add(1).ok_or_else(|| {
        CoreError::new(
            "AGENT_JOURNAL_SEQUENCE_EXHAUSTED",
            "agent progress sequence is exhausted",
        )
    })
}

fn journal_replay(
    journal: &Arc<Mutex<AgentExecutionJournal>>,
    request_id: &str,
) -> CoreResult<AgentExecutionReplay> {
    let journal = lock(journal, "AGENT_JOURNAL_POISONED")?;
    if let Some(entry) = journal.entry(request_id) {
        return Ok(entry.replay_metadata());
    }
    if let Some(tombstone) = journal.tombstone(request_id)? {
        return Ok(tombstone.replay_metadata());
    }
    Err(CoreError::new(
        "AGENT_JOURNAL_NOT_FOUND",
        "agent execution journal entry or tombstone was not found",
    ))
}

fn progress_from_pending_delivery(
    request_id: &str,
    pending: &crate::execution::agent_journal::AgentPendingDelivery,
) -> CoreResult<(AgentExecutionProgress, Option<AgentExecutionV2>)> {
    match pending.kind {
        AgentPendingDeliveryKind::Checkpoint => {
            let checkpoint: AgentSessionCheckpointV2 =
                serde_json::from_value(pending.payload.clone()).map_err(|_| {
                    CoreError::new(
                        "AGENT_JOURNAL_DELIVERY_INVALID",
                        "durable checkpoint delivery payload is invalid",
                    )
                })?;
            Ok((
                AgentExecutionProgress {
                    request_id: request_id.to_string(),
                    sequence: pending.sequence,
                    phase: AgentExecutionProgressPhase::SessionCheckpointed,
                    payload: AgentExecutionProgressPayload::SessionCheckpoint(checkpoint),
                },
                None,
            ))
        }
        AgentPendingDeliveryKind::Execution
        | AgentPendingDeliveryKind::Deferred
        | AgentPendingDeliveryKind::Terminal => {
            let execution: AgentExecutionV2 = serde_json::from_value(pending.payload.clone())
                .map_err(|_| {
                    CoreError::new(
                        "AGENT_JOURNAL_DELIVERY_INVALID",
                        "durable terminal delivery payload is invalid",
                    )
                })?;
            let phase = progress_phase_for_execution(execution.state);
            let kind_matches_state = match pending.kind {
                AgentPendingDeliveryKind::Execution => {
                    !execution.state.is_terminal()
                        && execution.state != AgentExecutionState::Blocked
                }
                AgentPendingDeliveryKind::Deferred => {
                    execution.state == AgentExecutionState::Blocked
                }
                AgentPendingDeliveryKind::Terminal => execution.state.is_terminal(),
                AgentPendingDeliveryKind::Checkpoint => unreachable!(),
            };
            if !kind_matches_state
                || execution.request_id != request_id
                || (pending.kind == AgentPendingDeliveryKind::Terminal
                    && !matches!(
                        phase,
                        AgentExecutionProgressPhase::Completed
                            | AgentExecutionProgressPhase::Failed
                            | AgentExecutionProgressPhase::Cancelled
                            | AgentExecutionProgressPhase::Indeterminate
                    ))
            {
                return Err(CoreError::new(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "durable terminal delivery identity or state is invalid",
                ));
            }
            Ok((
                AgentExecutionProgress {
                    request_id: request_id.to_string(),
                    sequence: pending.sequence,
                    phase,
                    payload: AgentExecutionProgressPayload::Execution(execution.clone()),
                },
                matches!(
                    pending.kind,
                    AgentPendingDeliveryKind::Deferred | AgentPendingDeliveryKind::Terminal
                )
                .then_some(execution),
            ))
        }
    }
}

fn emit_execution_progress(
    journal: &Arc<Mutex<AgentExecutionJournal>>,
    sink: &dyn AgentExecutionProgressSink,
    phase: AgentExecutionProgressPhase,
    execution: AgentExecutionV2,
) -> CoreResult<()> {
    let sequence = {
        let journal = lock(journal, "AGENT_JOURNAL_POISONED")?;
        journal
            .entry(&execution.request_id)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })?
            .last_progress_sequence
    };
    let request_id = execution.request_id.clone();
    sink.on_progress(AgentExecutionProgress {
        request_id: request_id.clone(),
        sequence,
        phase,
        payload: AgentExecutionProgressPayload::Execution(execution),
    })?;
    if sink.backend_acknowledged(phase) {
        let mut journal = lock(journal, "AGENT_JOURNAL_POISONED")?;
        if journal
            .pending_delivery(&request_id)?
            .is_some_and(|delivery| delivery.sequence == sequence)
        {
            journal.acknowledge_delivery(&request_id, sequence)?;
        }
    }
    Ok(())
}

fn progress_phase_for_execution(state: AgentExecutionState) -> AgentExecutionProgressPhase {
    match state {
        AgentExecutionState::Queued => AgentExecutionProgressPhase::Queued,
        AgentExecutionState::Probing => AgentExecutionProgressPhase::Probing,
        AgentExecutionState::Running => AgentExecutionProgressPhase::Running,
        AgentExecutionState::Blocked => AgentExecutionProgressPhase::Blocked,
        AgentExecutionState::Completed => AgentExecutionProgressPhase::Completed,
        AgentExecutionState::Failed => AgentExecutionProgressPhase::Failed,
        AgentExecutionState::Cancelled => AgentExecutionProgressPhase::Cancelled,
        AgentExecutionState::Indeterminate => AgentExecutionProgressPhase::Indeterminate,
    }
}

fn stable_id(prefix: &str, source: &str) -> String {
    let digest = sha256_payload_digest(source.as_bytes());
    format!(
        "{prefix}-{}",
        &digest["sha256:".len()..("sha256:".len() + 32)]
    )
}

fn lock<'a, T>(mutex: &'a Mutex<T>, code: &'static str) -> CoreResult<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| CoreError::new(code, "shared agent execution state is poisoned"))
}

struct Timestamp {
    epoch_ms: u64,
    timestamp: String,
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let epoch_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
    Timestamp {
        epoch_ms: epoch_ms.max(1),
        timestamp: rfc3339_utc(duration.as_secs(), duration.subsec_millis()),
    }
}

// Howard Hinnant's civil-from-days conversion, adapted to keep the core runtime dependency-free.
fn rfc3339_utc(epoch_seconds: u64, milliseconds: u32) -> String {
    let days = (epoch_seconds / 86_400) as i64;
    let seconds = epoch_seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use loomex_protocol::agent_runtime_v2::{
        AgentExecutionRequirements, AgentRemediationAction, AgentSessionContinuationV2,
        ModelFallbackPolicy, ModelSelection, ModelTarget, ReasoningEffort, AGENT_TASK_SCHEMA_V2,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        sync::Condvar,
        thread,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<AgentExecutionProgress>>,
    }

    impl AgentExecutionProgressSink for RecordingSink {
        fn on_progress(&self, progress: AgentExecutionProgress) -> CoreResult<()> {
            self.events.lock().unwrap().push(progress);
            Ok(())
        }
    }

    #[derive(Default)]
    struct BlockingCheckpointSink {
        events: Mutex<Vec<AgentExecutionProgress>>,
        checkpoint_reached: (Mutex<bool>, Condvar),
        checkpoint_release: (Mutex<bool>, Condvar),
    }

    impl AgentExecutionProgressSink for BlockingCheckpointSink {
        fn on_progress(&self, progress: AgentExecutionProgress) -> CoreResult<()> {
            let checkpointed = progress.phase == AgentExecutionProgressPhase::SessionCheckpointed;
            self.events.lock().unwrap().push(progress);
            if checkpointed {
                let (reached, notify) = &self.checkpoint_reached;
                *reached.lock().unwrap() = true;
                notify.notify_all();
                let (release, wait) = &self.checkpoint_release;
                let mut released = release.lock().unwrap();
                while !*released {
                    released = wait.wait(released).unwrap();
                }
            }
            Ok(())
        }
    }

    struct TestEnvironment {
        root: PathBuf,
        journal: Arc<Mutex<AgentExecutionJournal>>,
        service: AgentExecutionService,
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "loomex-agent-service-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn binding() -> AgentExecutionBindingV2 {
        AgentExecutionBindingV2 {
            workspace_binding_id: "binding_test".to_string(),
            workspace_binding_generation: 4,
            runner_id: "runner_test".to_string(),
        }
    }

    fn request(request_id: &str) -> AgentTaskRequestV2 {
        AgentTaskRequestV2 {
            schema_version: AGENT_TASK_SCHEMA_V2.to_string(),
            request_id: request_id.to_string(),
            idempotency_key: format!("idem_{request_id}"),
            binding: binding(),
            selection: ModelSelection {
                primary: ModelSelectionMode::Exact {
                    target: ModelTarget {
                        executor: ExecutorKind::CodexCli,
                        provider: AgentProvider::OpenAi,
                        model_key: "openai/test-model".to_string(),
                        provider_model_id: "test-model".to_string(),
                    },
                },
                fallback: ModelFallbackPolicy::None,
            },
            prompt: "perform the test task".to_string(),
            output_schema: None,
            requirements: AgentExecutionRequirements {
                structured_output: false,
                session_resume: true,
                cancellation: true,
                reasoning_effort: Some(ReasoningEffort::Low),
            },
            continuation: None,
        }
    }

    fn identity(
        request: &AgentTaskRequestV2,
        execution_id: &str,
        attempt_id: &str,
    ) -> AgentExecutionIdentity {
        identity_for_process(
            request,
            execution_id,
            attempt_id,
            1,
            AgentProcessRetryKindV2::Initial,
            None,
        )
    }

    fn identity_for_process(
        request: &AgentTaskRequestV2,
        execution_id: &str,
        attempt_id: &str,
        attempt_number: u32,
        retry_kind: AgentProcessRetryKindV2,
        from_attempt_id: Option<String>,
    ) -> AgentExecutionIdentity {
        let task = serde_json::to_value(request).unwrap();
        let mut task_intent = task.clone();
        if let Some(object) = task_intent.as_object_mut() {
            object.remove("continuation");
        }
        let task_hash = sha256_payload_digest(
            &loomex_protocol::agent_runtime_v2::agent_attempt_task_idempotency_preimage(
                execution_id,
                attempt_number,
            ),
        );
        let task_idempotency_key = format!(
            "loomex-agent-attempt-v2:{}",
            task_hash.strip_prefix("sha256:").unwrap()
        );
        let delivery_hash = sha256_payload_digest(
            &loomex_protocol::agent_runtime_v2::agent_attempt_delivery_idempotency_preimage(
                execution_id,
                attempt_number,
            ),
        );
        let delivery_idempotency_key = format!(
            "loomex-agent-delivery-v2:{}",
            delivery_hash.strip_prefix("sha256:").unwrap()
        );
        let mut dispatch = AgentProcessDispatchV2 {
            schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
            execution_id: execution_id.to_string(),
            attempt_id: attempt_id.to_string(),
            attempt_number,
            retry_kind,
            from_attempt_id: from_attempt_id.clone(),
            delivery: AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
            task_idempotency_key: task_idempotency_key.clone(),
            delivery_idempotency_key: delivery_idempotency_key.clone(),
            payload_digest: format!("sha256:{}", "0".repeat(64)),
            task: request.clone(),
        };
        dispatch.payload_digest = crate::execution::canonical_json_payload_digest(
            &dispatch.payload_digest_input().unwrap(),
        )
        .unwrap();
        AgentExecutionIdentity {
            execution_id: execution_id.to_string(),
            attempt_id: attempt_id.to_string(),
            attempt_number,
            retry_kind,
            from_attempt_id,
            delivery: AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
            task_idempotency_key,
            delivery_idempotency_key,
            payload_digest: dispatch.payload_digest,
            task_intent_digest: crate::execution::canonical_agent_task_payload_digest(&task_intent)
                .unwrap(),
        }
    }

    fn write_executable(root: &Path, body: &str) -> PathBuf {
        let path = root.join("fake-codex");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn environment(label: &str, executable: Option<PathBuf>) -> TestEnvironment {
        let root = executable
            .as_ref()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| test_root(label));
        let journal = Arc::new(Mutex::new(
            AgentExecutionJournal::open(root.join("agent-journal.json")).unwrap(),
        ));
        let mut config = RuntimeConfig::default();
        if let Some(executable) = executable {
            config
                .executables
                .insert(ExecutorKind::CodexCli, executable);
        }
        config.execution_limits.timeout = Duration::from_secs(15);
        config.execution_limits.poll_interval = Duration::from_millis(5);
        config.execution_limits.terminate_grace = Duration::from_millis(20);
        config.probe_limits.timeout = Duration::from_secs(10);
        config.probe_limits.poll_interval = Duration::from_millis(5);
        let service = AgentExecutionService::new(
            Arc::new(LocalAgentRuntime::default()),
            Arc::new(Mutex::new(config)),
            Arc::new(Mutex::new(root.clone())),
            Arc::new(Mutex::new(binding())),
            Arc::clone(&journal),
        );
        TestEnvironment {
            root,
            journal,
            service,
        }
    }

    fn success_script(counter: &Path) -> String {
        format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 0.144.0"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
printf x >> '{}'
printf '%s\n' '{{"thread_id":"provider-session-1"}}'
printf '%s\n' '{{"item":{{"text":"done"}}}}'
"#,
            counter.display()
        )
    }

    fn acknowledged_running_cancellation(
        label: &str,
    ) -> (TestEnvironment, AgentTaskRequestV2, String) {
        struct RunnerSink {
            job_id: String,
        }
        impl AgentExecutionProgressSink for RunnerSink {
            fn delivery_route(&self) -> AgentDeliveryRoute {
                AgentDeliveryRoute::RunnerJob {
                    job_id: self.job_id.clone(),
                    predecessor_job_id: None,
                }
            }

            fn on_progress(&self, _progress: AgentExecutionProgress) -> CoreResult<()> {
                Ok(())
            }
        }

        let env = environment(label, None);
        let task = request(&format!("request_{label}"));
        let job_id = "51111111-1111-4111-8111-111111111111";
        let cancellation_id = "52222222-2222-4222-8222-222222222222".to_string();
        let mut backend_identity = identity(
            &task,
            "53333333-3333-4333-8333-333333333333",
            "54444444-4444-4444-8444-444444444444",
        );
        backend_identity.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(job_id.to_string()),
            lease_target_runner_id: Some(task.binding.runner_id.clone()),
        };
        let mut dispatch = process_dispatch(&task, &backend_identity);
        dispatch.payload_digest = format!("sha256:{}", "0".repeat(64));
        backend_identity.payload_digest = crate::execution::canonical_json_payload_digest(
            &dispatch.payload_digest_input().unwrap(),
        )
        .unwrap();
        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(
                task.clone(),
                backend_identity.clone(),
                Arc::new(RunnerSink {
                    job_id: job_id.to_string(),
                }),
            )
            .unwrap()
        else {
            panic!("test cancellation must acquire a durable claim");
        };
        drop(claimed);
        let mut execution = env
            .service
            .prepare_execution(&task, &backend_identity, None)
            .unwrap();
        {
            let mut journal = env.journal.lock().unwrap();
            let sequence = journal
                .entry(&task.request_id)
                .and_then(|entry| entry.pending_delivery.as_ref())
                .map(|delivery| delivery.sequence)
                .unwrap();
            journal
                .acknowledge_delivery(&task.request_id, sequence)
                .unwrap();
        }
        env.service.mark_running(&mut execution).unwrap();
        {
            let mut journal = env.journal.lock().unwrap();
            let sequence = journal
                .entry(&task.request_id)
                .and_then(|entry| entry.pending_delivery.as_ref())
                .map(|delivery| delivery.sequence)
                .unwrap();
            journal
                .acknowledge_delivery(&task.request_id, sequence)
                .unwrap();
        }
        env.service
            .reserve_runner_cancellation(
                &task.request_id,
                "backend-cancel:52222222-2222-4222-8222-222222222222",
                &cancellation_id,
                job_id,
                &backend_identity.attempt_id,
                1,
                task.binding.workspace_binding_generation,
                "2026-07-27T00:00:01Z",
            )
            .unwrap();
        env.service
            .acknowledge_runner_cancellation(&task.request_id, &cancellation_id)
            .unwrap();
        (env, task, cancellation_id)
    }

    #[test]
    fn durable_prepare_replays_conflicts_and_checkpoints_before_terminal() {
        let root = test_root("claim-replay");
        let counter = root.join("spawn-count");
        let executable = write_executable(&root, &success_script(&counter));
        let env = environment("claim-replay", Some(executable));
        let sink = Arc::new(RecordingSink::default());
        let task = request("request_claim");
        let backend_identity = identity(
            &task,
            "11111111-1111-4111-8111-111111111111",
            "21111111-1111-4111-8111-111111111111",
        );

        let preparation = env
            .service
            .prepare_with_sink(task.clone(), backend_identity.clone(), sink.clone())
            .unwrap();
        let AgentExecutionPreparation::Ready(claimed) = preparation else {
            panic!("first request must receive a durable claimed handle");
        };
        assert_eq!(AgentExecutionState::Queued, claimed.receipt().state);
        assert!(!counter.exists(), "prepare must not spawn any process");
        assert_eq!(
            AgentExecutionState::Queued,
            env.journal
                .lock()
                .unwrap()
                .entry(&task.request_id)
                .unwrap()
                .state
        );

        let duplicate = env
            .service
            .prepare_with_sink(task.clone(), backend_identity.clone(), sink.clone())
            .unwrap();
        assert!(matches!(duplicate, AgentExecutionPreparation::Replay(_)));
        let mut active_payload_conflict = task.clone();
        active_payload_conflict.prompt = "different active prompt".to_string();
        let active_payload_identity = identity(
            &active_payload_conflict,
            &backend_identity.execution_id,
            &backend_identity.attempt_id,
        );
        let active_payload_error = match env.service.prepare_with_sink(
            active_payload_conflict,
            active_payload_identity,
            sink.clone(),
        ) {
            Ok(_) => panic!("different active payload must conflict"),
            Err(error) => error,
        };
        assert_eq!(
            "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
            active_payload_error.code
        );
        let identity_conflict = match env.service.prepare_with_sink(
            task.clone(),
            identity(
                &task,
                &backend_identity.execution_id,
                "21111111-1111-4111-8111-222222222222",
            ),
            sink.clone(),
        ) {
            Ok(_) => panic!("different active Backend attempt id must conflict"),
            Err(error) => error,
        };
        assert_eq!("AGENT_EXECUTION_IDENTITY_CONFLICT", identity_conflict.code);

        let AgentExecutionServiceOutcome::Executed(completed) = claimed.execute().unwrap() else {
            panic!("claimed execution must run exactly once");
        };
        assert_eq!(AgentExecutionState::Completed, completed.state);
        assert_eq!(backend_identity.execution_id, completed.execution_id);
        assert_eq!(
            backend_identity.attempt_id,
            completed.attempts[0].attempt_id
        );
        assert_eq!(
            backend_identity.execution_id,
            completed.attempts[0].session.as_ref().unwrap().execution_id
        );
        assert_eq!(
            backend_identity.attempt_id,
            completed.attempts[0].session.as_ref().unwrap().attempt_id
        );
        assert_eq!("x", fs::read_to_string(&counter).unwrap());

        let replay = env
            .service
            .execute(&task, backend_identity.clone())
            .unwrap();
        assert!(matches!(replay, AgentExecutionServiceOutcome::Replay(_)));
        assert_eq!("x", fs::read_to_string(&counter).unwrap());

        let mut conflicting = task.clone();
        conflicting.prompt = "different immutable prompt".to_string();
        let conflicting_identity = identity(
            &conflicting,
            &backend_identity.execution_id,
            &backend_identity.attempt_id,
        );
        let error = env
            .service
            .execute(&conflicting, conflicting_identity)
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_IDEMPOTENCY_CONFLICT", error.code);

        let events = sink.events.lock().unwrap();
        assert!(events
            .windows(2)
            .all(|window| window[0].sequence < window[1].sequence));
        let checkpoint_index = events
            .iter()
            .position(|event| event.phase == AgentExecutionProgressPhase::SessionCheckpointed)
            .unwrap();
        let completed_index = events
            .iter()
            .position(|event| event.phase == AgentExecutionProgressPhase::Completed)
            .unwrap();
        assert!(checkpoint_index < completed_index);
        let journal = env.journal.lock().unwrap();
        let tombstone = journal.tombstone(&task.request_id).unwrap().unwrap();
        assert_eq!(
            tombstone.terminal_sequence,
            events[completed_index].sequence
        );
    }

    #[test]
    fn active_duplicate_does_not_race_checkpoint_delivery_acknowledgement() {
        let root = test_root("checkpoint-duplicate-race");
        let counter = root.join("spawn-count");
        let executable = write_executable(&root, &success_script(&counter));
        let env = environment("checkpoint-duplicate-race", Some(executable));
        let sink = Arc::new(BlockingCheckpointSink::default());
        let task = request("request_checkpoint_duplicate");
        let backend_identity = identity(
            &task,
            "11999999-9999-4999-8999-999999999999",
            "21999999-9999-4999-8999-999999999999",
        );
        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(task.clone(), backend_identity.clone(), sink.clone())
            .unwrap()
        else {
            panic!("first request must own the active execution");
        };

        let worker = thread::spawn(move || claimed.execute());
        {
            let (reached, wait) = &sink.checkpoint_reached;
            let mut checkpointed = reached.lock().unwrap();
            while !*checkpointed {
                checkpointed = wait.wait(checkpointed).unwrap();
            }
        }
        assert!(env
            .journal
            .lock()
            .unwrap()
            .pending_delivery(&task.request_id)
            .unwrap()
            .is_some());

        let duplicate = env
            .service
            .prepare_with_sink(task.clone(), backend_identity, sink.clone())
            .unwrap();
        assert!(matches!(duplicate, AgentExecutionPreparation::Replay(_)));
        assert!(env
            .journal
            .lock()
            .unwrap()
            .pending_delivery(&task.request_id)
            .unwrap()
            .is_some());

        {
            let (release, notify) = &sink.checkpoint_release;
            *release.lock().unwrap() = true;
            notify.notify_all();
        }
        let AgentExecutionServiceOutcome::Executed(execution) = worker.join().unwrap().unwrap()
        else {
            panic!("the original execution must complete");
        };
        assert_eq!(AgentExecutionState::Completed, execution.state);
        assert_eq!("x", fs::read_to_string(&counter).unwrap());
        assert!(env
            .journal
            .lock()
            .unwrap()
            .pending_delivery(&task.request_id)
            .unwrap()
            .is_none());
        assert_eq!(
            1,
            sink.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| { event.phase == AgentExecutionProgressPhase::SessionCheckpointed })
                .count()
        );
    }

    #[test]
    fn inactive_queued_cancellation_converges_without_spawning() {
        let root = test_root("inactive-cancel");
        let counter = root.join("spawn-count");
        let executable = write_executable(&root, &success_script(&counter));
        let env = environment("inactive-cancel", Some(executable));
        let sink = Arc::new(RecordingSink::default());
        let task = request("request_inactive_cancel");
        let backend_identity = identity(
            &task,
            "11888888-8888-4888-8888-888888888888",
            "21888888-8888-4888-8888-888888888888",
        );
        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(task.clone(), backend_identity, sink.clone())
            .unwrap()
        else {
            panic!("request must be durably queued");
        };
        drop(claimed);
        env.service
            .cancel(&task.request_id, "cancel-after-restart")
            .unwrap();
        let cancelled = env
            .service
            .converge_inactive_cancellation(&task, sink.clone())
            .unwrap()
            .expect("inactive cancellation must terminalize");
        assert_eq!(AgentExecutionState::Cancelled, cancelled.state);
        assert!(
            !counter.exists(),
            "cancellation must not spawn the provider"
        );
        assert!(env
            .journal
            .lock()
            .unwrap()
            .pending_delivery(&task.request_id)
            .unwrap()
            .is_none());
        let sequences = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        assert_eq!(vec![1, 2], sequences);
    }

    #[test]
    fn missing_executor_returns_typed_blocked_execution() {
        let env = environment("blocked", None);
        let task = request("request_blocked");
        let backend_identity = identity(
            &task,
            "12222222-2222-4222-8222-222222222222",
            "22222222-2222-4222-8222-222222222222",
        );
        let AgentExecutionServiceOutcome::Executed(blocked) = env
            .service
            .execute(&task, backend_identity.clone())
            .unwrap()
        else {
            panic!("missing executor must advance to blocked");
        };
        assert_eq!(AgentExecutionState::Blocked, blocked.state);
        assert_eq!(backend_identity.execution_id, blocked.execution_id);
        assert_eq!(backend_identity.attempt_id, blocked.attempts[0].attempt_id);
        assert_eq!(
            Some(backend_identity.execution_id.as_str()),
            blocked
                .error
                .as_ref()
                .unwrap()
                .context
                .execution_id
                .as_deref()
        );
        assert_eq!(
            Some(backend_identity.attempt_id.as_str()),
            blocked
                .error
                .as_ref()
                .unwrap()
                .context
                .attempt_id
                .as_deref()
        );
        assert_eq!(
            AgentErrorCode::ProviderNotInstalled,
            blocked.error.as_ref().unwrap().code
        );
        assert_eq!(
            AgentRetryDisposition::UserActionRequired,
            blocked.error.as_ref().unwrap().retry
        );
    }

    #[test]
    fn fresh_remediation_claim_recovers_pre_spawn_without_duplicate_spawn() {
        let root = test_root("fresh-remediation");
        let counter = root.join("spawn-count");
        let env = environment("fresh-remediation", None);
        let task = request("request_fresh_remediation");
        let initial_identity = identity(
            &task,
            "13333333-3333-4333-8333-333333333333",
            "23333333-3333-4333-8333-333333333333",
        );
        let AgentExecutionServiceOutcome::Executed(blocked) = env
            .service
            .execute(&task, initial_identity.clone())
            .unwrap()
        else {
            panic!("missing executor must block the initial process");
        };
        assert_eq!(AgentExecutionState::Blocked, blocked.state);

        let executable = write_executable(&root, &success_script(&counter));
        env.service
            .config
            .lock()
            .unwrap()
            .executables
            .insert(ExecutorKind::CodexCli, executable);
        let retry_identity = identity_for_process(
            &task,
            &initial_identity.execution_id,
            "23333333-3333-4333-8333-444444444444",
            2,
            AgentProcessRetryKindV2::FreshAfterRemediation,
            Some(initial_identity.attempt_id.clone()),
        );

        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(
                task.clone(),
                retry_identity.clone(),
                Arc::new(NoopProgressSink),
            )
            .unwrap()
        else {
            panic!("fresh successor must acquire a durable process claim");
        };
        // Simulate restart after the successor claim fsync but before the lifecycle attempt/spawn
        // fence. The same exact claim is safe to recover exactly once.
        drop(claimed);
        let AgentExecutionServiceOutcome::Executed(completed) =
            env.service.execute(&task, retry_identity.clone()).unwrap()
        else {
            panic!("claimed-but-not-started fresh successor must execute");
        };
        assert_eq!(AgentExecutionState::Completed, completed.state);
        assert_eq!(2, completed.attempts.len());
        assert_eq!("x", fs::read_to_string(&counter).unwrap());

        assert!(matches!(
            env.service.execute(&task, retry_identity).unwrap(),
            AgentExecutionServiceOutcome::Replay(_)
        ));
        assert_eq!("x", fs::read_to_string(counter).unwrap());
    }

    #[test]
    fn concurrent_cancel_stops_process_and_records_cancelled() {
        let root = test_root("cancel");
        let marker = root.join("started");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 0.144.0"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
printf started > '{}'
sleep 10
printf '%s\n' '{{"item":{{"text":"too late"}}}}'
"#,
            marker.display()
        );
        let executable = write_executable(&root, &script);
        let env = environment("cancel", Some(executable));
        let task = request("request_cancel");
        let backend_identity = identity(
            &task,
            "13333333-3333-4333-8333-333333333333",
            "23333333-3333-4333-8333-333333333333",
        );
        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(
                task.clone(),
                backend_identity.clone(),
                Arc::new(NoopProgressSink),
            )
            .unwrap()
        else {
            panic!("cancel test requires claimed execution");
        };
        let worker = thread::spawn(move || claimed.execute().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "fake process did not start");
        let cancellation = env.service.cancel(&task.request_id, "cancel_once").unwrap();
        assert_eq!(CancelRequestOutcome::Requested, cancellation.outcome);
        let AgentExecutionServiceOutcome::Executed(cancelled) = worker.join().unwrap() else {
            panic!("cancelled worker must return its terminal execution");
        };
        assert_eq!(AgentExecutionState::Cancelled, cancelled.state);
        assert_eq!(backend_identity.execution_id, cancelled.execution_id);
        assert_eq!(
            backend_identity.attempt_id,
            cancelled.attempts[0].attempt_id
        );
        assert_eq!(
            AgentErrorCode::Cancelled,
            cancelled.error.as_ref().unwrap().code
        );
        assert_eq!(
            CancelRequestOutcome::Replay,
            env.service
                .cancel(&task.request_id, "cancel_once")
                .unwrap()
                .outcome
        );
    }

    #[test]
    fn lease_loss_supersedes_unacknowledged_local_completion_with_indeterminate() {
        struct PendingTerminalSink;
        impl AgentExecutionProgressSink for PendingTerminalSink {
            fn on_progress(&self, _progress: AgentExecutionProgress) -> CoreResult<()> {
                Ok(())
            }

            fn backend_acknowledged(&self, phase: AgentExecutionProgressPhase) -> bool {
                !matches!(
                    phase,
                    AgentExecutionProgressPhase::Completed
                        | AgentExecutionProgressPhase::Failed
                        | AgentExecutionProgressPhase::Cancelled
                        | AgentExecutionProgressPhase::Indeterminate
                )
            }
        }

        let root = test_root("lease-loss-completion-race");
        let counter = root.join("spawn-count");
        let executable = write_executable(&root, &success_script(&counter));
        let env = environment("lease-loss-completion-race", Some(executable));
        let task = request("request_lease_loss_completion");
        let backend_identity = identity(
            &task,
            "14444444-4444-4444-8444-444444444444",
            "24444444-4444-4444-8444-444444444444",
        );
        let AgentExecutionServiceOutcome::Executed(completed) = env
            .service
            .execute_with_sink(&task, backend_identity, Arc::new(PendingTerminalSink))
            .unwrap()
        else {
            panic!("lease-loss race requires a local completion");
        };
        assert_eq!(AgentExecutionState::Completed, completed.state);
        let completed_sequence = completed.sequence;

        let fenced = env.service.reconcile_lease_loss(&task.request_id).unwrap();
        assert_eq!(AgentExecutionState::Indeterminate, fenced.state);
        assert_eq!(completed_sequence + 1, fenced.sequence);
        assert_eq!(
            Some(AgentPendingDeliveryKind::Terminal),
            env.journal
                .lock()
                .unwrap()
                .entry(&task.request_id)
                .and_then(|entry| entry.pending_delivery.as_ref())
                .map(|delivery| delivery.kind)
        );
        let reopened = AgentExecutionJournal::open(root.join("agent-journal.json")).unwrap();
        assert_eq!(
            Some(AgentExecutionState::Indeterminate),
            reopened.entry(&task.request_id).map(|entry| entry.state)
        );
    }

    #[test]
    fn acknowledged_cancellation_worker_disconnect_converges_to_indeterminate() {
        let (env, task, cancellation_id) = acknowledged_running_cancellation("cancel-disconnect");
        let execution = env
            .service
            .converge_acknowledged_runner_cancellation(
                &task.request_id,
                &cancellation_id,
                AgentProcessLoss::Crash,
            )
            .unwrap()
            .expect("worker disconnect must converge");
        assert_eq!(AgentExecutionState::Indeterminate, execution.state);
        assert_eq!(
            Some(AgentErrorCode::ExecutionIndeterminate),
            execution.error.as_ref().map(|error| error.code)
        );
    }

    #[test]
    fn acknowledged_cancellation_shutdown_budget_converges_to_indeterminate() {
        let (env, task, cancellation_id) = acknowledged_running_cancellation("cancel-timeout");
        let execution = env
            .service
            .converge_acknowledged_runner_cancellation(
                &task.request_id,
                &cancellation_id,
                AgentProcessLoss::Timeout,
            )
            .unwrap()
            .expect("shutdown timeout must converge");
        assert_eq!(AgentExecutionState::Indeterminate, execution.state);
        assert_eq!(
            Some(AgentErrorCode::ExecutionIndeterminate),
            execution.error.as_ref().map(|error| error.code)
        );
    }

    #[test]
    fn runner_cancellation_is_durable_before_signal_and_survives_pre_ack_restart() {
        struct RunnerNoopSink {
            job_id: String,
        }
        impl AgentExecutionProgressSink for RunnerNoopSink {
            fn delivery_route(&self) -> AgentDeliveryRoute {
                AgentDeliveryRoute::RunnerJob {
                    job_id: self.job_id.clone(),
                    predecessor_job_id: None,
                }
            }

            fn on_progress(&self, _progress: AgentExecutionProgress) -> CoreResult<()> {
                Ok(())
            }

            fn backend_acknowledged(&self, phase: AgentExecutionProgressPhase) -> bool {
                !matches!(
                    phase,
                    AgentExecutionProgressPhase::Completed
                        | AgentExecutionProgressPhase::Failed
                        | AgentExecutionProgressPhase::Cancelled
                        | AgentExecutionProgressPhase::Indeterminate
                )
            }
        }

        let root = test_root("runner-cancel");
        let marker = root.join("started");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 0.144.0"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
printf started > '{}'
sleep 10
printf '%s\n' '{{"item":{{"text":"too late"}}}}'
"#,
            marker.display()
        );
        let executable = write_executable(&root, &script);
        let env = environment("runner-cancel", Some(executable));
        let task = request("request_runner_cancel");
        let job_id = "11111111-1111-4111-8111-111111111111";
        let cancellation_id = "22222222-2222-4222-8222-222222222222";
        let attempt_id = "33333333-3333-4333-8333-333333333333";
        let mut backend_identity =
            identity(&task, "13333333-3333-4333-8333-333333333333", attempt_id);
        backend_identity.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(job_id.to_string()),
            lease_target_runner_id: Some(task.binding.runner_id.clone()),
        };
        let mut dispatch = AgentProcessDispatchV2 {
            schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
            execution_id: backend_identity.execution_id.clone(),
            attempt_id: backend_identity.attempt_id.clone(),
            attempt_number: backend_identity.attempt_number,
            retry_kind: backend_identity.retry_kind,
            from_attempt_id: backend_identity.from_attempt_id.clone(),
            delivery: backend_identity.delivery.clone(),
            task_idempotency_key: backend_identity.task_idempotency_key.clone(),
            delivery_idempotency_key: backend_identity.delivery_idempotency_key.clone(),
            payload_digest: format!("sha256:{}", "0".repeat(64)),
            task: task.clone(),
        };
        dispatch.payload_digest = crate::execution::canonical_json_payload_digest(
            &dispatch.payload_digest_input().unwrap(),
        )
        .unwrap();
        backend_identity.payload_digest = dispatch.payload_digest;
        let AgentExecutionPreparation::Ready(claimed) = env
            .service
            .prepare_with_sink(
                task.clone(),
                backend_identity,
                Arc::new(RunnerNoopSink {
                    job_id: job_id.to_string(),
                }),
            )
            .unwrap()
        else {
            panic!("runner cancellation test requires claimed execution");
        };
        let worker = thread::spawn(move || claimed.execute().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "fake process did not start");

        let key = format!("backend-cancel:{cancellation_id}");
        assert_eq!(
            CancelRequestOutcome::Requested,
            env.service
                .reserve_runner_cancellation(
                    &task.request_id,
                    &key,
                    cancellation_id,
                    job_id,
                    attempt_id,
                    4,
                    task.binding.workspace_binding_generation,
                    "2026-07-27T10:30:00Z",
                )
                .unwrap()
        );
        {
            let journal = env.journal.lock().unwrap();
            let directive = journal
                .entry(&task.request_id)
                .unwrap()
                .cancellation
                .as_ref()
                .unwrap()
                .runner_directive
                .as_ref()
                .unwrap();
            assert_eq!(cancellation_id, directive.cancellation_id);
            assert!(!directive.acknowledged);
        }
        assert!(
            env.service
                .cancellation_registry()
                .is_active(&task.request_id)
                .unwrap(),
            "durable reservation must not signal before the runner does so explicitly"
        );

        env.service
            .signal_reserved_runner_cancellation(&task.request_id, cancellation_id)
            .unwrap();
        let AgentExecutionServiceOutcome::Executed(cancelled) = worker.join().unwrap() else {
            panic!("signalled worker must return its terminal execution");
        };
        assert_eq!(AgentExecutionState::Cancelled, cancelled.state);

        // Simulate daemon loss after process termination but before Backend/local ACK. The exact
        // directive remains durable and can be acknowledged after restart without a second kill.
        let journal_path = root.join("agent-journal.json");
        let mut reopened = AgentExecutionJournal::open(journal_path).unwrap();
        let directive = reopened
            .entry(&task.request_id)
            .unwrap()
            .cancellation
            .as_ref()
            .unwrap()
            .runner_directive
            .as_ref()
            .unwrap();
        assert_eq!(cancellation_id, directive.cancellation_id);
        assert!(!directive.acknowledged);
        assert_eq!(
            CancelRequestOutcome::Requested,
            reopened
                .request_runner_cancel(
                    &task.request_id,
                    &key,
                    cancellation_id,
                    job_id,
                    attempt_id,
                    5,
                    task.binding.workspace_binding_generation,
                    "2026-07-27T10:30:00Z",
                    1_500,
                )
                .unwrap()
        );
        assert_eq!(
            5,
            reopened
                .entry(&task.request_id)
                .unwrap()
                .cancellation
                .as_ref()
                .unwrap()
                .runner_directive
                .as_ref()
                .unwrap()
                .lease_version
        );
        reopened
            .acknowledge_runner_cancel(&task.request_id, cancellation_id)
            .unwrap();
        assert!(
            reopened
                .entry(&task.request_id)
                .unwrap()
                .cancellation
                .as_ref()
                .unwrap()
                .runner_directive
                .as_ref()
                .unwrap()
                .acknowledged
        );
    }

    #[test]
    fn indeterminate_execution_resumes_only_exact_durable_checkpoint() {
        let root = test_root("resume");
        let counter = root.join("spawn-count");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 0.144.0"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
printf x >> '{}'
printf '%s\n' '{{"thread_id":"provider-session-resume"}}'
case " $* " in
  *" resume "*)
    printf '%s\n' '{{"item":{{"text":"resumed"}}}}'
    exit 0
    ;;
esac
echo "provider crashed after session start" >&2
exit 7
"#,
            counter.display()
        );
        let executable = write_executable(&root, &script);
        let env = environment("resume", Some(executable));
        let mut task = request("request_resume");
        let initial_identity = identity(
            &task,
            "14444444-4444-4444-8444-444444444444",
            "24444444-4444-4444-8444-444444444444",
        );
        let AgentExecutionServiceOutcome::Executed(indeterminate) = env
            .service
            .execute(&task, initial_identity.clone())
            .unwrap()
        else {
            panic!("first execution must run");
        };
        assert_eq!(AgentExecutionState::Indeterminate, indeterminate.state);
        assert_eq!(initial_identity.execution_id, indeterminate.execution_id);
        assert_eq!(
            initial_identity.attempt_id,
            indeterminate.attempts[0].attempt_id
        );
        let checkpoint = env
            .journal
            .lock()
            .unwrap()
            .entry(&task.request_id)
            .unwrap()
            .session_checkpoint
            .clone()
            .unwrap();
        assert_eq!(AgentSessionState::Lost, checkpoint.state);
        task.continuation =
            Some(loomex_protocol::agent_runtime_v2::AgentSessionContinuationV2::from(&checkpoint));
        let reused_attempt_error = env
            .service
            .execute(&task, initial_identity.clone())
            .unwrap_err();
        assert_eq!("AGENT_PROCESS_DISPATCH_INVALID", reused_attempt_error.code);
        let resumed_identity = identity_for_process(
            &task,
            "14444444-4444-4444-8444-444444444444",
            "24444444-4444-4444-8444-555555555555",
            2,
            AgentProcessRetryKindV2::ResumeFromCheckpoint,
            Some(initial_identity.attempt_id.clone()),
        );

        let AgentExecutionPreparation::Ready(claimed_resume) = env
            .service
            .prepare_with_sink(
                task.clone(),
                resumed_identity.clone(),
                Arc::new(NoopProgressSink),
            )
            .unwrap()
        else {
            panic!("resume successor must acquire a durable process claim");
        };
        // Crash after claim fsync but before the resumed lifecycle/spawn fence.
        drop(claimed_resume);
        let AgentExecutionServiceOutcome::Executed(completed) = env
            .service
            .execute(&task, resumed_identity.clone())
            .unwrap()
        else {
            panic!("exact continuation must resume");
        };
        assert_eq!(AgentExecutionState::Completed, completed.state);
        assert_eq!(resumed_identity.execution_id, completed.execution_id);
        assert_eq!(2, completed.attempts.len());
        assert_eq!(
            initial_identity.attempt_id,
            completed.attempts[0].attempt_id
        );
        assert_eq!(
            resumed_identity.attempt_id,
            completed.attempts[1].attempt_id
        );
        assert_eq!("xx", fs::read_to_string(counter).unwrap());
        assert_eq!(
            "provider-session-resume",
            completed.attempts[1]
                .session
                .as_ref()
                .unwrap()
                .provider_session_id
        );
        assert_eq!(
            resumed_identity.execution_id,
            completed.attempts[1].session.as_ref().unwrap().execution_id
        );
        assert_eq!(
            resumed_identity.attempt_id,
            completed.attempts[1].session.as_ref().unwrap().attempt_id
        );
    }

    #[test]
    fn unresolved_auto_checkpoint_round_trips_without_inventing_model_identity() {
        let root = test_root("auto-unresolved-resume");
        let args_path = root.join("execution-args");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 1.2.3"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
echo "$*" >> '{}'
printf '%s\n' '{{"thread_id":"provider-auto-session"}}'
case " $* " in
  *" resume "*)
    printf '%s\n' '{{"item":{{"text":"resumed"}}}}'
    exit 0
    ;;
esac
echo "provider crashed after auto session start" >&2
exit 7
"#,
            args_path.display()
        );
        let executable = write_executable(&root, &script);
        let env = environment("auto-unresolved-resume", Some(executable));
        let mut task = request("request_auto_unresolved");
        task.selection = ModelSelection {
            primary: ModelSelectionMode::Auto {
                executor: ExecutorKind::CodexCli,
                provider: AgentProvider::OpenAi,
            },
            fallback: ModelFallbackPolicy::None,
        };
        let initial_identity = identity(
            &task,
            "16666666-6666-4666-8666-666666666666",
            "26666666-6666-4666-8666-666666666666",
        );
        let AgentExecutionServiceOutcome::Executed(indeterminate) = env
            .service
            .execute(&task, initial_identity.clone())
            .unwrap()
        else {
            panic!("initial auto execution must run");
        };
        assert_eq!(AgentExecutionState::Indeterminate, indeterminate.state);
        let checkpoint = env
            .journal
            .lock()
            .unwrap()
            .entry(&task.request_id)
            .unwrap()
            .session_checkpoint
            .clone()
            .unwrap();
        assert_eq!(checkpoint.model_key, None);
        assert_eq!(checkpoint.provider_model_id, None);

        task.continuation = Some(AgentSessionContinuationV2::from(&checkpoint));
        let resumed_identity = identity_for_process(
            &task,
            &initial_identity.execution_id,
            "26666666-6666-4666-8666-777777777777",
            2,
            AgentProcessRetryKindV2::ResumeFromCheckpoint,
            Some(initial_identity.attempt_id.clone()),
        );
        let AgentExecutionServiceOutcome::Executed(completed) =
            env.service.execute(&task, resumed_identity).unwrap()
        else {
            panic!("unresolved auto continuation must resume");
        };
        assert_eq!(AgentExecutionState::Completed, completed.state);
        assert_eq!(completed.attempts[1].resolved_model_key, None);
        assert_eq!(completed.attempts[1].resolved_provider_model_id, None);
        let args = fs::read_to_string(args_path).unwrap();
        assert!(!args.contains("--model"));
        assert!(!args.contains("model=auto"));
    }

    #[test]
    fn pre_spawn_probe_timeout_stays_failed_retryable_without_session_loss() {
        let root = test_root("probe-timeout");
        let marker = root.join("execution-spawned");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  sleep 10
  exit 0
fi
printf spawned > '{}'
printf '%s\n' '{{"thread_id":"never","text":"never"}}'
"#,
            marker.display()
        );
        let executable = write_executable(&root, &script);
        let env = environment("probe-timeout", Some(executable));
        {
            let mut config = env.service.config.lock().unwrap();
            config.probe_limits.timeout = Duration::from_millis(60);
            config.probe_limits.terminate_grace = Duration::from_millis(20);
        }
        let task = request("request_probe_timeout");
        let backend_identity = identity(
            &task,
            "15555555-5555-4555-8555-555555555555",
            "25555555-5555-4555-8555-555555555555",
        );
        let AgentExecutionServiceOutcome::Executed(failed) =
            env.service.execute(&task, backend_identity).unwrap()
        else {
            panic!("probe timeout must produce a durable failed execution");
        };
        assert_eq!(AgentExecutionState::Failed, failed.state);
        let error = failed.error.as_ref().unwrap();
        assert_eq!(AgentErrorCode::Timeout, error.code);
        assert_eq!(AgentRetryDisposition::Retryable, error.retry);
        assert!(!error
            .remediation
            .contains(&AgentRemediationAction::ResumeSession));
        assert!(failed.attempts[0].session.is_none());
        assert!(!marker.exists());
    }

    #[test]
    fn terminal_output_limit_accepts_near_boundary_and_rejects_oversized_output() {
        for (label, content_bytes, expected_state) in [
            (
                "near",
                loomex_protocol::AGENT_TERMINAL_OUTPUT_MAX_BYTES - 256,
                AgentExecutionState::Completed,
            ),
            (
                "over",
                loomex_protocol::AGENT_TERMINAL_OUTPUT_MAX_BYTES,
                AgentExecutionState::Failed,
            ),
        ] {
            let root = test_root(&format!("terminal-output-{label}"));
            let script = format!(
                r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-codex 1.2.3"
  exit 0
fi
if [ "$1" = "login" ]; then
  echo "Logged in"
  exit 0
fi
printf '%s' '{{"thread_id":"size-session","text":"'
head -c {content_bytes} /dev/zero | tr '\0' a
printf '%s\n' '"}}'
"#
            );
            let executable = write_executable(&root, &script);
            let env = environment(&format!("terminal-output-{label}"), Some(executable));
            let task = request(&format!("request_terminal_output_{label}"));
            let backend_identity = identity(
                &task,
                if label == "near" {
                    "17777777-7777-4777-8777-777777777777"
                } else {
                    "18888888-8888-4888-8888-888888888888"
                },
                if label == "near" {
                    "27777777-7777-4777-8777-777777777777"
                } else {
                    "28888888-8888-4888-8888-888888888888"
                },
            );
            let AgentExecutionServiceOutcome::Executed(execution) =
                env.service.execute(&task, backend_identity).unwrap()
            else {
                panic!("terminal size case must execute");
            };
            assert_eq!(execution.state, expected_state, "{label}");
            if expected_state == AgentExecutionState::Failed {
                assert_eq!(
                    execution.error.as_ref().map(|error| error.code),
                    Some(AgentErrorCode::OutputInvalid)
                );
            }
        }
    }
}
