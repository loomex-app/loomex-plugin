use std::collections::BTreeMap;
use std::time::Duration;

use prost_types::{Duration as ProtoDuration, Timestamp};

use crate::grpc::pb;
use crate::lifecycle::{
    CancelOutcome, InflightToolCallRegistry, ReconnectPolicy, ReconnectState, RunnerLifecycleEvent,
    RunnerStateMachine, RunnerStateSnapshot, ShutdownCoordinator, ToolCallRuntimeState,
};
use crate::protocol::{StreamIdentity, MINIMUM_SUPPORTED_VERSION, PROTOCOL_VERSION};
use crate::transport::{FlowControlPermit, FlowControlWindow, TransportMetrics};
use crate::{CoreError, CoreResult};

const EXECUTION_PROVIDER_LOCAL_RUNNER: i32 = 1;
const OUTPUT_STREAM_STDOUT: i32 = 1;
const OUTPUT_STREAM_STDERR: i32 = 2;
const STREAM_ERROR_CODE_CANCELLED: i32 = 10;
const STREAM_ERROR_CODE_INTERNAL: i32 = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSupervisorConfig {
    pub identity: StreamIdentity,
    pub project_runner_binding_id: String,
    pub local_root_path: String,
    pub capabilities: Vec<String>,
    pub default_heartbeat_interval: Duration,
    pub default_max_output_chunk_bytes: usize,
    pub transport_max_inflight_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    Registered,
    ToolCallReceived {
        tool_call_id: String,
    },
    ToolCallCancel {
        tool_call_id: String,
        outcome: CancelOutcome,
    },
    StreamError(StreamFailure),
    Ack,
    Ping,
    Drain,
    RefreshRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFailure {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ToolCallStatus {
    Accepted,
    Running,
    Cancelling,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputPosition {
    next_sequence: u64,
    next_offset: u64,
}

#[derive(Clone)]
struct InflightToolCall {
    request: pb::ToolCallRequest,
    status: ToolCallStatus,
    output_positions: BTreeMap<i32, OutputPosition>,
}

#[derive(Clone)]
pub struct StreamSupervisor {
    config: StreamSupervisorConfig,
    registered: bool,
    next_runner_sequence: u64,
    last_received_server_sequence: u64,
    heartbeat_interval: Duration,
    last_heartbeat_epoch_ms: Option<u64>,
    inflight: BTreeMap<String, InflightToolCall>,
    lifecycle: RunnerStateMachine,
    reconnect: ReconnectState,
    runtime_calls: InflightToolCallRegistry,
    shutdown: ShutdownCoordinator,
    metrics: TransportMetrics,
    output_flow_control: FlowControlWindow,
}

impl StreamSupervisor {
    pub fn new(config: StreamSupervisorConfig) -> CoreResult<Self> {
        if config.project_runner_binding_id.trim().is_empty() {
            return Err(CoreError::new(
                "STREAM_BINDING_MISSING",
                "project runner binding id is required",
            ));
        }
        if config.default_max_output_chunk_bytes == 0 {
            return Err(CoreError::new(
                "STREAM_CHUNK_LIMIT_INVALID",
                "max output chunk bytes must be greater than zero",
            ));
        }

        let output_flow_control =
            FlowControlWindow::new(config.transport_max_inflight_output_bytes)?;

        Ok(Self {
            heartbeat_interval: config.default_heartbeat_interval,
            config,
            registered: false,
            next_runner_sequence: 1,
            last_received_server_sequence: 0,
            last_heartbeat_epoch_ms: None,
            inflight: BTreeMap::new(),
            lifecycle: RunnerStateMachine::new(),
            reconnect: ReconnectState::new(ReconnectPolicy::default()),
            runtime_calls: InflightToolCallRegistry::new(),
            shutdown: ShutdownCoordinator::new(),
            metrics: TransportMetrics::new(),
            output_flow_control,
        })
    }

    pub fn state_snapshot(&self) -> RunnerStateSnapshot {
        self.lifecycle.snapshot(
            self.runtime_calls.active_count(),
            self.runtime_calls.pending_approval_count(),
            self.reconnect.attempt(),
            self.shutdown.is_emergency_stopped(),
            self.shutdown.is_draining(),
        )
    }

    pub fn transport_metrics(&self) -> &TransportMetrics {
        &self.metrics
    }

    pub fn release_output_flow_control(&mut self, bytes: usize) {
        self.output_flow_control.release(bytes);
    }

    pub fn reserve_output_flow_control(&self, bytes: usize) -> CoreResult<FlowControlPermit> {
        self.output_flow_control.reserve(bytes)
    }

    pub fn output_flow_control_inflight_bytes(&self) -> usize {
        self.output_flow_control.inflight_bytes()
    }

    pub fn record_transport_fallback(&mut self) {
        self.metrics.record_fallback();
    }

    pub fn authenticate(&mut self) -> CoreResult<()> {
        self.lifecycle
            .transition(RunnerLifecycleEvent::Authenticated)?;
        Ok(())
    }

    pub fn bind_project(&mut self) -> CoreResult<()> {
        self.lifecycle
            .transition(RunnerLifecycleEvent::ProjectBound)?;
        Ok(())
    }

    pub fn runner_hello(&mut self, now_epoch_ms: u64) -> pb::RunnerToServer {
        let _ = self
            .lifecycle
            .transition(RunnerLifecycleEvent::ConnectStarted);
        let hello = pb::RunnerHello {
            runner_version: self.config.identity.runner_version.clone(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            minimum_supported_version: MINIMUM_SUPPORTED_VERSION.to_string(),
            capabilities: self.config.capabilities.clone(),
            nonce: format!("{}-{now_epoch_ms}", self.config.identity.runner_session_id),
            runner_device_id: self.config.identity.runner_device_id.clone(),
            runner_session_id: self.config.identity.runner_session_id.clone(),
            binding: Some(pb::BindingContext {
                organization_id: self.config.identity.organization_id.clone(),
                project_id: self.config.identity.project_id.clone(),
                project_runner_binding_id: self.config.project_runner_binding_id.clone(),
                local_root_path: self.config.local_root_path.clone(),
            }),
            last_received_server_sequence: self.last_received_server_sequence,
            resume_after_server_sequence: self.last_received_server_sequence,
            ..Default::default()
        };

        self.runner_envelope(
            pb::runner_to_server::Payload::Hello(hello),
            "runner-hello".to_string(),
            now_epoch_ms,
        )
    }

    pub fn accept_server_message(
        &mut self,
        message: pb::ServerToRunner,
        now_epoch_ms: u64,
    ) -> CoreResult<ServerEvent> {
        let sequence = message.sequence;
        let message_for_metrics = message.clone();
        if let Err(err) = self.validate_server_sequence(sequence) {
            self.metrics
                .observe_rejected_server_message(&message_for_metrics, now_epoch_ms);
            return Err(err);
        }

        let event = match message.payload {
            Some(pb::server_to_runner::Payload::Hello(hello)) => {
                self.accept_server_hello(hello)?;
                ServerEvent::Registered
            }
            Some(pb::server_to_runner::Payload::ToolCallRequest(request)) => {
                let tool_call_id = request.tool_call_id.clone();
                self.accept_tool_call_request(request, now_epoch_ms)?;
                ServerEvent::ToolCallReceived { tool_call_id }
            }
            Some(pb::server_to_runner::Payload::ToolCallCancel(cancel)) => {
                let tool_call_id = cancel.tool_call_id.clone();
                let outcome = self.accept_tool_call_cancel(cancel);
                ServerEvent::ToolCallCancel {
                    tool_call_id,
                    outcome,
                }
            }
            Some(pb::server_to_runner::Payload::Error(error)) => {
                self.lifecycle.set_error("GRPC_STREAM_ERROR");
                ServerEvent::StreamError(StreamFailure {
                    code: "GRPC_STREAM_ERROR",
                    message: error.message,
                    retryable: error.retryable,
                })
            }
            Some(pb::server_to_runner::Payload::Ack(_)) => ServerEvent::Ack,
            Some(pb::server_to_runner::Payload::Ping(_)) => ServerEvent::Ping,
            Some(pb::server_to_runner::Payload::Drain(_)) => ServerEvent::Drain,
            Some(pb::server_to_runner::Payload::StreamTokenRefresh(_)) => {
                ServerEvent::RefreshRequested
            }
            Some(pb::server_to_runner::Payload::ApprovalRequest(approval)) => {
                let _ = self
                    .lifecycle
                    .transition(RunnerLifecycleEvent::ApprovalRequired);
                let _ = self.runtime_calls.mark_state(
                    &approval.tool_call_id,
                    ToolCallRuntimeState::WaitingForApproval,
                );
                ServerEvent::Ack
            }
            Some(pb::server_to_runner::Payload::PolicySync(_)) => ServerEvent::Ack,
            None => Err(CoreError::new(
                "GRPC_UNKNOWN_SERVER_MESSAGE",
                "server message had no recognized payload",
            ))?,
        };

        self.metrics
            .observe_server_message(&message_for_metrics, now_epoch_ms);
        self.last_received_server_sequence = sequence;
        Ok(event)
    }

    pub fn accept_server_hello(&mut self, hello: pb::ServerHello) -> CoreResult<()> {
        if hello.update_required {
            return Err(CoreError::new(
                "RUNNER_UPDATE_REQUIRED",
                "server requires a newer runner version",
            ));
        }
        self.registered = true;
        self.lifecycle.transition(RunnerLifecycleEvent::Connected)?;
        self.reconnect.reset();
        self.heartbeat_interval = hello
            .heartbeat
            .and_then(|heartbeat| heartbeat.interval)
            .map(proto_duration_to_std)
            .transpose()?
            .unwrap_or(self.config.default_heartbeat_interval);
        self.next_runner_sequence = hello.last_received_runner_sequence + 1;
        Ok(())
    }

    pub fn heartbeat_due(&self, now_epoch_ms: u64) -> bool {
        match self.last_heartbeat_epoch_ms {
            None => self.registered,
            Some(last) => {
                now_epoch_ms.saturating_sub(last) >= self.heartbeat_interval.as_millis() as u64
            }
        }
    }

    pub fn heartbeat(&mut self, now_epoch_ms: u64) -> CoreResult<pb::RunnerToServer> {
        self.ensure_registered()?;
        self.last_heartbeat_epoch_ms = Some(now_epoch_ms);
        let heartbeat = pb::RunnerHeartbeat {
            state: 2,
            runner_time: Some(timestamp_from_epoch_ms(now_epoch_ms)),
            active_capabilities: self.config.capabilities.clone(),
            status_message: "ready".to_string(),
            ..Default::default()
        };

        Ok(self.runner_envelope(
            pb::runner_to_server::Payload::Heartbeat(heartbeat),
            format!("heartbeat-{now_epoch_ms}"),
            now_epoch_ms,
        ))
    }

    pub fn accept_tool_call_request(
        &mut self,
        request: pb::ToolCallRequest,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        self.ensure_registered()?;
        self.ensure_accepting_new_calls()?;
        validate_tool_call_request(&request)?;

        if request.provider != EXECUTION_PROVIDER_LOCAL_RUNNER {
            return Err(CoreError::new(
                "STREAM_PROVIDER_UNSUPPORTED",
                "tool call provider must be local runner",
            ));
        }

        let expires_at = request
            .expires_at
            .as_ref()
            .ok_or_else(|| CoreError::new("STREAM_TOOL_CALL_MISSING_FIELD", "expires_at"))?;
        let expires_at_epoch_ms = timestamp_to_epoch_ms(expires_at)?;
        if now_epoch_ms >= expires_at_epoch_ms {
            return Err(CoreError::new(
                "STREAM_DEADLINE_EXCEEDED",
                "tool call expired before it could start",
            ));
        }
        if self.inflight.contains_key(&request.tool_call_id) {
            return Err(CoreError::new(
                "STREAM_DUPLICATE_TOOL_CALL",
                request.tool_call_id,
            ));
        }

        let requires_approval = request
            .approval
            .as_ref()
            .map(|approval| approval.required)
            .unwrap_or(false);
        let runtime_state = if requires_approval {
            ToolCallRuntimeState::WaitingForApproval
        } else {
            ToolCallRuntimeState::Accepted
        };

        self.inflight.insert(
            request.tool_call_id.clone(),
            InflightToolCall {
                request: request.clone(),
                status: ToolCallStatus::Accepted,
                output_positions: BTreeMap::new(),
            },
        );
        self.runtime_calls.insert(
            request.tool_call_id,
            request.workflow_run_id,
            request.attempt,
            runtime_state,
        )?;
        if requires_approval {
            self.lifecycle
                .transition(RunnerLifecycleEvent::ApprovalRequired)?;
        }
        Ok(())
    }

    pub fn accept_tool_call_cancel(&mut self, cancel: pb::ToolCallCancel) -> CancelOutcome {
        let tool_call_id = cancel.tool_call_id;
        let reason = cancel.reason;
        let idempotency_key = cancel.idempotency_key;
        let grace_period = match cancel.grace_period {
            Some(grace_period) => {
                proto_duration_to_std(grace_period).unwrap_or_else(|_| Duration::from_secs(0))
            }
            None => Duration::from_secs(0),
        };
        let outcome =
            self.runtime_calls
                .cancel(&tool_call_id, reason, idempotency_key, grace_period);
        if outcome == CancelOutcome::Accepted {
            if let Some(call) = self.inflight.get_mut(&tool_call_id) {
                call.status = ToolCallStatus::Cancelling;
            }
            let _ = self
                .lifecycle
                .transition(RunnerLifecycleEvent::ApprovalResolved);
        }
        outcome
    }

    pub fn tool_call_started(
        &mut self,
        tool_call_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<pb::RunnerToServer> {
        self.ensure_registered()?;
        let started = {
            let call = self.inflight_call_mut(tool_call_id)?;
            if call.status == ToolCallStatus::Cancelling {
                return Err(CoreError::new(
                    "STREAM_TOOL_CALL_CANCELLED",
                    "cancelled tool calls cannot be started",
                ));
            }
            reject_after_deadline(call, now_epoch_ms)?;
            call.status = ToolCallStatus::Running;
            pb::ToolCallStarted {
                tool_call_id: call.request.tool_call_id.clone(),
                workflow_run_id: call.request.workflow_run_id.clone(),
                attempt: call.request.attempt,
                started_at: Some(timestamp_from_epoch_ms(now_epoch_ms)),
            }
        };
        self.runtime_calls
            .mark_state(tool_call_id, ToolCallRuntimeState::Running)?;
        self.lifecycle
            .transition(RunnerLifecycleEvent::ToolCallStarted)?;

        Ok(self.runner_envelope(
            pb::runner_to_server::Payload::ToolCallStarted(started),
            format!("{tool_call_id}:started"),
            now_epoch_ms,
        ))
    }

    pub fn tool_call_output(
        &mut self,
        tool_call_id: &str,
        stream: i32,
        data: &[u8],
        final_chunk: bool,
        now_epoch_ms: u64,
    ) -> CoreResult<Vec<pb::RunnerToServer>> {
        self.ensure_registered()?;
        let default_chunk_limit = self.config.default_max_output_chunk_bytes;
        if !self.runtime_calls.can_emit_output(tool_call_id) {
            return Err(CoreError::new(
                "STREAM_TOOL_CALL_CANCELLED",
                "cancelled tool calls cannot emit output",
            ));
        }
        let chunk_limit = {
            let call = self.inflight_call_mut(tool_call_id)?;
            if call.status == ToolCallStatus::Terminal {
                return Err(CoreError::new(
                    "STREAM_TOOL_CALL_TERMINAL",
                    "terminal tool calls cannot emit output",
                ));
            }
            let chunk_limit =
                (call.request.max_output_chunk_bytes as usize).min(default_chunk_limit);
            if chunk_limit == 0 {
                return Err(CoreError::new(
                    "STREAM_CHUNK_LIMIT_INVALID",
                    "max output chunk bytes must be greater than zero",
                ));
            }
            chunk_limit
        };
        let outputs = {
            let call = self.inflight_call_mut(tool_call_id)?;
            let mut outputs = Vec::new();
            let mut remaining = data;
            while !remaining.is_empty() {
                let take = remaining.len().min(chunk_limit);
                let chunk_data = remaining[..take].to_vec();
                remaining = &remaining[take..];
                outputs.push(next_output(
                    call,
                    stream,
                    chunk_data,
                    remaining.is_empty() && final_chunk,
                    now_epoch_ms,
                ));
            }

            if data.is_empty() && final_chunk {
                outputs.push(next_output(call, stream, Vec::new(), true, now_epoch_ms));
            }
            outputs
        };

        let messages = outputs
            .into_iter()
            .map(|output| {
                let key = format!(
                    "{}:{}:{}:{}",
                    output.tool_call_id, output.attempt, output.stream, output.chunk_sequence
                );
                self.runner_envelope(
                    pb::runner_to_server::Payload::ToolCallOutput(output),
                    key,
                    now_epoch_ms,
                )
            })
            .collect::<Vec<_>>();
        Ok(messages)
    }

    pub fn stdout(
        &mut self,
        tool_call_id: &str,
        data: &[u8],
        final_chunk: bool,
        now_epoch_ms: u64,
    ) -> CoreResult<Vec<pb::RunnerToServer>> {
        self.tool_call_output(
            tool_call_id,
            OUTPUT_STREAM_STDOUT,
            data,
            final_chunk,
            now_epoch_ms,
        )
    }

    pub fn stderr(
        &mut self,
        tool_call_id: &str,
        data: &[u8],
        final_chunk: bool,
        now_epoch_ms: u64,
    ) -> CoreResult<Vec<pb::RunnerToServer>> {
        self.tool_call_output(
            tool_call_id,
            OUTPUT_STREAM_STDERR,
            data,
            final_chunk,
            now_epoch_ms,
        )
    }

    pub fn tool_call_result(
        &mut self,
        tool_call_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<pb::RunnerToServer> {
        self.ensure_registered()?;
        let result = {
            let call = self.inflight_call_mut(tool_call_id)?;
            reject_after_deadline(call, now_epoch_ms)?;
            if call.status == ToolCallStatus::Terminal {
                return Err(CoreError::new(
                    "STREAM_DUPLICATE_TERMINAL",
                    "terminal result already accepted",
                ));
            }
            call.status = ToolCallStatus::Terminal;
            pb::ToolCallResult {
                tool_call_id: call.request.tool_call_id.clone(),
                workflow_run_id: call.request.workflow_run_id.clone(),
                attempt: call.request.attempt,
                completed_at: Some(timestamp_from_epoch_ms(now_epoch_ms)),
                has_exit_code: false,
                ..Default::default()
            }
        };
        self.runtime_calls.mark_terminal(tool_call_id)?;
        if !self.runtime_calls.has_active() {
            let _ = self
                .lifecycle
                .transition(RunnerLifecycleEvent::ToolCallCompleted);
        }

        Ok(self.runner_envelope(
            pb::runner_to_server::Payload::ToolCallResult(result),
            format!("{tool_call_id}:result"),
            now_epoch_ms,
        ))
    }

    pub fn tool_call_error(
        &mut self,
        tool_call_id: &str,
        code: i32,
        message: impl Into<String>,
        retryable: bool,
        now_epoch_ms: u64,
    ) -> CoreResult<pb::RunnerToServer> {
        self.ensure_registered()?;
        let error = {
            let call = self.inflight_call_mut(tool_call_id)?;
            if call.status == ToolCallStatus::Terminal {
                return Err(CoreError::new(
                    "STREAM_DUPLICATE_TERMINAL",
                    "terminal error already accepted",
                ));
            }
            call.status = ToolCallStatus::Terminal;
            pb::ToolCallError {
                tool_call_id: call.request.tool_call_id.clone(),
                workflow_run_id: call.request.workflow_run_id.clone(),
                attempt: call.request.attempt,
                code,
                message: message.into(),
                retryable,
                failed_at: Some(timestamp_from_epoch_ms(now_epoch_ms)),
                ..Default::default()
            }
        };
        self.runtime_calls.mark_terminal(tool_call_id)?;
        if !self.runtime_calls.has_active() {
            let _ = self
                .lifecycle
                .transition(RunnerLifecycleEvent::ToolCallCompleted);
        }

        Ok(self.runner_envelope(
            pb::runner_to_server::Payload::ToolCallError(error),
            format!("{tool_call_id}:error"),
            now_epoch_ms,
        ))
    }

    pub fn internal_tool_call_error(
        &mut self,
        tool_call_id: &str,
        message: impl Into<String>,
        now_epoch_ms: u64,
    ) -> CoreResult<pb::RunnerToServer> {
        self.tool_call_error(
            tool_call_id,
            STREAM_ERROR_CODE_INTERNAL,
            message,
            true,
            now_epoch_ms,
        )
    }

    pub fn cancelled_tool_call_error(
        &mut self,
        tool_call_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<pb::RunnerToServer> {
        self.tool_call_error(
            tool_call_id,
            STREAM_ERROR_CODE_CANCELLED,
            "tool call cancelled",
            false,
            now_epoch_ms,
        )
    }

    pub fn receive_server_close(&mut self) -> StreamFailure {
        self.registered = false;
        let _ = self
            .lifecycle
            .transition(RunnerLifecycleEvent::Disconnected);
        self.reconnect.record_disconnect(
            self.last_received_server_sequence,
            self.next_runner_sequence - 1,
        );
        self.metrics.record_reconnect();
        StreamFailure {
            code: "GRPC_STREAM_CLOSED",
            message: "server closed runner stream".to_string(),
            retryable: true,
        }
    }

    pub fn next_reconnect_attempt(&mut self) -> CoreResult<crate::lifecycle::ReconnectAttempt> {
        self.reconnect.next_attempt()
    }

    pub fn graceful_shutdown(&mut self) -> bool {
        self.shutdown.graceful_shutdown(&self.runtime_calls)
    }

    pub fn runner_disconnect(
        &mut self,
        reason: impl Into<String>,
        graceful: bool,
        now_epoch_ms: u64,
    ) -> pb::RunnerToServer {
        let disconnect = pb::RunnerDisconnect {
            reason: reason.into(),
            graceful,
            inflight_tool_call_ids: self.runtime_calls.active_tool_call_ids(),
        };
        self.runner_envelope(
            pb::runner_to_server::Payload::Disconnect(disconnect),
            format!("disconnect-{now_epoch_ms}"),
            now_epoch_ms,
        )
    }

    pub fn client_ack(
        &mut self,
        received_server_sequence: u64,
        received_idempotency_key: impl Into<String>,
        now_epoch_ms: u64,
    ) -> pb::RunnerToServer {
        let ack = pb::ClientAck {
            received_server_sequence,
            received_idempotency_key: received_idempotency_key.into(),
        };
        self.runner_envelope(
            pb::runner_to_server::Payload::Ack(ack),
            format!("ack-{received_server_sequence}"),
            now_epoch_ms,
        )
    }

    pub fn emergency_stop(&mut self) {
        self.shutdown.emergency_stop();
        self.registered = false;
    }

    pub fn network_timeout(timeout: Duration) -> StreamFailure {
        StreamFailure {
            code: "GRPC_NETWORK_TIMEOUT",
            message: format!("network timeout after {}ms", timeout.as_millis()),
            retryable: true,
        }
    }

    pub fn unknown_server_message(message_name: &str) -> StreamFailure {
        StreamFailure {
            code: "GRPC_UNKNOWN_SERVER_MESSAGE",
            message: message_name.to_string(),
            retryable: false,
        }
    }

    fn ensure_registered(&self) -> CoreResult<()> {
        if !self.registered {
            return Err(CoreError::new(
                "STREAM_REGISTRATION_REQUIRED",
                "runner must receive ServerHello before stream messages",
            ));
        }
        Ok(())
    }

    fn validate_server_sequence(&self, sequence: u64) -> CoreResult<()> {
        if sequence == 0 {
            return Err(CoreError::new(
                "STREAM_SERVER_SEQUENCE_INVALID",
                "server sequence must start at one",
            ));
        }
        let expected = self.last_received_server_sequence + 1;
        if sequence == self.last_received_server_sequence {
            return Err(CoreError::new(
                "STREAM_DUPLICATE_SERVER_SEQUENCE",
                format!("duplicate server sequence {sequence}"),
            ));
        }
        if sequence != expected {
            return Err(CoreError::new(
                "STREAM_OUT_OF_ORDER_SERVER_SEQUENCE",
                format!("expected server sequence {expected}, got {sequence}"),
            ));
        }
        Ok(())
    }

    fn ensure_accepting_new_calls(&self) -> CoreResult<()> {
        if self.shutdown.blocks_new_calls() {
            return Err(CoreError::new(
                "RUNNER_NOT_ACCEPTING_CALLS",
                "runner shutdown or emergency stop blocks new tool calls",
            ));
        }
        Ok(())
    }

    fn runner_envelope(
        &mut self,
        payload: pb::runner_to_server::Payload,
        idempotency_key: String,
        now_epoch_ms: u64,
    ) -> pb::RunnerToServer {
        let sequence = self.next_sequence();
        pb::RunnerToServer {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: self.config.identity.runner_session_id.clone(),
            runner_device_id: self.config.identity.runner_device_id.clone(),
            organization_id: self.config.identity.organization_id.clone(),
            project_id: self.config.identity.project_id.clone(),
            sequence,
            idempotency_key,
            sent_at: Some(timestamp_from_epoch_ms(now_epoch_ms)),
            payload: Some(payload),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_runner_sequence;
        self.next_runner_sequence += 1;
        sequence
    }

    fn inflight_call_mut(&mut self, tool_call_id: &str) -> CoreResult<&mut InflightToolCall> {
        self.inflight
            .get_mut(tool_call_id)
            .ok_or_else(|| CoreError::new("STREAM_TOOL_CALL_NOT_FOUND", tool_call_id))
    }
}

fn validate_tool_call_request(request: &pb::ToolCallRequest) -> CoreResult<()> {
    for (field, value) in [
        ("tool_call_id", &request.tool_call_id),
        ("workflow_run_id", &request.workflow_run_id),
        (
            "project_runner_binding_id",
            &request.project_runner_binding_id,
        ),
        ("capability", &request.capability),
        ("idempotency_key", &request.idempotency_key),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("STREAM_TOOL_CALL_MISSING_FIELD", field));
        }
    }
    if request.attempt == 0 {
        return Err(CoreError::new(
            "STREAM_TOOL_CALL_MISSING_FIELD",
            "attempt must be greater than zero",
        ));
    }
    if request.requested_at.is_none() {
        return Err(CoreError::new(
            "STREAM_TOOL_CALL_MISSING_FIELD",
            "requested_at",
        ));
    }
    if request.expires_at.is_none() {
        return Err(CoreError::new(
            "STREAM_TOOL_CALL_MISSING_FIELD",
            "expires_at",
        ));
    }
    if request.deadline.is_none() {
        return Err(CoreError::new("STREAM_TOOL_CALL_MISSING_FIELD", "deadline"));
    }
    if request.max_output_chunk_bytes == 0 {
        return Err(CoreError::new(
            "STREAM_CHUNK_LIMIT_INVALID",
            "max output chunk bytes must be greater than zero",
        ));
    }
    Ok(())
}

fn reject_after_deadline(call: &InflightToolCall, now_epoch_ms: u64) -> CoreResult<()> {
    let expires_at = call
        .request
        .expires_at
        .as_ref()
        .ok_or_else(|| CoreError::new("STREAM_TOOL_CALL_MISSING_FIELD", "expires_at"))?;
    if now_epoch_ms >= timestamp_to_epoch_ms(expires_at)? {
        return Err(CoreError::new(
            "STREAM_DEADLINE_EXCEEDED",
            "tool call deadline exceeded",
        ));
    }
    Ok(())
}

fn next_output(
    call: &mut InflightToolCall,
    stream: i32,
    data: Vec<u8>,
    final_chunk: bool,
    now_epoch_ms: u64,
) -> pb::ToolCallOutput {
    let position = call
        .output_positions
        .entry(stream)
        .or_insert(OutputPosition {
            next_sequence: 1,
            next_offset: 0,
        });
    let chunk_sequence = position.next_sequence;
    let offset = position.next_offset;
    position.next_sequence += 1;
    position.next_offset += data.len() as u64;

    pb::ToolCallOutput {
        tool_call_id: call.request.tool_call_id.clone(),
        workflow_run_id: call.request.workflow_run_id.clone(),
        attempt: call.request.attempt,
        chunk_sequence,
        stream,
        data,
        text_encoding: "utf-8".to_string(),
        offset,
        final_chunk,
        emitted_at: Some(timestamp_from_epoch_ms(now_epoch_ms)),
        ..Default::default()
    }
}

fn timestamp_from_epoch_ms(epoch_ms: u64) -> Timestamp {
    Timestamp {
        seconds: (epoch_ms / 1000) as i64,
        nanos: ((epoch_ms % 1000) * 1_000_000) as i32,
    }
}

fn timestamp_to_epoch_ms(timestamp: &Timestamp) -> CoreResult<u64> {
    if timestamp.seconds < 0 || timestamp.nanos < 0 {
        return Err(CoreError::new(
            "STREAM_TIMESTAMP_INVALID",
            "timestamp must not be negative",
        ));
    }
    Ok(timestamp.seconds as u64 * 1000 + timestamp.nanos as u64 / 1_000_000)
}

fn proto_duration_to_std(duration: ProtoDuration) -> CoreResult<Duration> {
    if duration.seconds < 0 || duration.nanos < 0 {
        return Err(CoreError::new(
            "STREAM_DURATION_INVALID",
            "duration must not be negative",
        ));
    }
    Ok(Duration::from_secs(duration.seconds as u64) + Duration::from_nanos(duration.nanos as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supervisor() -> StreamSupervisor {
        let mut supervisor = StreamSupervisor::new(StreamSupervisorConfig {
            identity: StreamIdentity {
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_device_id: "device_123".to_string(),
                runner_session_id: "session_123".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                runner_version: "0.1.0".to_string(),
            },
            project_runner_binding_id: "binding_123".to_string(),
            local_root_path: "/tmp/project".to_string(),
            capabilities: vec!["shell.exec".to_string()],
            default_heartbeat_interval: Duration::from_millis(1000),
            default_max_output_chunk_bytes: 4,
            transport_max_inflight_output_bytes: 16,
        })
        .unwrap();
        supervisor.authenticate().unwrap();
        supervisor.bind_project().unwrap();
        supervisor
    }

    fn server_hello() -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 1,
            idempotency_key: "server-hello".to_string(),
            sent_at: Some(timestamp_from_epoch_ms(1000)),
            payload: Some(pb::server_to_runner::Payload::Hello(pb::ServerHello {
                protocol_version: PROTOCOL_VERSION.to_string(),
                minimum_supported_version: MINIMUM_SUPPORTED_VERSION.to_string(),
                minimum_supported_runner_version: "0.1.0".to_string(),
                accepted_capabilities: vec!["shell.exec".to_string()],
                heartbeat: Some(pb::HeartbeatConfig {
                    interval: Some(ProtoDuration {
                        seconds: 0,
                        nanos: 500_000_000,
                    }),
                    ..Default::default()
                }),
                last_received_runner_sequence: 1,
                ..Default::default()
            })),
        }
    }

    fn tool_call_request() -> pb::ToolCallRequest {
        pb::ToolCallRequest {
            tool_call_id: "tool_123".to_string(),
            workflow_run_id: "run_123".to_string(),
            project_runner_binding_id: "binding_123".to_string(),
            attempt: 1,
            capability: "shell.exec".to_string(),
            provider: EXECUTION_PROVIDER_LOCAL_RUNNER,
            idempotency_key: "idem_123".to_string(),
            requested_at: Some(timestamp_from_epoch_ms(1000)),
            expires_at: Some(timestamp_from_epoch_ms(5000)),
            deadline: Some(ProtoDuration {
                seconds: 4,
                nanos: 0,
            }),
            max_output_chunk_bytes: 4,
            ..Default::default()
        }
    }

    fn tool_call_message() -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 2,
            idempotency_key: "tool-call".to_string(),
            sent_at: Some(timestamp_from_epoch_ms(1100)),
            payload: Some(pb::server_to_runner::Payload::ToolCallRequest(
                tool_call_request(),
            )),
        }
    }

    fn cancel_message() -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 3,
            idempotency_key: "cancel".to_string(),
            sent_at: Some(timestamp_from_epoch_ms(1300)),
            payload: Some(pb::server_to_runner::Payload::ToolCallCancel(
                pb::ToolCallCancel {
                    tool_call_id: "tool_123".to_string(),
                    workflow_run_id: "run_123".to_string(),
                    attempt: 1,
                    reason: "user requested cancel".to_string(),
                    requested_at: Some(timestamp_from_epoch_ms(1300)),
                    grace_period: Some(ProtoDuration {
                        seconds: 1,
                        nanos: 0,
                    }),
                    idempotency_key: "cancel_123".to_string(),
                },
            )),
        }
    }

    fn cancel_message_for(tool_call_id: &str, sequence: u64) -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence,
            idempotency_key: format!("cancel-{tool_call_id}"),
            sent_at: Some(timestamp_from_epoch_ms(1300)),
            payload: Some(pb::server_to_runner::Payload::ToolCallCancel(
                pb::ToolCallCancel {
                    tool_call_id: tool_call_id.to_string(),
                    workflow_run_id: "run_123".to_string(),
                    attempt: 1,
                    reason: "user requested cancel".to_string(),
                    requested_at: Some(timestamp_from_epoch_ms(1300)),
                    grace_period: Some(ProtoDuration {
                        seconds: 1,
                        nanos: 0,
                    }),
                    idempotency_key: format!("cancel_idem_{tool_call_id}"),
                },
            )),
        }
    }

    fn invalid_no_payload_message(sequence: u64) -> pb::ServerToRunner {
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence,
            idempotency_key: format!("invalid-{sequence}"),
            sent_at: Some(timestamp_from_epoch_ms(1100)),
            payload: None,
        }
    }

    fn rejected_provider_message() -> pb::ServerToRunner {
        let mut request = tool_call_request();
        request.provider = 2;
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 2,
            idempotency_key: "rejected-provider".to_string(),
            sent_at: Some(timestamp_from_epoch_ms(1100)),
            payload: Some(pb::server_to_runner::Payload::ToolCallRequest(request)),
        }
    }

    fn approval_tool_call_message() -> pb::ServerToRunner {
        let mut request = tool_call_request();
        request.approval = Some(pb::ApprovalRequirement {
            required: true,
            approval_request_id: "approval_123".to_string(),
            prompt: "Approve shell command".to_string(),
            expires_at: Some(timestamp_from_epoch_ms(4000)),
        });
        pb::ServerToRunner {
            protocol_version: PROTOCOL_VERSION.to_string(),
            runner_session_id: "session_123".to_string(),
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            sequence: 2,
            idempotency_key: "approval-tool-call".to_string(),
            sent_at: Some(timestamp_from_epoch_ms(1100)),
            payload: Some(pb::server_to_runner::Payload::ToolCallRequest(request)),
        }
    }

    #[test]
    fn connect_success_sends_proto_hello_and_accepts_registration() {
        let mut supervisor = supervisor();
        let hello = supervisor.runner_hello(1000);
        assert_eq!(1, hello.sequence);
        assert!(matches!(
            hello.payload,
            Some(pb::runner_to_server::Payload::Hello(_))
        ));

        let event = supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        assert_eq!(ServerEvent::Registered, event);
        assert!(supervisor.heartbeat_due(1500));
    }

    #[test]
    fn heartbeat_interval_is_enforced_with_proto_message() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        let heartbeat = supervisor.heartbeat(1000).unwrap();

        assert_eq!(2, heartbeat.sequence);
        assert!(matches!(
            heartbeat.payload,
            Some(pb::runner_to_server::Payload::Heartbeat(_))
        ));
        assert!(!supervisor.heartbeat_due(1200));
        assert!(supervisor.heartbeat_due(1500));
    }

    #[test]
    fn receive_tool_call_consumes_generated_request() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();

        let event = supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();

        assert_eq!(
            ServerEvent::ToolCallReceived {
                tool_call_id: "tool_123".to_string()
            },
            event
        );
    }

    #[test]
    fn started_result_and_error_are_generated_runner_messages() {
        let mut started_supervisor = supervisor();
        started_supervisor.runner_hello(1000);
        started_supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        started_supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();

        let started = started_supervisor
            .tool_call_started("tool_123", 1200)
            .unwrap();
        assert!(matches!(
            started.payload,
            Some(pb::runner_to_server::Payload::ToolCallStarted(_))
        ));

        let result = started_supervisor
            .tool_call_result("tool_123", 1300)
            .unwrap();
        assert!(matches!(
            result.payload,
            Some(pb::runner_to_server::Payload::ToolCallResult(_))
        ));

        let mut error_supervisor = supervisor();
        error_supervisor.runner_hello(1000);
        error_supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        error_supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        let error = error_supervisor
            .internal_tool_call_error("tool_123", "failed", 1300)
            .unwrap();
        assert!(matches!(
            error.payload,
            Some(pb::runner_to_server::Payload::ToolCallError(_))
        ));
    }

    #[test]
    fn server_close_returns_retryable_error() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();

        let failure = supervisor.receive_server_close();

        assert_eq!("GRPC_STREAM_CLOSED", failure.code);
        assert!(failure.retryable);
    }

    #[test]
    fn reconnect_after_server_restart_uses_resume_positions() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.receive_server_close();

        let attempt = supervisor.next_reconnect_attempt().unwrap();
        let hello = supervisor.runner_hello(2000);
        let hello_payload = match hello.payload.unwrap() {
            pb::runner_to_server::Payload::Hello(hello) => hello,
            _ => panic!("expected hello"),
        };

        assert_eq!(1, attempt.attempt);
        assert_eq!(2, attempt.resume_after_server_sequence);
        assert_eq!(2, hello_payload.resume_after_server_sequence);
        assert_eq!(1, supervisor.transport_metrics().reconnect_count);
        assert_eq!(2, supervisor.transport_metrics().accepted_events);
    }

    #[test]
    fn invalid_server_message_does_not_advance_resume_sequence() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();

        assert_eq!(
            "GRPC_UNKNOWN_SERVER_MESSAGE",
            supervisor
                .accept_server_message(invalid_no_payload_message(2), 1100)
                .unwrap_err()
                .code
        );

        supervisor.receive_server_close();
        let attempt = supervisor.next_reconnect_attempt().unwrap();
        assert_eq!(1, attempt.resume_after_server_sequence);
    }

    #[test]
    fn rejected_server_message_does_not_advance_resume_sequence() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();

        assert_eq!(
            "STREAM_PROVIDER_UNSUPPORTED",
            supervisor
                .accept_server_message(rejected_provider_message(), 1100)
                .unwrap_err()
                .code
        );

        supervisor.receive_server_close();
        let attempt = supervisor.next_reconnect_attempt().unwrap();
        assert_eq!(1, attempt.resume_after_server_sequence);
    }

    #[test]
    fn duplicate_or_out_of_order_server_sequence_is_rejected_without_advancing() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();

        assert_eq!(
            "STREAM_DUPLICATE_SERVER_SEQUENCE",
            supervisor
                .accept_server_message(server_hello(), 1000)
                .unwrap_err()
                .code
        );
        assert_eq!(
            "STREAM_OUT_OF_ORDER_SERVER_SEQUENCE",
            supervisor
                .accept_server_message(invalid_no_payload_message(3), 1100)
                .unwrap_err()
                .code
        );

        supervisor.receive_server_close();
        let attempt = supervisor.next_reconnect_attempt().unwrap();
        assert_eq!(1, attempt.resume_after_server_sequence);
        assert_eq!(1, supervisor.transport_metrics().duplicate_events);
        assert_eq!(1, supervisor.transport_metrics().dropped_events);
    }

    #[test]
    fn network_timeout_is_structured_retryable_error() {
        let failure = StreamSupervisor::network_timeout(Duration::from_millis(250));
        assert_eq!("GRPC_NETWORK_TIMEOUT", failure.code);
        assert!(failure.retryable);
    }

    #[test]
    fn large_stdout_is_chunked_into_proto_output_messages() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        let chunks = supervisor
            .stdout("tool_123", b"abcdefghi", true, 1250)
            .unwrap();

        assert_eq!(3, chunks.len());
        let outputs: Vec<pb::ToolCallOutput> = chunks
            .into_iter()
            .map(|message| match message.payload.unwrap() {
                pb::runner_to_server::Payload::ToolCallOutput(output) => output,
                _ => panic!("expected output"),
            })
            .collect();
        assert_eq!(b"abcd", outputs[0].data.as_slice());
        assert_eq!(b"efgh", outputs[1].data.as_slice());
        assert_eq!(b"i", outputs[2].data.as_slice());
        assert!(outputs[2].final_chunk);
    }

    #[test]
    fn output_offset_continues_across_multiple_emits_per_stream() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        let first = supervisor.stdout("tool_123", b"abcd", false, 1250).unwrap();
        let second = supervisor.stdout("tool_123", b"ef", true, 1260).unwrap();

        let first_output = match first.into_iter().next().unwrap().payload.unwrap() {
            pb::runner_to_server::Payload::ToolCallOutput(output) => output,
            _ => panic!("expected output"),
        };
        let second_output = match second.into_iter().next().unwrap().payload.unwrap() {
            pb::runner_to_server::Payload::ToolCallOutput(output) => output,
            _ => panic!("expected output"),
        };

        assert_eq!(0, first_output.offset);
        assert_eq!(4, second_output.offset);
        assert_eq!(1, first_output.chunk_sequence);
        assert_eq!(2, second_output.chunk_sequence);
    }

    #[test]
    fn output_flow_control_reservation_uses_release_permit() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        let first = supervisor
            .stdout("tool_123", b"abcdefghijkl", false, 1250)
            .unwrap();
        assert_eq!(3, first.len());
        let permit = supervisor.reserve_output_flow_control(12).unwrap();
        assert_eq!(12, supervisor.output_flow_control_inflight_bytes());

        assert_eq!(
            "TRANSPORT_BACKPRESSURE",
            supervisor.reserve_output_flow_control(5).unwrap_err().code
        );
        assert_eq!(12, supervisor.output_flow_control_inflight_bytes());

        permit.release();
        let second = supervisor.stdout("tool_123", b"12345", true, 1270).unwrap();
        let first_second_output = match second.into_iter().next().unwrap().payload.unwrap() {
            pb::runner_to_server::Payload::ToolCallOutput(output) => output,
            _ => panic!("expected output"),
        };

        let _second_permit = supervisor.reserve_output_flow_control(5).unwrap();
        assert_eq!(5, supervisor.output_flow_control_inflight_bytes());
        assert_eq!(4, first_second_output.chunk_sequence);
        assert_eq!(12, first_second_output.offset);
    }

    #[test]
    fn stderr_has_independent_output_offset() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        supervisor.stdout("tool_123", b"abcd", false, 1250).unwrap();
        let stderr = supervisor.stderr("tool_123", b"err", true, 1260).unwrap();
        let stderr_output = match stderr.into_iter().next().unwrap().payload.unwrap() {
            pb::runner_to_server::Payload::ToolCallOutput(output) => output,
            _ => panic!("expected output"),
        };

        assert_eq!(0, stderr_output.offset);
        assert_eq!(1, stderr_output.chunk_sequence);
    }

    #[test]
    fn result_after_deadline_is_rejected() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        assert_eq!(
            "STREAM_DEADLINE_EXCEEDED",
            supervisor
                .tool_call_result("tool_123", 5000)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn cancel_message_blocks_output_and_can_emit_cancelled_error() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor.tool_call_started("tool_123", 1200).unwrap();

        let event = supervisor
            .accept_server_message(cancel_message(), 1300)
            .unwrap();
        assert!(matches!(
            event,
            ServerEvent::ToolCallCancel {
                outcome: CancelOutcome::Accepted,
                ..
            }
        ));
        assert_eq!(
            "STREAM_TOOL_CALL_CANCELLED",
            supervisor
                .stdout("tool_123", b"late", true, 1310)
                .unwrap_err()
                .code
        );

        let error = supervisor
            .cancelled_tool_call_error("tool_123", 1320)
            .unwrap();
        assert!(matches!(
            error.payload,
            Some(pb::runner_to_server::Payload::ToolCallError(_))
        ));
    }

    #[test]
    fn cancel_before_started_blocks_started() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        supervisor
            .accept_server_message(cancel_message(), 1300)
            .unwrap();

        assert_eq!(
            "STREAM_TOOL_CALL_CANCELLED",
            supervisor
                .tool_call_started("tool_123", 1400)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn cancel_during_approval_blocks_started() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(approval_tool_call_message(), 1100)
            .unwrap();
        supervisor
            .accept_server_message(cancel_message(), 1300)
            .unwrap();

        assert_eq!(
            "STREAM_TOOL_CALL_CANCELLED",
            supervisor
                .tool_call_started("tool_123", 1400)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn cancel_ack_is_generated_for_accepted_unknown_and_terminal_cancel() {
        let mut accepted_supervisor = supervisor();
        accepted_supervisor.runner_hello(1000);
        accepted_supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        accepted_supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        let cancel = cancel_message();
        let cancel_sequence = cancel.sequence;
        let cancel_key = cancel.idempotency_key.clone();
        assert!(matches!(
            accepted_supervisor
                .accept_server_message(cancel, 1300)
                .unwrap(),
            ServerEvent::ToolCallCancel {
                outcome: CancelOutcome::Accepted,
                ..
            }
        ));
        let ack = accepted_supervisor.client_ack(cancel_sequence, cancel_key, 1310);
        let ack_payload = match ack.payload.unwrap() {
            pb::runner_to_server::Payload::Ack(ack) => ack,
            _ => panic!("expected ack"),
        };
        assert_eq!(3, ack_payload.received_server_sequence);
        assert_eq!("cancel", ack_payload.received_idempotency_key);

        let mut unknown_supervisor = supervisor();
        unknown_supervisor.runner_hello(1000);
        unknown_supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        let unknown_cancel = cancel_message_for("unknown_tool", 2);
        let unknown_sequence = unknown_cancel.sequence;
        let unknown_key = unknown_cancel.idempotency_key.clone();
        assert!(matches!(
            unknown_supervisor
                .accept_server_message(unknown_cancel, 1300)
                .unwrap(),
            ServerEvent::ToolCallCancel {
                outcome: CancelOutcome::IgnoredUnknown,
                ..
            }
        ));
        let ack = unknown_supervisor.client_ack(unknown_sequence, unknown_key, 1310);
        let ack_payload = match ack.payload.unwrap() {
            pb::runner_to_server::Payload::Ack(ack) => ack,
            _ => panic!("expected ack"),
        };
        assert_eq!(2, ack_payload.received_server_sequence);
        assert_eq!("cancel-unknown_tool", ack_payload.received_idempotency_key);

        let mut terminal_supervisor = supervisor();
        terminal_supervisor.runner_hello(1000);
        terminal_supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        terminal_supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();
        terminal_supervisor
            .tool_call_started("tool_123", 1200)
            .unwrap();
        terminal_supervisor
            .tool_call_result("tool_123", 1250)
            .unwrap();
        let terminal_cancel = cancel_message();
        let terminal_sequence = terminal_cancel.sequence;
        let terminal_key = terminal_cancel.idempotency_key.clone();
        assert!(matches!(
            terminal_supervisor
                .accept_server_message(terminal_cancel, 1300)
                .unwrap(),
            ServerEvent::ToolCallCancel {
                outcome: CancelOutcome::IgnoredTerminal,
                ..
            }
        ));
        let ack = terminal_supervisor.client_ack(terminal_sequence, terminal_key, 1310);
        let ack_payload = match ack.payload.unwrap() {
            pb::runner_to_server::Payload::Ack(ack) => ack,
            _ => panic!("expected ack"),
        };
        assert_eq!(3, ack_payload.received_server_sequence);
        assert_eq!("cancel", ack_payload.received_idempotency_key);
    }

    #[test]
    fn cannot_send_before_registration() {
        let mut supervisor = supervisor();
        assert_eq!(
            "STREAM_REGISTRATION_REQUIRED",
            supervisor.heartbeat(1000).unwrap_err().code
        );
    }

    #[test]
    fn server_provider_is_rejected() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        let mut request = tool_call_request();
        request.provider = 2;

        assert_eq!(
            "STREAM_PROVIDER_UNSUPPORTED",
            supervisor
                .accept_tool_call_request(request, 1100)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn fake_server_happy_path_accepts_stdout_and_result() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();

        let started = supervisor.tool_call_started("tool_123", 1200).unwrap();
        let chunks = supervisor.stdout("tool_123", b"ok", true, 1250).unwrap();
        let result = supervisor.tool_call_result("tool_123", 1300).unwrap();

        assert_eq!(2, started.sequence);
        assert_eq!(3, chunks[0].sequence);
        assert_eq!(4, result.sequence);
    }

    #[test]
    fn emergency_stop_blocks_new_tool_calls() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor.emergency_stop();

        assert_eq!(
            "STREAM_REGISTRATION_REQUIRED",
            supervisor
                .accept_server_message(tool_call_message(), 1100)
                .unwrap_err()
                .code
        );
        assert!(supervisor.state_snapshot().emergency_stopped);
    }

    #[test]
    fn graceful_shutdown_can_emit_runner_disconnect_with_inflight_ids() {
        let mut supervisor = supervisor();
        supervisor.runner_hello(1000);
        supervisor
            .accept_server_message(server_hello(), 1000)
            .unwrap();
        supervisor
            .accept_server_message(tool_call_message(), 1100)
            .unwrap();

        assert!(!supervisor.graceful_shutdown());
        let disconnect = supervisor.runner_disconnect("shutdown", true, 1400);
        let payload = match disconnect.payload.unwrap() {
            pb::runner_to_server::Payload::Disconnect(disconnect) => disconnect,
            _ => panic!("expected disconnect"),
        };

        assert!(payload.graceful);
        assert_eq!(vec!["tool_123".to_string()], payload.inflight_tool_call_ids);
    }

    #[test]
    fn unknown_server_message_is_non_retryable() {
        let failure = StreamSupervisor::unknown_server_message("mystery_payload");
        assert_eq!("GRPC_UNKNOWN_SERVER_MESSAGE", failure.code);
        assert!(!failure.retryable);
    }
}
