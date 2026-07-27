//! Authenticated, versioned local control protocol used by Codex and other local clients.
//!
//! The wire format is newline-delimited JSON. The daemon deliberately owns workflow state only
//! through the management API: disconnecting an IPC client never cancels a workflow or exits the
//! daemon.

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use getrandom::fill as random_fill;
use loomex_protocol::agent_runtime_v2::{
    AgentExecutionBindingV2, AgentExecutionState, AgentExecutionV2, AgentProcessDispatchV2,
    AgentRetryDisposition, AgentSessionCheckpointV2, AgentTaskRequestV2, ExecutorKind,
    ModelSelectionMode, AGENT_CAPABILITY_SCHEMA_V2, AGENT_PROCESS_DISPATCH_SCHEMA_V2,
};
use loomex_protocol::validate_agent_terminal_submission;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    agent_execution_service::{
        AgentCancellationRegistry, AgentExecutionIdentity, AgentExecutionPreparation,
        AgentExecutionProgress, AgentExecutionProgressPayload, AgentExecutionProgressPhase,
        AgentExecutionProgressSink, AgentExecutionService,
    },
    agent_runtime::{CancellationToken, LocalAgentRuntime, RuntimeConfig},
    executable_config::{AgentExecutableConfig, AgentExecutableProvider},
    execution::{
        canonical_agent_task_payload_digest, canonical_json_payload_digest,
        constant_time_digest_eq, sha256_payload_digest, AgentDeliveryRoute, AgentExecutionJournal,
        AgentExecutionJournalEntry, AgentExecutionReplay, AgentPendingDeliveryKind,
        AgentProcessLoss,
    },
    read_recent_log_entries, redact_log_entry_for_local_output, CoreError, CoreResult,
    CredentialKind, LegacyAgentTaskMode, ManagementApiClient, ManagementCredential,
    PluginAgentCancellationRequest, PluginAgentSuccessorRequest, ProjectRunnerBindingCreateRequest,
    RunnerHumanRequestListQuery,
};

pub const LOCAL_CONTROL_PROTOCOL_VERSION: &str = "loomex.local-control/v1";
pub const LOCAL_CONTROL_SOCKET_NAME: &str = "control.sock";
pub const LOCAL_CONTROL_TOKEN_NAME: &str = "control.token";
pub const LOCAL_CONTROL_MAX_LINE_BYTES: usize = 1024 * 1024;
const AGENT_PROGRESS_OUTBOX_SCHEMA_VERSION: &str = "loomex.agent-progress-outbox/v1";
const AGENT_PROGRESS_OUTBOX_MAX_ENTRIES: usize = 256;
// The execution service admits at most eight active agents and rejects a serialized terminal
// output above 7,000,000 bytes. This budget holds every concurrent terminal plus checkpoints.
const AGENT_PROGRESS_OUTBOX_MAX_BYTES: usize = 96 * 1024 * 1024;
const AGENT_PROGRESS_SEND_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalControlRequest {
    pub protocol_version: String,
    pub id: String,
    pub auth_token: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalControlResponse {
    pub protocol_version: String,
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LocalControlError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalControlError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl LocalControlResponse {
    pub fn success(id: impl Into<String>, result: Value) -> Self {
        Self {
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION.to_string(),
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(
        id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION.to_string(),
            id: id.into(),
            ok: false,
            result: None,
            error: Some(LocalControlError {
                code: code.into(),
                message: message.into(),
                retryable,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalControlPaths {
    pub runtime_dir: PathBuf,
    pub socket_path: PathBuf,
    pub token_path: PathBuf,
}

impl LocalControlPaths {
    pub fn for_runtime_dir(runtime_dir: impl Into<PathBuf>) -> Self {
        let runtime_dir = runtime_dir.into();
        Self {
            socket_path: runtime_dir.join(LOCAL_CONTROL_SOCKET_NAME),
            token_path: runtime_dir.join(LOCAL_CONTROL_TOKEN_NAME),
            runtime_dir,
        }
    }

    pub fn for_home(home: &Path) -> Self {
        Self::for_runtime_dir(home.join(".loomex").join("run"))
    }

    pub fn from_environment() -> CoreResult<Self> {
        if let Some(dir) = std::env::var_os("LOOMEX_RUNTIME_DIR") {
            return Ok(Self::for_runtime_dir(dir));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            CoreError::new("LOCAL_CONTROL_HOME_REQUIRED", "HOME is not configured")
        })?;
        Ok(Self::for_home(Path::new(&home)))
    }
}

pub fn prepare_local_control_paths(paths: &LocalControlPaths) -> CoreResult<String> {
    reject_symlink(&paths.runtime_dir)?;
    fs::create_dir_all(&paths.runtime_dir)
        .map_err(|err| CoreError::new("LOCAL_CONTROL_DIR_CREATE_FAILED", err.to_string()))?;
    set_dir_private(&paths.runtime_dir)?;
    reject_symlink(&paths.token_path)?;
    if paths.token_path.exists() {
        validate_private_file(&paths.token_path)?;
        let token = fs::read_to_string(&paths.token_path)
            .map_err(|err| CoreError::new("LOCAL_CONTROL_TOKEN_READ_FAILED", err.to_string()))?;
        let token = token.trim().to_string();
        if token.len() < 32 {
            return Err(CoreError::new(
                "LOCAL_CONTROL_TOKEN_INVALID",
                "local control credential is too short",
            ));
        }
        return Ok(token);
    }
    let mut bytes = [0u8; 32];
    random_fill(&mut bytes)
        .map_err(|err| CoreError::new("LOCAL_CONTROL_RANDOM_FAILED", err.to_string()))?;
    let token = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = paths
        .token_path
        .with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, token.as_bytes())
        .map_err(|err| CoreError::new("LOCAL_CONTROL_TOKEN_WRITE_FAILED", err.to_string()))?;
    set_file_private(&temporary)?;
    fs::rename(&temporary, &paths.token_path)
        .map_err(|err| CoreError::new("LOCAL_CONTROL_TOKEN_WRITE_FAILED", err.to_string()))?;
    Ok(token)
}

pub fn read_local_control_token(paths: &LocalControlPaths) -> CoreResult<String> {
    validate_private_dir(&paths.runtime_dir)?;
    reject_symlink(&paths.token_path)?;
    validate_private_file(&paths.token_path)?;
    fs::read_to_string(&paths.token_path)
        .map(|value| value.trim().to_string())
        .map_err(|err| CoreError::new("LOCAL_CONTROL_TOKEN_READ_FAILED", err.to_string()))
}

pub struct LocalControlDispatcher<C> {
    client: Arc<Mutex<C>>,
    credential: ManagementCredential,
    user_control_credential: Option<ManagementCredential>,
    project_id: Option<String>,
    runner_id: Option<String>,
    binding_id: Option<String>,
    workspace_path: Option<String>,
    log_path: Option<PathBuf>,
    agent_executable_config_path: Option<PathBuf>,
    agent_progress_outbox_path: Option<PathBuf>,
    agent_journal: Option<Arc<Mutex<AgentExecutionJournal>>>,
    agent_cancellations: Option<Arc<AgentCancellationRegistry>>,
    agent_runtime_v2_enabled: bool,
    legacy_agent_task_mode: LegacyAgentTaskMode,
    started_at: Instant,
}

impl<C: ManagementApiClient + Clone + Send + 'static> LocalControlDispatcher<C> {
    pub fn new(client: C, credential: ManagementCredential) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            credential,
            user_control_credential: None,
            project_id: None,
            runner_id: None,
            binding_id: None,
            workspace_path: None,
            log_path: None,
            agent_executable_config_path: None,
            agent_progress_outbox_path: None,
            agent_journal: None,
            agent_cancellations: None,
            agent_runtime_v2_enabled: true,
            legacy_agent_task_mode: LegacyAgentTaskMode::DrainOnly,
            started_at: Instant::now(),
        }
    }

    pub fn with_user_control_credential(
        mut self,
        credential: Option<ManagementCredential>,
    ) -> Self {
        self.user_control_credential = credential;
        self
    }

    pub fn with_context(
        mut self,
        project_id: Option<String>,
        runner_id: Option<String>,
        binding_id: Option<String>,
        workspace_path: Option<String>,
        log_path: Option<PathBuf>,
    ) -> Self {
        self.project_id = project_id;
        self.runner_id = runner_id;
        self.binding_id = binding_id;
        self.workspace_path = workspace_path;
        self.log_path = log_path;
        self
    }

    pub fn with_agent_runtime(
        mut self,
        executable_config_path: PathBuf,
        journal: Arc<Mutex<AgentExecutionJournal>>,
        cancellations: Arc<AgentCancellationRegistry>,
    ) -> Self {
        self.agent_progress_outbox_path =
            Some(executable_config_path.with_extension("progress-outbox.json"));
        self.agent_executable_config_path = Some(executable_config_path);
        self.agent_journal = Some(journal);
        self.agent_cancellations = Some(cancellations);
        self
    }

    pub fn with_agent_cutover(
        mut self,
        agent_runtime_v2_enabled: bool,
        legacy_agent_task_mode: LegacyAgentTaskMode,
    ) -> Self {
        self.agent_runtime_v2_enabled = agent_runtime_v2_enabled;
        self.legacy_agent_task_mode = legacy_agent_task_mode;
        self
    }

    pub fn dispatch(&self, method: &str, params: &Value) -> CoreResult<Value> {
        match method {
            "ping" => Ok(json!({"pong": true, "protocolVersion": LOCAL_CONTROL_PROTOCOL_VERSION})),
            "status" | "runner.status" => self.with_client(|client| {
                Ok(json!({
                    "running": true,
                    "authenticated": true,
                    "profile": self.credential.profile,
                    "organizationId": self.credential.organization_id,
                    "projectId": self.project_id,
                    "runnerId": self.runner_id,
                    "bindingId": self.binding_id,
                    "workspacePath": self.workspace_path,
                    "self": client.get_runner_self_status(&self.credential)?,
                    "bindings": client.list_runner_binding_statuses(&self.credential)?,
                    "uptimeSeconds": self.started_at.elapsed().as_secs(),
                    "protocolVersion": LOCAL_CONTROL_PROTOCOL_VERSION,
                    "runtimeVersion": env!("CARGO_PKG_VERSION"),
                    "service": {"available": false, "status": "unknown", "reason": "service-manager telemetry is provided by the bootstrap client"},
                    "health": {"healthy": true, "status": "ok"},
                    "connection": {"available": true, "status": "connected"},
                    "queue": {"available": false, "depth": null, "reason": "queue telemetry is not exposed by runner-control"},
                    "activeExecutions": {"available": false, "count": null, "items": [], "reason": "active execution telemetry is not exposed by runner-control"},
                    "updateHealth": {"available": false, "status": "unknown", "reason": "update telemetry is not exposed by runner-control"},
                }))
            }),
            "workflow.list" => self.with_client(|client| {
                client.list_runner_workflows_filtered(
                    &self.credential,
                    optional_string(params, "projectId"),
                    Some("plugin"),
                    optional_string(params, "query"),
                    optional_string(params, "cursor"),
                    params.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize,
                )
            }),
            "workflow.show" | "workflow.schema" => {
                let workflow_id = required_string(params, "workflowId")?;
                let version = optional_string(params, "version");
                self.with_client(|client| {
                    serde_json::to_value(client.get_runner_workflow_input_schema_scoped(
                        &self.credential,
                        workflow_id,
                        version,
                        Some("plugin"),
                    )?)
                    .map_err(json_error)
                })
            }
            "workflow.run" => {
                let workflow_id = required_string(params, "workflowId")?;
                let inputs = params.get("inputs").cloned().unwrap_or_else(|| json!({}));
                let binding_id = required_string(params, "bindingId")?;
                let session_id = optional_string(params, "sessionId");
                let version = optional_string(params, "version");
                let idempotency_key = required_string(params, "idempotencyKey")?;
                self.with_client(|client| {
                    run_detail_value(client.start_runner_workflow_execution_scoped(
                        &self.credential,
                        crate::RunnerWorkflowExecutionStartOptions {
                            workflow_id,
                            binding_id,
                            inputs,
                            session_id,
                            version,
                            execution_mode: Some("plugin"),
                            idempotency_key,
                        },
                    )?)
                })
            }
            "run.get" => {
                let execution_id = required_execution_id(params)?;
                self.get_run(execution_id)
            }
            "run.list" => {
                let workflow_id = required_string(params, "workflowId")?;
                let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(20).clamp(1, 200) as usize;
                self.with_client(|client| {
                    run_list_value(client.list_runner_workflow_executions_filtered_scoped(
                        &self.credential,
                        workflow_id,
                        Some("plugin"),
                        optional_string(params, "status"),
                        optional_string(params, "cursor"),
                        limit,
                    )?)
                })
            }
            "run.wait" => self.wait_for_run(params),
            "run.cancel" => {
                let execution_id = required_execution_id(params)?;
                let reason = required_string(params, "reason")?;
                let idempotency_key = required_string(params, "idempotencyKey")?;
                self.with_client(|client| {
                    let mut value = client.cancel_runner_workflow_execution_mode_scoped(
                        &self.credential,
                        execution_id,
                        reason,
                        idempotency_key,
                        Some("plugin"),
                    )?;
                    normalize_execution_field(&mut value);
                    Ok(value)
                })
            }
            "human.list" | "approval.list" => {
                let workflow_id = optional_string(params, "workflowId").unwrap_or("");
                let execution_id = optional_string(params, "executionId");
                let request_type = if method == "approval.list" {
                    Some("approval")
                } else {
                    optional_string(params, "requestType").or(Some("human"))
                };
                self.with_client(|client| {
                    let requests = client.list_human_requests_page(
                        &self.credential,
                        &crate::RunnerHumanRequestListQuery {
                            workflow_id,
                            execution_id,
                            request_type,
                            status: optional_string(params, "status"),
                            cursor: optional_string(params, "cursor"),
                            limit: params
                                .get("limit")
                                .and_then(Value::as_u64)
                                .unwrap_or(100) as usize,
                        },
                    )?;
                    human_request_list_value(requests, method == "approval.list")
                })
            }
            "human.respond" | "approval.decide" => {
                let request_id = required_string(params, "requestId")?;
                let payload = human_resolution_payload(method, params)?;
                self.with_client(|client| {
                    human_resolution_value(client.resolve_human_request_idempotent(
                        &self.credential,
                        request_id,
                        &payload,
                        optional_string(params, "idempotencyKey"),
                    )?)
                })
            }
            "agent.list" => {
                let workflow_id = optional_string(params, "workflowId").unwrap_or("");
                let execution_id = optional_string(params, "executionId");
                self.with_client(|client| {
                    let requests = client.list_human_requests_page(
                        &self.credential,
                        &crate::RunnerHumanRequestListQuery {
                            workflow_id,
                            execution_id,
                            request_type: Some("plugin_agent"),
                            status: optional_string(params, "status"),
                            cursor: optional_string(params, "cursor"),
                            limit: params.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize,
                        },
                    )?;
                    agent_request_list_value(
                        requests,
                        self.agent_runtime_v2_enabled,
                        self.legacy_agent_task_mode,
                    )
                })
            }
            "agent.respond" => {
                let request_id = required_string(params, "requestId")?;
                let request = self.validate_legacy_agent_response_request(request_id)?;
                let mut payload = human_resolution_payload("agent.respond", params)?;
                enrich_legacy_agent_response_identity(&mut payload, &request)?;
                self.with_client(|client| {
                    human_resolution_value(client.resolve_human_request_idempotent(
                        &self.credential,
                        request_id,
                        &payload,
                        optional_string(params, "idempotencyKey"),
                    )?)
                })
            }
            "agent.runtime.status" => self.agent_runtime_status(params),
            "agent.execute" => self.agent_operation_receipt(params, AgentOperation::Execute),
            "agent.resume" => self.agent_operation_receipt(params, AgentOperation::Resume),
            "agent.cancel" => self.agent_operation_receipt(params, AgentOperation::Cancel),
            "agent.checkpoint" => {
                self.agent_operation_receipt(params, AgentOperation::Checkpoint)
            }
            "binding.list" => {
                self.with_client(|client| client.list_runner_binding_statuses_filtered(
                    &self.credential,
                    optional_string(params, "projectId"),
                    optional_string(params, "status"),
                ))
            }
            "binding.create" => {
                let project_id = required_string(params, "projectId")?;
                let runner_id = optional_string(params, "runnerId")
                    .or(self.runner_id.as_deref())
                    .ok_or_else(|| CoreError::new("RUNNER_ID_REQUIRED", "runnerId is required"))?;
                let local_root_path = required_string(params, "localRootPath")?;
                let request = ProjectRunnerBindingCreateRequest {
                    organization_id: optional_string(params, "organizationId")
                        .unwrap_or(&self.credential.organization_id).to_string(),
                    runner_id: runner_id.to_string(),
                    local_root_path: local_root_path.to_string(),
                    local_root_fingerprint: optional_string(params, "localRootFingerprint").map(str::to_string),
                };
                let key = format!("local-control-binding-{}", request.local_root_fingerprint.as_deref().unwrap_or("root"));
                self.with_client(|client| {
                    serde_json::to_value(client.create_project_runner_binding(&self.credential, project_id, &request, &key)?)
                        .map_err(json_error)
                })
            }
            "binding.revoke" => {
                let project_id = required_string(params, "projectId")?;
                let binding_id = required_string(params, "bindingId")?;
                let key = format!("local-control-revoke-{binding_id}");
                self.with_client(|client| {
                    client.revoke_project_runner_binding(&self.credential, project_id, binding_id, &key)?;
                    Ok(json!({"revoked": true, "bindingId": binding_id}))
                })
            }
            "logs.tail" => {
                let log_path = self.log_path.as_deref().ok_or_else(|| CoreError::new("LOG_PATH_NOT_CONFIGURED", "runner log path is not configured"))?;
                let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(100).clamp(1, 200) as usize;
                let offset = optional_string(params, "cursor")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let level = optional_string(params, "level");
                let mut entries = read_recent_log_entries(log_path, 1_000)?;
                if let Some(level) = level {
                    entries.retain(|entry| entry.level == level);
                }
                entries.reverse();
                let total = entries.len();
                let entries = entries
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .map(redact_log_entry_for_local_output)
                    .collect::<Vec<_>>();
                let next_cursor = (offset + entries.len() < total)
                    .then(|| (offset + entries.len()).to_string());
                Ok(json!({"entries": entries, "nextCursor": next_cursor}))
            }
            "doctor" => self.doctor(params),
            "setup.status" | "setup.plan" | "setup.apply" | "setup.rollback" | "auth.status" |
            "auth.start" | "auth.wait" |
            "auth.logout" | "org.list" | "org.select" | "project.list" | "project.select" |
            "runner.control" => Err(CoreError::new(
                "LOCAL_CONTROL_METHOD_REQUIRES_BOOTSTRAP_CLIENT",
                format!("{method} must be handled by the bootstrap client before/around the authenticated service"),
            )),
            _ => Err(CoreError::new(
                "LOCAL_CONTROL_METHOD_NOT_FOUND",
                format!("unknown local control method {method}"),
            )),
        }
    }

    fn agent_runtime_status(&self, params: &Value) -> CoreResult<Value> {
        require_exact_object_fields(params, &[])?;
        if !self.agent_runtime_v2_enabled {
            return Ok(json!({
                "schema": AGENT_CAPABILITY_SCHEMA_V2,
                "observedAt": current_rfc3339_timestamp()?,
                "ttlSeconds": 1,
                "runtimes": [],
            }));
        }
        let config_path = self
            .agent_executable_config_path
            .as_deref()
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "agent executable configuration is not attached to local control",
                )
            })?;
        let workspace = self
            .workspace_path
            .as_deref()
            .map(PathBuf::from)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "the bound agent workspace is not configured",
                )
            })?
            .canonicalize()
            .map_err(|_| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "the bound agent workspace is not accessible",
                )
            })?;
        let executable_config = AgentExecutableConfig::load_or_default(config_path)?;
        let runtime_config = runtime_config_from_persisted(&executable_config);
        let cancellation = CancellationToken::default();
        let runtimes = local_agent_runtime()
            .probe_all_force(&runtime_config, &workspace, &cancellation)
            .into_iter()
            .map(public_runtime_capability)
            .collect::<Vec<_>>();
        Ok(json!({
            "schema": AGENT_CAPABILITY_SCHEMA_V2,
            "observedAt": current_rfc3339_timestamp()?,
            "ttlSeconds": runtime_config.probe_ttl.as_secs().clamp(1, 300),
            "runtimes": runtimes,
        }))
    }

    fn agent_operation_receipt(
        &self,
        params: &Value,
        operation: AgentOperation,
    ) -> CoreResult<Value> {
        let idempotency_field =
            if matches!(operation, AgentOperation::Resume | AgentOperation::Cancel) {
                "operationIdempotencyKey"
            } else {
                "idempotencyKey"
            };
        require_exact_object_fields(params, &["requestId", idempotency_field])?;
        let request_id = required_string(params, "requestId")?;
        let idempotency_key = required_string(params, idempotency_field)?;
        if matches!(operation, AgentOperation::Resume | AgentOperation::Cancel) {
            validate_agent_control_operation_key(idempotency_key)?;
        }
        let disabled_new_work = match operation {
            AgentOperation::Resume => !self.agent_runtime_v2_enabled,
            AgentOperation::Execute => {
                !self.agent_runtime_v2_enabled && !self.has_durable_v2_ownership(request_id)?
            }
            AgentOperation::Cancel | AgentOperation::Checkpoint => false,
        };
        if disabled_new_work {
            return Err(CoreError::new(
                "AGENT_RUNTIME_V2_DISABLED",
                "agent runtime v2 is disabled; new executions are not accepted",
            ));
        }

        match operation {
            AgentOperation::Resume => {
                let (
                    process_attempt_id,
                    process_attempt_number,
                    runner_job_id,
                    binding_generation,
                    checkpoint_id,
                    agent_execution_id,
                    predecessor_sequence,
                ) = {
                    let journal = self.agent_journal.as_ref().ok_or_else(|| {
                        CoreError::new(
                            "AGENT_RUNTIME_UNAVAILABLE",
                            "the durable agent journal is not attached to local control",
                        )
                    })?;
                    let journal = journal.lock().map_err(|_| {
                        CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
                    })?;
                    let entry = journal.entry(request_id).ok_or_else(|| {
                        CoreError::new(
                            "AGENT_INVALID_REQUEST",
                            "no durable execution exists for requestId",
                        )
                    })?;
                    let AgentDeliveryRoute::RunnerJob { job_id, .. } = &entry.delivery_route else {
                        return Err(CoreError::new(
                            "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED",
                            "Backend-owned direct-control successors are unsupported; redispatch through runner_job",
                        ));
                    };
                    let process = entry
                        .attempt_claims
                        .iter()
                        .max_by_key(|claim| claim.attempt_number)
                        .ok_or_else(|| {
                            CoreError::new(
                                "AGENT_SESSION_NOT_FOUND",
                                "the durable agent execution has no predecessor process",
                            )
                        })?;
                    (
                        process.attempt_id.clone(),
                        process.attempt_number,
                        job_id.clone(),
                        entry.binding.workspace_binding_generation,
                        entry
                            .session_checkpoint
                            .as_ref()
                            .map(|checkpoint| checkpoint.checkpoint_id.clone())
                            .unwrap_or_default(),
                        entry.execution_id.clone(),
                        entry.last_progress_sequence,
                    )
                };
                let user_credential = self.validated_agent_user_credential(
                    "AGENT_SUCCESSOR_AUTHORIZATION_REQUIRED",
                    "sign in as a user before authorizing an agent successor",
                )?;
                let receipt = self.with_client(|client| {
                    client.request_plugin_agent_successor(
                        user_credential,
                        request_id,
                        &PluginAgentSuccessorRequest {
                            expected_process_attempt_id: process_attempt_id.clone(),
                            expected_binding_generation: binding_generation,
                            expected_checkpoint_id: checkpoint_id,
                            reason:
                                "User authorized an agent successor through the Loomex Codex plugin."
                                    .to_string(),
                        },
                        idempotency_key,
                    )
                })?;
                if receipt.request_id != request_id
                    || receipt.agent_execution_id != agent_execution_id
                    || receipt.sequence < predecessor_sequence
                    || receipt.predecessor.process_attempt_id != process_attempt_id
                    || !matches!(
                        receipt.predecessor.state.as_str(),
                        "blocked" | "indeterminate"
                    )
                    || receipt.successor.process_attempt_id.trim().is_empty()
                    || receipt.successor.process_attempt_id == process_attempt_id
                    || receipt.successor.attempt_number != process_attempt_number.saturating_add(1)
                    || receipt.successor.job_id == runner_job_id
                    || receipt.successor.job_status != "queued"
                    || !matches!(
                        receipt.successor.mode.as_str(),
                        "resume_exact_session"
                            | "retry_same_selection"
                            | "retry_unresolved_selection"
                    )
                {
                    return Err(CoreError::new(
                        "AGENT_SUCCESSOR_RESPONSE_INVALID",
                        "Backend successor response does not match the durable predecessor",
                    ));
                }
                let mut value = serde_json::to_value(&receipt).map_err(|_| {
                    CoreError::new(
                        "AGENT_SUCCESSOR_RESPONSE_INVALID",
                        "Backend successor receipt could not be serialized",
                    )
                })?;
                let object = value.as_object_mut().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_SUCCESSOR_RESPONSE_INVALID",
                        "Backend successor receipt is not an object",
                    )
                })?;
                object.insert(
                    "schemaVersion".to_string(),
                    Value::String("loomex.agent-successor-control/v1".to_string()),
                );
                object.insert(
                    "controlState".to_string(),
                    Value::String("queued".to_string()),
                );
                Ok(value)
            }
            AgentOperation::Execute => {
                self.validate_durable_agent_idempotency(request_id, idempotency_key)?;
                if let Some(receipt) = self.terminal_agent_replay(request_id, idempotency_key)? {
                    return Ok(receipt);
                }
                self.drain_agent_progress_outbox(request_id)?;
                let authoritative = self.authoritative_agent_task(request_id)?;
                let task = authoritative.task;
                if task.idempotency_key != idempotency_key {
                    return Err(CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "idempotencyKey does not match the authoritative agent task",
                    ));
                }
                self.validate_agent_task_binding(&task)?;
                let service = self.agent_execution_service(&task)?;
                let execution_identity = AgentExecutionIdentity {
                    execution_id: authoritative.update_identity.execution_id.clone(),
                    attempt_id: authoritative.update_identity.attempt_id.clone(),
                    attempt_number: authoritative.process_dispatch.attempt_number,
                    retry_kind: authoritative.process_dispatch.retry_kind,
                    from_attempt_id: authoritative.process_dispatch.from_attempt_id.clone(),
                    delivery: authoritative.process_dispatch.delivery.clone(),
                    task_idempotency_key: authoritative
                        .process_dispatch
                        .task_idempotency_key
                        .clone(),
                    delivery_idempotency_key: authoritative
                        .process_dispatch
                        .delivery_idempotency_key
                        .clone(),
                    payload_digest: authoritative.update_identity.payload_digest.clone(),
                    task_intent_digest: authoritative.task_intent_digest.clone(),
                };
                let sink: Arc<dyn AgentExecutionProgressSink> =
                    Arc::new(HumanRequestAgentProgressSink {
                        client: Arc::clone(&self.client),
                        credential: self.credential.clone(),
                        request_id: request_id.to_string(),
                        identity: authoritative.update_identity,
                        journal: Arc::clone(self.agent_journal.as_ref().ok_or_else(|| {
                            CoreError::new(
                                "AGENT_RUNTIME_UNAVAILABLE",
                                "the durable agent journal is not attached to local control",
                            )
                        })?),
                        outbox_path: self.agent_progress_outbox_path.clone().ok_or_else(|| {
                            CoreError::new(
                                "AGENT_RUNTIME_UNAVAILABLE",
                                "the durable agent progress outbox is not attached to local control",
                            )
                        })?,
                    });
                match service.prepare_with_sink(task.clone(), execution_identity, sink)? {
                    AgentExecutionPreparation::Ready(claimed) => {
                        let receipt = claimed.receipt().clone();
                        thread::Builder::new()
                            .name(format!("loomex-agent-{}", task.request_id))
                            .spawn(move || {
                                if let Err(error) = claimed.execute() {
                                    eprintln!(
                                        "agent execution stopped: {}: {}",
                                        error.code, error.message
                                    );
                                }
                            })
                            .map_err(|_| {
                                CoreError::new(
                                    "AGENT_EXECUTION_THREAD_FAILED",
                                    "agent execution background worker could not be started",
                                )
                            })?;
                        Ok(agent_replay_receipt(&task, &receipt, true))
                    }
                    AgentExecutionPreparation::Replay(replay) => {
                        Ok(agent_replay_receipt(&task, &replay, false))
                    }
                    AgentExecutionPreparation::Reconciled(execution) => Ok(
                        agent_operation_receipt_from_execution(&task, &execution, false),
                    ),
                }
            }
            AgentOperation::Cancel => {
                let user_credential = self.validated_agent_user_credential(
                    "AGENT_CANCELLATION_AUTHORIZATION_REQUIRED",
                    "sign in as a user before requesting agent cancellation",
                )?;
                let (
                    process_attempt_id,
                    runner_job_id,
                    binding_generation,
                    operation_replay,
                    blocked_immediate,
                    agent_execution_id,
                    local_sequence,
                ) = {
                    let journal = self.agent_journal.as_ref().ok_or_else(|| {
                        CoreError::new(
                            "AGENT_RUNTIME_UNAVAILABLE",
                            "the durable agent journal is not attached to local control",
                        )
                    })?;
                    let mut journal = journal.lock().map_err(|_| {
                        CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
                    })?;
                    if let Some(entry) = journal.entry(request_id) {
                        let AgentDeliveryRoute::RunnerJob { job_id, .. } = &entry.delivery_route
                        else {
                            return Err(CoreError::new(
                                "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED",
                                "Backend-owned direct-control cancellation is unsupported; redispatch through runner_job",
                            ));
                        };
                        let process_attempt_id = entry
                            .active_attempt_id
                            .clone()
                            .or_else(|| {
                                entry
                                    .attempt_claims
                                    .iter()
                                    .max_by_key(|claim| claim.attempt_number)
                                    .map(|claim| claim.attempt_id.clone())
                            })
                            .ok_or_else(|| {
                                CoreError::new(
                                    "AGENT_CANCELLATION_STATE_CONFLICT",
                                    "runner-owned agent execution has no process attempt",
                                )
                            })?;
                        let result = (
                            process_attempt_id,
                            job_id.clone(),
                            entry.binding.workspace_binding_generation,
                            entry.cancellation_control_idempotency_key.as_deref()
                                == Some(idempotency_key),
                            entry.state == AgentExecutionState::Blocked,
                            entry.execution_id.clone(),
                            entry.last_progress_sequence,
                        );
                        journal.reserve_cancellation_control(request_id, idempotency_key)?;
                        result
                    } else if let Some(tombstone) = journal.tombstone(request_id)? {
                        let AgentDeliveryRoute::RunnerJob { job_id, .. } =
                            &tombstone.delivery_route
                        else {
                            return Err(CoreError::new(
                                "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED",
                                "Backend-owned direct-control cancellation is unsupported; redispatch through runner_job",
                            ));
                        };
                        if tombstone.cancellation_control_idempotency_key.as_deref()
                            != Some(idempotency_key)
                        {
                            return Err(CoreError::new(
                                "AGENT_CANCELLATION_STATE_CONFLICT",
                                "terminal cancellation can only replay its durably reserved operation key",
                            ));
                        }
                        let process_attempt_id = tombstone
                            .attempt_claims
                            .iter()
                            .max_by_key(|claim| claim.attempt_number)
                            .map(|claim| claim.attempt_id.clone())
                            .ok_or_else(|| {
                                CoreError::new(
                                    "AGENT_CANCELLATION_STATE_CONFLICT",
                                    "archived runner-owned execution has no process attempt",
                                )
                            })?;
                        (
                            process_attempt_id,
                            job_id.clone(),
                            tombstone.binding.workspace_binding_generation,
                            true,
                            false,
                            tombstone.execution_id.clone(),
                            tombstone.terminal_sequence,
                        )
                    } else {
                        return Err(CoreError::new(
                            "AGENT_INVALID_REQUEST",
                            "no durable execution exists for requestId",
                        ));
                    }
                };
                let receipt = self.with_client(|client| {
                    client.request_plugin_agent_cancellation(
                        user_credential,
                        request_id,
                        &PluginAgentCancellationRequest {
                            expected_process_attempt_id: process_attempt_id.clone(),
                            expected_runner_job_id: Some(runner_job_id.clone()),
                            expected_binding_generation: binding_generation,
                            reason: "User requested cancellation through the Loomex Codex plugin."
                                .to_string(),
                        },
                        idempotency_key,
                    )
                })?;
                let job = receipt.job.as_ref().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_CANCELLATION_RESPONSE_INVALID",
                        "runner-owned cancellation response is missing its job",
                    )
                })?;
                let canceling_response = job.status == "canceling"
                    && matches!(
                        receipt.cancellation.state.as_str(),
                        "requested" | "acknowledged"
                    );
                let blocked_response = (blocked_immediate
                    || (operation_replay && receipt.replayed))
                    && job.status == "deferred"
                    && receipt.cancellation.state == "completed";
                let terminal_replay_response = operation_replay
                    && receipt.replayed
                    && job.status == "canceled"
                    && matches!(
                        receipt.cancellation.state.as_str(),
                        "completed" | "indeterminate"
                    );
                let sequence_matches = if canceling_response {
                    true
                } else if blocked_response {
                    if blocked_immediate {
                        receipt.sequence == local_sequence.saturating_add(1)
                    } else {
                        operation_replay && receipt.replayed && receipt.sequence == local_sequence
                    }
                } else if terminal_replay_response {
                    receipt.sequence == local_sequence
                } else {
                    false
                };
                if receipt.request_id != request_id
                    || receipt.agent_execution_id != agent_execution_id
                    || !sequence_matches
                    || receipt.process_attempt_id != process_attempt_id
                    || receipt.cancellation.delivery_route != "runner_job"
                    || receipt.local_cancellation_authorized
                    || job.id != runner_job_id
                    || job.lease_version == 0
                    || !(canceling_response || blocked_response || terminal_replay_response)
                {
                    return Err(CoreError::new(
                        "AGENT_CANCELLATION_RESPONSE_INVALID",
                        "Backend cancellation response does not match the durable runner-owned process",
                    ));
                }
                if blocked_immediate && blocked_response {
                    let journal = self.agent_journal.as_ref().ok_or_else(|| {
                        CoreError::new(
                            "AGENT_RUNTIME_UNAVAILABLE",
                            "the durable agent journal is not attached to local control",
                        )
                    })?;
                    journal
                        .lock()
                        .map_err(|_| {
                            CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
                        })?
                        .archive_authoritative_blocked_cancellation(
                            request_id,
                            idempotency_key,
                            receipt.sequence,
                            &receipt.cancellation.requested_at,
                        )?;
                }
                let mut value = serde_json::to_value(&receipt).map_err(|_| {
                    CoreError::new(
                        "AGENT_CANCELLATION_RESPONSE_INVALID",
                        "Backend cancellation receipt could not be serialized",
                    )
                })?;
                let object = value.as_object_mut().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_CANCELLATION_RESPONSE_INVALID",
                        "Backend cancellation receipt is not an object",
                    )
                })?;
                object.insert(
                    "schemaVersion".to_string(),
                    Value::String("loomex.agent-cancellation-control/v1".to_string()),
                );
                object.insert(
                    "controlState".to_string(),
                    Value::String(
                        if terminal_replay_response {
                            receipt.cancellation.state.as_str()
                        } else if blocked_response {
                            "completed"
                        } else {
                            "canceling"
                        }
                        .to_string(),
                    ),
                );
                Ok(value)
            }
            AgentOperation::Checkpoint => {
                let journal = self.agent_journal.as_ref().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_RUNTIME_UNAVAILABLE",
                        "the durable agent journal is not attached to local control",
                    )
                })?;
                let journal = journal.lock().map_err(|_| {
                    CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
                })?;
                let entry = journal.entry(request_id).ok_or_else(|| {
                    CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "no durable execution exists for requestId",
                    )
                })?;
                if entry.idempotency_key != idempotency_key {
                    return Err(CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "idempotencyKey does not match the durable execution",
                    ));
                }
                Ok(agent_journal_receipt(entry, idempotency_key, false))
            }
        }
    }

    fn drain_agent_progress_outbox(&self, request_id: &str) -> CoreResult<()> {
        let Some(path) = self.agent_progress_outbox_path.as_deref() else {
            return Ok(());
        };
        let _ = request_id;
        drain_agent_progress_outbox(
            path,
            &self.client,
            &self.credential,
            None,
            self.agent_journal.as_ref(),
        )
    }

    fn validate_durable_agent_idempotency(
        &self,
        request_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<()> {
        let Some(journal) = self.agent_journal.as_ref() else {
            return Ok(());
        };
        let journal = journal.lock().map_err(|_| {
            CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
        })?;
        let active_conflict = journal
            .entry(request_id)
            .is_some_and(|entry| entry.idempotency_key != idempotency_key);
        let tombstone_conflict = journal
            .tombstone(request_id)?
            .is_some_and(|tombstone| tombstone.idempotency_key != idempotency_key);
        if active_conflict || tombstone_conflict {
            return Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "idempotencyKey does not match the durable execution",
            ));
        }
        Ok(())
    }

    fn terminal_agent_replay(
        &self,
        request_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<Option<Value>> {
        let Some(journal) = self.agent_journal.as_ref() else {
            return Ok(None);
        };
        let (binding, receipt) = {
            let journal = journal.lock().map_err(|_| {
                CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
            })?;
            if let Some(entry) = journal.entry(request_id) {
                if entry.idempotency_key != idempotency_key {
                    return Err(CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "idempotencyKey does not match the durable execution",
                    ));
                }
                if !matches!(
                    entry.state,
                    AgentExecutionState::Completed
                        | AgentExecutionState::Failed
                        | AgentExecutionState::Cancelled
                ) || entry.pending_delivery.is_some()
                {
                    // A terminal receipt is safe only after its exact pending payload was
                    // acknowledged. Otherwise the authoritative pending task must be rebuilt
                    // with its sink so prepare_with_sink can redeliver it.
                    return Ok(None);
                }
                (
                    entry.binding.clone(),
                    agent_journal_receipt(entry, idempotency_key, false),
                )
            } else if let Some(tombstone) = journal.tombstone(request_id)? {
                if tombstone.idempotency_key != idempotency_key {
                    return Err(CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "idempotencyKey does not match the archived execution",
                    ));
                }
                let replay = tombstone.replay_metadata();
                (
                    tombstone.binding,
                    json!({
                        "requestId": replay.request_id,
                        "idempotencyKey": idempotency_key,
                        "executionId": replay.execution_id,
                        "state": replay.state,
                        "accepted": false,
                        "sequence": replay.last_progress_sequence,
                    }),
                )
            } else {
                return Ok(None);
            }
        };
        if self.binding_id.as_deref() != Some(binding.workspace_binding_id.as_str())
            || self.runner_id.as_deref() != Some(binding.runner_id.as_str())
        {
            return Err(CoreError::new(
                "AGENT_SESSION_MISMATCH",
                "durable execution belongs to a different runner or workspace binding",
            ));
        }
        let self_status =
            self.with_client(|client| client.get_runner_self_status(&self.credential))?;
        let generation = self_status
            .pointer("/runner/bindingGeneration")
            .or_else(|| self_status.pointer("/runner/binding_generation"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_SESSION_MISMATCH",
                    "the authenticated runner binding generation is unavailable",
                )
            })?;
        if generation != binding.workspace_binding_generation {
            return Err(CoreError::new(
                "AGENT_SESSION_MISMATCH",
                "durable execution binding generation is stale",
            ));
        }
        Ok(Some(receipt))
    }

    fn authoritative_agent_task(&self, request_id: &str) -> CoreResult<AuthoritativeAgentTask> {
        let summary = self.with_client(|client| {
            let mut cursor: Option<String> = None;
            let mut seen_cursors = std::collections::BTreeSet::new();
            for _ in 0..100 {
                let page = client.list_human_requests_page(
                    &self.credential,
                    &RunnerHumanRequestListQuery {
                        workflow_id: "",
                        execution_id: None,
                        request_type: Some("plugin_agent"),
                        status: Some("pending"),
                        cursor: cursor.as_deref(),
                        limit: 200,
                    },
                )?;
                if let Some(summary) = page
                    .human_requests
                    .into_iter()
                    .find(|request| request.id == request_id)
                {
                    return Ok(summary);
                }
                let Some(next_cursor) = page.next_cursor.filter(|value| !value.trim().is_empty())
                else {
                    break;
                };
                if !seen_cursors.insert(next_cursor.clone()) {
                    return Err(CoreError::new(
                        "AGENT_TASK_LIST_INVALID",
                        "plugin agent task pagination cursor repeated",
                    ));
                }
                cursor = Some(next_cursor);
            }
            Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "pending plugin agent task was not found",
            ))
        })?;
        match classify_agent_task_schema(&summary.extra) {
            AgentTaskSchemaKind::V2 => {}
            AgentTaskSchemaKind::V1 => {
                return Err(CoreError::new(
                    "AGENT_LEGACY_EXECUTION_REQUIRED",
                    "plugin agent task v1 must use the legacy drain response path",
                ));
            }
            AgentTaskSchemaKind::Unsupported => {
                return Err(CoreError::new(
                    "AGENT_TASK_SCHEMA_UNSUPPORTED",
                    "plugin agent task schema is missing or unsupported",
                ));
            }
        }
        let task_value = summary
            .extra
            .get("agentTask")
            .or_else(|| summary.extra.get("agent_task"))
            .cloned()
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "the authoritative request does not contain an agent task payload",
                )
            })?;
        let authoritative_task_payload_digest = canonical_agent_task_payload_digest(&task_value)?;
        let mut task_intent_value = task_value.clone();
        task_intent_value
            .as_object_mut()
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "the authoritative agent task payload must be an object",
                )
            })?
            .remove("continuation");
        let task_intent_digest = canonical_agent_task_payload_digest(&task_intent_value)?;
        let task: AgentTaskRequestV2 = serde_json::from_value(task_value).map_err(|_| {
            CoreError::new(
                "AGENT_PROTOCOL_MISMATCH",
                "the authoritative request is not a valid plugin agent task v2 payload",
            )
        })?;
        task.validate().map_err(|_| {
            CoreError::new(
                "AGENT_INVALID_REQUEST",
                "the authoritative plugin agent task v2 payload failed validation",
            )
        })?;
        if task.request_id != request_id {
            return Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "requestId does not match the authoritative task",
            ));
        }
        let attempt = summary
            .extra
            .get("agentAttempt")
            .or_else(|| summary.extra.get("agent_attempt"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "the authoritative request does not contain agent attempt metadata",
                )
            })?;
        let execution_id = required_value_string(attempt, "id")?;
        let binding: AgentExecutionBindingV2 =
            serde_json::from_value(attempt.get("binding").cloned().ok_or_else(|| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "agent attempt binding metadata is missing",
                )
            })?)
            .map_err(|_| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "agent attempt binding metadata is invalid",
                )
            })?;
        let process_attempt_id = required_value_string(attempt, "currentProcessAttemptId")?;
        let process = attempt
            .get("processAttempts")
            .and_then(Value::as_array)
            .and_then(|processes| {
                processes.iter().find(|process| {
                    process.get("attemptId").and_then(Value::as_str)
                        == Some(process_attempt_id.as_str())
                })
            })
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "the authoritative request does not contain its current process attempt",
                )
            })?;
        if process
            .get("runnerJobId")
            .is_some_and(|value| !value.is_null())
        {
            return Err(CoreError::new(
                "AGENT_RUNNER_JOB_OWNED",
                "this agent process dispatch is owned by a leased runner job and cannot execute through direct control",
            ));
        }
        let process_dispatch = AgentProcessDispatchV2 {
            schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
            execution_id: execution_id.clone(),
            attempt_id: process_attempt_id.clone(),
            attempt_number: required_value_u32(process, "attemptNumber")?,
            retry_kind: serde_json::from_value(process.get("retryKind").cloned().ok_or_else(
                || {
                    CoreError::new(
                        "AGENT_PROTOCOL_MISMATCH",
                        "agent process retryKind metadata is required",
                    )
                },
            )?)
            .map_err(|_| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "agent process retryKind metadata is invalid",
                )
            })?,
            from_attempt_id: process
                .get("predecessorAttemptId")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            delivery: serde_json::from_value(process.get("delivery").cloned().ok_or_else(
                || {
                    CoreError::new(
                        "AGENT_PROTOCOL_MISMATCH",
                        "agent process delivery metadata is required",
                    )
                },
            )?)
            .map_err(|_| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "agent process delivery metadata is invalid",
                )
            })?,
            task_idempotency_key: required_value_string(process, "taskIdempotencyKey")?,
            delivery_idempotency_key: required_value_string(process, "deliveryIdempotencyKey")?,
            payload_digest: required_value_string(process, "payloadDigest")?,
            task: task.clone(),
        };
        process_dispatch
            .validate_for_direct_control()
            .map_err(|error| {
                if error
                    == loomex_protocol::agent_runtime_v2::AgentProcessDispatchValidationError::PayloadDigestMismatch
                {
                    CoreError::new(
                        "AGENT_INVALID_REQUEST",
                        "authoritative process dispatch payloadDigest does not match its JCS payload",
                    )
                } else {
                    CoreError::new(
                        "AGENT_PROTOCOL_MISMATCH",
                        "the authoritative agent process dispatch failed validation",
                    )
                }
            })?;
        let outer_digest = canonical_json_payload_digest(
            &process_dispatch.payload_digest_input().map_err(|_| {
                CoreError::new(
                    "AGENT_PROTOCOL_MISMATCH",
                    "the authoritative agent process dispatch could not be canonicalized",
                )
            })?,
        )?;
        if !constant_time_digest_eq(&outer_digest, &process_dispatch.payload_digest) {
            return Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "authoritative process dispatch payloadDigest does not match its JCS payload",
            ));
        }
        let update_identity = AgentAttemptUpdateIdentity {
            execution_id,
            attempt_id: process_attempt_id,
            idempotency_key: required_value_string(attempt, "idempotencyKey")?,
            payload_digest: process_dispatch.payload_digest.clone(),
            binding,
        };
        if update_identity.idempotency_key != task.idempotency_key
            || update_identity.binding != task.binding
        {
            return Err(CoreError::new(
                "AGENT_PROTOCOL_MISMATCH",
                "agent task and attempt metadata identities do not match",
            ));
        }
        if !constant_time_digest_eq(
            &required_value_string(attempt, "payloadDigest")?,
            &authoritative_task_payload_digest,
        ) {
            return Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "authoritative agent task payload digest does not match its attempt metadata",
            ));
        }
        Ok(AuthoritativeAgentTask {
            task,
            update_identity,
            task_intent_digest,
            process_dispatch,
        })
    }

    fn validate_legacy_agent_response_request(
        &self,
        request_id: &str,
    ) -> CoreResult<crate::management::HumanRequestSummary> {
        if self.legacy_agent_task_mode == LegacyAgentTaskMode::Disabled {
            return Err(CoreError::new(
                "AGENT_LEGACY_TASKS_DISABLED",
                "legacy agent task responses are disabled",
            ));
        }
        if self.has_durable_v2_ownership(request_id)? {
            return Err(CoreError::new(
                "AGENT_V2_EXECUTION_OWNED",
                "this requestId is owned by the durable agent runtime v2 journal",
            ));
        }
        let summary = self.with_client(|client| {
            let mut cursor: Option<String> = None;
            let mut seen_cursors = std::collections::BTreeSet::new();
            for _ in 0..100 {
                let page = client.list_human_requests_page(
                    &self.credential,
                    &RunnerHumanRequestListQuery {
                        workflow_id: "",
                        execution_id: None,
                        request_type: Some("plugin_agent"),
                        status: Some("all"),
                        cursor: cursor.as_deref(),
                        limit: 200,
                    },
                )?;
                if let Some(summary) = page
                    .human_requests
                    .into_iter()
                    .find(|request| request.id == request_id)
                {
                    return Ok(summary);
                }
                let Some(next_cursor) = page.next_cursor.filter(|value| !value.trim().is_empty())
                else {
                    break;
                };
                if !seen_cursors.insert(next_cursor.clone()) {
                    return Err(CoreError::new(
                        "AGENT_TASK_LIST_INVALID",
                        "plugin agent task pagination cursor repeated",
                    ));
                }
                cursor = Some(next_cursor);
            }
            Err(CoreError::new(
                "AGENT_INVALID_REQUEST",
                "pending plugin agent task was not found",
            ))
        })?;
        match classify_agent_task_schema(&summary.extra) {
            AgentTaskSchemaKind::V1 => Ok(summary),
            AgentTaskSchemaKind::V2 => Err(CoreError::new(
                "AGENT_LEGACY_RESPONSE_FORBIDDEN",
                "legacy agent.respond is allowed only for plugin agent task v1",
            )),
            AgentTaskSchemaKind::Unsupported => Err(CoreError::new(
                "AGENT_TASK_SCHEMA_UNSUPPORTED",
                "plugin agent task schema is missing or unsupported",
            )),
        }
    }

    fn has_durable_v2_ownership(&self, request_id: &str) -> CoreResult<bool> {
        let Some(journal) = self.agent_journal.as_ref() else {
            return Ok(false);
        };
        let journal = journal.lock().map_err(|_| {
            CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
        })?;
        Ok(journal.entry(request_id).is_some() || journal.tombstone(request_id)?.is_some())
    }

    fn agent_execution_service(
        &self,
        task: &AgentTaskRequestV2,
    ) -> CoreResult<AgentExecutionService> {
        let config_path = self
            .agent_executable_config_path
            .as_deref()
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "agent executable configuration is not attached to local control",
                )
            })?;
        let executable_config = AgentExecutableConfig::load_or_default(config_path)?;
        let config = runtime_config_from_persisted(&executable_config);
        let workspace = self
            .workspace_path
            .as_deref()
            .map(PathBuf::from)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "the bound agent workspace is not configured",
                )
            })?
            .canonicalize()
            .map_err(|_| {
                CoreError::new(
                    "AGENT_RUNTIME_UNAVAILABLE",
                    "the bound agent workspace is not accessible",
                )
            })?;
        let journal = self.agent_journal.as_ref().cloned().ok_or_else(|| {
            CoreError::new(
                "AGENT_RUNTIME_UNAVAILABLE",
                "the durable agent journal is not attached to local control",
            )
        })?;
        let cancellations = self.agent_cancellations.as_ref().cloned().ok_or_else(|| {
            CoreError::new(
                "AGENT_RUNTIME_UNAVAILABLE",
                "agent cancellation coordination is not attached to local control",
            )
        })?;
        Ok(AgentExecutionService::with_cancellation_registry(
            Arc::clone(local_agent_runtime()),
            Arc::new(Mutex::new(config)),
            Arc::new(Mutex::new(workspace)),
            Arc::new(Mutex::new(task.binding.clone())),
            journal,
            cancellations,
        ))
    }

    fn validate_agent_task_binding(&self, task: &AgentTaskRequestV2) -> CoreResult<()> {
        if self.binding_id.as_deref() != Some(task.binding.workspace_binding_id.as_str())
            || self.runner_id.as_deref() != Some(task.binding.runner_id.as_str())
        {
            return Err(CoreError::new(
                "AGENT_SESSION_MISMATCH",
                "agent task is assigned to a different runner or workspace binding",
            ));
        }
        let self_status =
            self.with_client(|client| client.get_runner_self_status(&self.credential))?;
        let generation = self_status
            .pointer("/runner/bindingGeneration")
            .or_else(|| self_status.pointer("/runner/binding_generation"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_SESSION_MISMATCH",
                    "the authenticated runner binding generation is unavailable",
                )
            })?;
        if generation != task.binding.workspace_binding_generation {
            return Err(CoreError::new(
                "AGENT_SESSION_MISMATCH",
                "agent task binding generation is stale",
            ));
        }
        Ok(())
    }

    fn validated_agent_user_credential(
        &self,
        code: &'static str,
        message: &'static str,
    ) -> CoreResult<&ManagementCredential> {
        let credential = self
            .user_control_credential
            .as_ref()
            .filter(|credential| credential.kind == CredentialKind::User)
            .ok_or_else(|| CoreError::new(code, message))?;
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "system clock is invalid"))?
            .as_secs();
        credential
            .validate_not_expiring(now_epoch_seconds, 30)
            .map_err(|_| CoreError::new(code, message))?;
        Ok(credential)
    }

    fn with_client<T>(&self, f: impl FnOnce(&mut C) -> CoreResult<T>) -> CoreResult<T> {
        // Management calls are synchronous and `run.wait` can intentionally remain in a
        // backend long-poll for tens of seconds. Clone the cheap client handle while holding the
        // lock, then release it before performing network I/O so cancel/HITL/status requests can
        // use independent HTTP connections concurrently.
        let mut client = self
            .client
            .lock()
            .map_err(|_| {
                CoreError::new(
                    "LOCAL_CONTROL_CLIENT_POISONED",
                    "management client lock is poisoned",
                )
            })?
            .clone();
        f(&mut client)
    }

    fn doctor(&self, params: &Value) -> CoreResult<Value> {
        let mut checks = vec![doctor_check(
            "ipc",
            "ok",
            format!("authenticated {LOCAL_CONTROL_PROTOCOL_VERSION} request received"),
        )];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let auth_ok = match self.credential.validate_not_expiring(now, 30) {
            Ok(()) => {
                checks.push(doctor_check(
                    "auth",
                    "ok",
                    "management credential is present and valid",
                ));
                true
            }
            Err(error) => {
                checks.push(doctor_check(
                    "auth",
                    "failed",
                    format!("{}: {}", error.code, error.message),
                ));
                false
            }
        };
        if auth_ok {
            let backend =
                self.with_client(|client| client.get_runner_self_status(&self.credential));
            match backend {
                Ok(status) => {
                    let authenticated_runner_id = status
                        .get("data")
                        .and_then(|value| value.get("runner"))
                        .or_else(|| status.get("runner"))
                        .and_then(|runner| runner.get("id"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    match (self.runner_id.as_deref(), authenticated_runner_id) {
                        (Some(configured), Some(authenticated)) if configured != authenticated => {
                            checks.push(doctor_check(
                                "backend",
                                "failed",
                                "RUNNER_IDENTITY_MISMATCH: authenticated runner does not match configured runnerId",
                            ));
                        }
                        (_, None) => checks.push(doctor_check(
                            "backend",
                            "failed",
                            "RUNNER_SELF_RESPONSE_INVALID: authenticated runner.id is missing",
                        )),
                        _ => checks.push(doctor_check(
                            "backend",
                            "ok",
                            "authenticated runner-control request succeeded",
                        )),
                    }
                }
                Err(error) => checks.push(doctor_check(
                    "backend",
                    "failed",
                    format!("{}: {}", error.code, error.message),
                )),
            }
        } else {
            checks.push(doctor_check(
                "backend",
                "warning",
                "backend check skipped because authentication is invalid",
            ));
        }
        checks.push(workspace_local_control_doctor_check(
            self.workspace_path.as_deref(),
        ));
        if params
            .get("verbose")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let context_ready = self.project_id.is_some()
                && self.runner_id.is_some()
                && self.binding_id.is_some()
                && self.workspace_path.is_some();
            checks.push(doctor_check(
                "context",
                if context_ready { "ok" } else { "warning" },
                if context_ready {
                    "project, runner, binding, and workspace context is complete"
                } else {
                    "runner context is incomplete"
                },
            ));
            match self.log_path.as_deref() {
                Some(path) => match read_recent_log_entries(path, 1) {
                    Ok(_) => checks.push(doctor_check(
                        "logs",
                        "ok",
                        format!("structured log is readable at {}", path.display()),
                    )),
                    Err(error) => checks.push(doctor_check(
                        "logs",
                        "failed",
                        format!("{}: {}", error.code, error.message),
                    )),
                },
                None => checks.push(doctor_check(
                    "logs",
                    "warning",
                    "structured log path is not configured",
                )),
            }
        }
        let status = if checks.iter().any(|check| check["status"] == "failed") {
            "failed"
        } else if checks.iter().any(|check| check["status"] == "warning") {
            "warning"
        } else {
            "ok"
        };
        Ok(json!({"status": status, "checks": checks}))
    }

    fn get_run(&self, execution_id: &str) -> CoreResult<Value> {
        self.with_client(|client| {
            run_detail_value(client.get_runner_workflow_execution_scoped(
                &self.credential,
                execution_id,
                Some("plugin"),
            )?)
        })
    }

    fn wait_for_run(&self, params: &Value) -> CoreResult<Value> {
        let execution_id = required_execution_id(params)?;
        let timeout_seconds = params
            .get("timeoutSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .clamp(0, 45);
        let after_sequence = params
            .get("afterSequence")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.with_client(|client| {
            let response = client.wait_runner_workflow_execution_scoped(
                &self.credential,
                execution_id,
                after_sequence,
                timeout_seconds,
                Some("plugin"),
            )?;
            run_detail_value(response)
        })
    }
}

fn run_detail_value(mut response: crate::RunnerWorkflowExecutionResponse) -> CoreResult<Value> {
    normalize_run_status(&mut response.execution);
    serde_json::to_value(response).map_err(json_error)
}

fn run_list_value(mut response: crate::RunnerWorkflowExecutionListResponse) -> CoreResult<Value> {
    for execution in &mut response.executions {
        normalize_run_status(execution);
    }
    serde_json::to_value(response).map_err(json_error)
}

fn normalize_execution_field(value: &mut Value) {
    if let Some(execution) = value.get_mut("execution") {
        normalize_run_status(execution);
    }
}

fn normalize_run_status(execution: &mut Value) {
    let Some(status) = execution.get_mut("status") else {
        return;
    };
    let Some(raw) = status.as_str() else {
        return;
    };
    let Some(canonical) = canonical_run_status(raw) else {
        return;
    };
    *status = Value::String(canonical.to_string());
}

fn human_resolution_value(mut response: crate::HumanRequestResolveResponse) -> CoreResult<Value> {
    if let Some(status) = response.execution_status.as_deref() {
        if let Some(canonical) = canonical_run_status(status) {
            response.execution_status = Some(canonical.to_string());
        }
    }
    serde_json::to_value(response).map_err(json_error)
}

fn human_request_list_value(
    mut response: crate::RunnerHumanRequestListResponse,
    approvals: bool,
) -> CoreResult<Value> {
    if approvals {
        for request in &mut response.human_requests {
            if request.status != "resolved" {
                continue;
            }
            let decision = request
                .extra
                .get("answer")
                .and_then(Value::as_object)
                .and_then(|answer| answer.get("decision"))
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase);
            request.status = match decision.as_deref() {
                Some("approve" | "approved" | "allow" | "allow_once") => "approved".to_string(),
                Some("reject" | "rejected" | "deny" | "denied") => "rejected".to_string(),
                _ => continue,
            };
        }
    }
    serde_json::to_value(response).map_err(json_error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentTaskSchemaKind {
    V1,
    V2,
    Unsupported,
}

fn classify_agent_task_schema(extra: &Map<String, Value>) -> AgentTaskSchemaKind {
    let schema_version = extra
        .get("agentTask")
        .or_else(|| extra.get("agent_task"))
        .and_then(Value::as_object)
        .and_then(|task| {
            task.get("schemaVersion")
                .or_else(|| task.get("schema_version"))
        })
        .and_then(Value::as_str);
    match schema_version {
        Some("loomex.plugin-agent-task/v1") => AgentTaskSchemaKind::V1,
        Some(loomex_protocol::agent_runtime_v2::AGENT_TASK_SCHEMA_V2) => AgentTaskSchemaKind::V2,
        _ => AgentTaskSchemaKind::Unsupported,
    }
}

fn agent_request_list_value(
    mut response: crate::RunnerHumanRequestListResponse,
    agent_runtime_v2_enabled: bool,
    legacy_agent_task_mode: LegacyAgentTaskMode,
) -> CoreResult<Value> {
    for request in &mut response.human_requests {
        let support = match classify_agent_task_schema(&request.extra) {
            AgentTaskSchemaKind::V1 if legacy_agent_task_mode == LegacyAgentTaskMode::DrainOnly => {
                "legacy_drain"
            }
            AgentTaskSchemaKind::V1 => "disabled",
            AgentTaskSchemaKind::V2 if agent_runtime_v2_enabled => "agent_runtime_v2",
            AgentTaskSchemaKind::V2 => "disabled",
            AgentTaskSchemaKind::Unsupported => "unsupported",
        };
        request.extra.insert(
            "executionSupport".to_string(),
            Value::String(support.to_string()),
        );
    }
    serde_json::to_value(response).map_err(json_error)
}

fn canonical_run_status(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "waiting" => "waiting_for_human",
        "completed" => "succeeded",
        "canceled" | "cancelled" => "cancelled",
        _ => return None,
    })
}

fn validate_agent_control_operation_key(value: &str) -> CoreResult<()> {
    loomex_protocol::agent_runtime_v2::validate_idempotency_key(value).map_err(|_| {
        CoreError::new(
            "IDEMPOTENCY_KEY_INVALID",
            "operationIdempotencyKey must use the protocol-safe grammar and not exceed 160 bytes",
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentOperation {
    Execute,
    Resume,
    Cancel,
    Checkpoint,
}

#[derive(Debug, Clone)]
struct AuthoritativeAgentTask {
    task: AgentTaskRequestV2,
    update_identity: AgentAttemptUpdateIdentity,
    task_intent_digest: String,
    process_dispatch: AgentProcessDispatchV2,
}

#[derive(Debug, Clone)]
struct AgentAttemptUpdateIdentity {
    execution_id: String,
    attempt_id: String,
    idempotency_key: String,
    payload_digest: String,
    binding: AgentExecutionBindingV2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentProgressOutboxDocument {
    schema_version: String,
    pending: Vec<PendingAgentProgressUpdate>,
}

impl Default for AgentProgressOutboxDocument {
    fn default() -> Self {
        Self {
            schema_version: AGENT_PROGRESS_OUTBOX_SCHEMA_VERSION.to_string(),
            pending: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingAgentProgressUpdate {
    request_id: String,
    sequence: u64,
    idempotency_header: String,
    payload: Value,
}

struct AgentProgressOutbox {
    path: PathBuf,
    document: AgentProgressOutboxDocument,
}

impl AgentProgressOutbox {
    fn open(path: &Path) -> CoreResult<Self> {
        reject_symlink(path)?;
        let document = if path.exists() {
            validate_private_file(path).map_err(|_| {
                CoreError::new(
                    "AGENT_PROGRESS_OUTBOX_INSECURE",
                    "agent progress outbox must be a private regular file",
                )
            })?;
            let metadata = fs::metadata(path).map_err(|error| {
                CoreError::new("AGENT_PROGRESS_OUTBOX_READ_FAILED", error.to_string())
            })?;
            if metadata.len() > AGENT_PROGRESS_OUTBOX_MAX_BYTES as u64 {
                return Err(CoreError::new(
                    "AGENT_PROGRESS_OUTBOX_TOO_LARGE",
                    "agent progress outbox exceeds its safe size limit",
                ));
            }
            let bytes = fs::read(path).map_err(|error| {
                CoreError::new("AGENT_PROGRESS_OUTBOX_READ_FAILED", error.to_string())
            })?;
            serde_json::from_slice(&bytes).map_err(|_| {
                CoreError::new(
                    "AGENT_PROGRESS_OUTBOX_CORRUPT",
                    "agent progress outbox is not valid JSON",
                )
            })?
        } else {
            AgentProgressOutboxDocument::default()
        };
        validate_agent_progress_outbox(&document)?;
        Ok(Self {
            path: path.to_path_buf(),
            document,
        })
    }

    fn enqueue(&mut self, update: PendingAgentProgressUpdate) -> CoreResult<()> {
        validate_pending_agent_progress(&update)?;
        if let Some(existing) = self.document.pending.iter().find(|existing| {
            existing.request_id == update.request_id && existing.sequence == update.sequence
        }) {
            if existing == &update {
                return Ok(());
            }
            return Err(CoreError::new(
                "AGENT_PROGRESS_OUTBOX_CONFLICT",
                "agent progress sequence is already pending with a different update",
            ));
        }
        if self.document.pending.len() >= AGENT_PROGRESS_OUTBOX_MAX_ENTRIES {
            return Err(CoreError::new(
                "AGENT_PROGRESS_OUTBOX_FULL",
                "agent progress outbox reached its bounded entry limit",
            ));
        }
        self.document.pending.push(update);
        self.document
            .pending
            .sort_by_key(|update| (update.request_id.clone(), update.sequence));
        self.persist()
    }

    fn matching(&self, request_id: Option<&str>) -> Vec<PendingAgentProgressUpdate> {
        let mut pending = self
            .document
            .pending
            .iter()
            .filter(|update| request_id.is_none_or(|value| update.request_id == value))
            .cloned()
            .collect::<Vec<_>>();
        pending.sort_by_key(|update| update.sequence);
        pending
    }

    fn acknowledge(&mut self, request_id: &str, sequence: u64) -> CoreResult<()> {
        let previous_len = self.document.pending.len();
        self.document
            .pending
            .retain(|update| update.request_id != request_id || update.sequence != sequence);
        if self.document.pending.len() == previous_len {
            return Err(CoreError::new(
                "AGENT_PROGRESS_OUTBOX_INCONSISTENT",
                "acknowledged agent progress was not present in the outbox",
            ));
        }
        self.persist()
    }

    fn persist(&self) -> CoreResult<()> {
        let bytes = serde_json::to_vec(&self.document).map_err(json_error)?;
        if bytes.len() > AGENT_PROGRESS_OUTBOX_MAX_BYTES {
            return Err(CoreError::new(
                "AGENT_PROGRESS_OUTBOX_TOO_LARGE",
                "agent progress outbox exceeds its safe size limit",
            ));
        }
        let parent = self.path.parent().ok_or_else(|| {
            CoreError::new(
                "AGENT_PROGRESS_OUTBOX_PATH_INVALID",
                "agent progress outbox path has no parent directory",
            )
        })?;
        reject_symlink(parent)?;
        fs::create_dir_all(parent).map_err(|error| {
            CoreError::new("AGENT_PROGRESS_OUTBOX_WRITE_FAILED", error.to_string())
        })?;
        set_dir_private(parent)?;
        let mut random = [0_u8; 8];
        random_fill(&mut random).map_err(|error| {
            CoreError::new("AGENT_PROGRESS_OUTBOX_WRITE_FAILED", error.to_string())
        })?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary = self
            .path
            .with_extension(format!("tmp-{}-{suffix}", std::process::id()));
        reject_symlink(&temporary)?;
        write_private_agent_progress_temporary(&temporary, &bytes)?;
        fs::rename(&temporary, &self.path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            CoreError::new("AGENT_PROGRESS_OUTBOX_WRITE_FAILED", error.to_string())
        })?;
        set_file_private(&self.path)?;
        sync_agent_progress_outbox_directory(parent).map_err(|error| {
            CoreError::new("AGENT_PROGRESS_OUTBOX_WRITE_FAILED", error.to_string())
        })
    }
}

struct HumanRequestAgentProgressSink<C> {
    client: Arc<Mutex<C>>,
    credential: ManagementCredential,
    request_id: String,
    identity: AgentAttemptUpdateIdentity,
    outbox_path: PathBuf,
    journal: Arc<Mutex<AgentExecutionJournal>>,
}

impl<C: ManagementApiClient + Clone + Send + 'static> AgentExecutionProgressSink
    for HumanRequestAgentProgressSink<C>
{
    fn on_progress(&self, progress: AgentExecutionProgress) -> CoreResult<()> {
        if progress.request_id != self.request_id {
            return Err(CoreError::new(
                "AGENT_PROGRESS_IDENTITY_MISMATCH",
                "agent progress request identity changed during execution",
            ));
        }
        let answer = human_request_agent_update(&progress, &self.identity)?;
        let payload = json!({"requestType": "plugin_agent", "answer": answer});
        validate_agent_terminal_submission(&payload).map_err(|_| {
            CoreError::new(
                "AGENT_TERMINAL_SUBMISSION_TOO_LARGE",
                "agent progress exceeds the bounded Backend submission limit",
            )
        })?;
        let header_key = sha256_payload_digest(
            format!(
                "loomex-agent-progress-delivery-v1\u{0}{}\u{0}{}",
                self.identity.idempotency_key, progress.sequence
            )
            .as_bytes(),
        );
        let gate = agent_progress_outbox_gate(&self.outbox_path)?;
        let _guard = gate.lock().map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_OUTBOX_LOCK_POISONED",
                "agent progress outbox transaction lock is poisoned",
            )
        })?;
        let mut outbox = AgentProgressOutbox::open(&self.outbox_path)?;
        outbox.enqueue(PendingAgentProgressUpdate {
            request_id: self.request_id.clone(),
            sequence: progress.sequence,
            idempotency_header: header_key,
            payload,
        })?;
        drop(outbox);
        drain_agent_progress_outbox_locked(
            &self.outbox_path,
            &self.client,
            &self.credential,
            Some(&self.request_id),
            Some(&self.journal),
        )
    }
}

fn drain_agent_progress_outbox<C: ManagementApiClient + Clone + Send + 'static>(
    path: &Path,
    client: &Arc<Mutex<C>>,
    credential: &ManagementCredential,
    request_id: Option<&str>,
    journal: Option<&Arc<Mutex<AgentExecutionJournal>>>,
) -> CoreResult<()> {
    let gate = agent_progress_outbox_gate(path)?;
    let _guard = gate.lock().map_err(|_| {
        CoreError::new(
            "AGENT_PROGRESS_OUTBOX_LOCK_POISONED",
            "agent progress outbox transaction lock is poisoned",
        )
    })?;
    drain_agent_progress_outbox_locked(path, client, credential, request_id, journal)
}

/// Reconciles every durable local-control agent update after service startup or Backend reconnect.
///
/// Callers provide the private executable-config path; the outbox remains a sibling private file.
pub fn reconcile_pending_agent_progress<C: ManagementApiClient + Clone + Send + 'static>(
    client: C,
    credential: &ManagementCredential,
    executable_config_path: &Path,
) -> CoreResult<()> {
    let path = executable_config_path.with_extension("progress-outbox.json");
    drain_agent_progress_outbox(&path, &Arc::new(Mutex::new(client)), credential, None, None)
}

pub fn reconcile_pending_agent_progress_with_journal<
    C: ManagementApiClient + Clone + Send + 'static,
>(
    client: C,
    credential: &ManagementCredential,
    executable_config_path: &Path,
    journal: &Arc<Mutex<AgentExecutionJournal>>,
) -> CoreResult<()> {
    let path = executable_config_path.with_extension("progress-outbox.json");
    materialize_journal_pending_agent_progress(&path, journal)?;
    drain_agent_progress_outbox(
        &path,
        &Arc::new(Mutex::new(client)),
        credential,
        None,
        Some(journal),
    )
}

/// Startup-only recovery for executions whose process ownership was lost with the prior daemon.
///
/// This must run before accepting local requests or runner jobs. Heartbeats/reconnects must use
/// `reconcile_pending_agent_progress_with_journal` instead so they never terminalize a live worker.
pub fn reconcile_stale_agent_executions_at_startup<
    C: ManagementApiClient + Clone + Send + 'static,
>(
    client: C,
    credential: &ManagementCredential,
    executable_config_path: &Path,
    journal: &Arc<Mutex<AgentExecutionJournal>>,
) -> CoreResult<()> {
    reconcile_pending_agent_progress_with_journal(
        client.clone(),
        credential,
        executable_config_path,
        journal,
    )?;
    let stale = journal
        .lock()
        .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned"))?
        .entries()
        .iter()
        .filter(|entry| {
            entry.pending_delivery.is_none()
                && entry.delivery_route == crate::execution::AgentDeliveryRoute::DirectHuman
                && entry.state == AgentExecutionState::Running
        })
        .map(|entry| (entry.request_id.clone(), entry.last_progress_sequence))
        .collect::<Vec<_>>();
    for (request_id, last_sequence) in stale {
        let sequence = last_sequence.checked_add(1).ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_SEQUENCE_EXHAUSTED",
                "agent progress sequence is exhausted",
            )
        })?;
        let timestamp = current_rfc3339_timestamp()?;
        let epoch_ms = current_epoch_ms_core()?;
        journal
            .lock()
            .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned"))?
            .mark_process_lost(
                &request_id,
                sequence,
                AgentProcessLoss::Crash,
                timestamp,
                epoch_ms,
            )?;
    }
    if !journal
        .lock()
        .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned"))?
        .entries()
        .iter()
        .any(|entry| entry.pending_delivery.is_some())
    {
        return Ok(());
    }
    reconcile_pending_agent_progress_with_journal(
        client,
        credential,
        executable_config_path,
        journal,
    )
}

fn materialize_journal_pending_agent_progress(
    path: &Path,
    journal: &Arc<Mutex<AgentExecutionJournal>>,
) -> CoreResult<()> {
    let entries = journal
        .lock()
        .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned"))?
        .entries()
        .iter()
        .filter(|entry| {
            entry.pending_delivery.is_some()
                && entry.delivery_route == crate::execution::AgentDeliveryRoute::DirectHuman
        })
        .cloned()
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Ok(());
    }
    let gate = agent_progress_outbox_gate(path)?;
    let _guard = gate.lock().map_err(|_| {
        CoreError::new(
            "AGENT_PROGRESS_OUTBOX_LOCK_POISONED",
            "agent progress outbox transaction lock is poisoned",
        )
    })?;
    let mut outbox = AgentProgressOutbox::open(path)?;
    for entry in entries {
        let pending = entry.pending_delivery.as_ref().ok_or_else(|| {
            CoreError::new(
                "AGENT_JOURNAL_DELIVERY_INVALID",
                "journal pending delivery disappeared during reconciliation",
            )
        })?;
        let (progress, attempt_id) = match pending.kind {
            AgentPendingDeliveryKind::Checkpoint => {
                let checkpoint: AgentSessionCheckpointV2 =
                    serde_json::from_value(pending.payload.clone()).map_err(|_| {
                        CoreError::new(
                            "AGENT_JOURNAL_DELIVERY_INVALID",
                            "journal checkpoint delivery is invalid",
                        )
                    })?;
                (
                    AgentExecutionProgress {
                        request_id: entry.request_id.clone(),
                        sequence: pending.sequence,
                        phase: AgentExecutionProgressPhase::SessionCheckpointed,
                        payload: AgentExecutionProgressPayload::SessionCheckpoint(
                            checkpoint.clone(),
                        ),
                    },
                    checkpoint.attempt_id,
                )
            }
            AgentPendingDeliveryKind::Execution
            | AgentPendingDeliveryKind::Deferred
            | AgentPendingDeliveryKind::Terminal => {
                let execution: AgentExecutionV2 = serde_json::from_value(pending.payload.clone())
                    .map_err(|_| {
                    CoreError::new(
                        "AGENT_JOURNAL_DELIVERY_INVALID",
                        "journal terminal delivery is invalid",
                    )
                })?;
                let attempt_id = execution
                    .attempts
                    .iter()
                    .max_by_key(|attempt| attempt.attempt_number)
                    .map(|attempt| attempt.attempt_id.clone())
                    .or_else(|| {
                        entry
                            .attempt_claims
                            .last()
                            .map(|claim| claim.attempt_id.clone())
                    })
                    .ok_or_else(|| {
                        CoreError::new(
                            "AGENT_JOURNAL_DELIVERY_INVALID",
                            "journal terminal delivery has no attempt identity",
                        )
                    })?;
                (
                    AgentExecutionProgress {
                        request_id: entry.request_id.clone(),
                        sequence: pending.sequence,
                        phase: agent_execution_progress_phase(execution.state),
                        payload: AgentExecutionProgressPayload::Execution(execution),
                    },
                    attempt_id,
                )
            }
        };
        let payload_digest = entry
            .attempt_claims
            .iter()
            .find(|claim| claim.attempt_id == attempt_id)
            .map(|claim| claim.payload_digest.clone())
            .ok_or_else(|| {
                CoreError::new(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "journal delivery has no authoritative attempt payload digest",
                )
            })?;
        let identity = AgentAttemptUpdateIdentity {
            execution_id: entry.execution_id,
            attempt_id,
            idempotency_key: entry.idempotency_key.clone(),
            payload_digest,
            binding: entry.binding,
        };
        let answer = human_request_agent_update(&progress, &identity)?;
        let payload = json!({"requestType": "plugin_agent", "answer": answer});
        validate_agent_terminal_submission(&payload).map_err(|_| {
            CoreError::new(
                "AGENT_TERMINAL_SUBMISSION_TOO_LARGE",
                "agent progress exceeds the bounded Backend submission limit",
            )
        })?;
        let header_key = sha256_payload_digest(
            format!(
                "loomex-agent-progress-delivery-v1\u{0}{}\u{0}{}",
                identity.idempotency_key, pending.sequence
            )
            .as_bytes(),
        );
        outbox.enqueue(PendingAgentProgressUpdate {
            request_id: progress.request_id,
            sequence: pending.sequence,
            idempotency_header: header_key,
            payload,
        })?;
    }
    Ok(())
}

fn agent_execution_progress_phase(state: AgentExecutionState) -> AgentExecutionProgressPhase {
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

fn drain_agent_progress_outbox_locked<C: ManagementApiClient + Clone + Send + 'static>(
    path: &Path,
    client: &Arc<Mutex<C>>,
    credential: &ManagementCredential,
    request_id: Option<&str>,
    journal: Option<&Arc<Mutex<AgentExecutionJournal>>>,
) -> CoreResult<()> {
    let mut outbox = AgentProgressOutbox::open(path)?;
    for pending in outbox.matching(request_id) {
        send_agent_progress_update_bounded(client, credential, &pending)?;
        if let Some(journal) = journal {
            let mut journal = journal.lock().map_err(|_| {
                CoreError::new("AGENT_INTERNAL_ERROR", "agent journal lock is poisoned")
            })?;
            if journal
                .entry(&pending.request_id)
                .and_then(|entry| entry.pending_delivery.as_ref())
                .is_some_and(|delivery| delivery.sequence == pending.sequence)
            {
                journal.acknowledge_delivery(&pending.request_id, pending.sequence)?;
            }
        }
        outbox.acknowledge(&pending.request_id, pending.sequence)?;
    }
    Ok(())
}

fn agent_progress_outbox_gate(path: &Path) -> CoreResult<Arc<Mutex<()>>> {
    static GATES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let mut gates = GATES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| {
            CoreError::new(
                "AGENT_PROGRESS_OUTBOX_LOCK_POISONED",
                "agent progress outbox lock registry is poisoned",
            )
        })?;
    if let Some(gate) = gates.get(path).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(path.to_path_buf(), Arc::downgrade(&gate));
    Ok(gate)
}

fn send_agent_progress_update_bounded<C: ManagementApiClient + Clone + Send + 'static>(
    client: &Arc<Mutex<C>>,
    credential: &ManagementCredential,
    pending: &PendingAgentProgressUpdate,
) -> CoreResult<()> {
    let mut last_error = None;
    for _ in 0..AGENT_PROGRESS_SEND_ATTEMPTS {
        let mut sender = client
            .lock()
            .map_err(|_| {
                CoreError::new(
                    "LOCAL_CONTROL_CLIENT_POISONED",
                    "management client lock is poisoned",
                )
            })?
            .clone();
        match sender.resolve_human_request_idempotent(
            credential,
            &pending.request_id,
            &pending.payload,
            Some(&pending.idempotency_header),
        ) {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    let detail = last_error
        .map(|error| {
            let code = error.code;
            if !code.is_empty()
                && code.len() <= 80
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            {
                code.to_string()
            } else {
                "MANAGEMENT_API_ERROR".to_string()
            }
        })
        .unwrap_or_else(|| "DELIVERY_ATTEMPT_INCOMPLETE".to_string());
    Err(CoreError::new(
        "AGENT_PROGRESS_DELIVERY_UNAVAILABLE",
        format!("agent progress delivery exhausted its bounded retry budget: {detail}"),
    ))
}

fn validate_agent_progress_outbox(document: &AgentProgressOutboxDocument) -> CoreResult<()> {
    if document.schema_version != AGENT_PROGRESS_OUTBOX_SCHEMA_VERSION
        || document.pending.len() > AGENT_PROGRESS_OUTBOX_MAX_ENTRIES
    {
        return Err(CoreError::new(
            "AGENT_PROGRESS_OUTBOX_CORRUPT",
            "agent progress outbox schema or entry count is invalid",
        ));
    }
    for (index, update) in document.pending.iter().enumerate() {
        validate_pending_agent_progress(update)?;
        if document.pending[..index].iter().any(|existing| {
            existing.request_id == update.request_id && existing.sequence == update.sequence
        }) {
            return Err(CoreError::new(
                "AGENT_PROGRESS_OUTBOX_CORRUPT",
                "agent progress outbox contains duplicate request sequences",
            ));
        }
    }
    Ok(())
}

fn validate_pending_agent_progress(update: &PendingAgentProgressUpdate) -> CoreResult<()> {
    let answer = update
        .payload
        .as_object()
        .filter(|payload| {
            payload.len() == 2
                && payload.get("requestType").and_then(Value::as_str) == Some("plugin_agent")
        })
        .and_then(|payload| payload.get("answer"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_PROGRESS_OUTBOX_CORRUPT",
                "pending agent progress payload is not a plugin-agent update",
            )
        })?;
    if update.request_id.is_empty()
        || update.request_id.len() > 256
        || update.sequence == 0
        || answer.get("sequence").and_then(Value::as_u64) != Some(update.sequence)
        || update.idempotency_header.is_empty()
        || update.idempotency_header.len() > 512
    {
        return Err(CoreError::new(
            "AGENT_PROGRESS_OUTBOX_CORRUPT",
            "pending agent progress identity or sequence is invalid",
        ));
    }
    Ok(())
}

fn write_private_agent_progress_temporary(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| CoreError::new("AGENT_PROGRESS_OUTBOX_WRITE_FAILED", error.to_string()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CoreError::new(
            "AGENT_PROGRESS_OUTBOX_WRITE_FAILED",
            error.to_string(),
        ));
    }
    drop(file);
    set_file_private(path)
}

#[cfg(unix)]
fn sync_agent_progress_outbox_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_agent_progress_outbox_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn local_agent_runtime() -> &'static Arc<LocalAgentRuntime> {
    static RUNTIME: OnceLock<Arc<LocalAgentRuntime>> = OnceLock::new();
    RUNTIME.get_or_init(|| Arc::new(LocalAgentRuntime::default()))
}

fn runtime_config_from_persisted(executables: &AgentExecutableConfig) -> RuntimeConfig {
    let mut config = RuntimeConfig::default();
    for (provider, executor) in [
        (AgentExecutableProvider::Codex, ExecutorKind::CodexCli),
        (AgentExecutableProvider::Claude, ExecutorKind::ClaudeCli),
        (AgentExecutableProvider::Agy, ExecutorKind::AgyCli),
    ] {
        if let Ok(path) = executables.resolve_executable(provider) {
            config.executables.insert(executor, path);
        }
    }
    config
}

fn public_runtime_capability(
    capability: loomex_protocol::agent_runtime_v2::AgentExecutorCapability,
) -> Value {
    let installed = matches!(
        capability.installation,
        loomex_protocol::agent_runtime_v2::InstallationState::Installed
    );
    let models = capability
        .models
        .into_iter()
        .map(|model| {
            json!({
                "modelKey": model.model_key,
                "providerModelId": model.provider_model_id,
                "availability": model.availability,
            })
        })
        .collect::<Vec<_>>();
    let mut object = Map::new();
    object.insert("provider".to_string(), json!(capability.provider));
    object.insert("executor".to_string(), json!(capability.executor));
    object.insert("installed".to_string(), Value::Bool(installed));
    object.insert(
        "authentication".to_string(),
        json!(capability.authentication),
    );
    object.insert("readiness".to_string(), json!(capability.readiness));
    object.insert(
        "modelDiscovery".to_string(),
        json!(capability.model_discovery),
    );
    object.insert("models".to_string(), Value::Array(models));
    object.insert("features".to_string(), json!(capability.features));
    if let Some(version) = capability.executor_version {
        object.insert("version".to_string(), Value::String(version));
    }
    Value::Object(object)
}

fn require_exact_object_fields(params: &Value, required: &[&str]) -> CoreResult<()> {
    let object = params.as_object().ok_or_else(|| {
        CoreError::new(
            "AGENT_INVALID_REQUEST",
            "agent operation params must be an object",
        )
    })?;
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err(CoreError::new(
            "AGENT_INVALID_REQUEST",
            "agent operation params do not match the strict local-control contract",
        ));
    }
    Ok(())
}

fn required_value_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> CoreResult<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_PROTOCOL_MISMATCH",
                format!("agent attempt metadata field {field} is required"),
            )
        })
}

fn required_value_u32(object: &serde_json::Map<String, Value>, field: &str) -> CoreResult<u32> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CoreError::new(
                "AGENT_PROTOCOL_MISMATCH",
                format!("agent attempt metadata field {field} must be a positive u32"),
            )
        })
}

fn human_request_agent_update(
    progress: &AgentExecutionProgress,
    identity: &AgentAttemptUpdateIdentity,
) -> CoreResult<Value> {
    let status = match progress.phase {
        AgentExecutionProgressPhase::Queued => "started",
        AgentExecutionProgressPhase::Probing | AgentExecutionProgressPhase::Running => "progress",
        AgentExecutionProgressPhase::SessionCheckpointed => "session_checkpoint",
        AgentExecutionProgressPhase::Blocked => "blocked",
        AgentExecutionProgressPhase::Completed => "completed",
        AgentExecutionProgressPhase::Failed => "failed",
        AgentExecutionProgressPhase::Cancelled => "canceled",
        AgentExecutionProgressPhase::Indeterminate => "indeterminate",
    };
    let mut update = json!({
        "status": status,
        "sequence": progress.sequence,
        "executionId": identity.execution_id,
        "attemptId": identity.attempt_id,
        "idempotencyKey": identity.idempotency_key,
        "payloadDigest": identity.payload_digest,
        "binding": identity.binding,
    });
    let object = update.as_object_mut().ok_or_else(|| {
        CoreError::new(
            "AGENT_INTERNAL_ERROR",
            "agent lifecycle update could not be constructed",
        )
    })?;
    match &progress.payload {
        AgentExecutionProgressPayload::SessionCheckpoint(checkpoint) => {
            validate_progress_checkpoint(checkpoint, identity)?;
            object.insert("provider".to_string(), json!(checkpoint.provider));
            object.insert("executor".to_string(), json!(checkpoint.executor));
            if let (Some(model_key), Some(provider_model_id)) =
                (&checkpoint.model_key, &checkpoint.provider_model_id)
            {
                object.insert(
                    "resolvedModelKey".to_string(),
                    Value::String(model_key.clone()),
                );
                object.insert(
                    "model".to_string(),
                    Value::String(provider_model_id.clone()),
                );
            }
            object.insert(
                "session".to_string(),
                serde_json::to_value(checkpoint).map_err(json_error)?,
            );
        }
        AgentExecutionProgressPayload::Execution(execution) => {
            validate_progress_execution(execution, identity)?;
            if status == "progress" {
                object.insert(
                    "progress".to_string(),
                    json!({"phase": agent_progress_phase_name(progress.phase)}),
                );
            }
            if let Some(attempt) = execution.attempts.last() {
                object.insert("provider".to_string(), json!(attempt.provider));
                object.insert("executor".to_string(), json!(attempt.executor));
                let model_key = attempt
                    .resolved_model_key
                    .as_ref()
                    .or(attempt.requested_model_key.as_ref());
                let provider_model_id = attempt
                    .resolved_provider_model_id
                    .as_ref()
                    .or(attempt.requested_provider_model_id.as_ref());
                if let (Some(model_key), Some(provider_model_id)) = (model_key, provider_model_id) {
                    object.insert(
                        "resolvedModelKey".to_string(),
                        Value::String(model_key.clone()),
                    );
                    object.insert(
                        "model".to_string(),
                        Value::String(provider_model_id.clone()),
                    );
                }
            }
            if let Some(error) = &execution.error {
                object.insert(
                    "error".to_string(),
                    serde_json::to_value(error).map_err(json_error)?,
                );
            }
            if status == "completed" {
                let output = execution.output.as_ref().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_EXECUTION_INVALID",
                        "completed agent execution is missing output",
                    )
                })?;
                let output = output
                    .structured
                    .clone()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| json!({"content": output.content}));
                object.insert("output".to_string(), output);
            }
        }
    }
    Ok(update)
}

fn validate_progress_execution(
    execution: &AgentExecutionV2,
    identity: &AgentAttemptUpdateIdentity,
) -> CoreResult<()> {
    if execution.request_id.trim().is_empty()
        || execution.execution_id != identity.execution_id
        || execution.binding != identity.binding
        || execution
            .attempts
            .last()
            .is_some_and(|attempt| attempt.attempt_id != identity.attempt_id)
    {
        return Err(CoreError::new(
            "AGENT_PROGRESS_IDENTITY_MISMATCH",
            "agent execution progress does not match the authoritative attempt binding",
        ));
    }
    Ok(())
}

fn validate_progress_checkpoint(
    checkpoint: &AgentSessionCheckpointV2,
    identity: &AgentAttemptUpdateIdentity,
) -> CoreResult<()> {
    if checkpoint.binding != identity.binding
        || checkpoint.execution_id != identity.execution_id
        || checkpoint.attempt_id != identity.attempt_id
    {
        return Err(CoreError::new(
            "AGENT_PROGRESS_IDENTITY_MISMATCH",
            "agent checkpoint does not match the authoritative attempt binding",
        ));
    }
    Ok(())
}

fn agent_progress_phase_name(phase: AgentExecutionProgressPhase) -> &'static str {
    match phase {
        AgentExecutionProgressPhase::Queued => "queued",
        AgentExecutionProgressPhase::Probing => "probing",
        AgentExecutionProgressPhase::Running => "running",
        AgentExecutionProgressPhase::SessionCheckpointed => "session_checkpointed",
        AgentExecutionProgressPhase::Blocked => "blocked",
        AgentExecutionProgressPhase::Completed => "completed",
        AgentExecutionProgressPhase::Failed => "failed",
        AgentExecutionProgressPhase::Cancelled => "cancelled",
        AgentExecutionProgressPhase::Indeterminate => "indeterminate",
    }
}

fn agent_operation_receipt_object(
    task: &AgentTaskRequestV2,
    existing: Option<&AgentExecutionJournalEntry>,
    accepted: bool,
) -> Map<String, Value> {
    let (provider, executor, model_key, provider_model_id) = match &task.selection.primary {
        ModelSelectionMode::Exact { target } => (
            Some(target.provider),
            Some(target.executor),
            Some(target.model_key.as_str()),
            Some(target.provider_model_id.as_str()),
        ),
        ModelSelectionMode::Auto { executor, provider } => {
            (Some(*provider), Some(*executor), None, None)
        }
    };
    let state = existing
        .map(|entry| entry.state)
        .unwrap_or(AgentExecutionState::Queued);
    let mut object = Map::new();
    object.insert(
        "requestId".to_string(),
        Value::String(task.request_id.clone()),
    );
    object.insert(
        "idempotencyKey".to_string(),
        Value::String(task.idempotency_key.clone()),
    );
    object.insert("state".to_string(), json!(state));
    object.insert("accepted".to_string(), Value::Bool(accepted));
    object.insert(
        "sequence".to_string(),
        json!(existing
            .map(|entry| entry.last_progress_sequence)
            .unwrap_or(0)),
    );
    if let Some(entry) = existing {
        object.insert(
            "executionId".to_string(),
            Value::String(entry.execution_id.clone()),
        );
        if let Some(checkpoint) = &entry.session_checkpoint {
            object.insert(
                "sessionId".to_string(),
                Value::String(checkpoint.session_id.clone()),
            );
        }
        if let Some(error) = &entry.error {
            object.insert("error".to_string(), public_agent_error(error));
        }
    }
    if let Some(provider) = provider {
        object.insert("provider".to_string(), json!(provider));
    }
    if let Some(executor) = executor {
        object.insert("executor".to_string(), json!(executor));
    }
    if let Some(model_key) = model_key {
        object.insert("modelKey".to_string(), Value::String(model_key.to_string()));
    }
    if let Some(provider_model_id) = provider_model_id {
        object.insert(
            "providerModelId".to_string(),
            Value::String(provider_model_id.to_string()),
        );
    }
    object
}

fn agent_replay_receipt(
    task: &AgentTaskRequestV2,
    replay: &AgentExecutionReplay,
    accepted: bool,
) -> Value {
    let mut object = agent_operation_receipt_object(task, None, accepted);
    object.insert(
        "executionId".to_string(),
        Value::String(replay.execution_id.clone()),
    );
    object.insert("state".to_string(), json!(replay.state));
    object.insert("sequence".to_string(), json!(replay.last_progress_sequence));
    Value::Object(object)
}

fn agent_operation_receipt_from_execution(
    task: &AgentTaskRequestV2,
    execution: &AgentExecutionV2,
    accepted: bool,
) -> Value {
    let mut object = agent_operation_receipt_object(task, None, accepted);
    object.insert(
        "executionId".to_string(),
        Value::String(execution.execution_id.clone()),
    );
    object.insert("state".to_string(), json!(execution.state));
    if let Some(error) = &execution.error {
        object.insert("error".to_string(), public_agent_error(error));
    }
    if let Some(checkpoint) = execution
        .attempts
        .iter()
        .rev()
        .find_map(|attempt| attempt.session.as_ref())
    {
        object.insert(
            "sessionId".to_string(),
            Value::String(checkpoint.session_id.clone()),
        );
    }
    Value::Object(object)
}

fn agent_journal_receipt(
    entry: &AgentExecutionJournalEntry,
    idempotency_key: &str,
    accepted: bool,
) -> Value {
    let latest_attempt = entry
        .attempts
        .iter()
        .max_by_key(|attempt| attempt.attempt_number);
    let mut object = Map::new();
    object.insert(
        "requestId".to_string(),
        Value::String(entry.request_id.clone()),
    );
    object.insert(
        "idempotencyKey".to_string(),
        Value::String(idempotency_key.to_string()),
    );
    object.insert(
        "executionId".to_string(),
        Value::String(entry.execution_id.clone()),
    );
    object.insert("state".to_string(), json!(entry.state));
    object.insert("accepted".to_string(), Value::Bool(accepted));
    object.insert("sequence".to_string(), json!(entry.last_progress_sequence));
    if let Some(attempt) = latest_attempt {
        object.insert("provider".to_string(), json!(attempt.provider));
        object.insert("executor".to_string(), json!(attempt.executor));
        let resolved_pair = attempt
            .resolved_model_key
            .as_ref()
            .zip(attempt.resolved_provider_model_id.as_ref());
        let requested_pair = attempt
            .requested_model_key
            .as_ref()
            .zip(attempt.requested_provider_model_id.as_ref());
        if let Some((model_key, provider_model_id)) = resolved_pair.or(requested_pair) {
            object.insert("modelKey".to_string(), Value::String(model_key.clone()));
            object.insert(
                "providerModelId".to_string(),
                Value::String(provider_model_id.clone()),
            );
        }
    }
    if let Some(checkpoint) = &entry.session_checkpoint {
        object.insert(
            "sessionId".to_string(),
            Value::String(checkpoint.session_id.clone()),
        );
    }
    if let Some(error) = &entry.error {
        object.insert("error".to_string(), public_agent_error(error));
    }
    Value::Object(object)
}

fn public_agent_error(
    error: &loomex_protocol::agent_runtime_v2::AgentRuntimeErrorEnvelopeV2,
) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "retryable": error.retry == AgentRetryDisposition::Retryable,
        "remediation": error.remediation,
    })
}

fn current_epoch_ms_core() -> CoreResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| CoreError::new("AGENT_INTERNAL_ERROR", "system clock is before Unix epoch"))
}

fn current_rfc3339_timestamp() -> CoreResult<String> {
    let seconds = current_epoch_ms_core()? as i64 / 1_000;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn doctor_check(name: &str, status: &str, message: impl Into<String>) -> Value {
    json!({"name": name, "status": status, "message": message.into()})
}

fn workspace_local_control_doctor_check(workspace_path: Option<&str>) -> Value {
    let Some(workspace_path) = workspace_path else {
        return doctor_check("workspace", "warning", "no workspace binding is selected");
    };
    match validate_local_control_workspace(workspace_path) {
        Ok(path) => doctor_check(
            "workspace",
            "ok",
            format!("read/write check succeeded for {}", path.display()),
        ),
        Err(error) => doctor_check(
            "workspace",
            "failed",
            format!("{}: {}", error.code, error.message),
        ),
    }
}

fn validate_local_control_workspace(workspace_path: &str) -> CoreResult<PathBuf> {
    let path = PathBuf::from(workspace_path);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| CoreError::new("WORKSPACE_PATH_INVALID", error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoreError::new(
            "WORKSPACE_PATH_INVALID",
            "workspace must be a non-symlink directory",
        ));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| CoreError::new("WORKSPACE_PATH_INVALID", error.to_string()))?;
    if canonical.parent().is_none() {
        return Err(CoreError::new(
            "WORKSPACE_PATH_UNSAFE",
            "filesystem root cannot be used as a workspace",
        ));
    }
    fs::read_dir(&canonical)
        .map_err(|error| CoreError::new("WORKSPACE_READ_FAILED", error.to_string()))?;
    validate_workspace_access_without_mutation(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_workspace_access_without_mutation(path: &Path) -> CoreResult<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        CoreError::new(
            "WORKSPACE_PATH_INVALID",
            "workspace path contains a NUL byte",
        )
    })?;
    let result = unsafe { libc::access(path.as_ptr(), libc::R_OK | libc::W_OK | libc::X_OK) };
    if result == 0 {
        Ok(())
    } else {
        Err(CoreError::new(
            "WORKSPACE_ACCESS_FAILED",
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

#[cfg(not(unix))]
fn validate_workspace_access_without_mutation(path: &Path) -> CoreResult<()> {
    if fs::metadata(path)
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(true)
    {
        Err(CoreError::new(
            "WORKSPACE_ACCESS_FAILED",
            "workspace is read-only",
        ))
    } else {
        Ok(())
    }
}

pub fn handle_local_control_request<C: ManagementApiClient + Clone + Send + 'static>(
    request: LocalControlRequest,
    expected_token: &str,
    dispatcher: &LocalControlDispatcher<C>,
) -> LocalControlResponse {
    if request.protocol_version != LOCAL_CONTROL_PROTOCOL_VERSION {
        return LocalControlResponse::failure(
            request.id,
            "LOCAL_CONTROL_VERSION_UNSUPPORTED",
            format!("supported protocol is {LOCAL_CONTROL_PROTOCOL_VERSION}"),
            false,
        );
    }
    if !tokens_equal(request.auth_token.as_bytes(), expected_token.as_bytes()) {
        return LocalControlResponse::failure(
            request.id,
            "LOCAL_CONTROL_UNAUTHENTICATED",
            "local control credential is invalid",
            false,
        );
    }
    match dispatcher.dispatch(&request.method, &request.params) {
        Ok(value) => LocalControlResponse::success(request.id, value),
        Err(err) => LocalControlResponse::failure(
            request.id,
            err.code,
            err.message,
            is_retryable_code(err.code),
        ),
    }
}

#[cfg(unix)]
pub struct UnixLocalControlServer<C> {
    paths: LocalControlPaths,
    token: String,
    dispatcher: Arc<LocalControlDispatcher<C>>,
}

#[cfg(unix)]
impl<C: ManagementApiClient + Clone + Send + 'static> UnixLocalControlServer<C> {
    pub fn bind(
        paths: LocalControlPaths,
        dispatcher: LocalControlDispatcher<C>,
    ) -> CoreResult<Self> {
        let token = prepare_local_control_paths(&paths)?;
        if paths.socket_path.exists() {
            reject_symlink(&paths.socket_path)?;
            match std::os::unix::net::UnixStream::connect(&paths.socket_path) {
                Ok(_) => {
                    return Err(CoreError::new(
                        "LOCAL_CONTROL_ALREADY_RUNNING",
                        "local control socket is already accepting connections",
                    ))
                }
                Err(_) => fs::remove_file(&paths.socket_path).map_err(|err| {
                    CoreError::new("LOCAL_CONTROL_STALE_SOCKET_REMOVE_FAILED", err.to_string())
                })?,
            }
        }
        Ok(Self {
            paths,
            token,
            dispatcher: Arc::new(dispatcher),
        })
    }

    pub fn serve(self) -> CoreResult<()> {
        self.serve_connections(None)
    }

    fn serve_connections(self, max_clients: Option<usize>) -> CoreResult<()> {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        let listener = UnixListener::bind(&self.paths.socket_path)
            .map_err(|err| CoreError::new("LOCAL_CONTROL_BIND_FAILED", err.to_string()))?;
        fs::set_permissions(&self.paths.socket_path, fs::Permissions::from_mode(0o600)).map_err(
            |err| CoreError::new("LOCAL_CONTROL_SOCKET_PERMISSION_FAILED", err.to_string()),
        )?;
        for (index, stream) in listener.incoming().enumerate() {
            match stream {
                Ok(stream) => {
                    let dispatcher = Arc::clone(&self.dispatcher);
                    let token = self.token.clone();
                    thread::spawn(move || {
                        let _ = serve_unix_client(stream, &token, &dispatcher);
                    });
                }
                Err(err) => {
                    return Err(CoreError::new(
                        "LOCAL_CONTROL_ACCEPT_FAILED",
                        err.to_string(),
                    ))
                }
            }
            if max_clients.is_some_and(|limit| index + 1 >= limit) {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn serve_unix_client<C: ManagementApiClient + Clone + Send + 'static>(
    stream: std::os::unix::net::UnixStream,
    token: &str,
    dispatcher: &LocalControlDispatcher<C>,
) -> CoreResult<()> {
    let peer_uid = unix_peer_uid(&stream)?;
    let current_uid = unsafe { libc::geteuid() };
    if peer_uid != current_uid {
        return Err(CoreError::new(
            "LOCAL_CONTROL_PEER_REJECTED",
            "IPC peer does not have the daemon user id",
        ));
    }
    let reader_stream = stream
        .try_clone()
        .map_err(|err| CoreError::new("LOCAL_CONTROL_STREAM_FAILED", err.to_string()))?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| CoreError::new("LOCAL_CONTROL_READ_FAILED", err.to_string()))?;
        if read == 0 {
            return Ok(());
        }
        let response = if line.len() > LOCAL_CONTROL_MAX_LINE_BYTES {
            LocalControlResponse::failure(
                "",
                "LOCAL_CONTROL_REQUEST_TOO_LARGE",
                "request exceeds the one MiB protocol limit",
                false,
            )
        } else {
            match serde_json::from_str::<LocalControlRequest>(&line) {
                Ok(request) => handle_local_control_request(request, token, dispatcher),
                Err(err) => LocalControlResponse::failure(
                    "",
                    "LOCAL_CONTROL_REQUEST_INVALID",
                    err.to_string(),
                    false,
                ),
            }
        };
        serde_json::to_writer(&mut writer, &response).map_err(json_error)?;
        writer
            .write_all(b"\n")
            .and_then(|_| writer.flush())
            .map_err(|err| CoreError::new("LOCAL_CONTROL_WRITE_FAILED", err.to_string()))?;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_peer_uid(stream: &std::os::unix::net::UnixStream) -> CoreResult<u32> {
    use std::os::fd::AsRawFd;
    let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credential as *mut _ as *mut _,
            &mut len,
        )
    };
    if result != 0 {
        return Err(CoreError::new(
            "LOCAL_CONTROL_PEER_CREDENTIAL_FAILED",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(credential.uid)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn unix_peer_uid(stream: &std::os::unix::net::UnixStream) -> CoreResult<u32> {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(CoreError::new(
            "LOCAL_CONTROL_PEER_CREDENTIAL_FAILED",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(uid)
}

fn required_string<'a>(params: &'a Value, key: &str) -> CoreResult<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CoreError::new(
                "LOCAL_CONTROL_PARAMETER_REQUIRED",
                format!("{key} is required"),
            )
        })
}

fn optional_string<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required_execution_id(params: &Value) -> CoreResult<&str> {
    optional_string(params, "executionId")
        .or_else(|| optional_string(params, "runId"))
        .ok_or_else(|| {
            CoreError::new(
                "LOCAL_CONTROL_PARAMETER_REQUIRED",
                "executionId is required",
            )
        })
}

fn human_resolution_payload(method: &str, params: &Value) -> CoreResult<Value> {
    if method == "approval.decide" {
        return Ok(json!({
            "decision": required_string(params, "decision")?,
            "reason": optional_string(params, "reason"),
            "requestType": "approval",
        }));
    }
    let response = params.get("payload").cloned().ok_or_else(|| {
        CoreError::new(
            "LOCAL_CONTROL_PARAMETER_REQUIRED",
            "response payload is required",
        )
    })?;
    // The runner-control endpoint treats top-level `answer`, `response`, `payload`, and
    // `decision` keys as transport aliases. Always use an explicit answer envelope so an
    // arbitrary user object containing any of those keys survives unchanged.
    let request_type = if method == "agent.respond" {
        "plugin_agent"
    } else {
        "human"
    };
    Ok(json!({"answer": response, "requestType": request_type}))
}

/// Legacy host sub-agents return only their result. Bind that result to the
/// authoritative attempt fetched from Loomex before resolving the request.
/// This prevents a generated sub-agent session id from being mistaken for the
/// durable attempt identity required by the Backend.
fn enrich_legacy_agent_response_identity(
    payload: &mut Value,
    request: &crate::management::HumanRequestSummary,
) -> CoreResult<()> {
    let Some(attempt) = request
        .extra
        .get("agentAttempt")
        .or_else(|| request.extra.get("agent_attempt"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let answer = payload
        .get_mut("answer")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            CoreError::new("AGENT_RESPONSE_INVALID", "agent response must be an object")
        })?;
    let execution_id = request
        .execution
        .as_ref()
        .map(|execution| execution.id.as_str())
        .unwrap_or_default();
    answer.insert(
        "executionId".to_string(),
        Value::String(execution_id.to_string()),
    );
    for key in ["id", "idempotencyKey", "payloadDigest"] {
        if let Some(value) = attempt.get(key).cloned() {
            let output_key = if key == "id" { "attemptId" } else { key };
            answer.insert(output_key.to_string(), value);
        }
    }
    if let Some(binding) = attempt.get("binding").cloned() {
        answer.insert("binding".to_string(), binding);
    }
    Ok(())
}

fn is_retryable_code(code: &str) -> bool {
    code.contains("HTTP")
        || code.contains("TIMEOUT")
        || code.contains("UNAVAILABLE")
        || code.contains("CONNECT")
}

fn tokens_equal(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        diff |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    diff == 0
}

fn json_error(err: serde_json::Error) -> CoreError {
    CoreError::new("LOCAL_CONTROL_JSON_FAILED", err.to_string())
}

fn reject_symlink(path: &Path) -> CoreResult<()> {
    if fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(CoreError::new(
            "LOCAL_CONTROL_SYMLINK_REJECTED",
            format!("{} must not be a symlink", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_private(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| CoreError::new("LOCAL_CONTROL_PERMISSION_FAILED", err.to_string()))
}
#[cfg(not(unix))]
fn set_dir_private(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_private(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| CoreError::new("LOCAL_CONTROL_PERMISSION_FAILED", err.to_string()))
}
#[cfg(not(unix))]
fn set_file_private(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_dir(path: &Path) -> CoreResult<()> {
    use std::os::unix::{fs::MetadataExt, fs::PermissionsExt};
    let metadata = fs::metadata(path)
        .map_err(|err| CoreError::new("LOCAL_CONTROL_DIR_INVALID", err.to_string()))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CoreError::new(
            "LOCAL_CONTROL_DIR_INSECURE",
            "runtime directory must be owned by the current user with mode 0700",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_private_dir(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &Path) -> CoreResult<()> {
    use std::os::unix::{fs::MetadataExt, fs::PermissionsExt};
    let metadata = fs::metadata(path)
        .map_err(|err| CoreError::new("LOCAL_CONTROL_TOKEN_INVALID", err.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CoreError::new(
            "LOCAL_CONTROL_TOKEN_INSECURE",
            "credential must be owned by the current user with mode 0600",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_private_file(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use loomex_protocol::agent_runtime_v2::{
        AgentDeliveryRouteV2, AgentProcessDeliveryV2, AgentProcessRetryKindV2,
        AGENT_EXECUTION_SCHEMA_V2,
    };
    use std::{io::Read, net::TcpListener, sync::mpsc, time::Duration};

    fn test_credential() -> ManagementCredential {
        ManagementCredential::from_token_response(
            "test",
            "org-test",
            crate::AuthTokenResponse {
                access_token: "test-only-token".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            crate::CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap()
    }

    fn test_user_credential(expires_at: &str) -> ManagementCredential {
        ManagementCredential::from_user_token_response(
            "user-test",
            "org-test",
            crate::AuthTokenResponse {
                access_token: "test-only-user-token".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: expires_at.to_string(),
            },
            crate::CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap()
    }

    fn test_runner_credential() -> ManagementCredential {
        ManagementCredential::from_runner_token_response(
            "runner-test",
            "org-test",
            crate::AuthTokenResponse {
                access_token: "test-only-runner-token".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            crate::CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap()
    }

    fn control_test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "loomex-agent-control-{label}-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn seed_control_journal(
        root: &Path,
        request_id: &str,
        runner_job_id: Option<&str>,
    ) -> Arc<Mutex<AgentExecutionJournal>> {
        let binding = AgentExecutionBindingV2 {
            workspace_binding_id: "binding-control-1".to_string(),
            workspace_binding_generation: 7,
            runner_id: "runner-control-1".to_string(),
        };
        let process_attempt_id = "11111111-1111-4111-8111-111111111111";
        let execution_id = "22222222-2222-4222-8222-222222222222";
        let task_idempotency_key = format!("loomex-agent-attempt-v2:{}", "1".repeat(64));
        let delivery_idempotency_key = format!("loomex-agent-delivery-v2:{}", "2".repeat(64));
        let payload_digest = format!("sha256:{}", "3".repeat(64));
        let delivery = match runner_job_id {
            Some(job_id) => AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::RunnerJob,
                runner_job_id: Some(job_id.to_string()),
                lease_target_runner_id: Some(binding.runner_id.clone()),
            },
            None => AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
        };
        let delivery_route = match runner_job_id {
            Some(job_id) => AgentDeliveryRoute::RunnerJob {
                job_id: job_id.to_string(),
                predecessor_job_id: None,
            },
            None => AgentDeliveryRoute::DirectHuman,
        };
        let execution = AgentExecutionV2 {
            schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
            execution_id: execution_id.to_string(),
            request_id: request_id.to_string(),
            idempotency_key: "task-idempotency-key".to_string(),
            sequence: 1,
            binding: binding.clone(),
            state: AgentExecutionState::Queued,
            active_attempt_id: None,
            attempts: Vec::new(),
            output: None,
            error: None,
            created_at: "2026-07-27T00:00:00Z".to_string(),
            started_at: None,
            finished_at: None,
            updated_at: "2026-07-27T00:00:00Z".to_string(),
        };
        let mut journal =
            AgentExecutionJournal::open(root.join("agent-control-journal.json")).unwrap();
        journal
            .claim_before_spawn(crate::execution::AgentExecutionClaim {
                request_id: request_id.to_string(),
                idempotency_key: "task-idempotency-key".to_string(),
                attempt_id: process_attempt_id.to_string(),
                attempt_number: 1,
                retry_kind: AgentProcessRetryKindV2::Initial,
                from_attempt_id: None,
                delivery,
                task_idempotency_key,
                delivery_idempotency_key,
                task_intent_digest: payload_digest.clone(),
                payload_digest,
                binding,
                delivery_route,
                execution,
                claimed_at_epoch_ms: 1,
            })
            .unwrap();
        Arc::new(Mutex::new(journal))
    }

    fn transition_control_journal_to_cancelled(
        journal: &Arc<Mutex<AgentExecutionJournal>>,
        request_id: &str,
        runner_job_id: &str,
        operation_idempotency_key: &str,
    ) {
        let binding = AgentExecutionBindingV2 {
            workspace_binding_id: "binding-control-1".to_string(),
            workspace_binding_generation: 7,
            runner_id: "runner-control-1".to_string(),
        };
        let delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(runner_job_id.to_string()),
            lease_target_runner_id: Some(binding.runner_id.clone()),
        };
        let attempt = loomex_protocol::agent_runtime_v2::AgentAttemptV2 {
            attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
            attempt_number: 1,
            task_idempotency_key: format!("loomex-agent-attempt-v2:{}", "1".repeat(64)),
            delivery_idempotency_key: format!("loomex-agent-delivery-v2:{}", "2".repeat(64)),
            payload_digest: format!("sha256:{}", "3".repeat(64)),
            state: loomex_protocol::agent_runtime_v2::AgentAttemptState::Running,
            started_sequence: 2,
            finished_sequence: None,
            selection_index: 0,
            executor: ExecutorKind::CodexCli,
            provider: loomex_protocol::agent_runtime_v2::AgentProvider::OpenAi,
            requested_model_key: Some("openai/gpt-5.2".to_string()),
            requested_provider_model_id: Some("gpt-5.2".to_string()),
            resolved_model_key: Some("openai/gpt-5.2".to_string()),
            resolved_provider_model_id: Some("gpt-5.2".to_string()),
            started_at: "2026-07-27T00:00:01Z".to_string(),
            finished_at: None,
            session: None,
            retry: None,
            delivery,
            error: None,
        };
        let mut running = AgentExecutionV2 {
            schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
            execution_id: "22222222-2222-4222-8222-222222222222".to_string(),
            request_id: request_id.to_string(),
            idempotency_key: "task-idempotency-key".to_string(),
            sequence: 2,
            binding,
            state: AgentExecutionState::Running,
            active_attempt_id: Some(attempt.attempt_id.clone()),
            attempts: vec![attempt],
            output: None,
            error: None,
            created_at: "2026-07-27T00:00:00Z".to_string(),
            started_at: Some("2026-07-27T00:00:01Z".to_string()),
            finished_at: None,
            updated_at: "2026-07-27T00:00:01Z".to_string(),
        };
        let mut journal = journal.lock().unwrap();
        journal.acknowledge_delivery(request_id, 1).unwrap();
        journal
            .record_execution(request_id, 2, &running, 2)
            .unwrap();
        journal
            .reserve_cancellation_control(request_id, operation_idempotency_key)
            .unwrap();
        let cancellation_error = crate::agent_runtime::runtime_error(
            loomex_protocol::agent_runtime_v2::AgentErrorCode::Cancelled,
            "The local agent execution was cancelled.",
            crate::agent_runtime::RuntimeErrorContext::default(),
        );
        running.sequence = 3;
        running.state = AgentExecutionState::Cancelled;
        running.active_attempt_id = None;
        running.error = Some(cancellation_error.clone());
        running.finished_at = Some("2026-07-27T00:00:02Z".to_string());
        running.updated_at = "2026-07-27T00:00:02Z".to_string();
        running.attempts[0].state = loomex_protocol::agent_runtime_v2::AgentAttemptState::Cancelled;
        running.attempts[0].finished_sequence = Some(3);
        running.attempts[0].finished_at = running.finished_at.clone();
        running.attempts[0].error = Some(cancellation_error);
        journal
            .record_execution(request_id, 3, &running, 3)
            .unwrap();
    }

    fn transition_control_journal_to_blocked(
        journal: &Arc<Mutex<AgentExecutionJournal>>,
        request_id: &str,
        runner_job_id: &str,
    ) {
        let binding = AgentExecutionBindingV2 {
            workspace_binding_id: "binding-control-1".to_string(),
            workspace_binding_generation: 7,
            runner_id: "runner-control-1".to_string(),
        };
        let delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(runner_job_id.to_string()),
            lease_target_runner_id: Some(binding.runner_id.clone()),
        };
        let attempt = loomex_protocol::agent_runtime_v2::AgentAttemptV2 {
            attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
            attempt_number: 1,
            task_idempotency_key: format!("loomex-agent-attempt-v2:{}", "1".repeat(64)),
            delivery_idempotency_key: format!("loomex-agent-delivery-v2:{}", "2".repeat(64)),
            payload_digest: format!("sha256:{}", "3".repeat(64)),
            state: loomex_protocol::agent_runtime_v2::AgentAttemptState::Running,
            started_sequence: 2,
            finished_sequence: None,
            selection_index: 0,
            executor: ExecutorKind::CodexCli,
            provider: loomex_protocol::agent_runtime_v2::AgentProvider::OpenAi,
            requested_model_key: Some("openai/gpt-5.2".to_string()),
            requested_provider_model_id: Some("gpt-5.2".to_string()),
            resolved_model_key: Some("openai/gpt-5.2".to_string()),
            resolved_provider_model_id: Some("gpt-5.2".to_string()),
            started_at: "2026-07-27T00:00:01Z".to_string(),
            finished_at: None,
            session: None,
            retry: None,
            delivery,
            error: None,
        };
        let mut execution = AgentExecutionV2 {
            schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
            execution_id: "22222222-2222-4222-8222-222222222222".to_string(),
            request_id: request_id.to_string(),
            idempotency_key: "task-idempotency-key".to_string(),
            sequence: 2,
            binding,
            state: AgentExecutionState::Running,
            active_attempt_id: Some(attempt.attempt_id.clone()),
            attempts: vec![attempt],
            output: None,
            error: None,
            created_at: "2026-07-27T00:00:00Z".to_string(),
            started_at: Some("2026-07-27T00:00:01Z".to_string()),
            finished_at: None,
            updated_at: "2026-07-27T00:00:01Z".to_string(),
        };
        let mut journal = journal.lock().unwrap();
        journal.acknowledge_delivery(request_id, 1).unwrap();
        journal
            .record_execution(request_id, 2, &execution, 2)
            .unwrap();
        let blocked_error = crate::agent_runtime::runtime_error(
            loomex_protocol::agent_runtime_v2::AgentErrorCode::ModelNotAvailable,
            "The selected model is unavailable.",
            crate::agent_runtime::RuntimeErrorContext::default(),
        );
        execution.sequence = 3;
        execution.state = AgentExecutionState::Blocked;
        execution.active_attempt_id = None;
        execution.error = Some(blocked_error.clone());
        execution.updated_at = "2026-07-27T00:00:02Z".to_string();
        execution.attempts[0].state = loomex_protocol::agent_runtime_v2::AgentAttemptState::Blocked;
        execution.attempts[0].finished_sequence = Some(3);
        execution.attempts[0].finished_at = Some("2026-07-27T00:00:02Z".to_string());
        execution.attempts[0].error = Some(blocked_error);
        journal
            .record_execution_with_delivery(
                request_id,
                3,
                &execution,
                serde_json::to_value(&execution).unwrap(),
                3,
            )
            .unwrap();
        journal.acknowledge_delivery(request_id, 3).unwrap();
    }

    fn control_dispatcher(
        base_url: impl Into<String>,
        root: &Path,
        journal: Arc<Mutex<AgentExecutionJournal>>,
        user_credential: Option<ManagementCredential>,
    ) -> LocalControlDispatcher<crate::HttpManagementApiClient> {
        LocalControlDispatcher::new(
            crate::HttpManagementApiClient::new(base_url, None).unwrap(),
            test_runner_credential(),
        )
        .with_user_control_credential(user_credential)
        .with_agent_runtime(
            root.join("agent-executables.json"),
            journal,
            Arc::new(AgentCancellationRegistry::default()),
        )
    }

    fn write_http_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn runner_owned_successor_create_and_replay_preserve_authoritative_sequence_and_mode() {
        let root = control_test_root("successor-create-replay");
        let request_id = "agent-control-successor";
        let predecessor_id = "11111111-1111-4111-8111-111111111111";
        let predecessor_job_id = "33333333-3333-4333-8333-333333333333";
        let successor_job_id = "44444444-4444-4444-8444-444444444444";
        let successor_process_id = "55555555-5555-4555-8555-555555555555";
        let journal = seed_control_journal(&root, request_id, Some(predecessor_job_id));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for replayed in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with(
                    "POST /api/v1/workflow-runtime/plugin-agent-requests/agent-control-successor/successors/ "
                ));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-only-user-token"));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("idempotency-key: successor-operation-1"));
                let body = request.split_once("\r\n\r\n").unwrap().1;
                let request_body: Value = serde_json::from_str(body).unwrap();
                assert_eq!(request_body["expectedProcessAttemptId"], predecessor_id);
                assert_eq!(request_body["expectedBindingGeneration"], 7);
                assert_eq!(request_body["expectedCheckpointId"], "");
                assert!(!body.contains("task-idempotency-key"));
                let response = json!({
                    "data": {
                        "requestId": request_id,
                        "agentExecutionId": "22222222-2222-4222-8222-222222222222",
                        "sequence": 1,
                        "predecessor": {
                            "processAttemptId": predecessor_id,
                            "state": "blocked"
                        },
                        "successor": {
                            "processAttemptId": successor_process_id,
                            "attemptNumber": 2,
                            "mode": "retry_unresolved_selection",
                            "jobId": successor_job_id,
                            "jobStatus": "queued"
                        },
                        "authorizationId": "66666666-6666-4666-8666-666666666666",
                        "authorizedAt": "2026-07-27T01:00:00Z",
                        "replayed": replayed
                    }
                })
                .to_string();
                write_http_response(&mut stream, "200 OK", &response);
            }
        });
        let dispatcher = control_dispatcher(
            format!("http://{address}"),
            &root,
            Arc::clone(&journal),
            Some(test_user_credential("9999-12-31T23:59:59Z")),
        );
        let params = json!({
            "requestId": request_id,
            "operationIdempotencyKey": "successor-operation-1"
        });

        let created = dispatcher.dispatch("agent.resume", &params).unwrap();
        let replay = dispatcher.dispatch("agent.resume", &params).unwrap();

        assert_eq!(
            created["schemaVersion"],
            "loomex.agent-successor-control/v1"
        );
        assert_eq!(created["controlState"], "queued");
        assert_eq!(created["sequence"], 1);
        assert_eq!(created["successor"]["mode"], "retry_unresolved_selection");
        assert_eq!(created["replayed"], false);
        assert_eq!(replay["sequence"], 1);
        assert_eq!(replay["replayed"], true);
        assert_eq!(journal.lock().unwrap().entries().len(), 1);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runner_owned_cancellation_create_and_replay_preserve_authoritative_sequence() {
        let root = control_test_root("cancel-create-replay");
        let request_id = "agent-control-cancel";
        let process_id = "11111111-1111-4111-8111-111111111111";
        let job_id = "33333333-3333-4333-8333-333333333333";
        let journal = seed_control_journal(&root, request_id, Some(job_id));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for replayed in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with(
                    "POST /api/v1/workflow-runtime/plugin-agent-requests/agent-control-cancel/cancellations/ "
                ));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-only-user-token"));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("idempotency-key: cancellation-operation-1"));
                let body = request.split_once("\r\n\r\n").unwrap().1;
                let request_body: Value = serde_json::from_str(body).unwrap();
                assert_eq!(request_body["expectedProcessAttemptId"], process_id);
                assert_eq!(request_body["expectedRunnerJobId"], job_id);
                assert_eq!(request_body["expectedBindingGeneration"], 7);
                let response = json!({
                    "data": {
                        "requestId": request_id,
                        "agentExecutionId": "22222222-2222-4222-8222-222222222222",
                        "sequence": 0,
                        "processAttemptId": process_id,
                        "cancellation": {
                            "id": "77777777-7777-4777-8777-777777777777",
                            "state": "requested",
                            "deliveryRoute": "runner_job",
                            "requestedAt": "2026-07-27T01:00:00Z"
                        },
                        "job": {
                            "id": job_id,
                            "status": "canceling",
                            "leaseVersion": 9
                        },
                        "localCancellationAuthorized": false,
                        "replayed": replayed
                    }
                })
                .to_string();
                write_http_response(&mut stream, "200 OK", &response);
            }
        });
        let dispatcher = control_dispatcher(
            format!("http://{address}"),
            &root,
            Arc::clone(&journal),
            Some(test_user_credential("9999-12-31T23:59:59Z")),
        );
        let params = json!({
            "requestId": request_id,
            "operationIdempotencyKey": "cancellation-operation-1"
        });

        let created = dispatcher.dispatch("agent.cancel", &params).unwrap();
        let replay = dispatcher.dispatch("agent.cancel", &params).unwrap();

        assert_eq!(
            created["schemaVersion"],
            "loomex.agent-cancellation-control/v1"
        );
        assert_eq!(created["controlState"], "canceling");
        assert_eq!(created["sequence"], 0);
        assert_eq!(created["localCancellationAuthorized"], false);
        assert_eq!(created["replayed"], false);
        assert_eq!(replay["sequence"], 0);
        assert_eq!(replay["replayed"], true);
        assert_eq!(
            journal
                .lock()
                .unwrap()
                .entry(request_id)
                .unwrap()
                .cancellation_control_idempotency_key
                .as_deref(),
            Some("cancellation-operation-1")
        );
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blocked_deferred_cancellation_archives_and_replays_after_restart() {
        let root = control_test_root("blocked-deferred-cancel-replay");
        let request_id = "agent-blocked-deferred-cancel";
        let process_id = "11111111-1111-4111-8111-111111111111";
        let job_id = "33333333-3333-4333-8333-333333333333";
        let operation_key = "blocked-deferred-cancel-operation";
        let journal = seed_control_journal(&root, request_id, Some(job_id));
        transition_control_journal_to_blocked(&journal, request_id, job_id);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for replayed in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request
                    .to_ascii_lowercase()
                    .contains("idempotency-key: blocked-deferred-cancel-operation"));
                let response = json!({
                    "data": {
                        "requestId": request_id,
                        "agentExecutionId": "22222222-2222-4222-8222-222222222222",
                        "sequence": 4,
                        "processAttemptId": process_id,
                        "cancellation": {
                            "id": "77777777-7777-4777-8777-777777777777",
                            "state": "completed",
                            "deliveryRoute": "runner_job",
                            "requestedAt": "2026-07-27T01:00:00Z"
                        },
                        "job": {
                            "id": job_id,
                            "status": "deferred",
                            "leaseVersion": 9
                        },
                        "localCancellationAuthorized": false,
                        "replayed": replayed
                    }
                })
                .to_string();
                write_http_response(&mut stream, "200 OK", &response);
            }
        });
        let params = json!({
            "requestId": request_id,
            "operationIdempotencyKey": operation_key
        });
        let dispatcher = control_dispatcher(
            format!("http://{address}"),
            &root,
            Arc::clone(&journal),
            Some(test_user_credential("9999-12-31T23:59:59Z")),
        );

        let created = dispatcher.dispatch("agent.cancel", &params).unwrap();
        assert_eq!(created["controlState"], "completed");
        assert_eq!(created["sequence"], 4);
        assert_eq!(created["replayed"], false);
        {
            let locked = journal.lock().unwrap();
            assert!(locked.entry(request_id).is_none());
            let tombstone = locked.tombstone(request_id).unwrap().unwrap();
            assert_eq!(tombstone.terminal_state, AgentExecutionState::Cancelled);
            assert_eq!(tombstone.terminal_sequence, 4);
            assert_eq!(
                tombstone.cancellation_control_idempotency_key.as_deref(),
                Some(operation_key)
            );
        }
        drop(dispatcher);
        drop(journal);

        let reopened = Arc::new(Mutex::new(
            AgentExecutionJournal::open(root.join("agent-control-journal.json")).unwrap(),
        ));
        let replay_dispatcher = control_dispatcher(
            format!("http://{address}"),
            &root,
            Arc::clone(&reopened),
            Some(test_user_credential("9999-12-31T23:59:59Z")),
        );
        let replay = replay_dispatcher.dispatch("agent.cancel", &params).unwrap();
        assert_eq!(replay["controlState"], "completed");
        assert_eq!(replay["sequence"], 4);
        assert_eq!(replay["replayed"], true);
        assert!(reopened.lock().unwrap().entries().is_empty());

        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_terminal_cancellation_replays_same_key_at_equal_sequence() {
        for cancellation_state in ["completed", "indeterminate"] {
            let root = control_test_root(&format!("terminal-replay-{cancellation_state}"));
            let request_id = format!("agent-terminal-replay-{cancellation_state}");
            let process_id = "11111111-1111-4111-8111-111111111111";
            let job_id = "33333333-3333-4333-8333-333333333333";
            let operation_key = format!("terminal-replay-{cancellation_state}");
            let journal = seed_control_journal(&root, &request_id, Some(job_id));
            transition_control_journal_to_cancelled(&journal, &request_id, job_id, &operation_key);
            assert_eq!(
                journal.lock().unwrap().entry(&request_id).unwrap().state,
                AgentExecutionState::Cancelled
            );
            {
                let locked = journal.lock().unwrap();
                let entry = locked.entry(&request_id).unwrap();
                assert_eq!(entry.last_progress_sequence, 3);
                assert_eq!(
                    entry.cancellation_control_idempotency_key.as_deref(),
                    Some(operation_key.as_str())
                );
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let request_id_for_server = request_id.clone();
            let operation_key_for_server = operation_key.clone();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request
                    .to_ascii_lowercase()
                    .contains(&format!("idempotency-key: {}", operation_key_for_server)));
                let response = json!({
                    "data": {
                        "requestId": request_id_for_server,
                        "agentExecutionId": "22222222-2222-4222-8222-222222222222",
                        "sequence": 3,
                        "processAttemptId": process_id,
                        "cancellation": {
                            "id": "77777777-7777-4777-8777-777777777777",
                            "state": cancellation_state,
                            "deliveryRoute": "runner_job",
                            "requestedAt": "2026-07-27T01:00:00Z"
                        },
                        "job": {
                            "id": job_id,
                            "status": "canceled",
                            "leaseVersion": 9
                        },
                        "localCancellationAuthorized": false,
                        "replayed": true
                    }
                })
                .to_string();
                write_http_response(&mut stream, "200 OK", &response);
            });
            let dispatcher = control_dispatcher(
                format!("http://{address}"),
                &root,
                Arc::clone(&journal),
                Some(test_user_credential("9999-12-31T23:59:59Z")),
            );

            let receipt = dispatcher
                .dispatch(
                    "agent.cancel",
                    &json!({
                        "requestId": request_id,
                        "operationIdempotencyKey": operation_key
                    }),
                )
                .unwrap_or_else(|error| panic!("{cancellation_state}: {error:?}"));

            assert_eq!(receipt["sequence"], 3);
            assert_eq!(receipt["replayed"], true);
            assert_eq!(receipt["controlState"], cancellation_state);
            assert_eq!(receipt["cancellation"]["state"], cancellation_state);
            server.join().unwrap();
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn agent_user_control_requires_a_live_user_credential_for_both_routes() {
        for (label, credential) in [
            ("missing", None),
            (
                "expired",
                Some(test_user_credential("2000-01-01T00:00:00Z")),
            ),
            ("runner-kind", Some(test_runner_credential())),
        ] {
            for (method, expected_code) in [
                ("agent.resume", "AGENT_SUCCESSOR_AUTHORIZATION_REQUIRED"),
                ("agent.cancel", "AGENT_CANCELLATION_AUTHORIZATION_REQUIRED"),
            ] {
                let root = control_test_root(&format!("{label}-{method}"));
                let request_id = format!("agent-control-auth-{label}-{method}");
                let journal = seed_control_journal(
                    &root,
                    &request_id,
                    Some("33333333-3333-4333-8333-333333333333"),
                );
                let dispatcher =
                    control_dispatcher("http://127.0.0.1:9", &root, journal, credential.clone());
                let error = dispatcher
                    .dispatch(
                        method,
                        &json!({
                            "requestId": request_id,
                            "operationIdempotencyKey": format!("{label}-operation-1")
                        }),
                    )
                    .unwrap_err();
                assert_eq!(error.code, expected_code, "{label} {method}");
                let _ = fs::remove_dir_all(root);
            }
        }
    }

    #[test]
    fn direct_control_resume_and_cancel_are_unsupported_without_backend_or_local_mutation() {
        for method in ["agent.resume", "agent.cancel"] {
            let root = control_test_root(&format!("direct-{method}"));
            let request_id = format!("agent-control-direct-{method}");
            let journal = seed_control_journal(&root, &request_id, None);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let dispatcher = control_dispatcher(
                format!("http://{address}"),
                &root,
                Arc::clone(&journal),
                Some(test_user_credential("9999-12-31T23:59:59Z")),
            );

            let error = dispatcher
                .dispatch(
                    method,
                    &json!({
                        "requestId": request_id,
                        "operationIdempotencyKey": "direct-operation-1"
                    }),
                )
                .unwrap_err();

            assert_eq!(error.code, "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED");
            assert!(matches!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            ));
            let journal = journal.lock().unwrap();
            let entry = journal.entry(&request_id).unwrap();
            assert!(entry.cancellation.is_none());
            assert!(entry.cancellation_control_idempotency_key.is_none());
            assert_eq!(entry.state, AgentExecutionState::Queued);
            assert_eq!(entry.attempt_claims.len(), 1);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn user_control_preserves_backend_typed_conflict_and_stale_errors() {
        for (method, backend_code) in [
            ("agent.resume", "AGENT_SUCCESSOR_STATE_CONFLICT"),
            ("agent.cancel", "AGENT_CANCELLATION_STALE_PROCESS"),
        ] {
            let root = control_test_root(&format!("typed-error-{method}"));
            let request_id = format!("agent-control-error-{method}");
            let journal = seed_control_journal(
                &root,
                &request_id,
                Some("33333333-3333-4333-8333-333333333333"),
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let _ = read_http_request(&mut stream);
                let body = json!({
                    "error": {
                        "code": backend_code,
                        "message": "authoritative state rejected the control request",
                        "details": {"retry": "never"}
                    },
                    "meta": {"correlationId": "control-error-1"}
                })
                .to_string();
                write_http_response(&mut stream, "409 Conflict", &body);
            });
            let dispatcher = control_dispatcher(
                format!("http://{address}"),
                &root,
                journal,
                Some(test_user_credential("9999-12-31T23:59:59Z")),
            );

            let error = dispatcher
                .dispatch(
                    method,
                    &json!({
                        "requestId": request_id,
                        "operationIdempotencyKey": "typed-error-operation-1"
                    }),
                )
                .unwrap_err();

            assert_eq!(error.code, backend_code);
            assert!(error.message.contains("control-error-1"));
            server.join().unwrap();
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn response_shape_is_stable_and_does_not_serialize_empty_error() {
        let value =
            serde_json::to_value(LocalControlResponse::success("req-1", json!({"ok": 1}))).unwrap();
        assert_eq!(value["protocolVersion"], LOCAL_CONTROL_PROTOCOL_VERSION);
        assert_eq!(value["id"], "req-1");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn agent_updates_emit_resolved_model_identity_as_an_atomic_pair() {
        let binding = AgentExecutionBindingV2 {
            workspace_binding_id: "binding-1".to_string(),
            workspace_binding_generation: 1,
            runner_id: "runner-1".to_string(),
        };
        let identity = AgentAttemptUpdateIdentity {
            execution_id: "execution-1".to_string(),
            attempt_id: "attempt-1".to_string(),
            idempotency_key: "idem-1".to_string(),
            payload_digest: "a".repeat(64),
            binding: binding.clone(),
        };
        let attempt = loomex_protocol::agent_runtime_v2::AgentAttemptV2 {
            attempt_id: identity.attempt_id.clone(),
            attempt_number: 1,
            task_idempotency_key: format!("loomex-agent-attempt-v2:{}", "1".repeat(64)),
            delivery_idempotency_key: format!("loomex-agent-delivery-v2:{}", "2".repeat(64)),
            payload_digest: format!("sha256:{}", "3".repeat(64)),
            state: loomex_protocol::agent_runtime_v2::AgentAttemptState::Probing,
            started_sequence: 2,
            finished_sequence: None,
            selection_index: 0,
            executor: ExecutorKind::CodexCli,
            provider: loomex_protocol::agent_runtime_v2::AgentProvider::OpenAi,
            requested_model_key: Some("openai/gpt-5.2".to_string()),
            requested_provider_model_id: Some("gpt-5.2".to_string()),
            resolved_model_key: Some("openai/gpt-5.2".to_string()),
            resolved_provider_model_id: Some("gpt-5.2".to_string()),
            started_at: "2026-07-27T00:00:00Z".to_string(),
            finished_at: None,
            session: None,
            retry: None,
            delivery: AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
            error: None,
        };
        let execution = AgentExecutionV2 {
            schema_version: loomex_protocol::agent_runtime_v2::AGENT_EXECUTION_SCHEMA_V2
                .to_string(),
            execution_id: identity.execution_id.clone(),
            request_id: "request-1".to_string(),
            idempotency_key: identity.idempotency_key.clone(),
            sequence: 2,
            binding: binding.clone(),
            state: AgentExecutionState::Probing,
            active_attempt_id: Some(identity.attempt_id.clone()),
            attempts: vec![attempt],
            output: None,
            error: None,
            created_at: "2026-07-27T00:00:00Z".to_string(),
            started_at: Some("2026-07-27T00:00:00Z".to_string()),
            finished_at: None,
            updated_at: "2026-07-27T00:00:00Z".to_string(),
        };
        let exact = human_request_agent_update(
            &AgentExecutionProgress {
                request_id: "request-1".to_string(),
                sequence: 2,
                phase: AgentExecutionProgressPhase::Probing,
                payload: AgentExecutionProgressPayload::Execution(execution),
            },
            &identity,
        )
        .unwrap();
        assert_eq!(exact["resolvedModelKey"], "openai/gpt-5.2");
        assert_eq!(exact["model"], "gpt-5.2");

        let unresolved = AgentSessionCheckpointV2 {
            schema_version: loomex_protocol::agent_runtime_v2::AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: "checkpoint-1".to_string(),
            sequence: 3,
            session_id: "session-1".to_string(),
            provider_session_id: "provider-session-1".to_string(),
            binding,
            execution_id: identity.execution_id.clone(),
            attempt_id: identity.attempt_id.clone(),
            selection_index: 0,
            executor: ExecutorKind::CodexCli,
            provider: loomex_protocol::agent_runtime_v2::AgentProvider::OpenAi,
            model_key: None,
            provider_model_id: None,
            state: loomex_protocol::agent_runtime_v2::AgentSessionState::Created,
            recorded_at: "2026-07-27T00:00:01Z".to_string(),
        };
        let auto = human_request_agent_update(
            &AgentExecutionProgress {
                request_id: "request-1".to_string(),
                sequence: 3,
                phase: AgentExecutionProgressPhase::SessionCheckpointed,
                payload: AgentExecutionProgressPayload::SessionCheckpoint(unresolved),
            },
            &identity,
        )
        .unwrap();
        assert!(auto.get("resolvedModelKey").is_none());
        assert!(auto.get("model").is_none());
    }

    #[test]
    fn agent_runtime_status_is_strict_redacted_and_uses_agy() {
        let root = std::env::temp_dir().join(format!(
            "loomex-local-agent-status-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("agent-executables.json");
        let journal = Arc::new(Mutex::new(
            AgentExecutionJournal::open(root.join("agent-journal.json")).unwrap(),
        ));
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:9", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_context(
                Some("project-1".to_string()),
                Some("runner-1".to_string()),
                Some("binding-1".to_string()),
                Some(root.display().to_string()),
                None,
            )
            .with_agent_runtime(
                config_path,
                journal,
                Arc::new(AgentCancellationRegistry::default()),
            );

        let status = dispatcher
            .dispatch("agent.runtime.status", &json!({}))
            .unwrap();
        assert_eq!(status["schema"], AGENT_CAPABILITY_SCHEMA_V2);
        assert_eq!(status["ttlSeconds"], 60);
        assert_eq!(status["runtimes"].as_array().unwrap().len(), 3);
        assert!(status["runtimes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|runtime| runtime["executor"] == "agy_cli"));
        let serialized = status.to_string();
        assert!(!serialized.contains(root.to_string_lossy().as_ref()));
        assert!(!serialized.contains("gemini_cli"));
        assert!(!serialized.contains("rawStderr"));
        assert!(!serialized.contains("token"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn agent_local_control_operations_reject_arbitrary_execution_input() {
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:9", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());
        for method in [
            "agent.execute",
            "agent.resume",
            "agent.cancel",
            "agent.checkpoint",
        ] {
            let error = dispatcher
                .dispatch(
                    method,
                    &json!({
                        "requestId": "agent-1",
                        "idempotencyKey": "idem-1",
                        "prompt": "untrusted",
                    }),
                )
                .unwrap_err();
            assert_eq!(error.code, "AGENT_INVALID_REQUEST");
        }
        let error = dispatcher
            .dispatch("agent.runtime.status", &json!({"path": "/tmp/private"}))
            .unwrap_err();
        assert_eq!(error.code, "AGENT_INVALID_REQUEST");
    }

    #[test]
    fn agent_execute_rejects_tampered_authoritative_payload_before_claim_or_spawn() {
        let root = std::env::temp_dir().join(format!(
            "loomex-local-agent-digest-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let logical_execution_id = "6532af8c-d14c-4dda-82fb-3a919687f92b";
        let process_attempt_id = "0a744f87-1ed2-49b2-823c-7efc580d6531";
        let task_key_hash = sha256_payload_digest(
            &loomex_protocol::agent_runtime_v2::agent_attempt_task_idempotency_preimage(
                logical_execution_id,
                1,
            ),
        );
        let task_idempotency_key = format!(
            "loomex-agent-attempt-v2:{}",
            task_key_hash.strip_prefix("sha256:").unwrap()
        );
        let delivery_key_hash = sha256_payload_digest(
            &loomex_protocol::agent_runtime_v2::agent_attempt_delivery_idempotency_preimage(
                logical_execution_id,
                1,
            ),
        );
        let delivery_idempotency_key = format!(
            "loomex-agent-delivery-v2:{}",
            delivery_key_hash.strip_prefix("sha256:").unwrap()
        );
        let journal = Arc::new(Mutex::new(
            AgentExecutionJournal::open(root.join("agent-journal.json")).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET "));
            let body = json!({
                "data": {
                    "humanRequests": [{
                        "id": "agent-v2-tampered",
                        "status": "pending",
                        "title": "tampered v2 task",
                        "execution": {"id": "execution-v2-tampered"},
                        "agentTask": {
                            "schemaVersion": "loomex.plugin-agent-task/v2",
                            "requestId": "agent-v2-tampered",
                            "idempotencyKey": "idem-v2-tampered",
                            "binding": {
                                "workspaceBindingId": "binding-1",
                                "workspaceBindingGeneration": 7,
                                "runnerId": "runner-1"
                            },
                            "selection": {
                                "primary": {
                                    "mode": "exact",
                                    "target": {
                                        "executor": "codex_cli",
                                        "provider": "open_ai",
                                        "modelKey": "openai/gpt-5.2",
                                        "providerModelId": "gpt-5.2"
                                    }
                                },
                                "fallback": {"policy": "none"}
                            },
                            "prompt": "tampered after Backend digest",
                            "requirements": {
                                "structuredOutput": false,
                                "sessionResume": true,
                                "cancellation": true
                            }
                        },
                        "agentAttempt": {
                            "id": logical_execution_id,
                            "idempotencyKey": "idem-v2-tampered",
                            "payloadDigest": "0000000000000000000000000000000000000000000000000000000000000000",
                            "currentProcessAttemptId": process_attempt_id,
                            "processAttempts": [{
                                "attemptId": process_attempt_id,
                                "attemptNumber": 1,
                                "retryKind": "initial",
                                "predecessorAttemptId": null,
                                "delivery": {
                                    "route": "direct_control",
                                    "runnerJobId": null,
                                    "leaseTargetRunnerId": null
                                },
                                "runnerJobId": null,
                                "taskIdempotencyKey": task_idempotency_key,
                                "deliveryIdempotencyKey": delivery_idempotency_key,
                                "payloadDigest": concat!(
                                    "sha256:",
                                    "0000000000000000000000000000000000000000000000000000000000000000"
                                )
                            }],
                            "binding": {
                                "workspaceBindingId": "binding-1",
                                "workspaceBindingGeneration": 7,
                                "runnerId": "runner-1"
                            }
                        }
                    }],
                    "nextCursor": null
                }
            })
            .to_string();
            write_http_json(&mut stream, &body);
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_context(
                Some("project-1".to_string()),
                Some("runner-1".to_string()),
                Some("binding-1".to_string()),
                Some(root.display().to_string()),
                None,
            )
            .with_agent_runtime(
                root.join("agent-executables.json"),
                Arc::clone(&journal),
                Arc::new(AgentCancellationRegistry::default()),
            );

        let error = dispatcher
            .dispatch(
                "agent.execute",
                &json!({
                    "requestId": "agent-v2-tampered",
                    "idempotencyKey": "idem-v2-tampered"
                }),
            )
            .unwrap_err();

        assert_eq!(error.code, "AGENT_INVALID_REQUEST");
        assert!(journal.lock().unwrap().entry("agent-v2-tampered").is_none());
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn completed_agent_execute_retry_replays_before_pending_fetch_without_second_spawn() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "loomex-local-agent-terminal-replay-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("fake-codex");
        let counter = root.join("spawn-count");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'codex 1.2.3'; exit 0; fi\nif [ \"$1\" = \"login\" ]; then echo 'Logged in'; exit 0; fi\nprintf x >> '{}'\nprintf '%s\\n' '{{\"thread_id\":\"provider-session-1\"}}'\nprintf '%s\\n' '{{\"item\":{{\"text\":\"done\"}}}}'\n",
                counter.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let task_value = json!({
            "schemaVersion": "loomex.plugin-agent-task/v2",
            "requestId": "agent-v2-terminal",
            "idempotencyKey": "idem-v2-terminal",
            "binding": {
                "workspaceBindingId": "binding-1",
                "workspaceBindingGeneration": 7,
                "runnerId": "runner-1"
            },
            "selection": {
                "primary": {
                    "mode": "exact",
                    "target": {
                        "executor": "codex_cli",
                        "provider": "open_ai",
                        "modelKey": "openai/test-model",
                        "providerModelId": "test-model"
                    }
                },
                "fallback": {"policy": "none"}
            },
            "prompt": "complete once",
            "requirements": {
                "structuredOutput": false,
                "sessionResume": true,
                "cancellation": true
            }
        });
        let task: AgentTaskRequestV2 = serde_json::from_value(task_value.clone()).unwrap();
        let mut intent = task_value;
        intent.as_object_mut().unwrap().remove("continuation");
        let intent_digest = canonical_agent_task_payload_digest(&intent).unwrap();
        let task_idempotency_key = format!("loomex-agent-attempt-v2:{}", "1".repeat(64));
        let delivery_idempotency_key = format!("loomex-agent-delivery-v2:{}", "2".repeat(64));
        let delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::DirectControl,
            runner_job_id: None,
            lease_target_runner_id: None,
        };
        let mut dispatch = AgentProcessDispatchV2 {
            schema_version: AGENT_PROCESS_DISPATCH_SCHEMA_V2.to_string(),
            execution_id: "11111111-1111-4111-8111-111111111111".to_string(),
            attempt_id: "21111111-1111-4111-8111-111111111111".to_string(),
            attempt_number: 1,
            retry_kind: AgentProcessRetryKindV2::Initial,
            from_attempt_id: None,
            delivery: delivery.clone(),
            task_idempotency_key: task_idempotency_key.clone(),
            delivery_idempotency_key: delivery_idempotency_key.clone(),
            payload_digest: format!("sha256:{}", "0".repeat(64)),
            task: task.clone(),
        };
        dispatch.payload_digest =
            canonical_json_payload_digest(&dispatch.payload_digest_input().unwrap()).unwrap();
        let journal = Arc::new(Mutex::new(
            AgentExecutionJournal::open(root.join("agent-journal.json")).unwrap(),
        ));
        let mut config = RuntimeConfig::default();
        config
            .executables
            .insert(ExecutorKind::CodexCli, executable);
        let service = AgentExecutionService::new(
            Arc::new(LocalAgentRuntime::default()),
            Arc::new(Mutex::new(config)),
            Arc::new(Mutex::new(root.clone())),
            Arc::new(Mutex::new(task.binding.clone())),
            Arc::clone(&journal),
        );
        let outcome = service
            .execute(
                &task,
                AgentExecutionIdentity {
                    execution_id: "11111111-1111-4111-8111-111111111111".to_string(),
                    attempt_id: "21111111-1111-4111-8111-111111111111".to_string(),
                    attempt_number: 1,
                    retry_kind: AgentProcessRetryKindV2::Initial,
                    from_attempt_id: None,
                    delivery,
                    task_idempotency_key,
                    delivery_idempotency_key,
                    payload_digest: dispatch.payload_digest,
                    task_intent_digest: intent_digest,
                },
            )
            .unwrap();
        assert!(
            matches!(
                &outcome,
                crate::agent_execution_service::AgentExecutionServiceOutcome::Executed(
                    AgentExecutionV2 {
                        state: AgentExecutionState::Completed,
                        ..
                    }
                )
            ),
            "{outcome:?}"
        );
        assert_eq!(fs::read_to_string(&counter).unwrap(), "x");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET "));
            let body = json!({
                "data": {
                    "runner": {"bindingGeneration": 7}
                }
            })
            .to_string();
            write_http_json(&mut stream, &body);
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_context(
                Some("project-1".to_string()),
                Some("runner-1".to_string()),
                Some("binding-1".to_string()),
                Some(root.display().to_string()),
                None,
            )
            .with_agent_runtime(
                root.join("agent-executables.json"),
                Arc::clone(&journal),
                Arc::new(AgentCancellationRegistry::default()),
            );
        let replay = dispatcher
            .dispatch(
                "agent.execute",
                &json!({
                    "requestId": "agent-v2-terminal",
                    "idempotencyKey": "idem-v2-terminal"
                }),
            )
            .unwrap();

        assert_eq!(replay["accepted"], false);
        assert_eq!(replay["state"], "completed");
        assert_eq!(fs::read_to_string(&counter).unwrap(), "x");
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn daemon_status_exposes_truthful_telemetry_availability_shape() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for body in [
                r#"{"data":{"status":"online"}}"#,
                r#"{"data":{"bindings":[]}}"#,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        let status = dispatcher.dispatch("status", &json!({})).unwrap();

        assert_eq!(status["connection"]["available"], true);
        assert_eq!(status["runtimeVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["service"]["available"], false);
        assert_eq!(status["health"]["healthy"], true);
        assert_eq!(status["queue"]["available"], false);
        assert!(status["queue"]["depth"].is_null());
        assert_eq!(status["activeExecutions"]["available"], false);
        assert_eq!(status["updateHealth"]["status"], "unknown");
        server.join().unwrap();
    }

    #[test]
    fn token_comparison_rejects_prefix_and_suffix_variants() {
        assert!(tokens_equal(b"secret", b"secret"));
        assert!(!tokens_equal(b"secret", b"secret2"));
        assert!(!tokens_equal(b"xsecret", b"secret"));
    }

    #[test]
    fn human_response_envelope_preserves_backend_alias_shaped_objects() {
        for response in [
            json!({"answer": {"value": 1}}),
            json!({"response": ["yes", "no"]}),
            json!({"payload": {"nested": true}}),
            json!({"decision": "custom", "reason": "not a policy approval"}),
        ] {
            let params = json!({"requestId": "human-1", "payload": response.clone()});
            assert_eq!(
                human_resolution_payload("human.respond", &params).unwrap(),
                json!({"answer": response, "requestType": "human"})
            );
        }
    }

    #[test]
    fn approval_decision_remains_a_structured_backend_payload() {
        let params = json!({
            "requestId": "approval-1",
            "decision": "approve",
            "reason": "reviewed"
        });
        assert_eq!(
            human_resolution_payload("approval.decide", &params).unwrap(),
            json!({"decision": "approve", "reason": "reviewed", "requestType": "approval"})
        );
    }

    #[test]
    fn plugin_agent_response_uses_dedicated_backend_channel() {
        let response = json!({
            "status": "completed",
            "output": {"response_text": "done"}
        });
        let params = json!({"requestId": "agent-1", "payload": response.clone()});
        assert_eq!(
            human_resolution_payload("agent.respond", &params).unwrap(),
            json!({"answer": response, "requestType": "plugin_agent"})
        );
    }

    #[test]
    fn legacy_agent_respond_drains_only_authoritative_v1_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut list_stream, _) = listener.accept().unwrap();
            let list_request = read_http_request(&mut list_stream);
            assert!(list_request.starts_with("GET "));
            let list_body = json!({
                "data": {
                    "humanRequests": [{
                        "id": "agent-v1",
                        "status": "pending",
                        "title": "legacy agent",
                        "agentTask": {
                            "schemaVersion": "loomex.plugin-agent-task/v1"
                        }
                    }],
                    "nextCursor": null
                }
            })
            .to_string();
            write_http_json(&mut list_stream, &list_body);

            let (mut resolve_stream, _) = listener.accept().unwrap();
            let resolve_request = read_http_request(&mut resolve_stream);
            assert!(resolve_request
                .lines()
                .next()
                .unwrap_or_default()
                .contains("/human-requests/agent-v1/resolve/"));
            assert!(resolve_request.contains("\"requestType\":\"plugin_agent\""));
            let resolve_body = json!({
                "data": {
                    "requestId": "agent-v1",
                    "requestStatus": "resolved",
                    "executionId": "run-v1",
                    "executionStatus": "completed"
                }
            })
            .to_string();
            write_http_json(&mut resolve_stream, &resolve_body);
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        let result = dispatcher
            .dispatch(
                "agent.respond",
                &json!({
                    "requestId": "agent-v1",
                    "payload": {"status": "completed", "output": {"value": "done"}}
                }),
            )
            .unwrap();

        assert_eq!(result["requestId"], "agent-v1");
        server.join().unwrap();
    }

    #[test]
    fn legacy_agent_respond_follows_pagination_and_replays_resolved_v1_after_lost_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().unwrap();
            let first_request = read_http_request(&mut first_stream);
            assert!(first_request.starts_with("GET "));
            assert!(first_request.contains("status=all"));
            let first_body = json!({
                "data": {
                    "humanRequests": [{
                        "id": "other-agent",
                        "status": "pending",
                        "title": "other",
                        "agentTask": {"schemaVersion": "loomex.plugin-agent-task/v1"}
                    }],
                    "nextCursor": "page-2"
                }
            })
            .to_string();
            write_http_json(&mut first_stream, &first_body);

            let (mut second_stream, _) = listener.accept().unwrap();
            let second_request = read_http_request(&mut second_stream);
            assert!(second_request.contains("cursor=page-2"));
            let second_body = json!({
                "data": {
                    "humanRequests": [{
                        "id": "old-agent-v1",
                        "status": "resolved",
                        "title": "old",
                        "agentTask": {"schemaVersion": "loomex.plugin-agent-task/v1"}
                    }],
                    "nextCursor": null
                }
            })
            .to_string();
            write_http_json(&mut second_stream, &second_body);

            let (mut resolve_stream, _) = listener.accept().unwrap();
            let resolve_request = read_http_request(&mut resolve_stream);
            assert!(resolve_request.contains("/human-requests/old-agent-v1/resolve/"));
            let resolve_body = json!({
                "data": {
                    "requestId": "old-agent-v1",
                    "requestStatus": "resolved",
                    "executionId": "run-v1",
                    "executionStatus": "completed",
                    "replayed": true
                }
            })
            .to_string();
            write_http_json(&mut resolve_stream, &resolve_body);
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        let result = dispatcher
            .dispatch(
                "agent.respond",
                &json!({
                    "requestId": "old-agent-v1",
                    "payload": {"status": "completed"}
                }),
            )
            .unwrap();

        assert_eq!(result["requestId"], "old-agent-v1");
        server.join().unwrap();
    }

    #[test]
    fn legacy_agent_respond_rejects_v2_before_resolve() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET "));
            let body = json!({
                "data": {
                    "humanRequests": [{
                        "id": "agent-v2",
                        "status": "pending",
                        "title": "v2 agent",
                        "agentTask": {
                            "schemaVersion": loomex_protocol::agent_runtime_v2::AGENT_TASK_SCHEMA_V2
                        }
                    }],
                    "nextCursor": null
                }
            })
            .to_string();
            write_http_json(&mut stream, &body);
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        let error = dispatcher
            .dispatch(
                "agent.respond",
                &json!({
                    "requestId": "agent-v2",
                    "payload": {"status": "completed", "output": {"value": "wrong path"}}
                }),
            )
            .unwrap_err();

        assert_eq!(error.code, "AGENT_LEGACY_RESPONSE_FORBIDDEN");
        server.join().unwrap();
    }

    #[test]
    fn legacy_agent_respond_disabled_fails_before_backend_io() {
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_agent_cutover(true, LegacyAgentTaskMode::Disabled);

        let error = dispatcher
            .dispatch(
                "agent.respond",
                &json!({
                    "requestId": "agent-v1",
                    "payload": {"status": "completed"}
                }),
            )
            .unwrap_err();

        assert_eq!(error.code, "AGENT_LEGACY_TASKS_DISABLED");
    }

    #[test]
    fn legacy_agent_respond_rejects_active_and_tombstoned_v2_ownership_without_backend_io() {
        for tombstoned in [false, true] {
            let root = control_test_root(if tombstoned {
                "legacy-v2-tombstone-collision"
            } else {
                "legacy-v2-active-collision"
            });
            let request_id = if tombstoned {
                "agent-tombstone-collision"
            } else {
                "agent-active-collision"
            };
            let journal = seed_control_journal(&root, request_id, Some("job-collision"));
            if tombstoned {
                transition_control_journal_to_cancelled(
                    &journal,
                    request_id,
                    "job-collision",
                    "cancel-collision",
                );
                let mut journal_guard = journal.lock().unwrap();
                journal_guard
                    .remove_after_authoritative_ack(request_id)
                    .unwrap();
                assert!(journal_guard.entry(request_id).is_none());
                assert!(journal_guard.tombstone(request_id).unwrap().is_some());
            }
            let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
            let dispatcher = LocalControlDispatcher::new(client, test_credential())
                .with_agent_runtime(
                    root.join("agent-executables.json"),
                    Arc::clone(&journal),
                    Arc::new(AgentCancellationRegistry::default()),
                );

            let error = dispatcher
                .dispatch(
                    "agent.respond",
                    &json!({
                        "requestId": request_id,
                        "payload": {"status": "completed"}
                    }),
                )
                .unwrap_err();

            assert_eq!(error.code, "AGENT_V2_EXECUTION_OWNED");
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn unsupported_or_missing_agent_task_schema_is_visible_but_not_executable() {
        let response = crate::RunnerHumanRequestListResponse {
            human_requests: vec![
                crate::HumanRequestSummary {
                    id: "agent-v3".to_string(),
                    status: "pending".to_string(),
                    title: "future".to_string(),
                    execution: None,
                    description: String::new(),
                    blocking: true,
                    extra: Map::from_iter([(
                        "agentTask".to_string(),
                        json!({"schemaVersion": "loomex.plugin-agent-task/v3"}),
                    )]),
                },
                crate::HumanRequestSummary {
                    id: "agent-missing".to_string(),
                    status: "pending".to_string(),
                    title: "missing".to_string(),
                    execution: None,
                    description: String::new(),
                    blocking: true,
                    extra: Map::new(),
                },
            ],
            next_cursor: None,
        };
        let listed =
            agent_request_list_value(response, true, LegacyAgentTaskMode::DrainOnly).unwrap();
        assert_eq!(
            listed["humanRequests"][0]["executionSupport"],
            "unsupported"
        );
        assert_eq!(
            listed["humanRequests"][1]["executionSupport"],
            "unsupported"
        );
    }

    #[test]
    fn unsupported_or_missing_agent_task_schema_cannot_respond() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (request_id, task) in [
                (
                    "agent-v3",
                    Some(json!({"schemaVersion": "loomex.plugin-agent-task/v3"})),
                ),
                ("agent-missing", None),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with("GET "));
                let mut summary = json!({
                    "id": request_id,
                    "status": "pending",
                    "title": "unsupported agent"
                });
                if let Some(task) = task {
                    summary["agentTask"] = task;
                }
                let body = json!({
                    "data": {
                        "humanRequests": [summary],
                        "nextCursor": null
                    }
                })
                .to_string();
                write_http_json(&mut stream, &body);
            }
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        for request_id in ["agent-v3", "agent-missing"] {
            let error = dispatcher
                .dispatch(
                    "agent.respond",
                    &json!({
                        "requestId": request_id,
                        "payload": {"status": "completed"}
                    }),
                )
                .unwrap_err();
            assert_eq!(error.code, "AGENT_TASK_SCHEMA_UNSUPPORTED");
        }
        server.join().unwrap();
    }

    #[test]
    fn unsupported_or_missing_agent_task_schema_cannot_execute() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (request_id, task) in [
                (
                    "agent-v3",
                    Some(json!({"schemaVersion": "loomex.plugin-agent-task/v3"})),
                ),
                ("agent-missing", None),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with("GET "));
                let mut summary = json!({
                    "id": request_id,
                    "status": "pending",
                    "title": "unsupported agent"
                });
                if let Some(task) = task {
                    summary["agentTask"] = task;
                }
                let body = json!({
                    "data": {
                        "humanRequests": [summary],
                        "nextCursor": null
                    }
                })
                .to_string();
                write_http_json(&mut stream, &body);
            }
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential());

        for request_id in ["agent-v3", "agent-missing"] {
            let error = dispatcher
                .dispatch(
                    "agent.execute",
                    &json!({
                        "requestId": request_id,
                        "idempotencyKey": "task-key"
                    }),
                )
                .unwrap_err();
            assert_eq!(error.code, "AGENT_TASK_SCHEMA_UNSUPPORTED");
        }
        server.join().unwrap();
    }

    #[test]
    fn disabled_v2_rejects_new_execute_and_resume_before_backend_io() {
        let root = control_test_root("v2-disabled");
        let journal = seed_control_journal(&root, "blocked-predecessor", Some("job-predecessor"));
        transition_control_journal_to_blocked(&journal, "blocked-predecessor", "job-predecessor");
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_agent_cutover(false, LegacyAgentTaskMode::DrainOnly)
            .with_agent_runtime(
                root.join("agent-executables.json"),
                journal,
                Arc::new(AgentCancellationRegistry::default()),
            );

        let execute = dispatcher
            .dispatch(
                "agent.execute",
                &json!({"requestId": "brand-new", "idempotencyKey": "new-key"}),
            )
            .unwrap_err();
        assert_eq!(execute.code, "AGENT_RUNTIME_V2_DISABLED");

        let resume = dispatcher
            .dispatch(
                "agent.resume",
                &json!({
                    "requestId": "blocked-predecessor",
                    "operationIdempotencyKey": "resume-key"
                }),
            )
            .unwrap_err();
        assert_eq!(resume.code, "AGENT_RUNTIME_V2_DISABLED");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disabled_runtime_status_preserves_strict_shape_without_probing() {
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential())
            .with_agent_cutover(false, LegacyAgentTaskMode::DrainOnly);

        let status = dispatcher
            .dispatch("agent.runtime.status", &json!({}))
            .unwrap();

        assert_eq!(status["schema"], AGENT_CAPABILITY_SCHEMA_V2);
        assert!(status["observedAt"].as_str().is_some());
        assert_eq!(status["ttlSeconds"], 1);
        assert_eq!(status["runtimes"], json!([]));
        assert_eq!(status.as_object().unwrap().len(), 4);
    }

    #[test]
    fn human_and_approval_responses_canonicalize_execution_status() {
        for (backend, expected) in [
            ("waiting", "waiting_for_human"),
            ("completed", "succeeded"),
            ("canceled", "cancelled"),
        ] {
            let value = human_resolution_value(crate::HumanRequestResolveResponse {
                request_id: "human-1".to_string(),
                request_status: "resolved".to_string(),
                execution_id: Some("run-1".to_string()),
                execution_status: Some(backend.to_string()),
            })
            .unwrap();
            assert_eq!(
                value,
                json!({
                    "requestId": "human-1",
                    "requestStatus": "resolved",
                    "executionId": "run-1",
                    "executionStatus": expected
                })
            );
        }
    }

    fn resolved_approval(decision: &str) -> crate::HumanRequestSummary {
        let mut extra = serde_json::Map::new();
        extra.insert("answer".to_string(), json!({"decision": decision}));
        crate::HumanRequestSummary {
            id: format!("approval-{decision}"),
            status: "resolved".to_string(),
            title: "Policy approval".to_string(),
            execution: None,
            description: String::new(),
            blocking: true,
            extra,
        }
    }

    #[test]
    fn approval_list_exposes_approved_instead_of_resolved() {
        let value = human_request_list_value(
            crate::RunnerHumanRequestListResponse {
                human_requests: vec![resolved_approval("approve")],
                next_cursor: Some("cursor-2".to_string()),
            },
            true,
        )
        .unwrap();
        assert_eq!(value["humanRequests"][0]["status"], "approved");
        assert_eq!(value["humanRequests"][0]["answer"]["decision"], "approve");
        assert_eq!(value["nextCursor"], "cursor-2");
    }

    #[test]
    fn approval_list_exposes_rejected_without_changing_human_list() {
        let request = resolved_approval("reject");
        let page = |human_requests| crate::RunnerHumanRequestListResponse {
            human_requests,
            next_cursor: None,
        };
        let approval_value = human_request_list_value(page(vec![request.clone()]), true).unwrap();
        let human_value = human_request_list_value(page(vec![request]), false).unwrap();
        assert_eq!(approval_value["humanRequests"][0]["status"], "rejected");
        assert_eq!(
            approval_value["humanRequests"][0]["answer"]["decision"],
            "reject"
        );
        assert_eq!(human_value["humanRequests"][0]["status"], "resolved");
    }

    #[test]
    fn wait_response_has_the_same_flat_shape_as_get_and_canonical_status() {
        let response = crate::RunnerWorkflowExecutionResponse {
            execution: json!({"id": "run-1", "status": "completed"}),
            human_request: None,
            runner: Some(json!({"id": "runner-1"})),
            events: vec![json!({"sequence": 4, "type": "execution.completed"})],
            ai_trace: None,
            latest_sequence: 4,
            timed_out: false,
            extra: serde_json::Map::new(),
        };

        assert_eq!(
            run_detail_value(response).unwrap(),
            json!({
                "execution": {"id": "run-1", "status": "succeeded"},
                "humanRequest": null,
                "runner": {"id": "runner-1"},
                "events": [{"sequence": 4, "type": "execution.completed"}],
                "aiTrace": null,
                "latestSequence": 4,
                "timedOut": false
            })
        );
    }

    #[test]
    fn list_and_cancel_normalize_backend_run_status_vocabulary() {
        assert_eq!(
            run_list_value(crate::RunnerWorkflowExecutionListResponse {
                executions: vec![
                    json!({"id": "run-1", "status": "waiting"}),
                    json!({"id": "run-2", "status": "canceled"}),
                ],
                next_cursor: Some("2".to_string()),
            })
            .unwrap(),
            json!({
                "executions": [
                    {"id": "run-1", "status": "waiting_for_human"},
                    {"id": "run-2", "status": "cancelled"}
                ],
                "nextCursor": "2"
            })
        );

        let mut canceled = json!({
            "execution": {"id": "run-3", "status": "canceled"},
            "jobs": [{"id": "job-1", "status": "canceled"}]
        });
        normalize_execution_field(&mut canceled);
        assert_eq!(canceled["execution"]["status"], "cancelled");
        assert_eq!(canceled["jobs"][0]["status"], "canceled");
    }

    #[test]
    fn private_credentials_are_created_once() {
        let root = std::env::temp_dir().join(format!("loomex-control-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = LocalControlPaths::for_runtime_dir(&root);
        let first = prepare_local_control_paths(&paths).unwrap();
        let second = prepare_local_control_paths(&paths).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn daemon_accepts_a_new_client_after_the_previous_client_exits() {
        use std::os::unix::net::UnixStream;

        // Unix-domain socket paths have a small platform limit (104 bytes on macOS).
        let root = std::env::temp_dir().join(format!("lxipc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = LocalControlPaths::for_runtime_dir(&root);
        let credential = test_credential();
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let server = UnixLocalControlServer::bind(
            paths.clone(),
            LocalControlDispatcher::new(client, credential),
        )
        .unwrap();
        let token = read_local_control_token(&paths).unwrap();
        let thread = std::thread::spawn(move || server.serve_connections(Some(2)).unwrap());

        for id in ["first", "second"] {
            let mut stream = (0..100)
                .find_map(|_| {
                    UnixStream::connect(&paths.socket_path).ok().or_else(|| {
                        std::thread::sleep(Duration::from_millis(5));
                        None
                    })
                })
                .expect("server socket should become available");
            let request = LocalControlRequest {
                protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION.to_string(),
                id: id.to_string(),
                auth_token: token.clone(),
                method: "ping".to_string(),
                params: json!({}),
            };
            serde_json::to_writer(&mut stream, &request).unwrap();
            stream.write_all(b"\n").unwrap();
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).unwrap();
            let response: LocalControlResponse = serde_json::from_str(&response).unwrap();
            assert!(response.ok);
            assert_eq!(response.id, id);
            // Dropping this stream simulates Codex exiting. The daemon must accept the next one.
        }
        thread.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn doctor_reports_real_backend_failure_and_workspace_success() {
        let workspace =
            std::env::temp_dir().join(format!("loomex-doctor-workspace-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential()).with_context(
            Some("project-test".to_string()),
            Some("runner-test".to_string()),
            Some("binding-test".to_string()),
            Some(workspace.display().to_string()),
            None,
        );

        let result = dispatcher.dispatch("doctor", &json!({})).unwrap();

        assert_eq!(result["status"], "failed");
        assert_eq!(result["checks"][0]["name"], "ipc");
        assert_eq!(result["checks"][0]["status"], "ok");
        let backend = result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "backend")
            .unwrap();
        assert_eq!(backend["status"], "failed");
        let workspace_check = result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "workspace")
            .unwrap();
        assert_eq!(workspace_check["status"], "ok");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn daemon_doctor_rejects_configured_runner_identity_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).unwrap();
            let body = r#"{"data":{"runner":{"id":"runner-authenticated","status":"online"},"tokenScopes":["runner.read","runner.jobs"]}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential()).with_context(
            Some("project-test".to_string()),
            Some("runner-configured".to_string()),
            Some("binding-test".to_string()),
            Some(std::env::temp_dir().display().to_string()),
            None,
        );

        let result = dispatcher.dispatch("doctor", &json!({})).unwrap();

        let backend = result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "backend")
            .unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(backend["status"], "failed");
        assert!(backend["message"]
            .as_str()
            .unwrap()
            .contains("RUNNER_IDENTITY_MISMATCH"));
        server.join().unwrap();
    }

    #[test]
    fn verbose_doctor_adds_real_context_and_log_checks() {
        let log_path = std::env::temp_dir().join(format!(
            "loomex-doctor-verbose-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&log_path);
        fs::write(&log_path, "").unwrap();
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential()).with_context(
            Some("project-test".to_string()),
            Some("runner-test".to_string()),
            Some("binding-test".to_string()),
            Some(std::env::temp_dir().display().to_string()),
            Some(log_path.clone()),
        );

        let normal = dispatcher.dispatch("doctor", &json!({})).unwrap();
        let verbose = dispatcher
            .dispatch("doctor", &json!({"verbose": true}))
            .unwrap();

        assert!(normal["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["name"] != "logs"));
        assert!(verbose["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "logs" && check["status"] == "ok"));
        assert!(verbose["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "context" && check["status"] == "ok"));
        let _ = fs::remove_file(log_path);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_doctor_detects_read_only_directory_without_creating_a_probe() {
        use std::os::unix::fs::PermissionsExt;

        let workspace =
            std::env::temp_dir().join(format!("loomex-doctor-readonly-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o500)).unwrap();

        let check = workspace_local_control_doctor_check(Some(&workspace.display().to_string()));

        assert_eq!(check["status"], "failed");
        assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn logs_tail_redacts_tampered_structured_log_at_read_time() {
        let log_path = std::env::temp_dir().join(format!(
            "loomex-control-redaction-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&log_path);
        let entry = crate::LogEntry::new(
            "info",
            "legacy.log",
            "Authorization: Bearer leaked-local-control-token",
        )
        .with_metadata(json!({
            "safe": "visible",
            "token": "leaked-metadata-token",
            "nested": "api_key=leaked-inline-token"
        }));
        fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        let client = crate::HttpManagementApiClient::new("http://127.0.0.1:1", None).unwrap();
        let dispatcher = LocalControlDispatcher::new(client, test_credential()).with_context(
            None,
            None,
            None,
            None,
            Some(log_path.clone()),
        );

        let result = dispatcher
            .dispatch("logs.tail", &json!({"limit": 10}))
            .unwrap();
        let serialized = serde_json::to_string(&result).unwrap();

        assert!(serialized.contains("visible"));
        assert!(!serialized.contains("leaked-"));
        assert_eq!(result["entries"][0]["metadata"]["token"], "[REDACTED]");
        let _ = fs::remove_file(log_path);
    }

    #[test]
    fn long_poll_does_not_block_cancel_or_human_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (wait_started_sender, wait_started_receiver) = mpsc::channel();
        let (release_wait_sender, release_wait_receiver) = mpsc::channel();
        let release_wait_receiver = Arc::new(Mutex::new(release_wait_receiver));

        let backend = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let wait_started_sender = wait_started_sender.clone();
                let release_wait_receiver = Arc::clone(&release_wait_receiver);
                handlers.push(std::thread::spawn(move || {
                    let request = read_http_request(&mut stream);
                    let request_line = request.lines().next().unwrap_or_default();
                    let body = if request_line.contains("?afterSequence=") {
                        wait_started_sender.send(()).unwrap();
                        // Keep the backend long-poll open until both concurrent operations have
                        // had a chance to finish.
                        let _ = release_wait_receiver.lock().unwrap().recv();
                        json!({
                            "data": {
                                "execution": {"id": "run-1", "status": "running"},
                                "latestSequence": 1,
                                "timedOut": true
                            }
                        })
                    } else if request_line.contains("/cancel/") {
                        json!({
                            "data": {
                                "execution": {"id": "run-1", "status": "canceled"}
                            }
                        })
                    } else if request_line.contains("/human-requests/human-1/resolve/") {
                        json!({
                            "data": {
                                "requestId": "human-1",
                                "requestStatus": "resolved",
                                "executionId": "run-1",
                                "executionStatus": "running"
                            }
                        })
                    } else {
                        panic!("unexpected request: {request_line}");
                    };
                    let body = serde_json::to_string(&body).unwrap();
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                    stream.flush().unwrap();
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });

        let client =
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap();
        let dispatcher = Arc::new(LocalControlDispatcher::new(client, test_credential()));
        let wait_dispatcher = Arc::clone(&dispatcher);
        let wait = std::thread::spawn(move || {
            wait_dispatcher.dispatch(
                "run.wait",
                &json!({
                    "executionId": "run-1",
                    "afterSequence": 0,
                    "timeoutSeconds": 45
                }),
            )
        });
        wait_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("wait request should reach backend");

        let (cancel_sender, cancel_receiver) = mpsc::channel();
        let cancel_dispatcher = Arc::clone(&dispatcher);
        let cancel = std::thread::spawn(move || {
            let result = cancel_dispatcher.dispatch(
                "run.cancel",
                &json!({
                    "executionId": "run-1",
                    "reason": "test",
                    "idempotencyKey": "cancel-test-1"
                }),
            );
            cancel_sender.send(result).unwrap();
        });
        let (human_sender, human_receiver) = mpsc::channel();
        let human_dispatcher = Arc::clone(&dispatcher);
        let human = std::thread::spawn(move || {
            let result = human_dispatcher.dispatch(
                "human.respond",
                &json!({"requestId": "human-1", "payload": {"answer": "continue"}}),
            );
            human_sender.send(result).unwrap();
        });

        let early_cancel = cancel_receiver.recv_timeout(Duration::from_secs(2)).ok();
        let early_human = human_receiver.recv_timeout(Duration::from_secs(2)).ok();
        release_wait_sender.send(()).unwrap();

        let cancel_result = early_cancel
            .as_ref()
            .expect("cancel must finish while run.wait is still pending")
            .as_ref()
            .unwrap();
        let human_result = early_human
            .as_ref()
            .expect("human response must finish while run.wait is still pending")
            .as_ref()
            .unwrap();
        assert_eq!(cancel_result["execution"]["status"], "cancelled");
        assert_eq!(human_result["requestStatus"], "resolved");
        wait.join().unwrap().unwrap();
        cancel.join().unwrap();
        human.join().unwrap();
        backend.join().unwrap();
    }

    #[test]
    fn agent_progress_outbox_retries_fail_once_checkpoint_and_completed_updates() {
        let root = std::env::temp_dir().join(format!(
            "loomex-progress-outbox-retry-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("agent-progress-outbox.json");
        let (client, requests, backend) = progress_backend(&[503, 200, 503, 200]);
        let client = Arc::new(Mutex::new(client));
        let credential = test_credential();
        let mut outbox = AgentProgressOutbox::open(&path).unwrap();

        for (sequence, status) in [(7, "session_checkpoint"), (8, "completed")] {
            let delivery_key = sha256_payload_digest(
                format!("loomex-agent-progress-delivery-v1\u{0}idem-1\u{0}{sequence}").as_bytes(),
            );
            let payload = json!({
                "requestType": "plugin_agent",
                "answer": {
                    "status": status,
                    "sequence": sequence,
                    "executionId": "execution-1",
                    "attemptId": "attempt-1",
                    "idempotencyKey": "idem-1",
                    "payloadDigest": "a".repeat(64),
                    "output": {
                        "content": "/workspace/report"
                    }
                }
            });
            outbox
                .enqueue(PendingAgentProgressUpdate {
                    request_id: "request-1".to_string(),
                    sequence,
                    idempotency_header: delivery_key,
                    payload,
                })
                .unwrap();
        }
        let pending_bytes = fs::read_to_string(&path).unwrap();
        assert!(pending_bytes.contains("/workspace/report"));
        drop(outbox);

        drain_agent_progress_outbox(&path, &client, &credential, Some("request-1"), None).unwrap();
        backend.join().unwrap();

        let reopened = AgentProgressOutbox::open(&path).unwrap();
        assert!(reopened.document.pending.is_empty());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        let delivery_key = |sequence| {
            sha256_payload_digest(
                format!("loomex-agent-progress-delivery-v1\u{0}idem-1\u{0}{sequence}").as_bytes(),
            )
        };
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}", delivery_key(7))));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}", delivery_key(7))));
        assert!(requests[2]
            .to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}", delivery_key(8))));
        assert!(requests[3]
            .to_ascii_lowercase()
            .contains(&format!("idempotency-key: {}", delivery_key(8))));
        assert_eq!(delivery_key(7).len(), 71);
        let maximum_task_key = "k".repeat(160);
        let maximum_delivery_key = sha256_payload_digest(
            format!(
                "loomex-agent-progress-delivery-v1\u{0}{maximum_task_key}\u{0}{}",
                8
            )
            .as_bytes(),
        );
        assert_eq!(maximum_delivery_key.len(), 71);
        assert!(requests
            .iter()
            .all(|request| request.contains("/workspace/report")));
        let persisted = fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("/workspace/report"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn agent_progress_outbox_survives_failed_delivery_and_restart_drain() {
        let root = std::env::temp_dir().join(format!(
            "loomex-progress-outbox-restart-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("agent-executables.json");
        let path = config_path.with_extension("progress-outbox.json");
        let (failing_client, _, failing_backend) = progress_backend(&[503, 503, 503]);
        let failing_client = Arc::new(Mutex::new(failing_client));
        let credential = test_credential();
        let mut outbox = AgentProgressOutbox::open(&path).unwrap();
        outbox
            .enqueue(PendingAgentProgressUpdate {
                request_id: "request-restart".to_string(),
                sequence: 11,
                idempotency_header: "idem-restart:sequence:11".to_string(),
                payload: json!({
                    "requestType": "plugin_agent",
                    "answer": {"status": "completed", "sequence": 11}
                }),
            })
            .unwrap();
        drop(outbox);

        let error = drain_agent_progress_outbox(
            &path,
            &failing_client,
            &credential,
            Some("request-restart"),
            None,
        )
        .unwrap_err();
        assert!(is_retryable_code(error.code));
        failing_backend.join().unwrap();
        assert_eq!(
            AgentProgressOutbox::open(&path)
                .unwrap()
                .document
                .pending
                .len(),
            1
        );

        let (restarted_client, restarted_requests, restarted_backend) = progress_backend(&[200]);
        let restarted_client = Arc::new(Mutex::new(restarted_client));
        let restarted_client = restarted_client.lock().unwrap().clone();
        reconcile_pending_agent_progress(restarted_client, &credential, &config_path).unwrap();
        restarted_backend.join().unwrap();
        assert_eq!(restarted_requests.lock().unwrap().len(), 1);
        assert!(AgentProgressOutbox::open(&path)
            .unwrap()
            .document
            .pending
            .is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn agent_progress_outbox_accepts_max_runtime_sized_terminal_payload() {
        let root = std::env::temp_dir().join(format!(
            "loomex-progress-outbox-boundary-{}-{}",
            std::process::id(),
            current_epoch_ms_core().unwrap()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("agent-progress-outbox.json");
        let content = "x".repeat(6_500_000);
        let mut outbox = AgentProgressOutbox::open(&path).unwrap();

        outbox
            .enqueue(PendingAgentProgressUpdate {
                request_id: "request-boundary".to_string(),
                sequence: 1,
                idempotency_header: "idem-boundary:sequence:1".to_string(),
                payload: json!({
                    "requestType": "plugin_agent",
                    "answer": {
                        "status": "completed",
                        "sequence": 1,
                        "output": {"content": content}
                    }
                }),
            })
            .unwrap();

        assert_eq!(outbox.document.pending.len(), 1);
        assert!(fs::metadata(&path).unwrap().len() > 6_500_000);
        assert!(fs::metadata(&path).unwrap().len() < AGENT_PROGRESS_OUTBOX_MAX_BYTES as u64);
        let _ = fs::remove_dir_all(root);
    }

    fn progress_backend(
        statuses: &[u16],
    ) -> (
        crate::HttpManagementApiClient,
        Arc<Mutex<Vec<String>>>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let statuses = statuses.to_vec();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let backend = std::thread::spawn(move || {
            for status in statuses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                captured.lock().unwrap().push(request);
                let (reason, body) = if status == 200 {
                    (
                        "OK",
                        r#"{"data":{"requestId":"request-1","requestStatus":"pending","executionId":"execution-1","executionStatus":"running"}}"#,
                    )
                } else {
                    (
                        "Service Unavailable",
                        r#"{"error":{"code":"temporary","message":"retry"}}"#,
                    )
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (
            crate::HttpManagementApiClient::new(format!("http://{address}"), None).unwrap(),
            requests,
            backend,
        )
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 2048];
        let header_end = loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "client closed before sending request headers");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(position) = bytes.windows(4).position(|item| item == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "client closed before sending request body");
            bytes.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn write_http_json(stream: &mut std::net::TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }
}
