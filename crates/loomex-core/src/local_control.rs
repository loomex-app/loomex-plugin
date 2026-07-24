//! Authenticated, versioned local control protocol used by Codex and other local clients.
//!
//! The wire format is newline-delimited JSON. The daemon deliberately owns workflow state only
//! through the management API: disconnecting an IPC client never cancels a workflow or exits the
//! daemon.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    read_recent_log_entries, redact_log_entry_for_local_output, CoreError, CoreResult,
    ManagementApiClient, ManagementCredential, ProjectRunnerBindingCreateRequest,
};

pub const LOCAL_CONTROL_PROTOCOL_VERSION: &str = "loomex.local-control/v1";
pub const LOCAL_CONTROL_SOCKET_NAME: &str = "control.sock";
pub const LOCAL_CONTROL_TOKEN_NAME: &str = "control.token";
pub const LOCAL_CONTROL_MAX_LINE_BYTES: usize = 1024 * 1024;

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
    project_id: Option<String>,
    runner_id: Option<String>,
    binding_id: Option<String>,
    workspace_path: Option<String>,
    log_path: Option<PathBuf>,
    started_at: Instant,
}

impl<C: ManagementApiClient + Clone> LocalControlDispatcher<C> {
    pub fn new(client: C, credential: ManagementCredential) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            credential,
            project_id: None,
            runner_id: None,
            binding_id: None,
            workspace_path: None,
            log_path: None,
            started_at: Instant::now(),
        }
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
                    human_request_list_value(requests, false)
                })
            }
            "agent.respond" => {
                let request_id = required_string(params, "requestId")?;
                let payload = human_resolution_payload("agent.respond", params)?;
                self.with_client(|client| {
                    human_resolution_value(client.resolve_human_request_idempotent(
                        &self.credential,
                        request_id,
                        &payload,
                        optional_string(params, "idempotencyKey"),
                    )?)
                })
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

fn canonical_run_status(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "waiting" => "waiting_for_human",
        "completed" => "succeeded",
        "canceled" | "cancelled" => "cancelled",
        _ => return None,
    })
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

pub fn handle_local_control_request<C: ManagementApiClient + Clone>(
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
fn serve_unix_client<C: ManagementApiClient + Clone>(
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

    #[test]
    fn response_shape_is_stable_and_does_not_serialize_empty_error() {
        let value =
            serde_json::to_value(LocalControlResponse::success("req-1", json!({"ok": 1}))).unwrap();
        assert_eq!(value["protocolVersion"], LOCAL_CONTROL_PROTOCOL_VERSION);
        assert_eq!(value["id"], "req-1");
        assert!(value.get("error").is_none());
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
}
