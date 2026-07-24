use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    time::timeout,
};

pub const LOCAL_CONTROL_VERSION: &str = "loomex.local-control/v1";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(12);
const RESPONSE_LIMIT: u64 = 8 * 1024 * 1024;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct LocalControlClient {
    endpoint: PathBuf,
    token_path: PathBuf,
}

/// Routes lifecycle/configuration calls to the bundled CLI and workflow calls to the
/// long-lived daemon. This makes first-use setup possible before the daemon or its
/// local-control token exists while keeping workflow execution independent of Codex.
#[derive(Debug, Clone)]
pub struct ControlClient {
    daemon: LocalControlClient,
    bootstrap: BootstrapClient,
}

#[derive(Debug, Clone)]
pub struct BootstrapClient {
    executable: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlRequest<'a> {
    protocol_version: &'static str,
    id: String,
    auth_token: &'a str,
    method: &'a str,
    params: &'a Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ControlResponse {
    protocol_version: String,
    id: String,
    ok: bool,
    #[serde(default)]
    result: Value,
    error: Option<ControlError>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug)]
pub enum ClientError {
    Unavailable(String),
    Unauthorized(String),
    Protocol(String),
    Remote(ControlError),
    Timeout,
}

impl ClientError {
    pub fn code(&self) -> &str {
        match self {
            Self::Unavailable(_) => "runner_unavailable",
            Self::Unauthorized(_) => "local_auth_failed",
            Self::Protocol(_) => "ipc_protocol_error",
            Self::Remote(error) => &error.code,
            Self::Timeout => "ipc_timeout",
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::Unavailable(_) | Self::Timeout => true,
            Self::Remote(error) => error.retryable,
            Self::Unauthorized(_) | Self::Protocol(_) => false,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Unauthorized(message) | Self::Protocol(message) => {
                formatter.write_str(message)
            }
            Self::Remote(error) => formatter.write_str(&error.message),
            Self::Timeout => {
                formatter.write_str("the local runner did not respond before the deadline")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl LocalControlClient {
    pub fn from_environment() -> Self {
        let runtime_dir = env::var_os("LOOMEX_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_runtime_dir);
        Self {
            endpoint: env::var_os("LOOMEX_CONTROL_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| runtime_dir.join(default_endpoint_name())),
            token_path: env::var_os("LOOMEX_CONTROL_TOKEN_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| runtime_dir.join("control.token")),
        }
    }

    pub fn new(endpoint: PathBuf, token_path: PathBuf) -> Self {
        Self {
            endpoint,
            token_path,
        }
    }

    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    pub async fn call(
        &self,
        method: &str,
        params: &Value,
        deadline: Duration,
    ) -> Result<Value, ClientError> {
        let deadline = deadline.min(Duration::from_secs(47));
        timeout(deadline, self.call_inner(method, params))
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    pub async fn call_default(&self, method: &str, params: &Value) -> Result<Value, ClientError> {
        self.call(method, params, DEFAULT_TIMEOUT).await
    }

    async fn call_inner(&self, method: &str, params: &Value) -> Result<Value, ClientError> {
        let token = read_token(&self.token_path)?;
        let id = next_request_id();
        let request = ControlRequest {
            protocol_version: LOCAL_CONTROL_VERSION,
            id: id.clone(),
            auth_token: &token,
            method,
            params,
        };
        let mut payload = serde_json::to_vec(&request).map_err(|error| {
            ClientError::Protocol(format!("could not encode IPC request: {error}"))
        })?;
        payload.push(b'\n');

        #[cfg(unix)]
        let stream = {
            validate_unix_socket(&self.endpoint)?;
            tokio::net::UnixStream::connect(&self.endpoint)
                .await
                .map_err(|error| unavailable(&self.endpoint, error))?
        };

        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&self.endpoint)
            .map_err(|error| unavailable(&self.endpoint, error))?;

        #[cfg(not(any(unix, windows)))]
        return Err(ClientError::Unavailable(
            "local-control IPC is unsupported on this platform".to_string(),
        ));

        let (reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(&payload)
            .await
            .map_err(|error| unavailable(&self.endpoint, error))?;
        writer
            .shutdown()
            .await
            .map_err(|error| unavailable(&self.endpoint, error))?;

        let mut line = String::new();
        BufReader::new(reader)
            .take(RESPONSE_LIMIT)
            .read_line(&mut line)
            .await
            .map_err(|error| unavailable(&self.endpoint, error))?;
        if line.is_empty() {
            return Err(ClientError::Protocol(
                "the local runner closed IPC without a response".to_string(),
            ));
        }
        if !line.ends_with('\n') && line.len() as u64 >= RESPONSE_LIMIT {
            return Err(ClientError::Protocol(
                "the local runner IPC response exceeded 8 MiB".to_string(),
            ));
        }
        let response: ControlResponse = serde_json::from_str(&line)
            .map_err(|error| ClientError::Protocol(format!("invalid IPC response: {error}")))?;
        if response.protocol_version != LOCAL_CONTROL_VERSION {
            return Err(ClientError::Protocol(format!(
                "unsupported IPC protocol version: {}",
                response.protocol_version
            )));
        }
        if response.id != id {
            return Err(ClientError::Protocol(
                "IPC response request id did not match".to_string(),
            ));
        }
        if response.ok {
            Ok(response.result)
        } else {
            Err(ClientError::Remote(response.error.unwrap_or(
                ControlError {
                    code: "unknown_runner_error".to_string(),
                    message: "the local runner returned an unspecified error".to_string(),
                    retryable: false,
                },
            )))
        }
    }
}

impl From<LocalControlClient> for ControlClient {
    fn from(daemon: LocalControlClient) -> Self {
        Self {
            daemon,
            bootstrap: BootstrapClient::from_environment(),
        }
    }
}

impl ControlClient {
    pub fn from_environment() -> Self {
        LocalControlClient::from_environment().into()
    }

    pub fn new(daemon: LocalControlClient, bootstrap: BootstrapClient) -> Self {
        Self { daemon, bootstrap }
    }

    pub async fn call(
        &self,
        method: &str,
        params: &Value,
        deadline: Duration,
    ) -> Result<Value, ClientError> {
        if is_bootstrap_method(method) {
            return self.bootstrap.call(method, params, deadline).await;
        }
        match self.daemon.call(method, params, deadline).await {
            Err(ClientError::Unavailable(_)) if is_bootstrap_fallback_method(method) => {
                self.bootstrap.call(method, params, deadline).await
            }
            result => result,
        }
    }
}

impl BootstrapClient {
    pub fn from_environment() -> Self {
        let executable = env::var_os("LOOMEX_RUNNER_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(default_bootstrap_executable);
        Self { executable }
    }

    pub fn new(executable: PathBuf) -> Self {
        Self { executable }
    }

    async fn call(
        &self,
        method: &str,
        params: &Value,
        deadline: Duration,
    ) -> Result<Value, ClientError> {
        validate_bootstrap_executable(&self.executable)?;
        let encoded = serde_json::to_string(params).map_err(|error| {
            ClientError::Protocol(format!("could not encode bootstrap arguments: {error}"))
        })?;
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .args([
                "--json",
                "--non-interactive",
                "runner",
                "plugin-control",
                method,
                "--params-json",
                &encoded,
            ])
            .kill_on_drop(true);
        let output = timeout(deadline.min(Duration::from_secs(47)), command.output())
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| {
                ClientError::Unavailable(format!(
                    "could not start bundled Loomex runtime {}: {error}",
                    self.executable.display()
                ))
            })?;
        if output.status.success() {
            let envelope: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
                ClientError::Protocol(format!("invalid bootstrap response: {error}"))
            })?;
            if envelope.get("schemaVersion").and_then(Value::as_str)
                != Some("loomex.cli.pluginControl/v1")
                || envelope.get("method").and_then(Value::as_str) != Some(method)
            {
                return Err(ClientError::Protocol(
                    "bootstrap response did not match the plugin-control contract".to_string(),
                ));
            }
            return envelope.get("result").cloned().ok_or_else(|| {
                ClientError::Protocol("bootstrap response omitted result".to_string())
            });
        }

        Err(ClientError::Remote(parse_bootstrap_error(&output.stderr)))
    }
}

fn parse_bootstrap_error(stderr: &[u8]) -> ControlError {
    let error: Value = serde_json::from_slice(stderr).unwrap_or_else(|_| {
        json!({
            "code": "BOOTSTRAP_COMMAND_FAILED",
            "message": String::from_utf8_lossy(stderr).trim()
        })
    });
    let nested = error.get("error").filter(|value| value.is_object());
    let string_field = |field| {
        nested
            .and_then(|value| value.get(field))
            .and_then(Value::as_str)
            .or_else(|| error.get(field).and_then(Value::as_str))
    };
    let bool_field = |field| {
        nested
            .and_then(|value| value.get(field))
            .and_then(Value::as_bool)
            .or_else(|| error.get(field).and_then(Value::as_bool))
    };

    ControlError {
        code: string_field("code")
            .unwrap_or("BOOTSTRAP_COMMAND_FAILED")
            .to_string(),
        message: string_field("message")
            .unwrap_or("the bundled Loomex bootstrap command failed")
            .to_string(),
        retryable: bool_field("retryable").unwrap_or(false),
    }
}

fn is_bootstrap_method(method: &str) -> bool {
    matches!(
        method,
        "setup.status"
            | "setup.plan"
            | "setup.apply"
            | "setup.rollback"
            | "auth.status"
            | "auth.start"
            | "auth.wait"
            | "auth.logout"
            | "org.list"
            | "org.select"
            | "project.list"
            | "project.select"
            | "binding.list"
            | "binding.create"
            | "binding.revoke"
            | "runner.control"
    )
}

fn is_bootstrap_fallback_method(method: &str) -> bool {
    matches!(method, "status" | "doctor" | "logs.tail")
}

fn default_bootstrap_executable() -> PathBuf {
    let mut path = env::current_exe().unwrap_or_else(|_| PathBuf::from("loomex-mcp"));
    path.set_file_name(if cfg!(windows) {
        "loomex.exe"
    } else {
        "loomex"
    });
    path
}

fn validate_bootstrap_executable(path: &Path) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ClientError::Unavailable(format!(
            "bundled Loomex runtime is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ClientError::Unavailable(format!(
            "bundled Loomex runtime is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_token(path: &Path) -> Result<String, ClientError> {
    validate_secret_file(path)?;
    let token = fs::read_to_string(path).map_err(|error| {
        ClientError::Unavailable(format!("cannot read {}: {error}", path.display()))
    })?;
    let token = token.trim().to_string();
    if token.len() < 32 || token.len() > 4096 {
        return Err(ClientError::Unauthorized(format!(
            "{} does not contain a valid local-control credential",
            path.display()
        )));
    }
    Ok(token)
}

#[cfg(unix)]
fn validate_secret_file(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ClientError::Unavailable(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ClientError::Unauthorized(format!(
            "{} must be a regular, non-symlink file",
            path.display()
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(ClientError::Unauthorized(format!(
            "{} must be owned by this user and inaccessible to group/others",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file(path: &Path) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ClientError::Unavailable(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ClientError::Unauthorized(format!(
            "{} must be a regular, non-symlink file",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_socket(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ClientError::Unavailable(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
        return Err(ClientError::Unauthorized(format!(
            "{} must be a Unix socket, not a symlink",
            path.display()
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(ClientError::Unauthorized(format!(
            "{} must be owned by this user and inaccessible to group/others",
            path.display()
        )));
    }
    Ok(())
}

fn unavailable(path: &Path, error: io::Error) -> ClientError {
    ClientError::Unavailable(format!(
        "cannot connect to Loomex runner at {}: {error}",
        path.display()
    ))
}

fn default_runtime_dir() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join(".loomex")
        .join("run")
}

#[cfg(unix)]
fn default_endpoint_name() -> &'static str {
    "control.sock"
}

#[cfg(windows)]
fn default_endpoint_name() -> &'static str {
    r"\\.\pipe\loomex-control"
}

#[cfg(not(any(unix, windows)))]
fn default_endpoint_name() -> &'static str {
    "control.unsupported"
}

fn next_request_id() -> String {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("mcp-{epoch}-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ExpectedTransport {
        Bootstrap,
        Daemon,
        BootstrapFallback,
        Local,
    }

    fn tool_contracts() -> Vec<(&'static str, &'static str, ExpectedTransport, Value)> {
        use ExpectedTransport::{Bootstrap, BootstrapFallback, Daemon, Local};

        vec![
            ("loomex_setup_status", "setup.status", Bootstrap, json!({})),
            ("loomex_setup_plan", "setup.plan", Bootstrap, json!({})),
            (
                "loomex_setup_apply",
                "setup.apply",
                Bootstrap,
                json!({
                    "planId": "plan-1",
                    "channel": "stable",
                    "installService": true,
                    "confirm": true,
                }),
            ),
            (
                "loomex_setup_rollback",
                "setup.rollback",
                Bootstrap,
                json!({"targetVersion": "1.0.0", "confirm": true}),
            ),
            ("loomex_auth_status", "auth.status", Bootstrap, json!({})),
            ("loomex_auth_start", "auth.start", Bootstrap, json!({})),
            (
                "loomex_auth_wait",
                "auth.wait",
                Bootstrap,
                json!({"loginId": "login-1", "timeoutSeconds": 1}),
            ),
            (
                "loomex_auth_logout",
                "auth.logout",
                Bootstrap,
                json!({"confirm": true}),
            ),
            ("loomex_org_list", "org.list", Bootstrap, json!({})),
            (
                "loomex_org_select",
                "org.select",
                Bootstrap,
                json!({"organizationId": "org-1"}),
            ),
            ("loomex_project_list", "project.list", Bootstrap, json!({})),
            (
                "loomex_project_select",
                "project.select",
                Bootstrap,
                json!({"projectId": "project-1"}),
            ),
            ("loomex_binding_list", "binding.list", Bootstrap, json!({})),
            (
                "loomex_binding_create",
                "binding.create",
                Bootstrap,
                json!({"projectId": "project-1", "workspacePath": "/repo"}),
            ),
            (
                "loomex_binding_revoke",
                "binding.revoke",
                Bootstrap,
                json!({"projectId": "project-1", "bindingId": "binding-1", "confirm": true}),
            ),
            ("loomex_workflow_list", "workflow.list", Daemon, json!({})),
            (
                "loomex_workflow_show",
                "workflow.show",
                Daemon,
                json!({"workflowId": "workflow-1"}),
            ),
            (
                "loomex_workflow_run",
                "workflow.run",
                Daemon,
                json!({
                    "workflowId": "workflow-1",
                    "bindingId": "binding-1",
                    "idempotencyKey": "idem-run-123",
                }),
            ),
            (
                "loomex_run_list",
                "run.list",
                Daemon,
                json!({"workflowId": "workflow-1"}),
            ),
            (
                "loomex_run_get",
                "run.get",
                Daemon,
                json!({"executionId": "execution-1"}),
            ),
            (
                "loomex_run_wait",
                "run.wait",
                Daemon,
                json!({"executionId": "execution-1", "afterSequence": 3, "timeoutSeconds": 1}),
            ),
            (
                "loomex_run_cancel",
                "run.cancel",
                Daemon,
                json!({
                    "executionId": "execution-1",
                    "reason": "requested by contract test",
                    "idempotencyKey": "idem-cancel-123",
                }),
            ),
            ("loomex_human_list", "human.list", Daemon, json!({})),
            (
                "loomex_human_respond",
                "human.respond",
                Daemon,
                json!({"requestId": "request-1", "response": {"answer": "yes"}}),
            ),
            (
                "loomex_human_open",
                "human.open",
                Local,
                json!({"humanRequest": {"id": "request-1"}}),
            ),
            ("loomex_agent_task_list", "agent.list", Daemon, json!({})),
            (
                "loomex_agent_task_respond",
                "agent.respond",
                Daemon,
                json!({"requestId": "agent-1", "response": {"status": "completed", "output": {}}}),
            ),
            ("loomex_approval_list", "approval.list", Daemon, json!({})),
            (
                "loomex_approval_decide",
                "approval.decide",
                Daemon,
                json!({"approvalId": "approval-1", "decision": "approve"}),
            ),
            (
                "loomex_runner_status",
                "status",
                BootstrapFallback,
                json!({}),
            ),
            (
                "loomex_runner_control",
                "runner.control",
                Bootstrap,
                json!({"action": "start", "confirm": true}),
            ),
            (
                "loomex_runner_doctor",
                "doctor",
                BootstrapFallback,
                json!({}),
            ),
            (
                "loomex_runner_logs",
                "logs.tail",
                BootstrapFallback,
                json!({}),
            ),
        ]
    }

    #[test]
    fn every_advertised_tool_has_an_exact_transport_route_and_schema_valid_fixture() {
        use std::collections::HashSet;

        let contracts = tool_contracts();
        assert_eq!(contracts.len(), 33);
        let advertised = crate::tools::definitions();
        assert_eq!(advertised.len(), contracts.len());
        let expected_names = contracts
            .iter()
            .map(|(name, _, _, _)| *name)
            .collect::<HashSet<_>>();
        let advertised_names = advertised
            .iter()
            .map(|definition| definition.name)
            .collect::<HashSet<_>>();
        assert_eq!(advertised_names, expected_names);

        for (name, method, transport, arguments) in contracts {
            let definition = crate::tools::definition(name)
                .unwrap_or_else(|| panic!("missing MCP definition for {name}"));
            crate::tools::validate_arguments(&definition.input_schema, &arguments)
                .unwrap_or_else(|error| panic!("invalid contract fixture for {name}: {error}"));
            let route =
                crate::tools::route(name).unwrap_or_else(|| panic!("missing MCP route for {name}"));
            assert_eq!(
                route.method, method,
                "wrong local-control method for {name}"
            );
            assert_eq!(
                is_bootstrap_method(method),
                transport == ExpectedTransport::Bootstrap,
                "wrong bootstrap classification for {name}",
            );
            assert_eq!(
                is_bootstrap_fallback_method(method),
                transport == ExpectedTransport::BootstrapFallback,
                "wrong fallback classification for {name}",
            );
        }

        assert!(crate::tools::route("loomex_unknown").is_none());
        assert!(!is_bootstrap_method("unknown.method"));
        assert!(!is_bootstrap_fallback_method("unknown.method"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn all_bootstrap_and_fallback_methods_work_on_first_use() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("loomex");
        fs::write(
            &executable,
            r#"#!/bin/sh
method="$5"
printf '{"schemaVersion":"loomex.cli.pluginControl/v1","method":"%s","result":{"transport":"bootstrap","method":"%s"}}' "$method" "$method"
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let client = ControlClient::new(
            LocalControlClient::new(
                temp.path().join("missing.sock"),
                temp.path().join("missing.token"),
            ),
            BootstrapClient::new(executable),
        );

        for (_, method, transport, arguments) in tool_contracts() {
            if !matches!(
                transport,
                ExpectedTransport::Bootstrap | ExpectedTransport::BootstrapFallback
            ) {
                continue;
            }
            let result = client
                .call(method, &arguments, Duration::from_secs(2))
                .await
                .unwrap_or_else(|error| panic!("first-use {method} failed: {error}"));
            assert_eq!(
                result["transport"], "bootstrap",
                "wrong transport for {method}"
            );
            assert_eq!(result["method"], method);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_daemon_method_uses_authenticated_local_control() {
        use std::{
            io::{BufRead, BufReader, Write},
            os::unix::{fs::PermissionsExt, net::UnixListener},
            thread,
        };

        let contracts = tool_contracts()
            .into_iter()
            .filter(|(_, _, transport, _)| *transport == ExpectedTransport::Daemon)
            .collect::<Vec<_>>();
        assert_eq!(contracts.len(), 13);

        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("control.sock");
        let token_path = temp.path().join("control.token");
        let token = "a".repeat(64);
        fs::write(&token_path, &token).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
        let expected_methods = contracts
            .iter()
            .map(|(_, method, _, _)| *method)
            .collect::<Vec<_>>();
        let server_token = token.clone();
        let server = thread::spawn(move || {
            for expected_method in expected_methods {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["protocolVersion"], LOCAL_CONTROL_VERSION);
                assert_eq!(request["authToken"], server_token);
                assert_eq!(request["method"], expected_method);
                let response = json!({
                    "protocolVersion": LOCAL_CONTROL_VERSION,
                    "id": request["id"],
                    "ok": true,
                    "result": {"transport": "daemon", "method": expected_method},
                });
                serde_json::to_writer(&mut stream, &response).unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        let missing_bootstrap = temp.path().join("bootstrap-must-not-run");
        let client = ControlClient::new(
            LocalControlClient::new(socket_path, token_path),
            BootstrapClient::new(missing_bootstrap),
        );

        for (_, method, _, arguments) in contracts {
            let result = client
                .call(method, &arguments, Duration::from_secs(2))
                .await
                .unwrap_or_else(|error| panic!("daemon method {method} failed: {error}"));
            assert_eq!(result["transport"], "daemon");
            assert_eq!(result["method"], method);
        }
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bootstrap_errors_preserve_machine_readable_code() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("loomex");
        fs::write(
            &executable,
            r#"#!/bin/sh
printf '%s' '{"schemaVersion":"loomex.cli.error/v1","error":{"code":"MANAGEMENT_HTTP_FAILED","message":"connection refused","retryable":true},"exitCode":20}' >&2
exit 20
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let client = BootstrapClient::new(executable);

        let error = client
            .call("setup.apply", &json!({}), Duration::from_secs(2))
            .await
            .unwrap_err();

        assert_eq!(error.code(), "MANAGEMENT_HTTP_FAILED");
        assert_eq!(error.to_string(), "connection refused");
        assert!(error.retryable());
    }

    #[test]
    fn bootstrap_error_parser_reads_nested_retryability() {
        let error = parse_bootstrap_error(
            br#"{"schemaVersion":"loomex.cli.error/v1","error":{"code":"HTTP_ERROR","message":"backend unavailable","retryable":true},"exitCode":20}"#,
        );

        assert_eq!(error.code, "HTTP_ERROR");
        assert_eq!(error.message, "backend unavailable");
        assert!(error.retryable);
    }

    #[test]
    fn bootstrap_error_parser_remains_compatible_with_top_level_errors() {
        let error = parse_bootstrap_error(
            br#"{"schemaVersion":"loomex.cli.error/v1","code":"LEGACY_ERROR","message":"legacy failure","retryable":true}"#,
        );

        assert_eq!(error.code, "LEGACY_ERROR");
        assert_eq!(error.message, "legacy failure");
        assert!(error.retryable);
    }
}
