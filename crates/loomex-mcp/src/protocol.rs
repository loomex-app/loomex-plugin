use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{mpsc, Semaphore};

use crate::{
    ipc::{ClientError, ControlClient},
    tools::{self, DeadlineKind},
};

pub const MCP_ENVELOPE_VERSION: &str = "loomex.mcp/v1";
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MCP_APP_MIME_TYPE: &str = "text/html;profile=mcp-app";
const HUMAN_INPUT_APP_HTML: &str = include_str!("human_input_app.html");
const LIST_TABLE_APP_HTML: &str = include_str!("list_table_app.html");
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
static NEXT_ENVELOPE_ID: AtomicU64 = AtomicU64::new(1);

pub struct Server {
    client: ControlClient,
}

impl Server {
    pub fn new(client: impl Into<ControlClient>) -> Self {
        Self {
            client: client.into(),
        }
    }

    pub async fn handle(&self, request: Value) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(error_response(Value::Null, -32600, "Invalid Request", None));
        };
        let id = object.get("id").cloned();
        let is_notification = id.is_none();
        let response_id = id.unwrap_or(Value::Null);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return (!is_notification)
                .then(|| error_response(response_id, -32600, "Invalid Request", None));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return (!is_notification)
                .then(|| error_response(response_id, -32600, "Invalid Request", None));
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        if is_notification {
            // MCP lifecycle, cancellation, and log-level notifications require no acknowledgement.
            return None;
        }
        let result = match method {
            "initialize" => self.initialize(&params),
            "ping" => Ok(json!({})),
            "tools/list" => self.list_tools(&params),
            "tools/call" => self.call_tool(&params).await,
            "resources/list" => self.list_resources(&params),
            "resources/read" => self.read_resource(&params),
            _ => Err(RpcError::new(-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => success_response(response_id, result),
            Err(error) => error_response(response_id, error.code, &error.message, error.data),
        })
    }

    fn initialize(&self, params: &Value) -> Result<Value, RpcError> {
        require_object(params)?;
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let protocol_version = match requested {
            Some(version @ ("2024-11-05" | "2025-03-26" | "2025-06-18")) => version,
            _ => MCP_PROTOCOL_VERSION,
        };
        Ok(json!({
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": false}, "resources": {"listChanged": false}},
            "serverInfo": {"name": "loomex", "title": "Loomex Local Workflow Runner", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "For every Loomex request, first call loomex_setup_status and follow recommendedNextAction. For setup.plan, immediately call read-only loomex_setup_plan. Ask approval only before loomex_setup_apply. For binding.create after an identity mismatch, show the exact repair and ask before loomex_binding_create; never rewrite identity silently. Complete auth, scope, and binding, then resume the original request. Never require a special setup phrase."
        }))
    }

    fn list_tools(&self, params: &Value) -> Result<Value, RpcError> {
        let params = require_object(params)?;
        validate_request_meta(params)?;
        if let Some(cursor) = params.get("cursor") {
            if !cursor.is_null() {
                return Err(RpcError::invalid_params(
                    "tools/list does not use pagination",
                ));
            }
        }
        if params.keys().any(|key| key != "cursor" && key != "_meta") {
            return Err(RpcError::invalid_params("unexpected tools/list parameter"));
        }
        Ok(json!({"tools": tools::definitions()}))
    }

    fn list_resources(&self, params: &Value) -> Result<Value, RpcError> {
        let params = require_object(params)?;
        validate_request_meta(params)?;
        if params.keys().any(|key| key != "cursor" && key != "_meta") {
            return Err(RpcError::invalid_params(
                "unexpected resources/list parameter",
            ));
        }
        Ok(json!({
            "resources": [
                {
                    "uri": tools::HUMAN_INPUT_APP_URI,
                    "name": "Loomex Human Input",
                    "title": "Loomex Human Input",
                    "description": "Interactive side-panel form for Loomex human input requests.",
                    "mimeType": MCP_APP_MIME_TYPE
                },
                {
                    "uri": tools::LIST_TABLE_APP_URI,
                    "name": "Loomex List Table",
                    "title": "Loomex List Table",
                    "description": "Interactive table for Loomex organizations, projects, and workflows.",
                    "mimeType": MCP_APP_MIME_TYPE
                }
            ]
        }))
    }

    fn read_resource(&self, params: &Value) -> Result<Value, RpcError> {
        let params = require_object(params)?;
        validate_request_meta(params)?;
        if params.keys().any(|key| key != "uri" && key != "_meta") {
            return Err(RpcError::invalid_params(
                "unexpected resources/read parameter",
            ));
        }
        let uri = params
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("resources/read.uri is required"))?;
        let (text, resource_uri, prefers_border) = match uri {
            tools::HUMAN_INPUT_APP_URI => (HUMAN_INPUT_APP_HTML, tools::HUMAN_INPUT_APP_URI, false),
            tools::LIST_TABLE_APP_URI => (LIST_TABLE_APP_HTML, tools::LIST_TABLE_APP_URI, true),
            _ => return Err(RpcError::invalid_params("unknown Loomex resource")),
        };
        Ok(json!({
            "contents": [{
                "uri": resource_uri,
                "mimeType": MCP_APP_MIME_TYPE,
                "text": text,
                "_meta": {
                    "ui": {
                        "csp": {"connectDomains": [], "resourceDomains": []},
                        "prefersBorder": prefers_border
                    }
                }
            }]
        }))
    }

    async fn call_tool(&self, params: &Value) -> Result<Value, RpcError> {
        let params = require_object(params)?;
        validate_request_meta(params)?;
        if params
            .keys()
            .any(|key| key != "name" && key != "arguments" && key != "_meta")
        {
            return Err(RpcError::invalid_params("unexpected tools/call parameter"));
        }
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("tools/call.name is required"))?;
        let definition = tools::definition(name)
            .ok_or_else(|| RpcError::invalid_params(format!("unknown Loomex tool: {name}")))?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        tools::validate_arguments(&definition.input_schema, &arguments)
            .map_err(RpcError::invalid_params)?;
        if name == "loomex_human_open" {
            let request_id = next_envelope_id();
            let human_request = arguments
                .get("humanRequest")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let envelope =
                success_envelope(name, request_id, json!({"humanRequest": human_request}));
            return Ok(json!({
                "content": [{"type":"text", "text": "Opened the Loomex human input side panel. For non-text requests, keep the form as the active continuation surface; do not ask the user to say continue. The form submission will send the follow-up and resume the workflow."}],
                "structuredContent": envelope,
                "isError": false
            }));
        }
        let route = required_tool_route(name)?;
        let deadline = match route.deadline {
            DeadlineKind::Default => Duration::from_secs(12),
            DeadlineKind::Setup => Duration::from_secs(47),
            DeadlineKind::Wait => Duration::from_secs(
                arguments
                    .get("timeoutSeconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(30)
                    .min(45)
                    + 2,
            ),
        };
        let request_id = next_envelope_id();
        let daemon_arguments = normalize_daemon_arguments(name, arguments);
        let expected_agent_request_id = daemon_arguments
            .get("requestId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let expected_agent_idempotency_key = daemon_arguments
            .get("idempotencyKey")
            .and_then(Value::as_str)
            .map(str::to_string);
        let envelope = match self
            .client
            .call(route.method, &daemon_arguments, deadline)
            .await
        {
            Ok(data) => match sanitize_agent_runtime_data(
                name,
                data,
                expected_agent_request_id.as_deref(),
                expected_agent_idempotency_key.as_deref(),
            ) {
                Ok(data) => {
                    let success = success_envelope(name, request_id.clone(), data);
                    match tools::validate_output(&definition.output_schema, &success) {
                            Ok(()) => success,
                            Err(error) => failure_envelope(
                                name,
                                request_id,
                                &ClientError::Protocol(format!(
                                    "local control returned data outside the {name} output contract: {error}"
                                )),
                            ),
                        }
                }
                Err(error) => {
                    failure_envelope(name, request_id, &ClientError::Protocol(error.to_string()))
                }
            },
            Err(error) => failure_envelope(name, request_id, &error),
        };
        tools::validate_output(&definition.output_schema, &envelope).map_err(|_| {
            RpcError::new(
                -32603,
                "The Loomex tool result could not be represented safely.",
            )
        })?;
        let is_error = envelope.get("ok") == Some(&Value::Bool(false));
        let text = serde_json::to_string(&envelope).map_err(|error| {
            RpcError::new(-32603, format!("could not encode tool result: {error}"))
        })?;
        Ok(json!({
            "content": [{"type":"text", "text":text}],
            "structuredContent": envelope,
            "isError": is_error
        }))
    }
}

fn normalize_daemon_arguments(tool: &str, mut arguments: Value) -> Value {
    let Some(object) = arguments.as_object_mut() else {
        return arguments;
    };
    match tool {
        "loomex_binding_create" => {
            if let Some(path) = object.remove("workspacePath") {
                object.insert("localRootPath".to_string(), path);
            }
        }
        "loomex_human_respond" | "loomex_agent_task_respond" => {
            if let Some(response) = object.remove("response") {
                object.insert("payload".to_string(), response);
            }
        }
        "loomex_approval_decide" => {
            if let Some(approval_id) = object.remove("approvalId") {
                object.insert("requestId".to_string(), approval_id);
            }
        }
        _ => {}
    }
    arguments
}

fn required_tool_route(name: &str) -> Result<tools::ToolRoute, RpcError> {
    tools::route(name).ok_or_else(|| {
        RpcError::new(
            -32603,
            "The Loomex tool registry could not route this request.",
        )
    })
}

pub async fn serve(server: Server) -> Result<(), String> {
    let mut input = BufReader::new(io::stdin());
    let server = Arc::new(server);
    let concurrency = Arc::new(Semaphore::new(32));
    let (responses, mut response_receiver) = mpsc::channel::<Value>(64);
    let writer = tokio::spawn(async move {
        let mut output = BufWriter::new(io::stdout());
        while let Some(response) = response_receiver.recv().await {
            let encoded = serde_json::to_vec(&response)
                .map_err(|error| format!("failed to encode MCP response: {error}"))?;
            output
                .write_all(&encoded)
                .await
                .map_err(|error| format!("failed to write MCP stdout: {error}"))?;
            output
                .write_all(b"\n")
                .await
                .map_err(|error| format!("failed to frame MCP response: {error}"))?;
            output
                .flush()
                .await
                .map_err(|error| format!("failed to flush MCP stdout: {error}"))?;
        }
        Ok::<_, String>(())
    });
    let mut requests = tokio::task::JoinSet::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = input
            .read_line(&mut line)
            .await
            .map_err(|error| format!("failed to read MCP stdin: {error}"))?;
        if read == 0 {
            break;
        }
        let parsed = if read > MAX_REQUEST_BYTES {
            Some(error_response(
                Value::Null,
                -32600,
                "MCP request exceeds 1 MiB",
                None,
            ))
        } else {
            match serde_json::from_str::<Value>(&line) {
                Ok(request) => {
                    let server = Arc::clone(&server);
                    let responses = responses.clone();
                    let permit = Arc::clone(&concurrency)
                        .acquire_owned()
                        .await
                        .map_err(|_| "MCP concurrency limiter closed".to_string())?;
                    requests.spawn(async move {
                        let _permit = permit;
                        if let Some(response) = server.handle(request).await {
                            let _ = responses.send(response).await;
                        }
                    });
                    None
                }
                Err(error) => Some(error_response(
                    Value::Null,
                    -32700,
                    "Parse error",
                    Some(json!({"detail": error.to_string()})),
                )),
            }
        };
        if let Some(response) = parsed {
            responses
                .send(response)
                .await
                .map_err(|_| "MCP stdout writer stopped".to_string())?;
        }
    }
    while requests.join_next().await.is_some() {}
    drop(responses);
    writer
        .await
        .map_err(|error| format!("MCP stdout writer task failed: {error}"))?
}

#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }
}

fn require_object(value: &Value) -> Result<&serde_json::Map<String, Value>, RpcError> {
    value
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("params must be an object"))
}

fn validate_request_meta(params: &serde_json::Map<String, Value>) -> Result<(), RpcError> {
    if params
        .get("_meta")
        .is_some_and(|meta| !meta.is_object() && !meta.is_null())
    {
        return Err(RpcError::invalid_params(
            "params._meta must be an object or null",
        ));
    }
    Ok(())
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "result":result})
}

fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code":code, "message":message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc":"2.0", "id":id, "error":error})
}

fn success_envelope(tool: &str, request_id: String, data: Value) -> Value {
    json!({
        "schemaVersion": MCP_ENVELOPE_VERSION,
        "ok": true,
        "tool": tool,
        "data": data,
        "meta": {"requestId":request_id, "timestampMs":timestamp_ms()}
    })
}

fn failure_envelope(tool: &str, request_id: String, error: &ClientError) -> Value {
    let message = if is_agent_runtime_v2_tool(tool) {
        safe_agent_runtime_error_message(error)
    } else {
        error.to_string()
    };
    let mut envelope = json!({
        "schemaVersion": MCP_ENVELOPE_VERSION,
        "ok": false,
        "tool": tool,
        "error": {
            "code": if is_agent_runtime_v2_tool(tool) {
                safe_agent_runtime_error_code(error)
            } else {
                error.code()
            },
            "message":message,
            "retryable": if is_agent_runtime_v2_tool(tool) {
                safe_agent_runtime_retryable(error)
            } else {
                error.retryable()
            }
        },
        "meta": {"requestId":request_id, "timestampMs":timestamp_ms()}
    });
    if is_agent_runtime_v2_tool(tool) {
        let remediation = safe_agent_runtime_remediation(error);
        if !remediation.is_empty() {
            envelope["error"]["remediation"] = Value::Array(
                remediation
                    .iter()
                    .map(|action| Value::String(action.to_string()))
                    .collect(),
            );
        }
    }
    envelope
}

fn is_agent_runtime_v2_tool(tool: &str) -> bool {
    matches!(
        tool,
        "loomex_agent_runtime_status"
            | "loomex_agent_task_execute"
            | "loomex_agent_task_resume"
            | "loomex_agent_task_cancel"
            | "loomex_agent_task_checkpoint"
    )
}

fn safe_agent_runtime_error_message(error: &ClientError) -> String {
    match error {
        ClientError::Unavailable(_) => "The local Loomex runner is unavailable.".to_string(),
        ClientError::Unauthorized(_) => {
            "The local Loomex runner rejected the authenticated request.".to_string()
        }
        ClientError::Protocol(_) => {
            "The local Loomex runner returned an invalid agent-runtime response.".to_string()
        }
        ClientError::Timeout => {
            "The local Loomex runner did not respond before the deadline.".to_string()
        }
        ClientError::Remote(remote) => safe_agent_remote_message(&remote.code).to_string(),
    }
}

fn safe_agent_runtime_error_code(error: &ClientError) -> &'static str {
    match error {
        ClientError::Unavailable(_) => "runner_unavailable",
        ClientError::Unauthorized(_) => "local_auth_failed",
        ClientError::Protocol(_) => "ipc_protocol_error",
        ClientError::Timeout => "ipc_timeout",
        ClientError::Remote(remote) => safe_agent_remote_code(&remote.code),
    }
}

fn safe_agent_runtime_retryable(error: &ClientError) -> bool {
    match error {
        ClientError::Unavailable(_) | ClientError::Timeout => true,
        ClientError::Unauthorized(_) | ClientError::Protocol(_) => false,
        ClientError::Remote(remote) => {
            safe_agent_code_retryable(safe_agent_remote_code(&remote.code))
        }
    }
}

fn safe_agent_code_retryable(code: &str) -> bool {
    if code == "agent_runtime_v2_disabled" {
        return false;
    }
    matches!(
        code,
        "rate_limited"
            | "network_error"
            | "timeout"
            | "successor_runtime_unavailable"
            | "successor_remediation_incomplete"
    )
}

fn is_malformed_process_dispatch_code(code: &str) -> bool {
    matches!(
        code,
        "AGENT_PROCESS_DISPATCH_INVALID"
            | "AGENT_PROCESS_DISPATCH_DIGEST_MISMATCH"
            | "AGENT_PROCESS_DISPATCH_CANONICALIZATION_FAILED"
            | "PLUGIN_AGENT_PROCESS_DISPATCH_INVALID"
    )
}

fn safe_agent_remote_code(code: &str) -> &'static str {
    match code {
        "invalid_request" | "AGENT_INVALID_REQUEST" => "invalid_request",
        "protocol_mismatch" | "AGENT_PROTOCOL_MISMATCH" => "protocol_mismatch",
        "AGENT_PROCESS_DISPATCH_INVALID"
        | "AGENT_PROCESS_DISPATCH_DIGEST_MISMATCH"
        | "AGENT_PROCESS_DISPATCH_CANONICALIZATION_FAILED"
        | "PLUGIN_AGENT_PROCESS_DISPATCH_INVALID" => "protocol_mismatch",
        "agent_runtime_v2_disabled" | "AGENT_RUNTIME_V2_DISABLED" => "agent_runtime_v2_disabled",
        "provider_not_installed" | "AGENT_PROVIDER_NOT_INSTALLED" => "provider_not_installed",
        "provider_not_authenticated" | "AGENT_PROVIDER_NOT_AUTHENTICATED" => {
            "provider_not_authenticated"
        }
        "provider_not_eligible" | "AGENT_PROVIDER_NOT_ELIGIBLE" => "provider_not_eligible",
        "runtime_unavailable" | "AGENT_RUNTIME_UNAVAILABLE" => "runtime_unavailable",
        "model_unknown" | "AGENT_MODEL_UNKNOWN" => "model_unknown",
        "model_not_available" | "AGENT_MODEL_NOT_AVAILABLE" => "model_not_available",
        "unsupported_capability" | "AGENT_UNSUPPORTED_CAPABILITY" => "unsupported_capability",
        "rate_limited" | "AGENT_RATE_LIMITED" => "rate_limited",
        "network_error" | "AGENT_NETWORK_ERROR" => "network_error",
        "timeout" | "AGENT_TIMEOUT" => "timeout",
        "cancelled" | "AGENT_CANCELLED" => "cancelled",
        "output_invalid" | "AGENT_OUTPUT_INVALID" => "output_invalid",
        "session_not_found" | "AGENT_SESSION_NOT_FOUND" => "session_not_found",
        "session_mismatch" | "AGENT_SESSION_MISMATCH" => "session_mismatch",
        "execution_failed" | "AGENT_EXECUTION_FAILED" => "execution_failed",
        "execution_indeterminate"
        | "AGENT_EXECUTION_INDETERMINATE"
        | "PLUGIN_AGENT_EXECUTION_INDETERMINATE" => "execution_indeterminate",
        "internal_error" | "AGENT_INTERNAL_ERROR" => "internal_error",
        "direct_control_unsupported" | "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED" => {
            "direct_control_unsupported"
        }
        "successor_authorization_required" | "AGENT_SUCCESSOR_AUTHORIZATION_REQUIRED" => {
            "successor_authorization_required"
        }
        "cancellation_authorization_required" | "AGENT_CANCELLATION_AUTHORIZATION_REQUIRED" => {
            "cancellation_authorization_required"
        }
        "idempotency_key_invalid" | "IDEMPOTENCY_KEY_INVALID" => "idempotency_key_invalid",
        "successor_response_invalid" | "AGENT_SUCCESSOR_RESPONSE_INVALID" => {
            "successor_response_invalid"
        }
        "cancellation_response_invalid" | "AGENT_CANCELLATION_RESPONSE_INVALID" => {
            "cancellation_response_invalid"
        }
        "cancellation_state_conflict" | "AGENT_CANCELLATION_STATE_CONFLICT" => {
            "cancellation_state_conflict"
        }
        "successor_precondition_failed" | "PLUGIN_AGENT_SUCCESSOR_PRECONDITION_FAILED" => {
            "successor_precondition_failed"
        }
        "successor_binding_stale" | "PLUGIN_AGENT_SUCCESSOR_BINDING_STALE" => {
            "successor_binding_stale"
        }
        "successor_runtime_unavailable" | "PLUGIN_AGENT_SUCCESSOR_RUNTIME_UNAVAILABLE" => {
            "successor_runtime_unavailable"
        }
        "successor_remediation_incomplete" | "PLUGIN_AGENT_SUCCESSOR_REMEDIATION_INCOMPLETE" => {
            "successor_remediation_incomplete"
        }
        "successor_capability_mismatch" | "PLUGIN_AGENT_SUCCESSOR_CAPABILITY_MISMATCH" => {
            "successor_capability_mismatch"
        }
        "successor_checkpoint_mismatch" | "PLUGIN_AGENT_SUCCESSOR_CHECKPOINT_MISMATCH" => {
            "successor_checkpoint_mismatch"
        }
        "resume_checkpoint_required" | "PLUGIN_AGENT_RESUME_CHECKPOINT_REQUIRED" => {
            "resume_checkpoint_required"
        }
        "successor_conflict" | "PLUGIN_AGENT_SUCCESSOR_CONFLICT" => "successor_conflict",
        "successor_idempotency_conflict" | "PLUGIN_AGENT_SUCCESSOR_IDEMPOTENCY_CONFLICT" => {
            "successor_idempotency_conflict"
        }
        "cancellation_already_requested" | "PLUGIN_AGENT_CANCELLATION_ALREADY_REQUESTED" => {
            "cancellation_already_requested"
        }
        "binding_stale" | "PLUGIN_AGENT_BINDING_STALE" => "binding_stale",
        "already_terminal" | "PLUGIN_AGENT_ALREADY_TERMINAL" => "already_terminal",
        "runner_job_mismatch" | "PLUGIN_AGENT_RUNNER_JOB_MISMATCH" => "runner_job_mismatch",
        "cancellation_route_invalid" | "PLUGIN_AGENT_CANCELLATION_ROUTE_INVALID" => {
            "cancellation_route_invalid"
        }
        "idempotency_key_conflict" | "IDEMPOTENCY_KEY_CONFLICT" => "idempotency_key_conflict",
        "successor_state_conflict" | "AGENT_SUCCESSOR_STATE_CONFLICT" => "successor_state_conflict",
        "cancellation_stale_process" | "AGENT_CANCELLATION_STALE_PROCESS" => {
            "cancellation_stale_process"
        }
        "authorization_failed" | "AUTHORIZATION_FAILED" => "authorization_failed",
        "request_not_found" | "PLUGIN_AGENT_REQUEST_NOT_FOUND" => "request_not_found",
        "PLUGIN_AGENT_PROCESS_ATTEMPT_MISMATCH" => "cancellation_stale_process",
        "execution_thread_failed" | "AGENT_EXECUTION_THREAD_FAILED" => "execution_thread_failed",
        _ => "agent_operation_failed",
    }
}

fn safe_agent_remote_message(code: &str) -> &'static str {
    if is_malformed_process_dispatch_code(code) {
        return "The process dispatch payload was malformed.";
    }
    match safe_agent_remote_code(code) {
        "agent_runtime_v2_disabled" => "Local agent runtime v2 execution is disabled.",
        "provider_not_installed" => "The selected local agent provider is not installed.",
        "provider_not_authenticated" => "The selected local agent provider is not authenticated.",
        "provider_not_eligible" => {
            "The current provider account is not eligible for this agent execution."
        }
        "runtime_unavailable" => "The selected local agent runtime is unavailable.",
        "model_unknown" => "The requested model is unknown.",
        "model_not_available" => {
            "The requested model is not available to the selected local agent provider."
        }
        "rate_limited" => "The selected local agent provider is rate limited.",
        "network_error" => "The selected local agent provider could not be reached.",
        "timeout" => "The local agent execution timed out.",
        "cancelled" => "The local agent execution was cancelled.",
        "output_invalid" => "The local agent returned invalid output.",
        "session_not_found" => "The saved local agent session was not found.",
        "session_mismatch" => "The saved local agent session does not match this task.",
        "execution_indeterminate" => "The local agent execution has an indeterminate result.",
        "unsupported_capability" => {
            "The selected local agent does not support a required capability."
        }
        "direct_control_unsupported" => {
            "This operation is available only for a runner-job agent execution."
        }
        "successor_authorization_required" => {
            "Sign in to Loomex before authorizing an agent successor."
        }
        "cancellation_authorization_required" => {
            "Sign in to Loomex before requesting agent cancellation."
        }
        "idempotency_key_invalid" => "The operation idempotency key is invalid.",
        "successor_response_invalid" => "The agent successor authorization response was invalid.",
        "cancellation_response_invalid" => "The agent cancellation response was invalid.",
        "cancellation_state_conflict" => {
            "The agent execution cannot be cancelled from its current durable state."
        }
        "successor_precondition_failed" => {
            "The durable predecessor no longer satisfies successor preconditions."
        }
        "successor_binding_stale" => {
            "The runner binding changed after the predecessor was dispatched."
        }
        "successor_runtime_unavailable" => {
            "A fresh compatible local agent runtime snapshot is unavailable."
        }
        "successor_remediation_incomplete" => {
            "The predecessor runtime blocker has not been remediated."
        }
        "successor_capability_mismatch" => {
            "The available local agent runtime no longer satisfies the frozen task requirements."
        }
        "successor_checkpoint_mismatch" => {
            "The supplied successor checkpoint does not match durable continuity."
        }
        "resume_checkpoint_required" => {
            "A durable checkpoint is required to resume this indeterminate execution."
        }
        "successor_conflict" => "The durable predecessor can no longer accept another successor.",
        "successor_idempotency_conflict" => {
            "The successor operation key conflicts with a different persisted request."
        }
        "cancellation_already_requested" => {
            "Cancellation was already requested with a different operation identity."
        }
        "binding_stale" => "The runner binding changed after this agent execution was dispatched.",
        "already_terminal" => "The agent execution is already terminal.",
        "runner_job_mismatch" => "The cancellation request does not match the durable runner job.",
        "cancellation_route_invalid" => {
            "The durable execution route does not support this cancellation request."
        }
        "idempotency_key_conflict" => {
            "The operation key conflicts with a different persisted request."
        }
        "successor_state_conflict" => "The durable execution state cannot accept a successor.",
        "cancellation_stale_process" => {
            "The cancellation target is no longer the active durable process."
        }
        "authorization_failed" => {
            "The authenticated Loomex user is not authorized for this agent control operation."
        }
        "request_not_found" => "The durable plugin-agent request is no longer available.",
        "execution_thread_failed" => "The local agent execution worker could not be started.",
        "invalid_request" | "protocol_mismatch" => "The local agent request is invalid.",
        _ => "The local agent operation failed.",
    }
}

fn safe_agent_runtime_remediation(error: &ClientError) -> &'static [&'static str] {
    match error {
        ClientError::Unavailable(_) | ClientError::Timeout => &["retry"],
        ClientError::Unauthorized(_) => &["contact_support"],
        ClientError::Protocol(_) => &["contact_support"],
        ClientError::Remote(remote) if remote.code == "PLUGIN_AGENT_PROCESS_ATTEMPT_MISMATCH" => {
            &["reconfigure_workflow", "contact_support"]
        }
        ClientError::Remote(remote) => {
            safe_agent_code_remediation(safe_agent_remote_code(&remote.code))
        }
    }
}

fn safe_agent_code_remediation(code: &str) -> &'static [&'static str] {
    match code {
        "provider_not_installed" => &["install_executor", "refresh_executor_discovery"],
        "provider_not_authenticated"
        | "successor_authorization_required"
        | "cancellation_authorization_required" => &["authenticate"],
        "provider_not_eligible" => &["verify_provider_access", "contact_support"],
        "runtime_unavailable" => &["retry", "install_executor"],
        "model_unknown" | "model_not_available" => &["select_different_model"],
        "rate_limited" | "network_error" | "timeout" => &["retry"],
        "session_not_found" | "session_mismatch" | "execution_indeterminate" => {
            &["resume_session", "contact_support"]
        }
        "invalid_request" | "protocol_mismatch" => &["reconfigure_workflow"],
        "unsupported_capability" => &["upgrade_executor", "refresh_executor_discovery"],
        "output_invalid" | "execution_failed" | "internal_error" => &["contact_support"],
        "execution_thread_failed" => &["contact_support"],
        "direct_control_unsupported" | "idempotency_key_invalid" => &["reconfigure_workflow"],
        "successor_runtime_unavailable" | "successor_remediation_incomplete" => {
            &["retry", "refresh_executor_discovery"]
        }
        "successor_capability_mismatch" => &["reconfigure_workflow"],
        "successor_checkpoint_mismatch" | "resume_checkpoint_required" => {
            &["resume_session", "contact_support"]
        }
        "successor_precondition_failed"
        | "successor_binding_stale"
        | "successor_conflict"
        | "successor_idempotency_conflict"
        | "cancellation_already_requested"
        | "binding_stale"
        | "runner_job_mismatch"
        | "cancellation_route_invalid"
        | "idempotency_key_conflict" => &["reconfigure_workflow", "contact_support"],
        "successor_state_conflict" => &["reconfigure_workflow"],
        "cancellation_stale_process"
        | "authorization_failed"
        | "successor_response_invalid"
        | "cancellation_response_invalid"
        | "cancellation_state_conflict" => &["contact_support"],
        "request_not_found" => &["reconfigure_workflow", "contact_support"],
        "agent_runtime_v2_disabled"
        | "cancelled"
        | "already_terminal"
        | "agent_operation_failed" => &[],
        _ => &[],
    }
}

fn sanitize_agent_runtime_data(
    tool: &str,
    mut data: Value,
    expected_request_id: Option<&str>,
    expected_idempotency_key: Option<&str>,
) -> Result<Value, &'static str> {
    if !is_agent_runtime_v2_tool(tool) {
        return Ok(data);
    }
    if tool == "loomex_agent_runtime_status" {
        validate_agent_runtime_status_models(&data)?;
    }
    validate_agent_response_correlation(
        tool,
        &data,
        expected_request_id,
        expected_idempotency_key,
    )?;
    if is_agent_receipt_tool(tool) {
        validate_agent_model_identity(&data)?;
    }
    let Some(error) = data.get_mut("error").and_then(Value::as_object_mut) else {
        return Ok(data);
    };
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("agent_operation_failed")
        .to_string();
    let safe_code = safe_agent_remote_code(&code);
    let retryable = safe_agent_code_retryable(safe_code);
    let remediation = Value::Array(
        safe_agent_code_remediation(safe_code)
            .iter()
            .map(|action| Value::String((*action).to_string()))
            .collect(),
    );
    error.clear();
    error.insert("code".to_string(), Value::String(safe_code.to_string()));
    error.insert(
        "message".to_string(),
        Value::String(safe_agent_remote_message(&code).to_string()),
    );
    error.insert("retryable".to_string(), Value::Bool(retryable));
    if remediation
        .as_array()
        .is_some_and(|actions| !actions.is_empty())
    {
        error.insert("remediation".to_string(), remediation);
    }
    Ok(data)
}

fn validate_agent_runtime_status_models(data: &Value) -> Result<(), &'static str> {
    let runtimes = data
        .get("runtimes")
        .and_then(Value::as_array)
        .ok_or("agent runtime status omitted runtimes")?;
    for runtime in runtimes {
        let models = runtime
            .get("models")
            .and_then(Value::as_array)
            .ok_or("agent runtime status omitted models")?;
        for model in models {
            let model_key = model
                .get("modelKey")
                .and_then(Value::as_str)
                .ok_or("agent runtime model omitted modelKey")?;
            let provider_model_id = model
                .get("providerModelId")
                .and_then(Value::as_str)
                .ok_or("agent runtime model omitted providerModelId")?;
            if !tools::is_safe_cli_identifier(model_key, 192)
                || !tools::is_safe_cli_identifier(provider_model_id, 192)
            {
                return Err("agent runtime status contained an invalid model identity");
            }
        }
    }
    Ok(())
}

fn is_agent_operation_tool(tool: &str) -> bool {
    matches!(
        tool,
        "loomex_agent_task_execute"
            | "loomex_agent_task_resume"
            | "loomex_agent_task_cancel"
            | "loomex_agent_task_checkpoint"
    )
}

fn is_agent_receipt_tool(tool: &str) -> bool {
    matches!(
        tool,
        "loomex_agent_task_execute" | "loomex_agent_task_checkpoint"
    )
}

fn validate_agent_response_correlation(
    tool: &str,
    data: &Value,
    expected_request_id: Option<&str>,
    expected_idempotency_key: Option<&str>,
) -> Result<(), &'static str> {
    if !is_agent_operation_tool(tool) {
        return Ok(());
    }
    let object = data
        .as_object()
        .ok_or("agent control result must be an object")?;
    if expected_request_id.is_some()
        && object.get("requestId").and_then(Value::as_str) != expected_request_id
    {
        return Err("agent control result request identity did not match");
    }
    if is_agent_receipt_tool(tool)
        && expected_idempotency_key.is_some()
        && object.get("idempotencyKey").and_then(Value::as_str) != expected_idempotency_key
    {
        return Err("agent operation receipt idempotency identity did not match");
    }
    if tool == "loomex_agent_task_resume" {
        let predecessor = data
            .pointer("/predecessor/processAttemptId")
            .and_then(Value::as_str)
            .ok_or("agent successor result omitted predecessor identity")?;
        let successor = data
            .pointer("/successor/processAttemptId")
            .and_then(Value::as_str)
            .ok_or("agent successor result omitted successor identity")?;
        if predecessor == successor {
            return Err("agent successor result reused predecessor process identity");
        }
    }
    Ok(())
}

fn validate_agent_model_identity(data: &Value) -> Result<(), &'static str> {
    let object = data
        .as_object()
        .ok_or("agent operation receipt must be an object")?;
    match (object.get("modelKey"), object.get("providerModelId")) {
        (None, None) => Ok(()),
        (Some(Value::String(model_key)), Some(Value::String(provider_model_id)))
            if tools::is_safe_cli_identifier(model_key, 192)
                && tools::is_safe_cli_identifier(provider_model_id, 192) =>
        {
            Ok(())
        }
        _ => Err("agent operation receipt contained an invalid model identity"),
    }
}

fn timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn next_envelope_id() -> String {
    format!(
        "tool-{}-{}",
        timestamp_ms(),
        NEXT_ENVELOPE_ID.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn server() -> Server {
        Server::new(crate::ipc::LocalControlClient::new(
            PathBuf::from("/unavailable"),
            PathBuf::from("/unavailable"),
        ))
    }

    #[tokio::test]
    async fn initialize_advertises_tools() {
        let response = server().handle(json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
        })).await.unwrap();
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert_eq!(
            response["result"]["capabilities"]["resources"]["listChanged"],
            false
        );
        let instructions = response["result"]["instructions"].as_str().unwrap();
        assert!(instructions.len() <= 512);
        assert!(
            instructions.starts_with("For every Loomex request, first call loomex_setup_status")
        );
        assert!(instructions.contains("immediately call read-only loomex_setup_plan"));
        assert!(instructions.contains("Ask approval only before loomex_setup_apply"));
        assert!(instructions.contains("resume the original request"));
        assert!(instructions.contains("Never require a special setup phrase"));
    }

    #[tokio::test]
    async fn initialize_negotiates_supported_versions_without_panicking_and_falls_back_safely() {
        for version in ["2024-11-05", "2025-03-26", "2025-06-18"] {
            let response = server()
                .handle(json!({
                    "jsonrpc":"2.0",
                    "id":version,
                    "method":"initialize",
                    "params":{"protocolVersion":version}
                }))
                .await
                .unwrap();
            assert_eq!(response["result"]["protocolVersion"], version);
        }

        for unsupported in [json!("2099-01-01"), json!(403), Value::Null] {
            let response = server()
                .handle(json!({
                    "jsonrpc":"2.0",
                    "id":"fallback",
                    "method":"initialize",
                    "params":{"protocolVersion":unsupported}
                }))
                .await
                .unwrap();
            assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
            assert!(response.get("error").is_none());
        }
    }

    #[tokio::test]
    async fn notifications_have_no_response() {
        let response = server()
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn human_input_app_resource_is_advertised_and_readable() {
        let list = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":1, "method":"resources/list", "params":{}
            }))
            .await
            .unwrap();
        assert_eq!(
            list["result"]["resources"][0]["uri"],
            tools::HUMAN_INPUT_APP_URI
        );
        assert_eq!(
            list["result"]["resources"][0]["mimeType"],
            MCP_APP_MIME_TYPE
        );

        let read = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":2, "method":"resources/read",
                "params":{"uri":tools::HUMAN_INPUT_APP_URI}
            }))
            .await
            .unwrap();
        let content = &read["result"]["contents"][0];
        assert_eq!(content["mimeType"], MCP_APP_MIME_TYPE);
        let html = content["text"].as_str().unwrap();
        assert!(html.contains("requestDisplayMode"));
        assert!(html.contains("loomex_human_respond"));
        assert!(html.contains("ui/notifications/tool-result"));
        assert!(html.contains("structuredContent"));
        assert!(html.contains("multi_select"));
        assert!(html.contains("single_select"));
        assert!(html.contains("raw === \"radio\""));
        assert!(html.contains("raw === \"checkbox\""));
        assert!(html.contains("boolean"));
        assert!(html.contains("question-card"));
        assert!(html.contains("answers"));
        assert!(html.contains("normalizedOption"));
        assert!(html.contains("Review answers"));
        assert!(html.contains("sendFollowUpMessage"));
        assert!(html.contains("submissionSucceeded"));
        assert!(html.contains("return answersPayload[0] || {}"));
        assert!(html.contains("requiresReview"));
        assert!(html.contains("question?.input_type"));
        assert!(html.contains("inputType: questionType(question)"));
        assert!(html.contains("question: questionPrompt(question, index)"));
        assert!(html.contains("updateOtherInput"));
        assert!(html.contains("draftAnswerForQuestion"));
        assert!(html.contains("window.openai?.widgetState"));
        assert!(html.contains("window.openai?.setWidgetState"));
        assert!(html.contains("privateContent.loomexHumanInput = { version: 2, requests }"));
        assert!(html.contains("HUMAN_STATE_PREFIX"));
        assert!(html.contains("activeStateScope"));
        assert!(html.contains("structured?.meta?.requestId"));
        assert!(html.contains("window.localStorage"));
        assert!(html.contains("saveState(false)"));
        assert!(!html.contains("window.sessionStorage"));
        assert!(html.contains("form.requestSubmit"));
        assert!(html.contains("padding: 64px 72px 80px"));
        assert!(html.contains("submitted .actions"));
    }

    #[tokio::test]
    async fn list_table_app_resource_is_advertised_and_readable() {
        let list = server()
            .handle(json!({"jsonrpc":"2.0", "id":1, "method":"resources/list", "params":{}}))
            .await
            .unwrap();
        assert!(list["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource| resource["uri"] == tools::LIST_TABLE_APP_URI));

        let read = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":2, "method":"resources/read",
                "params":{"uri":tools::LIST_TABLE_APP_URI}
            }))
            .await
            .unwrap();
        let content = &read["result"]["contents"][0];
        assert_eq!(content["mimeType"], MCP_APP_MIME_TYPE);
        let html = content["text"].as_str().unwrap();
        assert!(html.contains("Loomex"));
        assert!(html.contains("structuredContent"));
        assert!(html.contains("loomex_org_select"));
        assert!(html.contains("loomex_project_select"));
        assert!(html.contains("loomex_workflow_run"));
        assert!(html.contains("sendFollowUpMessage"));
        assert!(html.contains("ui/notifications/tool-result"));
        assert!(html.contains("privateContent.loomexList = { version: 1, actions: state }"));
        assert!(html.contains("window.openai?.setWidgetState"));
        assert!(html.contains("ACTION_STATE_PREFIX"));
        assert!(html.contains("actionStateScope"));
        assert!(html.contains("result?.meta?.requestId"));
        assert!(html.contains("window.localStorage"));
        assert!(html.contains("nodeCount"));
        assert!(html.contains("executionCount"));
        assert!(html.contains("padding: 64px 72px 80px"));
    }

    #[tokio::test]
    async fn human_open_returns_the_exact_request_for_the_side_panel() {
        let human_request = json!({
            "id":"human-1",
            "status":"pending",
            "inputSpec":{
                "schemaVersion":"loomex.human-input/v1",
                "inputType":"boolean",
                "question":"Continue?"
            }
        });
        let response = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call",
                "params":{
                    "name":"loomex_human_open",
                    "arguments":{"humanRequest":human_request}
                }
            }))
            .await
            .unwrap();

        assert_eq!(
            response["result"]["structuredContent"]["data"]["humanRequest"],
            human_request
        );
        assert_eq!(response["result"]["isError"], false);
    }

    #[tokio::test]
    async fn invalid_tool_arguments_are_json_rpc_errors() {
        let response = server().handle(json!({
            "jsonrpc":"2.0", "id":"a", "method":"tools/call",
            "params":{"name":"loomex_run_wait","arguments":{"executionId":"r","timeoutSeconds":46}}
        })).await.unwrap();
        assert_eq!(response["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn tool_requests_accept_reserved_metadata_but_reject_unknown_parameters() {
        let metadata = json!({
            "progressToken": 1,
            "com.openai/codex": {"source": "tool-discovery"}
        });
        let list_response = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/list",
                "params":{"_meta":metadata.clone()}
            }))
            .await
            .unwrap();
        assert_eq!(
            list_response["result"]["tools"].as_array().unwrap().len(),
            38
        );
        let null_metadata_response = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":4, "method":"tools/list",
                "params":{"_meta":null}
            }))
            .await
            .unwrap();
        assert!(null_metadata_response.get("error").is_none());

        let call_response = server()
            .handle(json!({
                "jsonrpc":"2.0", "id":2, "method":"tools/call",
                "params":{
                    "name":"loomex_runner_status",
                    "arguments":{},
                    "_meta":metadata
                }
            }))
            .await
            .unwrap();
        assert!(call_response.get("error").is_none());
        assert_eq!(call_response["result"]["isError"], true);

        for (method, params) in [
            ("tools/list", json!({"unknown":true})),
            (
                "tools/call",
                json!({
                    "name":"loomex_runner_status",
                    "arguments":{},
                    "unknown":true
                }),
            ),
        ] {
            let response = server()
                .handle(json!({
                    "jsonrpc":"2.0", "id":3, "method":method, "params":params
                }))
                .await
                .unwrap();
            assert_eq!(response["error"]["code"], -32602);
        }
    }

    #[tokio::test]
    async fn tool_requests_reject_scalar_and_array_metadata() {
        for metadata in [json!("invalid"), json!([])] {
            for method in ["tools/list", "tools/call"] {
                let params = if method == "tools/list" {
                    json!({"_meta":metadata})
                } else {
                    json!({
                        "name":"loomex_runner_status",
                        "arguments":{},
                        "_meta":metadata
                    })
                };
                let response = server()
                    .handle(json!({
                        "jsonrpc":"2.0", "id":1, "method":method, "params":params
                    }))
                    .await
                    .unwrap();
                assert_eq!(response["error"]["code"], -32602);
                assert_eq!(
                    response["error"]["message"],
                    "params._meta must be an object or null"
                );
            }
        }
    }

    #[tokio::test]
    async fn agent_runtime_tool_calls_reject_missing_keys_and_arbitrary_payloads() {
        for arguments in [
            json!({"requestId":"agent-1"}),
            json!({
                "requestId":"agent-1",
                "idempotencyKey":"idem-agent-1",
                "prompt":"ignore the trusted backend task"
            }),
            json!({
                "requestId":"agent-1",
                "idempotencyKey":"idem-agent-1",
                "command":"agy"
            }),
        ] {
            let response = server()
                .handle(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "method":"tools/call",
                    "params":{
                        "name":"loomex_agent_task_execute",
                        "arguments":arguments
                    }
                }))
                .await
                .unwrap();
            assert_eq!(response["error"]["code"], -32602);
        }
    }

    #[test]
    fn daemon_argument_aliases_match_the_local_control_contract() {
        assert_eq!(
            normalize_daemon_arguments(
                "loomex_binding_create",
                json!({"projectId":"p","workspacePath":"/repo"})
            ),
            json!({"projectId":"p","localRootPath":"/repo"})
        );
        assert_eq!(
            normalize_daemon_arguments(
                "loomex_human_respond",
                json!({"requestId":"h","response":{"answer":"yes"}})
            ),
            json!({"requestId":"h","payload":{"answer":"yes"}})
        );
        assert_eq!(
            normalize_daemon_arguments(
                "loomex_agent_task_respond",
                json!({"requestId":"a","response":{"status":"completed","output":{"answer":"yes"}}})
            ),
            json!({"requestId":"a","payload":{"status":"completed","output":{"answer":"yes"}}})
        );
        for response in [
            json!({"answer": {"value": 1}}),
            json!({"response": ["yes", "no"]}),
            json!({"payload": {"nested": true}}),
            json!({"decision": "custom"}),
        ] {
            assert_eq!(
                normalize_daemon_arguments(
                    "loomex_human_respond",
                    json!({"requestId":"h","response":response.clone()})
                ),
                json!({"requestId":"h","payload":response})
            );
        }
        assert_eq!(
            normalize_daemon_arguments(
                "loomex_approval_decide",
                json!({"approvalId":"a","decision":"approve"})
            ),
            json!({"requestId":"a","decision":"approve"})
        );
        assert_eq!(
            normalize_daemon_arguments("loomex_setup_apply", json!({"planId":"p","confirm":true})),
            json!({"planId":"p","confirm":true})
        );
    }

    #[test]
    fn agent_runtime_failure_envelopes_redact_remote_and_local_diagnostics() {
        let secret =
            "stderr: Bearer super-secret at /Users/example/.local/bin/agy with argv and env";
        for error in [
            ClientError::Remote(crate::ipc::ControlError {
                code: "AGENT_PROVIDER_NOT_AUTHENTICATED".to_string(),
                message: secret.to_string(),
                retryable: false,
            }),
            ClientError::Protocol(secret.to_string()),
            ClientError::Unavailable(secret.to_string()),
            ClientError::Unauthorized(secret.to_string()),
        ] {
            let envelope =
                failure_envelope("loomex_agent_task_execute", "request-1".to_string(), &error);
            let encoded = serde_json::to_string(&envelope).unwrap();
            assert!(!encoded.contains("super-secret"));
            assert!(!encoded.contains("/Users/example"));
            assert!(!encoded.contains("stderr"));
            assert!(!encoded.contains("argv"));
            assert!(!encoded.contains("env"));
            crate::tools::validate_output(
                &crate::tools::definition("loomex_agent_task_execute")
                    .unwrap()
                    .output_schema,
                &envelope,
            )
            .unwrap();
        }

        let legacy = failure_envelope(
            "loomex_runner_status",
            "request-2".to_string(),
            &ClientError::Protocol(secret.to_string()),
        );
        assert_eq!(legacy["error"]["message"], secret);

        let malicious_code = ClientError::Remote(crate::ipc::ControlError {
            code: "Bearer super-secret /Users/example/.local/bin/agy".to_string(),
            message: secret.to_string(),
            retryable: false,
        });
        let envelope = failure_envelope(
            "loomex_agent_task_resume",
            "request-3".to_string(),
            &malicious_code,
        );
        assert_eq!(envelope["error"]["code"], "agent_operation_failed");
        assert_eq!(
            envelope["error"]["message"],
            "The local agent operation failed."
        );
        assert!(!serde_json::to_string(&envelope)
            .unwrap()
            .contains("super-secret"));

        let not_eligible = failure_envelope(
            "loomex_agent_task_execute",
            "request-4".to_string(),
            &ClientError::Remote(crate::ipc::ControlError {
                code: "AGENT_PROVIDER_NOT_ELIGIBLE".to_string(),
                message: secret.to_string(),
                retryable: true,
            }),
        );
        assert_eq!(not_eligible["error"]["code"], "provider_not_eligible");
        assert_eq!(
            not_eligible["error"]["message"],
            "The current provider account is not eligible for this agent execution."
        );
        assert_eq!(not_eligible["error"]["retryable"], false);
        let encoded = serde_json::to_string(&not_eligible).unwrap();
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("/Users/example"));
    }

    #[test]
    fn disabled_agent_runtime_codes_share_the_canonical_nonretryable_public_error() {
        let raw_message = "raw 403 Bearer provider-token at /Users/private/.local/bin/codex";
        for wire_code in ["agent_runtime_v2_disabled", "AGENT_RUNTIME_V2_DISABLED"] {
            let remote = ClientError::Remote(crate::ipc::ControlError {
                code: wire_code.to_string(),
                message: raw_message.to_string(),
                retryable: true,
            });
            let failure = failure_envelope(
                "loomex_agent_task_execute",
                "request-disabled".to_string(),
                &remote,
            );
            assert_eq!(
                failure["error"],
                json!({
                    "code":"agent_runtime_v2_disabled",
                    "message":"Local agent runtime v2 execution is disabled.",
                    "retryable":false
                })
            );
            crate::tools::validate_output(
                &crate::tools::definition("loomex_agent_task_execute")
                    .unwrap()
                    .output_schema,
                &failure,
            )
            .unwrap();

            let receipt = sanitize_agent_runtime_data(
                "loomex_agent_task_execute",
                json!({
                    "requestId":"agent-disabled",
                    "idempotencyKey":"idem-agent-disabled",
                    "executionId":"execution-disabled",
                    "state":"failed",
                    "accepted":false,
                    "sequence":1,
                    "error":{
                        "code":wire_code,
                        "category":"availability",
                        "message":raw_message,
                        "retry":"retryable",
                        "retryable":true,
                        "remediation":["contact_support"],
                        "token":"provider-token",
                        "path":"/Users/private/.local/bin/codex",
                        "stderr":"permission denied",
                        "argv":["codex","exec"],
                        "env":{"OPENAI_API_KEY":"provider-token"},
                        "rawError":"private daemon diagnostic"
                    }
                }),
                None,
                None,
            )
            .unwrap();
            assert_eq!(
                receipt["error"],
                json!({
                    "code":"agent_runtime_v2_disabled",
                    "message":"Local agent runtime v2 execution is disabled.",
                    "retryable":false
                })
            );
            crate::tools::validate_output(
                &crate::tools::definition("loomex_agent_task_execute")
                    .unwrap()
                    .output_schema,
                &success_envelope(
                    "loomex_agent_task_execute",
                    "receipt-disabled".to_string(),
                    receipt.clone(),
                ),
            )
            .unwrap();

            let encoded = serde_json::to_string(&(failure, receipt)).unwrap();
            for private in [
                "raw 403",
                "provider-token",
                "/Users/private",
                "stderr",
                "argv",
                "OPENAI_API_KEY",
                "rawError",
                "contact_support",
            ] {
                assert!(!encoded.contains(private), "leaked {private}");
            }
        }
    }

    #[test]
    fn agent_runtime_success_receipts_redact_embedded_error_diagnostics() {
        let data = json!({
            "requestId":"agent-1",
            "idempotencyKey":"idem-agent-1",
            "state":"blocked",
            "accepted":false,
            "sequence":2,
            "error":{
                "code":"AGENT_PROVIDER_NOT_AUTHENTICATED",
                "message":"stderr: Bearer super-secret at /Users/example/.config/agy",
                "retryable":false,
                "remediation":["authenticate"]
            }
        });
        let sanitized =
            sanitize_agent_runtime_data("loomex_agent_task_execute", data, None, None).unwrap();
        assert_eq!(sanitized["error"]["code"], "provider_not_authenticated");
        assert_eq!(
            sanitized["error"]["message"],
            "The selected local agent provider is not authenticated."
        );
        let encoded = serde_json::to_string(&sanitized).unwrap();
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("/Users/example"));

        let unsupported_executor = json!({
            "requestId":"agent-version",
            "idempotencyKey":"idem-agent-version",
            "state":"blocked",
            "accepted":false,
            "sequence":4,
            "error":{
                "code":"AGENT_UNSUPPORTED_CAPABILITY",
                "category":"validation",
                "message":"raw provider body at /Users/example/.local/bin/claude",
                "retryable":false,
                "retry":"user_action_required",
                "remediation":["upgrade_executor","refresh_executor_discovery"],
                "context":{
                    "safeDetails":{"reasonCode":"executor_version_unverified"},
                    "token":"super-secret"
                },
                "stderr":"unsupported revision"
            }
        });
        let sanitized = sanitize_agent_runtime_data(
            "loomex_agent_task_execute",
            unsupported_executor,
            None,
            None,
        )
        .unwrap();
        assert_eq!(sanitized["error"]["code"], "unsupported_capability");
        assert_eq!(
            sanitized["error"]["message"],
            "The selected local agent does not support a required capability."
        );
        assert_eq!(sanitized["error"]["retryable"], false);
        assert_eq!(
            sanitized["error"]["remediation"],
            json!(["upgrade_executor", "refresh_executor_discovery"])
        );
        assert_eq!(sanitized["error"].as_object().unwrap().len(), 4);
        crate::tools::validate_output(
            &crate::tools::definition("loomex_agent_task_execute")
                .unwrap()
                .output_schema,
            &success_envelope(
                "loomex_agent_task_execute",
                "request-unsupported-version".to_string(),
                sanitized.clone(),
            ),
        )
        .unwrap();
        let encoded = serde_json::to_string(&sanitized).unwrap();
        for private in [
            "raw provider body",
            "/Users/example",
            "super-secret",
            "safeDetails",
            "reasonCode",
            "stderr",
        ] {
            assert!(!encoded.contains(private), "leaked {private}");
        }

        let provider_not_installed = json!({
            "requestId":"agent-2",
            "idempotencyKey":"idem-agent-2",
            "state":"blocked",
            "accepted":false,
            "sequence":3,
            "error":{
                "code":"AGENT_PROVIDER_NOT_INSTALLED",
                "message":"local executable path is stale: /Users/example/.local/bin/claude",
                "retryable":false,
                "remediation":["install_executor","refresh_executor_discovery"]
            }
        });
        let sanitized = sanitize_agent_runtime_data(
            "loomex_agent_task_execute",
            provider_not_installed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(sanitized["error"]["code"], "provider_not_installed");
        assert_eq!(
            sanitized["error"]["remediation"],
            json!(["install_executor", "refresh_executor_discovery"])
        );
        crate::tools::validate_output(
            &crate::tools::definition("loomex_agent_task_execute")
                .unwrap()
                .output_schema,
            &success_envelope(
                "loomex_agent_task_execute",
                "request-provider-not-installed".to_string(),
                sanitized.clone(),
            ),
        )
        .unwrap();
        let encoded = serde_json::to_string(&sanitized).unwrap();
        assert!(!encoded.contains("/Users/example"));

        let not_eligible = json!({
            "requestId":"agent-3",
            "idempotencyKey":"idem-agent-3",
            "state":"blocked",
            "accepted":false,
            "sequence":4,
            "error":{
                "code":"AGENT_PROVIDER_NOT_ELIGIBLE",
                "message":"403 body: Bearer super-secret at /Users/example/.config/agy",
                "retryable":true,
                "remediation":["verify_provider_access","contact_support"],
                "stderr":"forbidden",
                "token":"super-secret",
                "path":"/Users/example/.config/agy"
            }
        });
        let sanitized =
            sanitize_agent_runtime_data("loomex_agent_task_execute", not_eligible, None, None)
                .unwrap();
        assert_eq!(sanitized["error"]["code"], "provider_not_eligible");
        assert_eq!(
            sanitized["error"]["message"],
            "The current provider account is not eligible for this agent execution."
        );
        assert_eq!(sanitized["error"]["retryable"], false);
        assert_eq!(
            sanitized["error"]["remediation"],
            json!(["verify_provider_access", "contact_support"])
        );
        assert_eq!(sanitized["error"].as_object().unwrap().len(), 4);
        crate::tools::validate_output(
            &crate::tools::definition("loomex_agent_task_execute")
                .unwrap()
                .output_schema,
            &success_envelope(
                "loomex_agent_task_execute",
                "request-4".to_string(),
                sanitized.clone(),
            ),
        )
        .unwrap();
        let encoded = serde_json::to_string(&sanitized).unwrap();
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("/Users/example"));
        assert!(!encoded.contains("stderr"));
    }

    #[test]
    fn canonical_embedded_error_dispositions_ignore_untrusted_daemon_claims() {
        for (remote_code, public_code, retryable, remediation) in [
            (
                "AGENT_INVALID_REQUEST",
                "invalid_request",
                false,
                &["reconfigure_workflow"][..],
            ),
            (
                "AGENT_PROTOCOL_MISMATCH",
                "protocol_mismatch",
                false,
                &["reconfigure_workflow"][..],
            ),
            (
                "AGENT_RUNTIME_UNAVAILABLE",
                "runtime_unavailable",
                false,
                &["retry", "install_executor"][..],
            ),
            (
                "AGENT_OUTPUT_INVALID",
                "output_invalid",
                false,
                &["contact_support"][..],
            ),
            (
                "AGENT_EXECUTION_FAILED",
                "execution_failed",
                false,
                &["contact_support"][..],
            ),
            (
                "AGENT_EXECUTION_THREAD_FAILED",
                "execution_thread_failed",
                false,
                &["contact_support"][..],
            ),
            ("AGENT_RATE_LIMITED", "rate_limited", true, &["retry"][..]),
        ] {
            let data = json!({
                "requestId":"agent-1",
                "idempotencyKey":"idem-agent-1",
                "state":"blocked",
                "accepted":false,
                "sequence":1,
                "error":{
                    "code":remote_code,
                    "message":"stderr Bearer secret /Users/example",
                    "retryable":!retryable,
                    "remediation":["authenticate","verify_provider_access"],
                    "rawError":"private"
                }
            });
            for tool in ["loomex_agent_task_execute", "loomex_agent_task_checkpoint"] {
                let sanitized =
                    sanitize_agent_runtime_data(tool, data.clone(), None, None).unwrap();
                assert_eq!(sanitized["error"]["code"], public_code);
                assert_eq!(sanitized["error"]["retryable"], retryable);
                assert_eq!(
                    sanitized["error"]["remediation"],
                    Value::Array(
                        remediation
                            .iter()
                            .map(|action| Value::String((*action).to_string()))
                            .collect()
                    )
                );
                let encoded = serde_json::to_string(&sanitized).unwrap();
                for private in ["stderr", "Bearer", "/Users/example", "rawError"] {
                    assert!(!encoded.contains(private), "{remote_code} leaked {private}");
                }
            }
        }
    }

    #[test]
    fn malformed_process_dispatch_aliases_have_a_narrow_canonical_public_contract() {
        let aliases = [
            "AGENT_PROCESS_DISPATCH_INVALID",
            "AGENT_PROCESS_DISPATCH_DIGEST_MISMATCH",
            "AGENT_PROCESS_DISPATCH_CANONICALIZATION_FAILED",
            "PLUGIN_AGENT_PROCESS_DISPATCH_INVALID",
        ];
        for remote_code in aliases {
            let remote_error = ClientError::Remote(crate::ipc::ControlError {
                code: remote_code.to_string(),
                message: "raw daemon stderr Bearer secret /Users/example/.local/bin/agy"
                    .to_string(),
                retryable: true,
            });
            let envelope = failure_envelope(
                "loomex_agent_task_execute",
                "request-malformed".to_string(),
                &remote_error,
            );
            assert_eq!(
                envelope["error"],
                json!({
                    "code":"protocol_mismatch",
                    "message":"The process dispatch payload was malformed.",
                    "retryable":false,
                    "remediation":["reconfigure_workflow"]
                }),
                "{remote_code}"
            );

            let receipt = json!({
                "requestId":"agent-malformed",
                "idempotencyKey":"idem-agent-malformed",
                "state":"failed",
                "accepted":false,
                "sequence":1,
                "error":{
                    "code":remote_code,
                    "message":"raw daemon stderr Bearer secret /Users/example/.local/bin/agy",
                    "retryable":true,
                    "remediation":["retry","contact_support"],
                    "rawError":"private",
                    "reasonCode":"malformed_dispatch",
                    "argv":["agy","--model","private"],
                    "env":{"GEMINI_API_KEY":"secret"}
                }
            });
            let sanitized = sanitize_agent_runtime_data(
                "loomex_agent_task_execute",
                receipt,
                Some("agent-malformed"),
                Some("idem-agent-malformed"),
            )
            .unwrap();
            assert_eq!(
                sanitized["error"],
                json!({
                    "code":"protocol_mismatch",
                    "message":"The process dispatch payload was malformed.",
                    "retryable":false,
                    "remediation":["reconfigure_workflow"]
                }),
                "{remote_code}"
            );
            let encoded = serde_json::to_string(&json!([envelope, sanitized])).unwrap();
            for private in [
                "raw daemon",
                "stderr",
                "Bearer",
                "/Users/example",
                "agy",
                "rawError",
                "reasonCode",
                "malformed_dispatch",
                "argv",
                "env",
                "GEMINI_API_KEY",
                "contact_support",
            ] {
                assert!(!encoded.contains(private), "{remote_code} leaked {private}");
            }
        }

        for (remote_code, public_code, message) in [
            (
                "AGENT_PROTOCOL_MISMATCH",
                "protocol_mismatch",
                "The local agent request is invalid.",
            ),
            (
                "AGENT_INVALID_REQUEST",
                "invalid_request",
                "The local agent request is invalid.",
            ),
            (
                "AGENT_UNKNOWN_FAILURE",
                "agent_operation_failed",
                "The local agent operation failed.",
            ),
        ] {
            let error = ClientError::Remote(crate::ipc::ControlError {
                code: remote_code.to_string(),
                message: "untrusted".to_string(),
                retryable: true,
            });
            let envelope = failure_envelope(
                "loomex_agent_task_execute",
                "request-guard".to_string(),
                &error,
            );
            assert_eq!(envelope["error"]["code"], public_code, "{remote_code}");
            assert_eq!(envelope["error"]["message"], message, "{remote_code}");
            assert_eq!(envelope["error"]["retryable"], false, "{remote_code}");
        }
    }

    #[test]
    fn agent_operation_model_identity_is_atomic_and_protocol_safe() {
        let receipt = |model_key: Option<Value>, provider_model_id: Option<Value>| {
            let mut receipt = json!({
                "requestId":"agent-model",
                "idempotencyKey":"idem-agent-model",
                "state":"queued",
                "accepted":true,
                "sequence":1
            });
            if let Some(model_key) = model_key {
                receipt["modelKey"] = model_key;
            }
            if let Some(provider_model_id) = provider_model_id {
                receipt["providerModelId"] = provider_model_id;
            }
            receipt
        };

        for valid in [
            receipt(None, None),
            receipt(Some(json!("openai/gpt-5.2")), Some(json!("gpt-5.2"))),
            receipt(Some(json!("vendor/_model")), Some(json!("vendor/.hidden"))),
            receipt(Some(json!("vendor/:model")), Some(json!("vendor/@model"))),
            receipt(Some(json!("vendor/+model")), Some(json!("vendor/-model"))),
        ] {
            assert!(
                sanitize_agent_runtime_data("loomex_agent_task_execute", valid, None, None).is_ok()
            );
        }

        let multibyte_over_192_bytes = "é".repeat(97);
        for invalid in [
            receipt(Some(json!("openai/gpt-5.2")), None),
            receipt(None, Some(json!("gpt-5.2"))),
            receipt(
                Some(json!(multibyte_over_192_bytes)),
                Some(json!("gpt-5.2")),
            ),
            receipt(
                Some(json!("openai/gpt-5.2")),
                Some(json!("gpt 5.2\n--help")),
            ),
            receipt(Some(json!("vendor//x")), Some(json!("gpt-5.2"))),
            receipt(Some(json!("vendor/.")), Some(json!("gpt-5.2"))),
            receipt(Some(json!("vendor/..")), Some(json!("gpt-5.2"))),
            receipt(Some(json!("-vendor/model")), Some(json!("gpt-5.2"))),
            receipt(Some(json!("openai/../private")), Some(json!("gpt-5.2"))),
        ] {
            assert!(
                sanitize_agent_runtime_data("loomex_agent_task_execute", invalid, None, None)
                    .is_err()
            );
        }
    }

    #[test]
    fn agent_control_results_must_correlate_and_successors_cannot_reuse_process_identity() {
        let execute = json!({
            "requestId":"agent-1",
            "idempotencyKey":"task-key-1",
            "state":"queued",
            "accepted":true,
            "sequence":1
        });
        assert!(sanitize_agent_runtime_data(
            "loomex_agent_task_execute",
            execute.clone(),
            Some("agent-1"),
            Some("task-key-1")
        )
        .is_ok());
        assert!(sanitize_agent_runtime_data(
            "loomex_agent_task_execute",
            execute.clone(),
            Some("agent-2"),
            Some("task-key-1")
        )
        .is_err());
        assert!(sanitize_agent_runtime_data(
            "loomex_agent_task_execute",
            execute,
            Some("agent-1"),
            Some("task-key-2")
        )
        .is_err());

        let successor = json!({
            "schemaVersion":"loomex.agent-successor-control/v1",
            "controlState":"queued",
            "requestId":"agent-1",
            "agentExecutionId":"execution-1",
            "sequence":2,
            "predecessor":{"processAttemptId":"attempt-1","state":"blocked"},
            "successor":{
                "processAttemptId":"attempt-2",
                "attemptNumber":2,
                "mode":"resume_exact_session",
                "jobId":"job-2",
                "jobStatus":"queued"
            },
            "authorizationId":"authorization-1",
            "authorizedAt":"2026-07-27T10:00:00Z",
            "replayed":false
        });
        assert!(sanitize_agent_runtime_data(
            "loomex_agent_task_resume",
            successor.clone(),
            Some("agent-1"),
            None
        )
        .is_ok());
        let mut reused = successor;
        reused["successor"]["processAttemptId"] = json!("attempt-1");
        assert!(sanitize_agent_runtime_data(
            "loomex_agent_task_resume",
            reused,
            Some("agent-1"),
            None
        )
        .is_err());
    }

    #[test]
    fn phase_four_control_errors_have_stable_safe_mappings() {
        let secret = "stderr Bearer secret at /Users/example/.local/bin/agy";
        for (tool, code, public_code, remediation) in [
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED",
                "direct_control_unsupported",
                json!(["reconfigure_workflow"]),
            ),
            (
                "loomex_agent_task_resume",
                "AGENT_SUCCESSOR_AUTHORIZATION_REQUIRED",
                "successor_authorization_required",
                json!(["authenticate"]),
            ),
            (
                "loomex_agent_task_cancel",
                "AGENT_CANCELLATION_AUTHORIZATION_REQUIRED",
                "cancellation_authorization_required",
                json!(["authenticate"]),
            ),
            (
                "loomex_agent_task_cancel",
                "IDEMPOTENCY_KEY_INVALID",
                "idempotency_key_invalid",
                json!(["reconfigure_workflow"]),
            ),
        ] {
            let envelope = failure_envelope(
                tool,
                "request-1".to_string(),
                &ClientError::Remote(crate::ipc::ControlError {
                    code: code.to_string(),
                    message: secret.to_string(),
                    retryable: true,
                }),
            );
            assert_eq!(envelope["error"]["code"], public_code);
            assert_eq!(envelope["error"]["retryable"], false);
            assert_eq!(envelope["error"]["remediation"], remediation);
            let encoded = serde_json::to_string(&envelope).unwrap();
            for private in ["stderr", "Bearer", "/Users/example", "agy"] {
                assert!(!encoded.contains(private), "{tool} leaked {private}");
            }
            crate::tools::validate_output(
                &crate::tools::definition(tool).unwrap().output_schema,
                &envelope,
            )
            .unwrap();
        }
    }

    #[test]
    fn typed_successor_and_cancellation_errors_never_collapse_to_generic_failures() {
        for (tool, code, public_code, retryable, remediation) in [
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_PRECONDITION_FAILED",
                "successor_precondition_failed",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_BINDING_STALE",
                "successor_binding_stale",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_RUNTIME_UNAVAILABLE",
                "successor_runtime_unavailable",
                true,
                &["retry", "refresh_executor_discovery"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_REMEDIATION_INCOMPLETE",
                "successor_remediation_incomplete",
                true,
                &["retry", "refresh_executor_discovery"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_CAPABILITY_MISMATCH",
                "successor_capability_mismatch",
                false,
                &["reconfigure_workflow"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_CHECKPOINT_MISMATCH",
                "successor_checkpoint_mismatch",
                false,
                &["resume_session", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_RESUME_CHECKPOINT_REQUIRED",
                "resume_checkpoint_required",
                false,
                &["resume_session", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_CONFLICT",
                "successor_conflict",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_SUCCESSOR_IDEMPOTENCY_CONFLICT",
                "successor_idempotency_conflict",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_CANCELLATION_ALREADY_REQUESTED",
                "cancellation_already_requested",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_BINDING_STALE",
                "binding_stale",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_EXECUTION_INDETERMINATE",
                "execution_indeterminate",
                false,
                &["resume_session", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_ALREADY_TERMINAL",
                "already_terminal",
                false,
                &[][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_RUNNER_JOB_MISMATCH",
                "runner_job_mismatch",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_CANCELLATION_ROUTE_INVALID",
                "cancellation_route_invalid",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "IDEMPOTENCY_KEY_CONFLICT",
                "idempotency_key_conflict",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "AGENT_SUCCESSOR_STATE_CONFLICT",
                "successor_state_conflict",
                false,
                &["reconfigure_workflow"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "AGENT_CANCELLATION_STALE_PROCESS",
                "cancellation_stale_process",
                false,
                &["contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "AUTHORIZATION_FAILED",
                "authorization_failed",
                false,
                &["contact_support"][..],
            ),
            (
                "loomex_agent_task_resume",
                "PLUGIN_AGENT_REQUEST_NOT_FOUND",
                "request_not_found",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
            (
                "loomex_agent_task_cancel",
                "PLUGIN_AGENT_PROCESS_ATTEMPT_MISMATCH",
                "cancellation_stale_process",
                false,
                &["reconfigure_workflow", "contact_support"][..],
            ),
        ] {
            let envelope = failure_envelope(
                tool,
                "request-typed".to_string(),
                &ClientError::Remote(crate::ipc::ControlError {
                    code: code.to_string(),
                    message: "stderr Bearer secret /Users/example".to_string(),
                    retryable: !retryable,
                }),
            );
            assert_eq!(envelope["error"]["code"], public_code);
            assert_ne!(envelope["error"]["code"], "agent_operation_failed");
            assert_eq!(envelope["error"]["retryable"], retryable);
            let expected_remediation = remediation
                .iter()
                .map(|action| Value::String((*action).to_string()))
                .collect::<Vec<_>>();
            if expected_remediation.is_empty() {
                assert!(envelope["error"].get("remediation").is_none());
            } else {
                assert_eq!(
                    envelope["error"]["remediation"],
                    Value::Array(expected_remediation)
                );
            }
            let encoded = serde_json::to_string(&envelope).unwrap();
            for private in ["stderr", "Bearer", "/Users/example"] {
                assert!(!encoded.contains(private), "{code} leaked {private}");
            }
        }
    }

    #[test]
    fn missing_tool_routes_return_a_safe_internal_error_without_panicking() {
        let error = required_tool_route("loomex_missing_agent_runtime_tool").unwrap_err();
        assert_eq!(error.code, -32603);
        assert_eq!(
            error.message,
            "The Loomex tool registry could not route this request."
        );
        assert!(error.data.is_none());
    }
}
