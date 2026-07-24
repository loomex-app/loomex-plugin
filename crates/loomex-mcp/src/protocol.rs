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
            Some("2024-11-05" | "2025-03-26" | "2025-06-18") => requested.unwrap(),
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
                "content": [{"type":"text", "text": "Opened the Loomex human input side panel."}],
                "structuredContent": envelope,
                "isError": false
            }));
        }
        let route = tools::route(name).expect("every definition has a route");
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
        let envelope = match self
            .client
            .call(route.method, &daemon_arguments, deadline)
            .await
        {
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
            Err(error) => failure_envelope(name, request_id, &error),
        };
        debug_assert!(tools::validate_output(&definition.output_schema, &envelope).is_ok());
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
    json!({
        "schemaVersion": MCP_ENVELOPE_VERSION,
        "ok": false,
        "tool": tool,
        "error": {"code":error.code(), "message":error.to_string(), "retryable":error.retryable()},
        "meta": {"requestId":request_id, "timestampMs":timestamp_ms()}
    })
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
        assert!(html.contains("multi_select"));
        assert!(html.contains("single_select"));
        assert!(html.contains("boolean"));
        assert!(html.contains("question-card"));
        assert!(html.contains("answers"));
        assert!(html.contains("normalizedOption"));
        assert!(html.contains("Review answers"));
        assert!(html.contains("sendFollowUpMessage"));
        assert!(html.contains("requiresReview"));
        assert!(html.contains("question?.input_type"));
        assert!(html.contains("inputType: questionType(question)"));
        assert!(html.contains("question: questionPrompt(question, index)"));
        assert!(html.contains("updateOtherInput"));
        assert!(html.contains("form.requestSubmit"));
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
        assert!(html.contains("ui/notifications/tool-result"));
        assert!(html.contains("nodeCount"));
        assert!(html.contains("executionCount"));
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
            33
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
}
