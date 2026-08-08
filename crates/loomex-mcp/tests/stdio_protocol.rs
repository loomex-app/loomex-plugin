#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixListener,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use serde_json::{json, Value};

fn run_embedded_server_result(server_result: Value, tool: &str, arguments: Value) -> Value {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("control.sock");
    let token = temp.path().join("control.token");
    fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();

    let expected_method = match tool {
        "loomex_workflow_create" => "workflow.create",
        "loomex_workflow_create_respond" => "workflow.create.respond",
        "loomex_workflow_create_finalize" => "workflow.create.finalize",
        "loomex_workflow_validate" => "workflow.validate",
        "loomex_workflow_run" => "workflow.run",
        other => panic!("wire-contract helper does not know tool route: {other}"),
    };
    let expected_arguments = arguments.clone();
    let daemon = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();
        let request: Value = serde_json::from_str(&request_line).unwrap();
        assert_eq!(
            request["method"], expected_method,
            "wrong local-control route"
        );
        assert_eq!(
            request["params"], expected_arguments,
            "daemon params were rewritten"
        );
        let mut response = json!({
            "protocolVersion":"loomex.local-control/v1",
            "id":request["id"],
            "ok":true,
            "result":server_result
        });
        response["id"] = request["id"].clone();
        writeln!(stream, "{}", response).unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env("LOOMEX_RUNTIME_DIR", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":tool,"arguments":arguments}
        })
    )
    .unwrap();
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected diagnostics: {:?}",
        output.stderr
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn workflow_definition(node_count: usize) -> Value {
    let nodes = (0..node_count)
        .map(|index| json!({"id": format!("node-{index}"), "type": "action"}))
        .collect::<Vec<_>>();
    json!({"nodes": nodes, "transitions": []})
}

#[test]
fn subprocess_speaks_clean_json_rpc_and_forwards_to_local_control() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("control.sock");
    let token = temp.path().join("control.token");
    fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();

    let daemon = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();
        let request: Value = serde_json::from_str(&request_line).unwrap();
        assert_eq!(request["protocolVersion"], "loomex.local-control/v1");
        assert_eq!(request["authToken"], "0123456789abcdef0123456789abcdef");
        assert_eq!(request["method"], "status");
        assert!(request.get("_meta").is_none());
        let response = json!({
            "protocolVersion":"loomex.local-control/v1", "id":request["id"], "ok":true,
            "result":{
                "running":true,
                "connection":{"available":true,"status":"connected"},
                "queue":{"available":false,"depth":null},
                "activeExecutions":{"available":true,"count":2,"items":[]},
                "updateHealth":{"available":false,"status":"unknown"}
            }
        });
        writeln!(stream, "{}", response).unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env("LOOMEX_RUNTIME_DIR", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/list",
            "params":{
                "_meta":{
                    "progressToken":2,
                    "com.openai/codex":{"source":"tool-discovery"}
                }
            }
        })
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc":"2.0",
            "id":3,
            "method":"tools/call",
            "params":{
                "name":"loomex_runner_status",
                "arguments":{},
                "_meta":{
                    "progressToken":3,
                    "com.openai/codex":{"source":"tool-call"}
                }
            }
        })
    )
    .unwrap();
    drop(stdin);

    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();
    daemon.join().unwrap();
    assert!(status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "unexpected diagnostics: {stderr}");

    let responses = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 3, "notifications must not emit a frame");
    let response = |id: i64| responses.iter().find(|item| item["id"] == id).unwrap();
    assert_eq!(response(1)["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(response(2)["result"]["tools"].as_array().unwrap().len(), 39);
    let agent_response_tool = response(2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "loomex_agent_task_respond")
        .unwrap();
    assert_eq!(
        agent_response_tool["inputSchema"]["properties"]["response"]["properties"]["agentSession"]
            ["required"],
        json!(["id", "host", "action"])
    );
    assert_eq!(
        agent_response_tool["inputSchema"]["properties"]["response"]["properties"]["agentSession"]
            ["properties"]["action"]["enum"],
        json!(["spawned", "resumed"])
    );
    assert_eq!(
        response(3)["result"]["structuredContent"]["schemaVersion"],
        "loomex.mcp/v1"
    );
    assert_eq!(
        response(3)["result"]["structuredContent"]["data"]["activeExecutions"]["count"],
        2
    );
    assert_eq!(response(3)["result"]["isError"], false);
}

#[test]
fn package_limit_ipc_errors_are_structured_failures_without_success_data() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("control.sock");
    let token = temp.path().join("control.token");
    fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();

    let daemon = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();
        let request: Value = serde_json::from_str(&request_line).unwrap();
        assert_eq!(request["method"], "workflow.create.finalize");
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":false,
                "error":{
                    "code":"WORKFLOW_NODE_LIMIT_EXCEEDED",
                    "message":"workflow node package limit exceeded",
                    "retryable":false,
                    "details":{
                        "metric":"workflow_nodes",
                        "current":5,
                        "requested":1,
                        "limit":5,
                        "period":"2026-08"
                    }
                }
            })
        )
        .unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env("LOOMEX_RUNTIME_DIR", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"loomex_workflow_create_finalize",
                "arguments":{"sessionId":"builder-1","idempotencyKey":"finalize-123"}
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ok"], false);
    assert_eq!(structured["error"]["code"], "WORKFLOW_NODE_LIMIT_EXCEEDED");
    assert_eq!(structured["error"]["details"]["metric"], "workflow_nodes");
    assert_eq!(structured["error"]["details"]["limit"], 5);
    assert!(structured.get("data").is_none());
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Structured package-limit context"));
}

#[test]
fn malformed_embedded_server_errors_fail_closed_over_stdio() {
    let malformed = [
        json!({"ok": false}),
        json!({"ok": false, "error": null, "details": {"raw": "null-error"}}),
        json!({"ok": false, "error": "not-an-object"}),
        json!({"ok": false, "error": []}),
        json!({"ok": false, "error": {"message": "missing code"}}),
        json!({"ok": false, "error": {"code": "MISSING_MESSAGE"}}),
    ];

    for server_result in malformed {
        let response = run_embedded_server_result(
            server_result,
            "loomex_workflow_validate",
            json!({"definition":{"nodes":[],"transitions":[]}}),
        );
        let structured = &response["result"]["structuredContent"];
        assert_eq!(structured["ok"], false);
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(structured["error"]["code"], "unknown_runner_error");
        assert_eq!(
            structured["error"]["message"],
            "the local runner returned an unspecified error"
        );
        assert!(structured.get("data").is_none());
    }

    let successful_result = json!({
        "ok": true,
        "valid": true,
        "errors": [],
        "workflow": {},
        "error": {"code": "RAW_DOMAIN_FIELD", "message": "not a failure"},
        "details": {"raw": "preserve"}
    });
    let response = run_embedded_server_result(
        successful_result.clone(),
        "loomex_workflow_validate",
        json!({"definition":{"nodes":[],"transitions":[]}}),
    );
    let structured = &response["result"]["structuredContent"];
    assert_eq!(structured["ok"], true);
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(structured["data"], successful_result);
}

#[test]
fn workflow_and_package_limit_wire_contract_matrix_preserves_server_failures() {
    let cases = [
        (
            "create",
            "loomex_workflow_create",
            json!({"prompt":"design","idempotencyKey":"create-1"}),
            "workflow.active.count",
            "workflows",
            "10",
            "1",
            "10",
            false,
        ),
        (
            "finalize",
            "loomex_workflow_create_finalize",
            json!({"sessionId":"builder-1","idempotencyKey":"finalize-1"}),
            "workflow.max.nodes",
            "nodes",
            "50",
            "1",
            "50",
            false,
        ),
        (
            "validate",
            "loomex_workflow_validate",
            json!({"definition":{"nodes":[],"transitions":[]}}),
            "workflow.max.nodes",
            "nodes",
            "50",
            "1",
            "50",
            false,
        ),
        (
            "edit-repair",
            "loomex_workflow_create_respond",
            json!({"sessionId":"builder-1","response":{},"idempotencyKey":"edit-123456"}),
            "workflow.max.nodes",
            "nodes",
            "50",
            "1",
            "50",
            false,
        ),
        (
            "execution-count",
            "loomex_workflow_run",
            json!({"workflowId":"workflow-1","idempotencyKey":"run-123456-1"}),
            "workflow.execution.count",
            "executions",
            "100",
            "1",
            "100",
            true,
        ),
        (
            "person",
            "loomex_workflow_run",
            json!({"workflowId":"workflow-1","idempotencyKey":"run-123456-2"}),
            "person.active.count",
            "persons",
            "25",
            "1",
            "25",
            false,
        ),
        (
            "memory",
            "loomex_workflow_run",
            json!({"workflowId":"workflow-1","idempotencyKey":"run-123456-3"}),
            "memory.volume_retention.byte_days",
            "byte_days",
            "1000000",
            "1",
            "1000000",
            false,
        ),
        (
            "duration",
            "loomex_workflow_run",
            json!({"workflowId":"workflow-1","idempotencyKey":"run-123456-4"}),
            "workflow.execution.duration.seconds",
            "seconds",
            "3600",
            "1",
            "3600",
            true,
        ),
    ];

    for (
        operation,
        tool,
        arguments,
        metric,
        unit,
        current_usage,
        requested_amount,
        limit,
        retryable,
    ) in cases
    {
        let details = json!({
            "metric": metric,
            "unit": unit,
            "limit": limit,
            "currentUsage": current_usage,
            "requestedAmount": requested_amount,
            "period": "2026-08"
        });
        let expected_error = json!({
            "code": "BILLING_LIMIT_EXCEEDED",
            "message": "Monthly package limit exceeded",
            "retryable": retryable,
            "details": details
        });
        let response =
            run_embedded_server_result(json!({"ok":false,"error":expected_error}), tool, arguments);
        let structured = &response["result"]["structuredContent"];
        assert_eq!(structured["ok"], false, "{operation}");
        assert_eq!(response["result"]["isError"], true, "{operation}");
        assert_eq!(structured["error"], expected_error, "{operation}");
        assert!(structured.get("data").is_none(), "{operation}");
    }

    let exact_limit = run_embedded_server_result(
        json!({
            "ok": true,
            "builderSession": {"id":"builder-1"},
            "status": "completed",
            "workflow": {"id":"workflow-1","nodeCount":50}
        }),
        "loomex_workflow_create_finalize",
        json!({"sessionId":"builder-1","idempotencyKey":"exact-123456"}),
    );
    assert_eq!(
        exact_limit["result"]["structuredContent"]["data"]["workflow"]["nodeCount"],
        50
    );
    assert_eq!(exact_limit["result"]["isError"], false);

    let validation_errors = json!([{
        "code": "WORKFLOW_NODE_LIMIT_EXCEEDED",
        "message": "Monthly package limit exceeded",
        "details": {
            "metric": "workflow.max.nodes",
            "unit": "nodes",
            "limit": "50",
            "currentUsage": "50",
            "requestedAmount": "1",
            "period": "2026-08"
        }
    }]);
    let validation = run_embedded_server_result(
        json!({
            "ok": true,
            "valid": false,
            "errors": [],
            "validationErrors": validation_errors,
            "workflow": {}
        }),
        "loomex_workflow_validate",
        json!({"definition":{"nodes":[],"transitions":[]}}),
    );
    assert_eq!(
        validation["result"]["structuredContent"]["data"]["validationErrors"],
        validation_errors
    );
    assert_eq!(validation["result"]["isError"], false);

    let exact_boundary_definition = workflow_definition(50);
    let exact_boundary = run_embedded_server_result(
        json!({
            "ok": true,
            "valid": true,
            "errors": [],
            "workflow": {"nodeCount": 50}
        }),
        "loomex_workflow_validate",
        json!({"definition": exact_boundary_definition}),
    );
    assert_eq!(
        exact_boundary["result"]["structuredContent"]["data"]["workflow"]["nodeCount"],
        50
    );
    assert_eq!(exact_boundary["result"]["isError"], false);

    let over_boundary_definition = workflow_definition(51);
    let over_boundary_error = json!({
        "code": "WORKFLOW_NODE_LIMIT_EXCEEDED",
        "message": "Monthly package limit exceeded",
        "retryable": false,
        "details": {
            "metric": "workflow.max.nodes",
            "unit": "nodes",
            "limit": "50",
            "currentUsage": "50",
            "requestedAmount": "1",
            "period": "2026-08"
        }
    });
    let over_boundary = run_embedded_server_result(
        json!({"ok": false, "error": over_boundary_error.clone()}),
        "loomex_workflow_validate",
        json!({"definition": over_boundary_definition}),
    );
    assert_eq!(
        over_boundary["result"]["structuredContent"]["error"],
        over_boundary_error
    );
    assert_eq!(over_boundary["result"]["structuredContent"]["ok"], false);
    assert_eq!(over_boundary["result"]["isError"], true);
    assert!(over_boundary["result"]["structuredContent"]
        .get("data")
        .is_none());
}

#[test]
fn parse_errors_are_framed_and_stdout_contains_only_json() {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env("LOOMEX_RUNTIME_DIR", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "not json").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], -32700);
}

#[test]
fn a_bounded_wait_does_not_block_other_tool_calls() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("control.sock");
    let token = temp.path().join("control.token");
    fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let daemon = thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            handlers.push(thread::spawn(move || {
                let mut request_line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request_line)
                    .unwrap();
                let request: Value = serde_json::from_str(&request_line).unwrap();
                if request["method"] == "run.wait" {
                    thread::sleep(Duration::from_millis(300));
                }
                writeln!(
                    stream,
                    "{}",
                    json!({"protocolVersion":"loomex.local-control/v1","id":request["id"],"ok":true,"result":{"method":request["method"]}})
                )
                .unwrap();
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env("LOOMEX_RUNTIME_DIR", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"loomex_run_wait","arguments":{"executionId":"run-1","timeoutSeconds":1}}})).unwrap();
    writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"loomex_runner_status","arguments":{}}})).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    let responses = String::from_utf8(output.stdout).unwrap();
    let ids = responses
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["id"]
                .as_i64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, vec![2, 1]);
}
