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

fn call_agent_tool_with_daemon(
    tool: &'static str,
    method: &'static str,
    arguments: Value,
    daemon_response: Value,
) -> Value {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("control.sock");
    let token = temp.path().join("control.token");
    fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let expected_arguments = arguments.clone();

    let daemon = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request_line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request_line)
            .unwrap();
        let request: Value = serde_json::from_str(&request_line).unwrap();
        assert_eq!(request["protocolVersion"], "loomex.local-control/v1");
        assert_eq!(request["method"], method);
        assert_eq!(request["params"], expected_arguments);
        let expected_param_count = usize::from(method != "agent.runtime.status") * 2;
        assert_eq!(
            request["params"].as_object().unwrap().len(),
            expected_param_count
        );
        let mut request_tail = Vec::new();
        stream.read_to_end(&mut request_tail).unwrap();
        assert!(request_tail.is_empty());
        let mut response = daemon_response;
        response["protocolVersion"] = json!("loomex.local-control/v1");
        response["id"] = request["id"].clone();
        writeln!(stream, "{response}").unwrap();
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
            "params":{"name":tool,"arguments":arguments}
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn call_agent_tool_without_daemon(tool: &str, arguments: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-mcp"))
        .env(
            "LOOMEX_RUNTIME_DIR",
            "/definitely/unavailable/loomex-runtime",
        )
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
            "params":{"name":tool,"arguments":arguments}
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn call_agent_execute_with_result(result: Value) -> Value {
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
        assert_eq!(request["method"], "agent.execute");
        let mut request_tail = Vec::new();
        stream.read_to_end(&mut request_tail).unwrap();
        assert!(request_tail.is_empty());
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":true,
                "result":result
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
                "name":"loomex_agent_task_execute",
                "arguments":{
                    "requestId":"agent-model",
                    "idempotencyKey":"idem-agent-model"
                }
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
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
    let discovered_tools = response(2)["result"]["tools"].as_array().unwrap();
    assert_eq!(discovered_tools.len(), 38);
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
    let status_tool = discovered_tools
        .iter()
        .find(|tool| tool["name"] == "loomex_agent_runtime_status")
        .unwrap();
    assert_eq!(status_tool["inputSchema"]["properties"], json!({}));
    assert_eq!(status_tool["inputSchema"]["required"], json!([]));
    assert_eq!(status_tool["inputSchema"]["additionalProperties"], false);

    for (name, key_name) in [
        ("loomex_agent_task_execute", "idempotencyKey"),
        ("loomex_agent_task_checkpoint", "idempotencyKey"),
        ("loomex_agent_task_resume", "operationIdempotencyKey"),
        ("loomex_agent_task_cancel", "operationIdempotencyKey"),
    ] {
        let tool = discovered_tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap();
        let properties = tool["inputSchema"]["properties"].as_object().unwrap();
        let mut keys = properties.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        let mut expected_keys = vec![key_name, "requestId"];
        expected_keys.sort_unstable();
        assert_eq!(keys, expected_keys, "{name}");
        assert_eq!(
            tool["inputSchema"]["required"],
            json!(["requestId", key_name])
        );
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        let encoded = serde_json::to_string(tool).unwrap();
        for unsafe_field in [
            "\"prompt\"",
            "\"command\"",
            "\"args\"",
            "\"path\"",
            "\"token\"",
            "\"rawError\"",
            "\"argv\"",
            "\"env\"",
        ] {
            assert!(
                !encoded.contains(unsafe_field),
                "{name} advertised unsafe field {unsafe_field}"
            );
        }
    }
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
fn agent_execute_forwards_only_safe_identifiers_over_unchanged_local_control() {
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
        assert_eq!(request["method"], "agent.execute");
        assert_eq!(
            request["params"],
            json!({
                "requestId":"agent-1",
                "idempotencyKey":"idem-agent-execute"
            })
        );
        assert!(request.get("_meta").is_none());
        assert_eq!(request["params"].as_object().unwrap().len(), 2);
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":true,
                "result":{
                    "requestId":"agent-1",
                    "idempotencyKey":"idem-agent-execute",
                    "executionId":"execution-1",
                    "state":"queued",
                    "accepted":true,
                    "sequence":1,
                    "provider":"google",
                    "executor":"agy_cli",
                    "modelKey":"gemini-2.5-pro",
                    "providerModelId":"gemini-2.5-pro"
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
                "name":"loomex_agent_task_execute",
                "arguments":{
                    "requestId":"agent-1",
                    "idempotencyKey":"idem-agent-execute"
                },
                "_meta":{"progressToken":1}
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["data"]["executor"],
        "agy_cli"
    );
    assert_eq!(
        response["result"]["structuredContent"]["data"]["accepted"],
        true
    );
}

#[test]
fn runtime_status_rejects_unsafe_model_identities_without_reflection() {
    for (field, invalid) in [
        ("modelKey", "/Users/example/private"),
        ("providerModelId", "model\n--help"),
        ("modelKey", "-flag"),
        ("providerModelId", "vendor/../private"),
    ] {
        let mut model = json!({
            "modelKey":"gemini-2.5-pro",
            "providerModelId":"gemini-2.5-pro",
            "availability":"available"
        });
        model[field] = json!(invalid);
        let response = call_agent_tool_with_daemon(
            "loomex_agent_runtime_status",
            "agent.runtime.status",
            json!({}),
            json!({
                "ok":true,
                "result":{
                    "schema":"loomex.agent-capabilities.v2",
                    "observedAt":"2026-07-27T10:00:00Z",
                    "ttlSeconds":30,
                    "runtimes":[{
                        "provider":"google",
                        "executor":"agy_cli",
                        "installed":true,
                        "authentication":"authenticated",
                        "readiness":"ready",
                        "version":"1.2.3",
                        "modelDiscovery":"runtime_probe",
                        "models":[model],
                        "features":{
                            "structuredOutput":true,
                            "sessionResume":true,
                            "cancellation":true,
                            "reasoningEffort":false
                        }
                    }]
                }
            }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(envelope["error"]["code"], "ipc_protocol_error");
        let encoded = serde_json::to_string(envelope).unwrap();
        for private in ["/Users/example", "--help", "-flag", "vendor/../private"] {
            assert!(!encoded.contains(private), "status leaked {private}");
        }
    }
}

#[test]
fn disabled_runtime_status_accepts_empty_v2_snapshot_and_rejects_null_or_unknown_schema() {
    let valid = call_agent_tool_with_daemon(
        "loomex_agent_runtime_status",
        "agent.runtime.status",
        json!({}),
        json!({
            "ok":true,
            "result":{
                "schema":"loomex.agent-capabilities.v2",
                "observedAt":"2026-07-27T10:00:00Z",
                "ttlSeconds":1,
                "runtimes":[]
            }
        }),
    );
    assert_eq!(valid["result"]["isError"], false);
    assert_eq!(
        valid["result"]["structuredContent"]["data"],
        json!({
            "schema":"loomex.agent-capabilities.v2",
            "observedAt":"2026-07-27T10:00:00Z",
            "ttlSeconds":1,
            "runtimes":[]
        })
    );

    for invalid_result in [
        json!({
            "schema":"loomex.agent-capabilities.v2",
            "observedAt":"2026-07-27T10:00:00Z",
            "ttlSeconds":1,
            "runtimes":null
        }),
        json!({
            "schema":"loomex.agent-capabilities.v3",
            "observedAt":"2026-07-27T10:00:00Z",
            "ttlSeconds":1,
            "runtimes":[]
        }),
    ] {
        let response = call_agent_tool_with_daemon(
            "loomex_agent_runtime_status",
            "agent.runtime.status",
            json!({}),
            json!({"ok":true,"result":invalid_result}),
        );
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "ipc_protocol_error"
        );
    }
}

#[test]
fn agent_resume_forwards_operation_key_and_returns_strict_successor_control() {
    let response = call_agent_tool_with_daemon(
        "loomex_agent_task_resume",
        "agent.resume",
        json!({
            "requestId":"agent-1",
            "operationIdempotencyKey":"resume-operation-1"
        }),
        json!({
            "ok":true,
            "result":{
                "schemaVersion":"loomex.agent-successor-control/v1",
                "controlState":"queued",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":9,
                "predecessor":{
                    "processAttemptId":"attempt-1",
                    "state":"indeterminate"
                },
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
            }
        }),
    );
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        envelope["data"]["schemaVersion"],
        "loomex.agent-successor-control/v1"
    );
    assert_eq!(
        envelope["data"]["sequence"], 9,
        "the daemon sequence must be preserved exactly"
    );
    assert_eq!(envelope["data"]["successor"]["jobStatus"], "queued");
    assert!(serde_json::to_string(envelope)
        .unwrap()
        .find("operationIdempotencyKey")
        .is_none());
}

#[test]
fn agent_cancel_forwards_operation_key_and_returns_strict_cancellation_control() {
    let response = call_agent_tool_with_daemon(
        "loomex_agent_task_cancel",
        "agent.cancel",
        json!({
            "requestId":"agent-1",
            "operationIdempotencyKey":"cancel-operation-1"
        }),
        json!({
            "ok":true,
            "result":{
                "schemaVersion":"loomex.agent-cancellation-control/v1",
                "controlState":"canceling",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":0,
                "processAttemptId":"attempt-1",
                "cancellation":{
                    "id":"cancellation-1",
                    "state":"acknowledged",
                    "deliveryRoute":"runner_job",
                    "requestedAt":"2026-07-27T10:00:00Z"
                },
                "job":{
                    "id":"job-1",
                    "status":"canceling",
                    "leaseVersion":7
                },
                "localCancellationAuthorized":false,
                "replayed":true
            }
        }),
    );
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        envelope["data"]["schemaVersion"],
        "loomex.agent-cancellation-control/v1"
    );
    assert_eq!(
        envelope["data"]["cancellation"]["deliveryRoute"],
        "runner_job"
    );
    assert_eq!(envelope["data"]["localCancellationAuthorized"], false);
    assert_eq!(
        envelope["data"]["sequence"], 0,
        "a canceling receipt sequence must be preserved exactly"
    );
}

#[test]
fn agent_cancel_accepts_only_explicit_indeterminate_and_deferred_terminal_variants() {
    let terminal =
        |control_state: &str, cancellation_state: &str, job_status: &str, replayed: bool| {
            json!({
                "schemaVersion":"loomex.agent-cancellation-control/v1",
                "controlState":control_state,
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":10,
                "processAttemptId":"attempt-1",
                "cancellation":{
                    "id":"cancellation-1",
                    "state":cancellation_state,
                    "deliveryRoute":"runner_job",
                    "requestedAt":"2026-07-27T10:00:00Z"
                },
                "job":{
                    "id":"job-1",
                    "status":job_status,
                    "leaseVersion":7
                },
                "localCancellationAuthorized":false,
                "replayed":replayed
            })
        };
    for (control_state, cancellation_state, job_status, replayed) in [
        ("indeterminate", "indeterminate", "canceled", true),
        ("completed", "completed", "deferred", false),
        ("completed", "completed", "deferred", true),
    ] {
        let response = call_agent_tool_with_daemon(
            "loomex_agent_task_cancel",
            "agent.cancel",
            json!({
                "requestId":"agent-1",
                "operationIdempotencyKey":"cancel-operation-1"
            }),
            json!({
                "ok":true,
                "result":terminal(
                    control_state,
                    cancellation_state,
                    job_status,
                    replayed
                )
            }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(envelope["data"]["controlState"], control_state);
        assert_eq!(
            envelope["data"]["cancellation"]["state"],
            cancellation_state
        );
        assert_eq!(envelope["data"]["job"]["status"], job_status);
        assert_eq!(envelope["data"]["replayed"], replayed);
        assert_eq!(envelope["data"]["sequence"], 10);
    }
}

#[test]
fn agent_control_inputs_reject_aliases_sensitive_fields_and_invalid_keys_before_ipc() {
    for (tool, correct_key, alias) in [
        (
            "loomex_agent_task_execute",
            "idempotencyKey",
            "operationIdempotencyKey",
        ),
        (
            "loomex_agent_task_checkpoint",
            "idempotencyKey",
            "operationIdempotencyKey",
        ),
        (
            "loomex_agent_task_resume",
            "operationIdempotencyKey",
            "idempotencyKey",
        ),
        (
            "loomex_agent_task_cancel",
            "operationIdempotencyKey",
            "idempotencyKey",
        ),
    ] {
        let mut alias_arguments = json!({"requestId":"agent-1"});
        alias_arguments[alias] = json!("operation-key-1");
        assert_eq!(
            call_agent_tool_without_daemon(tool, alias_arguments)["error"]["code"],
            -32602,
            "{tool} accepted alias {alias}"
        );

        for key in [
            "",
            "-leading-flag",
            "contains space",
            "contains\nnewline",
            "vendor//empty",
            "vendor/../traversal",
            "é",
        ] {
            let mut arguments = json!({"requestId":"agent-1"});
            arguments[correct_key] = json!(key);
            assert_eq!(
                call_agent_tool_without_daemon(tool, arguments)["error"]["code"],
                -32602,
                "{tool} accepted invalid key {key:?}"
            );
        }

        for sensitive in [
            "prompt",
            "command",
            "args",
            "path",
            "workspacePath",
            "model",
            "provider",
            "token",
            "env",
            "reason",
        ] {
            let mut arguments = json!({"requestId":"agent-1"});
            arguments[correct_key] = json!("operation-key-1");
            arguments[sensitive] = json!("secret");
            assert_eq!(
                call_agent_tool_without_daemon(tool, arguments)["error"]["code"],
                -32602,
                "{tool} accepted sensitive field {sensitive}"
            );
        }
        for request_id in [
            "/Users/example/private",
            "Users/Alice/private",
            "C:/Users/Alice/private",
            r"C:\Users\Alice\private",
            "agent:private",
        ] {
            let mut unsafe_request_id = json!({"requestId":request_id});
            unsafe_request_id[correct_key] = json!("operation-key-1");
            assert_eq!(
                call_agent_tool_without_daemon(tool, unsafe_request_id)["error"]["code"],
                -32602,
                "{tool} accepted unsafe requestId {request_id}"
            );
        }
    }
}

#[test]
fn disabled_runtime_wire_codes_return_the_same_redacted_nonretryable_error() {
    for wire_code in ["agent_runtime_v2_disabled", "AGENT_RUNTIME_V2_DISABLED"] {
        let response = call_agent_tool_with_daemon(
            "loomex_agent_task_execute",
            "agent.execute",
            json!({
                "requestId":"agent-disabled",
                "idempotencyKey":"operation-disabled"
            }),
            json!({
                "ok":false,
                "error":{
                    "code":wire_code,
                    "category":"availability",
                    "message":"raw 403: Bearer provider-token at /Users/private/.local/bin/codex",
                    "retry":"retryable",
                    "retryable":true,
                    "remediation":["contact_support"],
                    "details":{
                        "token":"provider-token",
                        "path":"/Users/private/.local/bin/codex",
                        "stderr":"permission denied",
                        "argv":["codex","exec"],
                        "env":{"OPENAI_API_KEY":"provider-token"},
                        "rawError":"private daemon diagnostic"
                    }
                }
            }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            envelope["error"],
            json!({
                "code":"agent_runtime_v2_disabled",
                "message":"Local agent runtime v2 execution is disabled.",
                "retryable":false
            })
        );
        let encoded = serde_json::to_string(&response).unwrap();
        for private in [
            "agent_operation_failed",
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
fn malformed_process_dispatch_failure_uses_canonical_public_contract() {
    let response = call_agent_tool_with_daemon(
        "loomex_agent_task_execute",
        "agent.execute",
        json!({
            "requestId":"agent-malformed",
            "idempotencyKey":"operation-malformed"
        }),
        json!({
            "ok":false,
            "error":{
                "code":"AGENT_PROCESS_DISPATCH_DIGEST_MISMATCH",
                "category":"protocol",
                "message":"raw daemon stderr: Bearer provider-token at /Users/private/.local/bin/agy",
                "retryable":true,
                "remediation":["retry","contact_support"],
                "reasonCode":"malformed_dispatch",
                "details":{
                    "token":"provider-token",
                    "path":"/Users/private/.local/bin/agy",
                    "stderr":"digest mismatch",
                    "argv":["agy","--model","gemini-private"],
                    "env":{"GEMINI_API_KEY":"provider-token"},
                    "rawError":"private daemon diagnostic"
                }
            }
        }),
    );
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        envelope["error"],
        json!({
            "code":"protocol_mismatch",
            "message":"The process dispatch payload was malformed.",
            "retryable":false,
            "remediation":["reconfigure_workflow"]
        })
    );
    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "raw daemon",
        "stderr",
        "Bearer",
        "provider-token",
        "/Users/private",
        "agy",
        "gemini-private",
        "reasonCode",
        "malformed_dispatch",
        "details",
        "argv",
        "env",
        "GEMINI_API_KEY",
        "rawError",
        "contact_support",
    ] {
        assert!(!encoded.contains(private), "leaked {private}");
    }
}

#[test]
fn malformed_process_dispatch_terminal_receipt_uses_canonical_public_contract() {
    let response = call_agent_tool_with_daemon(
        "loomex_agent_task_execute",
        "agent.execute",
        json!({
            "requestId":"agent-malformed",
            "idempotencyKey":"operation-malformed"
        }),
        json!({
            "ok":true,
            "result":{
                "requestId":"agent-malformed",
                "idempotencyKey":"operation-malformed",
                "state":"failed",
                "accepted":false,
                "sequence":1,
                "error":{
                    "code":"PLUGIN_AGENT_PROCESS_DISPATCH_INVALID",
                    "message":"raw daemon stderr: Bearer provider-token at /Users/private/.local/bin/agy",
                    "retryable":true,
                    "remediation":["retry","contact_support"],
                    "reasonCode":"malformed_dispatch",
                    "token":"provider-token",
                    "path":"/Users/private/.local/bin/agy",
                    "stderr":"invalid dispatch",
                    "argv":["agy","--model","gemini-private"],
                    "env":{"GEMINI_API_KEY":"provider-token"},
                    "rawError":"private daemon diagnostic"
                }
            }
        }),
    );
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["state"], "failed");
    assert_eq!(
        envelope["data"]["error"],
        json!({
            "code":"protocol_mismatch",
            "message":"The process dispatch payload was malformed.",
            "retryable":false,
            "remediation":["reconfigure_workflow"]
        })
    );
    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "raw daemon",
        "stderr",
        "Bearer",
        "provider-token",
        "/Users/private",
        "agy",
        "gemini-private",
        "reasonCode",
        "malformed_dispatch",
        "\"token\"",
        "\"path\"",
        "argv",
        "env",
        "GEMINI_API_KEY",
        "rawError",
        "contact_support",
    ] {
        assert!(!encoded.contains(private), "leaked {private}");
    }
}

#[test]
fn agent_control_errors_use_safe_public_taxonomy_and_authoritative_remediation() {
    for (tool, method, remote_code, public_code, retryable, remediation) in [
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "PLUGIN_AGENT_DIRECT_CONTROL_UNSUPPORTED",
            "direct_control_unsupported",
            false,
            json!(["reconfigure_workflow"]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "AGENT_SUCCESSOR_AUTHORIZATION_REQUIRED",
            "successor_authorization_required",
            false,
            json!(["authenticate"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "AGENT_CANCELLATION_AUTHORIZATION_REQUIRED",
            "cancellation_authorization_required",
            false,
            json!(["authenticate"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "IDEMPOTENCY_KEY_INVALID",
            "idempotency_key_invalid",
            false,
            json!(["reconfigure_workflow"]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "PLUGIN_AGENT_SUCCESSOR_RUNTIME_UNAVAILABLE",
            "successor_runtime_unavailable",
            true,
            json!(["retry", "refresh_executor_discovery"]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "PLUGIN_AGENT_SUCCESSOR_CHECKPOINT_MISMATCH",
            "successor_checkpoint_mismatch",
            false,
            json!(["resume_session", "contact_support"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "PLUGIN_AGENT_EXECUTION_INDETERMINATE",
            "execution_indeterminate",
            false,
            json!(["resume_session", "contact_support"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "PLUGIN_AGENT_ALREADY_TERMINAL",
            "already_terminal",
            false,
            json!([]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "AUTHORIZATION_FAILED",
            "authorization_failed",
            false,
            json!(["contact_support"]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "PLUGIN_AGENT_REQUEST_NOT_FOUND",
            "request_not_found",
            false,
            json!(["reconfigure_workflow", "contact_support"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "PLUGIN_AGENT_PROCESS_ATTEMPT_MISMATCH",
            "cancellation_stale_process",
            false,
            json!(["reconfigure_workflow", "contact_support"]),
        ),
        (
            "loomex_agent_task_resume",
            "agent.resume",
            "AGENT_SUCCESSOR_STATE_CONFLICT",
            "successor_state_conflict",
            false,
            json!(["reconfigure_workflow"]),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            "AGENT_CANCELLATION_STALE_PROCESS",
            "cancellation_stale_process",
            false,
            json!(["contact_support"]),
        ),
    ] {
        let response = call_agent_tool_with_daemon(
            tool,
            method,
            json!({
                "requestId":"agent-1",
                "operationIdempotencyKey":"operation-key-1"
            }),
            json!({
                "ok":false,
                "error":{
                    "code":remote_code,
                    "message":"stderr Bearer secret at /Users/example/.local/bin/agy --token",
                    "retryable":true
                }
            }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(envelope["error"]["code"], public_code);
        assert_eq!(envelope["error"]["retryable"], retryable);
        if remediation.as_array().is_some_and(Vec::is_empty) {
            assert!(envelope["error"].get("remediation").is_none());
        } else {
            assert_eq!(envelope["error"]["remediation"], remediation);
        }
        let encoded = serde_json::to_string(envelope).unwrap();
        for secret in ["Bearer", "/Users/example", "stderr", "--token"] {
            assert!(!encoded.contains(secret), "{tool} leaked {secret}");
        }
    }
}

#[test]
fn malformed_control_timestamps_fail_closed_without_reflection() {
    for (tool, method, result, private) in [
        (
            "loomex_agent_task_resume",
            "agent.resume",
            json!({
                "schemaVersion":"loomex.agent-successor-control/v1",
                "controlState":"queued",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":1,
                "predecessor":{"processAttemptId":"attempt-1","state":"blocked"},
                "successor":{
                    "processAttemptId":"attempt-2",
                    "attemptNumber":2,
                    "mode":"resume_exact_session",
                    "jobId":"job-2",
                    "jobStatus":"queued"
                },
                "authorizationId":"authorization-1",
                "authorizedAt":"2026-99-99T99:99:99Z",
                "replayed":false
            }),
            "2026-99-99",
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            json!({
                "schemaVersion":"loomex.agent-cancellation-control/v1",
                "controlState":"canceling",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":0,
                "processAttemptId":"attempt-1",
                "cancellation":{
                    "id":"cancellation-1",
                    "state":"requested",
                    "deliveryRoute":"runner_job",
                    "requestedAt":"2026-01-01T12:00:00+99:99"
                },
                "job":{"id":"job-1","status":"canceling","leaseVersion":1},
                "localCancellationAuthorized":false,
                "replayed":false
            }),
            "+99:99",
        ),
    ] {
        let response = call_agent_tool_with_daemon(
            tool,
            method,
            json!({
                "requestId":"agent-1",
                "operationIdempotencyKey":"operation-key-1"
            }),
            json!({"ok":true,"result":result}),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(envelope["error"]["code"], "ipc_protocol_error");
        assert!(!serde_json::to_string(envelope).unwrap().contains(private));
    }
}

#[test]
fn malformed_successor_and_cancellation_results_fail_closed_without_leaking() {
    for (tool, method, mut result) in [
        (
            "loomex_agent_task_resume",
            "agent.resume",
            json!({
                "schemaVersion":"loomex.agent-successor-control/v1",
                "controlState":"queued",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":1,
                "predecessor":{"processAttemptId":"attempt-1","state":"blocked"},
                "successor":{
                    "processAttemptId":"attempt-1",
                    "attemptNumber":2,
                    "mode":"resume_exact_session",
                    "jobId":"job-2",
                    "jobStatus":"queued"
                },
                "authorizationId":"authorization-1",
                "authorizedAt":"2026-07-27T10:00:00Z",
                "replayed":false,
                "stderr":"Bearer secret /Users/example"
            }),
        ),
        (
            "loomex_agent_task_cancel",
            "agent.cancel",
            json!({
                "schemaVersion":"loomex.agent-cancellation-control/v1",
                "controlState":"completed",
                "requestId":"agent-1",
                "agentExecutionId":"execution-1",
                "sequence":1,
                "processAttemptId":"attempt-1",
                "cancellation":{
                    "id":"cancellation-1",
                    "state":"completed",
                    "deliveryRoute":"direct",
                    "requestedAt":"2026-07-27T10:00:00Z"
                },
                "job":{"id":"job-1","status":"canceled","leaseVersion":1},
                "localCancellationAuthorized":true,
                "replayed":false,
                "token":"Bearer secret /Users/example"
            }),
        ),
    ] {
        result["rawError"] = json!("stderr Bearer secret /Users/example");
        let response = call_agent_tool_with_daemon(
            tool,
            method,
            json!({
                "requestId":"agent-1",
                "operationIdempotencyKey":"operation-key-1"
            }),
            json!({"ok":true,"result":result}),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(envelope["error"]["code"], "ipc_protocol_error");
        let encoded = serde_json::to_string(envelope).unwrap();
        for secret in ["Bearer", "/Users/example", "stderr", "rawError", "token"] {
            assert!(!encoded.contains(secret), "{tool} leaked {secret}");
        }
    }
}

#[test]
fn provider_not_eligible_receipt_is_preserved_and_redacted() {
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
        assert_eq!(request["method"], "agent.execute");
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":true,
                "result":{
                    "requestId":"agent-403",
                    "idempotencyKey":"idem-agent-403",
                    "executionId":"execution-403",
                    "state":"blocked",
                    "accepted":false,
                    "sequence":2,
                    "provider":"google",
                    "executor":"agy_cli",
                    "modelKey":"gemini-2.5-pro",
                    "providerModelId":"gemini-2.5-pro",
                    "error":{
                        "code":"AGENT_PROVIDER_NOT_ELIGIBLE",
                        "message":"raw 403 body: Bearer provider-token at /Users/private/.config/agy",
                        "retryable":true,
                        "remediation":["verify_provider_access","contact_support"],
                        "raw403Body":"forbidden account payload",
                        "token":"provider-token",
                        "path":"/Users/private/.config/agy",
                        "stderr":"403 forbidden"
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
                "name":"loomex_agent_task_execute",
                "arguments":{
                    "requestId":"agent-403",
                    "idempotencyKey":"idem-agent-403"
                }
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false);
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["error"]["code"], "provider_not_eligible");
    assert_eq!(
        envelope["data"]["error"]["message"],
        "The current provider account is not eligible for this agent execution."
    );
    assert_eq!(envelope["data"]["error"]["retryable"], false);
    assert_eq!(
        envelope["data"]["error"]["remediation"],
        json!(["verify_provider_access", "contact_support"])
    );
    assert_eq!(envelope["data"]["error"].as_object().unwrap().len(), 4);

    let encoded = serde_json::to_string(&response).unwrap();
    for secret in [
        "raw 403 body",
        "provider-token",
        "/Users/private",
        "stderr",
        "forbidden account payload",
    ] {
        assert!(!encoded.contains(secret), "leaked {secret}");
    }
}

#[test]
fn embedded_receipt_dispositions_ignore_daemon_retry_and_remediation_claims() {
    for (remote_code, public_code, remediation) in [
        (
            "AGENT_PROVIDER_NOT_INSTALLED",
            "provider_not_installed",
            json!(["install_executor", "refresh_executor_discovery"]),
        ),
        (
            "AGENT_PROVIDER_NOT_AUTHENTICATED",
            "provider_not_authenticated",
            json!(["authenticate"]),
        ),
        (
            "AGENT_MODEL_NOT_AVAILABLE",
            "model_not_available",
            json!(["select_different_model"]),
        ),
    ] {
        for (tool, method) in [
            ("loomex_agent_task_execute", "agent.execute"),
            ("loomex_agent_task_checkpoint", "agent.checkpoint"),
        ] {
            let response = call_agent_tool_with_daemon(
                tool,
                method,
                json!({
                    "requestId":"agent-model",
                    "idempotencyKey":"idem-agent-model"
                }),
                json!({
                    "ok":true,
                    "result":{
                        "requestId":"agent-model",
                        "idempotencyKey":"idem-agent-model",
                        "state":"blocked",
                        "accepted":false,
                        "sequence":1,
                        "error":{
                            "code":remote_code,
                            "message":"stderr Bearer secret /Users/example/private",
                            "retryable":true,
                            "remediation":["retry","contact_support"],
                            "token":"Bearer secret"
                        }
                    }
                }),
            );
            let envelope = &response["result"]["structuredContent"];
            assert_eq!(
                response["result"]["isError"], false,
                "{tool} {remote_code}: {response}"
            );
            assert_eq!(envelope["data"]["error"]["code"], public_code);
            assert_eq!(envelope["data"]["error"]["retryable"], false);
            assert_eq!(envelope["data"]["error"]["remediation"], remediation);
            let encoded = serde_json::to_string(envelope).unwrap();
            for private in ["stderr", "Bearer", "/Users/example", "\"token\""] {
                assert!(!encoded.contains(private), "{tool} leaked {private}");
            }
        }
    }
}

#[test]
fn provider_not_installed_receipt_preserves_refresh_discovery_remediation() {
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
        assert_eq!(request["method"], "agent.execute");
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":true,
                "result":{
                    "requestId":"agent-missing",
                    "idempotencyKey":"idem-agent-missing",
                    "executionId":"execution-missing",
                    "state":"blocked",
                    "accepted":false,
                    "sequence":2,
                    "provider":"anthropic",
                    "executor":"claude_cli",
                    "modelKey":"anthropic/claude-sonnet-4-6",
                    "providerModelId":"claude-sonnet-4-6",
                    "error":{
                        "code":"AGENT_PROVIDER_NOT_INSTALLED",
                        "message":"raw 403 body: Bearer provider-token; stale executable /Users/private/.local/bin/claude",
                        "retryable":false,
                        "remediation":["install_executor","refresh_executor_discovery"],
                        "raw403Body":"forbidden executable discovery payload",
                        "token":"provider-token",
                        "path":"/Users/private/.local/bin/claude",
                        "stderr":"executable missing",
                        "extra":"private daemon diagnostic"
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
                "name":"loomex_agent_task_execute",
                "arguments":{
                    "requestId":"agent-missing",
                    "idempotencyKey":"idem-agent-missing"
                }
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false);
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["error"]["code"], "provider_not_installed");
    assert_eq!(
        envelope["data"]["error"]["message"],
        "The selected local agent provider is not installed."
    );
    assert_eq!(envelope["data"]["error"]["retryable"], false);
    assert_eq!(
        envelope["data"]["error"]["remediation"],
        json!(["install_executor", "refresh_executor_discovery"])
    );
    assert_eq!(envelope["data"]["error"].as_object().unwrap().len(), 4);

    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "raw 403 body",
        "provider-token",
        "/Users/private",
        "stale executable",
        "stderr",
        "forbidden executable discovery payload",
        "private daemon diagnostic",
    ] {
        assert!(!encoded.contains(private), "leaked {private}");
    }
}

#[test]
fn unsupported_executor_version_receipt_preserves_upgrade_remediation_and_redacts_context() {
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
        assert_eq!(request["method"], "agent.execute");
        writeln!(
            stream,
            "{}",
            json!({
                "protocolVersion":"loomex.local-control/v1",
                "id":request["id"],
                "ok":true,
                "result":{
                    "requestId":"agent-version",
                    "idempotencyKey":"idem-agent-version",
                    "executionId":"execution-version",
                    "state":"blocked",
                    "accepted":false,
                    "sequence":2,
                    "provider":"anthropic",
                    "executor":"claude_cli",
                    "error":{
                        "code":"AGENT_UNSUPPORTED_CAPABILITY",
                        "category":"validation",
                        "message":"raw provider body: Bearer provider-token at /Users/private/.local/bin/claude",
                        "retryable":false,
                        "retry":"user_action_required",
                        "remediation":["upgrade_executor","refresh_executor_discovery"],
                        "context":{
                            "safeDetails":{"reasonCode":"executor_version_unverified"},
                            "token":"provider-token",
                            "path":"/Users/private/.local/bin/claude"
                        },
                        "stderr":"unsupported executor revision",
                        "extra":"private compatibility diagnostic"
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
                "name":"loomex_agent_task_execute",
                "arguments":{
                    "requestId":"agent-version",
                    "idempotencyKey":"idem-agent-version"
                }
            }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    daemon.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false);
    let envelope = &response["result"]["structuredContent"];
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["error"]["code"], "unsupported_capability");
    assert_eq!(
        envelope["data"]["error"]["message"],
        "The selected local agent does not support a required capability."
    );
    assert_eq!(envelope["data"]["error"]["retryable"], false);
    assert_eq!(
        envelope["data"]["error"]["remediation"],
        json!(["upgrade_executor", "refresh_executor_discovery"])
    );
    assert_eq!(envelope["data"]["error"].as_object().unwrap().len(), 4);

    let encoded = serde_json::to_string(&response).unwrap();
    for private in [
        "raw provider body",
        "provider-token",
        "/Users/private",
        "safeDetails",
        "reasonCode",
        "executor_version_unverified",
        "stderr",
        "private compatibility diagnostic",
    ] {
        assert!(!encoded.contains(private), "leaked {private}");
    }
}

#[test]
fn agent_model_identity_pair_is_enforced_before_crossing_mcp() {
    let receipt = |model_key: Option<Value>, provider_model_id: Option<Value>| {
        let mut result = json!({
            "requestId":"agent-model",
            "idempotencyKey":"idem-agent-model",
            "executionId":"execution-model",
            "state":"queued",
            "accepted":true,
            "sequence":1,
            "provider":"open_ai",
            "executor":"codex_cli"
        });
        if let Some(model_key) = model_key {
            result["modelKey"] = model_key;
        }
        if let Some(provider_model_id) = provider_model_id {
            result["providerModelId"] = provider_model_id;
        }
        result
    };

    let valid = call_agent_execute_with_result(receipt(
        Some(json!("vendor/_model")),
        Some(json!("vendor/.hidden")),
    ));
    assert_eq!(valid["result"]["isError"], false);
    assert_eq!(
        valid["result"]["structuredContent"]["data"]["modelKey"],
        "vendor/_model"
    );
    assert_eq!(
        valid["result"]["structuredContent"]["data"]["providerModelId"],
        "vendor/.hidden"
    );

    let multibyte_over_192_bytes = "é".repeat(97);
    for (result, private_values) in [
        (
            receipt(Some(json!("private-model-only")), None),
            vec!["private-model-only".to_string()],
        ),
        (
            receipt(None, Some(json!("private-provider-only"))),
            vec!["private-provider-only".to_string()],
        ),
        (
            receipt(
                Some(json!(multibyte_over_192_bytes.clone())),
                Some(json!("gpt-5.2")),
            ),
            vec![multibyte_over_192_bytes],
        ),
        (
            receipt(
                Some(json!("openai/gpt-5.2")),
                Some(json!("gpt 5.2\n--private-flag")),
            ),
            vec!["gpt 5.2".to_string(), "private-flag".to_string()],
        ),
        (
            receipt(Some(json!("vendor//x")), Some(json!("gpt-5.2"))),
            vec!["vendor//x".to_string()],
        ),
        (
            receipt(Some(json!("vendor/.")), Some(json!("gpt-5.2"))),
            vec!["vendor/.".to_string()],
        ),
        (
            receipt(Some(json!("vendor/..")), Some(json!("gpt-5.2"))),
            vec!["vendor/..".to_string()],
        ),
        (
            receipt(Some(json!("-vendor/model")), Some(json!("gpt-5.2"))),
            vec!["-vendor/model".to_string()],
        ),
    ] {
        let response = call_agent_execute_with_result(result);
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "ipc_protocol_error"
        );
        assert_eq!(
            response["result"]["structuredContent"]["error"]["message"],
            "The local Loomex runner returned an invalid agent-runtime response."
        );
        let encoded = serde_json::to_string(&response).unwrap();
        for private in private_values {
            assert!(!encoded.contains(&private), "leaked {private}");
        }
    }
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
