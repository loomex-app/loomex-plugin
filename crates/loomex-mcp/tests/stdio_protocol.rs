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
    assert_eq!(response(2)["result"]["tools"].as_array().unwrap().len(), 33);
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
