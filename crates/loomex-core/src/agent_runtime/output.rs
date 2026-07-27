use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAgentOutput {
    pub provider_session_id: Option<String>,
    pub text: String,
    pub structured: Option<Value>,
    pub machine_readable: bool,
}

pub fn parse_agent_output(stdout: &str) -> Result<ParsedAgentOutput, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("agent returned no output".to_string());
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return parse_value(&value, true)
            .filter(|parsed| !parsed.text.trim().is_empty())
            .ok_or_else(|| "JSON output contained no result".to_string());
    }

    let mut session_id = None;
    let mut last_text = None;
    let mut last_structured = None;
    let mut parsed_any = false;
    for line in trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        parsed_any = true;
        if let Some(parsed) = parse_value(&value, false) {
            session_id = parsed.provider_session_id.or(session_id);
            if !parsed.text.trim().is_empty() {
                last_text = Some(parsed.text);
            }
            if parsed.structured.is_some() {
                last_structured = parsed.structured;
            }
        }
    }
    if parsed_any {
        if let Some(text) = last_text {
            return Ok(ParsedAgentOutput {
                provider_session_id: session_id,
                text,
                structured: last_structured,
                machine_readable: true,
            });
        }
        return Err("JSONL output contained no final agent message".to_string());
    }

    Ok(ParsedAgentOutput {
        provider_session_id: None,
        text: trimmed.to_string(),
        structured: serde_json::from_str(trimmed).ok(),
        machine_readable: false,
    })
}

pub(crate) fn parse_agent_event(line: &str) -> Option<ParsedAgentOutput> {
    let value = serde_json::from_str::<Value>(line.trim()).ok()?;
    parse_value(&value, false)
}

fn parse_value(value: &Value, treat_plain_json_as_result: bool) -> Option<ParsedAgentOutput> {
    let session_id = find_string(
        value,
        &[
            "session_id",
            "sessionId",
            "thread_id",
            "threadId",
            "conversation_id",
            "conversationId",
        ],
    );

    let structured = value
        .get("structured_output")
        .or_else(|| value.get("structuredOutput"))
        .or_else(|| value.get("output").filter(|output| !output.is_string()))
        .cloned();

    let text = value
        .get("result")
        .and_then(Value::as_str)
        .or_else(|| value.get("text").and_then(Value::as_str))
        .or_else(|| value.get("content").and_then(Value::as_str))
        .or_else(|| {
            value
                .get("item")
                .and_then(|item| item.get("text"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
        })
        .map(str::to_string)
        .or_else(|| structured.as_ref().map(Value::to_string))
        .or_else(|| treat_plain_json_as_result.then(|| value.to_string()));

    if text.is_none() && session_id.is_none() {
        return None;
    }
    let text = text.unwrap_or_default();

    let structured = structured.or_else(|| {
        if treat_plain_json_as_result && value.is_object() && !looks_like_wrapper(value) {
            Some(value.clone())
        } else {
            serde_json::from_str::<Value>(&text).ok()
        }
    });

    Some(ParsedAgentOutput {
        provider_session_id: session_id,
        text,
        structured,
        machine_readable: true,
    })
}

fn find_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(key).and_then(Value::as_str) {
            return Some(found.to_string());
        }
    }
    for nested in ["item", "message", "metadata", "response"] {
        if let Some(found) = value.get(nested).and_then(|value| find_string(value, keys)) {
            return Some(found);
        }
    }
    None
}

fn looks_like_wrapper(value: &Value) -> bool {
    [
        "type",
        "result",
        "session_id",
        "sessionId",
        "thread_id",
        "threadId",
        "conversation_id",
        "conversationId",
        "usage",
    ]
    .iter()
    .any(|key| value.get(key).is_some())
}
