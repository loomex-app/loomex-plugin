use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{redaction::Redactor, CoreError, CoreResult};

const DEFAULT_MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const SENSITIVE_KEY_PARTS: &[&str] = &[
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp_epoch_ms: u64,
    pub level: String,
    pub event_type: String,
    pub message: String,
    pub correlation_id: String,
    pub workflow_run_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub metadata: Value,
}

impl LogEntry {
    pub fn new(
        level: impl Into<String>,
        event_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_epoch_ms: now_epoch_ms(),
            level: level.into(),
            event_type: event_type.into(),
            message: message.into(),
            correlation_id: String::new(),
            workflow_run_id: None,
            tool_call_id: None,
            metadata: Value::Object(Default::default()),
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = correlation_id.into();
        self
    }

    pub fn with_workflow_run_id(mut self, workflow_run_id: impl Into<String>) -> Self {
        self.workflow_run_id = Some(workflow_run_id.into());
        self
    }

    pub fn with_tool_call_id(mut self, tool_call_id: impl Into<String>) -> Self {
        self.tool_call_id = Some(tool_call_id.into());
        self
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

pub trait LogSink {
    fn append(&self, entry: LogEntry);
}

#[derive(Debug, Default, Clone)]
pub struct MemoryLogSink {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl MemoryLogSink {
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().expect("memory log poisoned").clone()
    }
}

impl LogSink for MemoryLogSink {
    fn append(&self, entry: LogEntry) {
        self.entries
            .lock()
            .expect("memory log poisoned")
            .push(entry);
    }
}

#[derive(Debug, Clone)]
pub struct FileLogSink {
    path: PathBuf,
    max_bytes: u64,
    redactor: Redactor,
    lock: Arc<Mutex<()>>,
}

impl FileLogSink {
    pub fn new(path: impl Into<PathBuf>, redactor: Redactor) -> Self {
        Self {
            path: path.into(),
            max_bytes: DEFAULT_MAX_LOG_BYTES,
            redactor,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes.max(256);
        self
    }

    pub fn append_result(&self, entry: LogEntry) -> CoreResult<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| CoreError::new("LOCAL_LOG_LOCK_POISONED", "local log lock is poisoned"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                CoreError::new(
                    "LOCAL_LOG_OPEN_FAILED",
                    format!("failed to create log directory: {err}"),
                )
            })?;
        }
        let line = self.redacted_json_line(entry)?;
        self.rotate_if_needed(line.len() as u64)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| {
                CoreError::new(
                    "LOCAL_LOG_OPEN_FAILED",
                    format!("failed to open log file: {err}"),
                )
            })?;
        file.write_all(line.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|err| {
                CoreError::new(
                    "LOCAL_LOG_WRITE_FAILED",
                    format!("failed to write log entry: {err}"),
                )
            })?;
        Ok(())
    }

    fn redacted_json_line(&self, entry: LogEntry) -> CoreResult<String> {
        let mut value = serde_json::to_value(entry).map_err(|err| {
            CoreError::new(
                "LOCAL_LOG_SERIALIZE_FAILED",
                format!("failed to serialize log entry: {err}"),
            )
        })?;
        redact_json_value(&mut value, &self.redactor);
        serde_json::to_string(&value).map_err(|err| {
            CoreError::new(
                "LOCAL_LOG_SERIALIZE_FAILED",
                format!("failed to serialize log entry: {err}"),
            )
        })
    }

    fn rotate_if_needed(&self, incoming_bytes: u64) -> CoreResult<()> {
        let current_size = fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current_size + incoming_bytes < self.max_bytes {
            return Ok(());
        }
        let rotated = rotated_path(&self.path);
        if rotated.exists() {
            fs::remove_file(&rotated).map_err(|err| {
                CoreError::new(
                    "LOCAL_LOG_ROTATE_FAILED",
                    format!("failed to remove old log: {err}"),
                )
            })?;
        }
        if self.path.exists() {
            fs::rename(&self.path, rotated).map_err(|err| {
                CoreError::new(
                    "LOCAL_LOG_ROTATE_FAILED",
                    format!("failed to rotate log: {err}"),
                )
            })?;
        }
        Ok(())
    }
}

impl LogSink for FileLogSink {
    fn append(&self, entry: LogEntry) {
        let _ = self.append_result(entry);
    }
}

pub fn read_recent_log_entries(path: impl AsRef<Path>, limit: usize) -> CoreResult<Vec<LogEntry>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|err| {
        CoreError::new(
            "LOCAL_LOG_READ_FAILED",
            format!("failed to open log file: {err}"),
        )
    })?;
    let mut entries = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|err| {
            CoreError::new(
                "LOCAL_LOG_READ_FAILED",
                format!("failed to read log line: {err}"),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<LogEntry>(&line).map_err(|err| {
            CoreError::new(
                "LOCAL_LOG_PARSE_FAILED",
                format!("failed to parse structured log line: {err}"),
            )
        })?;
        entries.push(entry);
    }
    let limit = limit.max(1);
    if entries.len() > limit {
        Ok(entries.split_off(entries.len() - limit))
    } else {
        Ok(entries)
    }
}

/// Redact an entry immediately before it crosses a local API boundary.
///
/// FileLogSink already redacts new records before persistence. This second pass is intentional:
/// older files and manually modified JSONL must not be trusted merely because they deserialize as
/// a `LogEntry`.
pub fn redact_log_entry_for_local_output(mut entry: LogEntry) -> LogEntry {
    entry.level = redact_untrusted_text(&entry.level);
    entry.event_type = redact_untrusted_text(&entry.event_type);
    entry.message = redact_untrusted_text(&entry.message);
    entry.correlation_id = redact_untrusted_text(&entry.correlation_id);
    entry.workflow_run_id = entry
        .workflow_run_id
        .map(|value| redact_untrusted_text(&value));
    entry.tool_call_id = entry
        .tool_call_id
        .map(|value| redact_untrusted_text(&value));
    redact_untrusted_json_value(&mut entry.metadata);
    entry
}

fn redact_untrusted_json_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_untrusted_text(text),
        Value::Array(items) => {
            for item in items {
                redact_untrusted_json_value(item);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *item = Value::String("[REDACTED]".to_string());
                } else {
                    redact_untrusted_json_value(item);
                }
            }
        }
        _ => {}
    }
}

fn redact_untrusted_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if lower.contains("bearer ")
        || SENSITIVE_KEY_PARTS.iter().any(|key| {
            compact.contains(&format!("{key}="))
                || compact.contains(&format!("{key}:"))
                || compact.contains(&format!("\"{key}\":"))
                || compact.contains(&format!("'{key}':"))
        })
    {
        "[REDACTED]".to_string()
    } else {
        Redactor::new(Vec::new()).redact(input)
    }
}

fn redact_json_value(value: &mut Value, redactor: &Redactor) {
    match value {
        Value::String(text) => {
            *text = redactor.redact(text);
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, redactor);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *item = Value::String("[REDACTED]".to_string());
                } else {
                    redact_json_value(item, redactor);
                }
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| normalized.contains(part))
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(".1");
    PathBuf::from(rotated)
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn memory_sink_records_structured_log_entry() {
        let sink = MemoryLogSink::default();

        sink.append(
            LogEntry::new("info", "runner.connected", "connected").with_correlation_id("run_123"),
        );

        let entries = sink.entries();
        assert_eq!(1, entries.len());
        assert_eq!("runner.connected", entries[0].event_type);
        assert_eq!("run_123", entries[0].correlation_id);
    }

    #[test]
    fn file_sink_writes_redacted_jsonl_and_reads_recent_entries() {
        let path = test_log_path("redacted");
        let _ = fs::remove_file(&path);
        let sink = FileLogSink::new(&path, Redactor::new(vec!["secret_value".to_string()]));

        sink.append_result(
            LogEntry::new("info", "local_tool.started", "Authorization: secret_value")
                .with_correlation_id("run_123")
                .with_metadata(json!({
                    "token": "secret_value",
                    "safe": "visible",
                    "headers": {"Authorization": "Bearer secret_value"}
                })),
        )
        .expect("write log");

        let raw = fs::read_to_string(&path).expect("read log file");
        assert!(raw.contains("visible"));
        assert!(raw.contains("[REDACTED]"));
        assert!(!raw.contains("secret_value"));
        let entries = read_recent_log_entries(&path, 10).expect("read recent");
        assert_eq!(1, entries.len());
        assert_eq!("run_123", entries[0].correlation_id);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_sink_rotates_when_size_limit_is_reached() {
        let path = test_log_path("rotate");
        let rotated = rotated_path(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&rotated);
        let sink = FileLogSink::new(&path, Redactor::new(Vec::new())).with_max_bytes(256);

        for index in 0..6 {
            sink.append_result(
                LogEntry::new("info", "local_tool.stdout", format!("line-{index}"))
                    .with_metadata(json!({"padding": "x".repeat(90)})),
            )
            .expect("write log");
        }

        assert!(path.exists());
        assert!(rotated.exists());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&rotated);
    }

    #[test]
    fn local_output_redacts_legacy_or_tampered_parsed_entries() {
        let entry = LogEntry::new(
            "info",
            "legacy.record",
            "Authorization: Bearer leaked-management-token",
        )
        .with_correlation_id("token=leaked-correlation-token")
        .with_metadata(json!({
            "safe": "visible",
            "nested": {
                "api-key": "leaked-api-key",
                "detail": "password: leaked-password"
            }
        }));

        let redacted = redact_log_entry_for_local_output(entry);

        let serialized = serde_json::to_string(&redacted).expect("serialize redacted entry");
        assert!(serialized.contains("visible"));
        assert!(!serialized.contains("leaked-"));
        assert_eq!(redacted.message, "[REDACTED]");
        assert_eq!(redacted.metadata["nested"]["api-key"], "[REDACTED]");
    }

    fn test_log_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "loomex-core-{name}-{}-{}.jsonl",
            std::process::id(),
            now_epoch_ms()
        ))
    }
}
