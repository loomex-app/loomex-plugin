use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CoreError, CoreResult};

const RUNNER_AUTH_EXCHANGE_PATH: &str = "/runner-control/runner/v1/auth/exchange/";
const RUNNER_AUTH_BOOTSTRAP_PATH: &str = "/runner-control/runner/v1/auth/bootstrap/";
const RUNNER_TOKEN_NON_EXPIRING_EXPIRES_AT: &str = "9999-12-31T23:59:59Z";

const MANAGEMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MANAGEMENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MANAGEMENT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MANAGEMENT_RETRY_BUDGET: u8 = 2;
const MANAGEMENT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const MANAGEMENT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
struct ManagementMetrics {
    timeout: AtomicU64,
    oversize: AtomicU64,
    breaker_open: AtomicU64,
    breaker_rejected: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagementClientMetricsSnapshot {
    pub timeout: u64,
    pub oversize: u64,
    pub breaker_open: u64,
    pub breaker_rejected: u64,
}

static MANAGEMENT_METRICS: OnceLock<ManagementMetrics> = OnceLock::new();
static MANAGEMENT_BREAKER: OnceLock<Mutex<(u32, Option<Instant>)>> = OnceLock::new();

fn management_metrics() -> &'static ManagementMetrics {
    MANAGEMENT_METRICS.get_or_init(ManagementMetrics::default)
}

pub fn management_client_metrics() -> ManagementClientMetricsSnapshot {
    let metrics = management_metrics();
    ManagementClientMetricsSnapshot {
        timeout: metrics.timeout.load(Ordering::Relaxed),
        oversize: metrics.oversize.load(Ordering::Relaxed),
        breaker_open: metrics.breaker_open.load(Ordering::Relaxed),
        breaker_rejected: metrics.breaker_rejected.load(Ordering::Relaxed),
    }
}

pub fn user_credential_profile(profile: &str) -> String {
    format!("{profile}.user")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLoginStartRequest {
    pub client_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLoginChallenge {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in_seconds: u64,
    pub interval_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyExchangeResult {
    pub token: AuthTokenResponse,
    pub organization_id: Option<String>,
    pub runner_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLoginResult {
    pub token: String,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceLoginOrRegisterResult {
    Authenticated(WorkspaceLoginResult),
    RegistrationChallenge(WorkspaceRegistrationChallenge),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePasswordResetResult {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRegistrationChallenge {
    pub challenge_id: String,
    pub email: String,
    pub status: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub resend_available_at: Option<String>,
    #[serde(default)]
    pub reused: bool,
}

impl ApiKeyExchangeResult {
    pub fn from_token(token: AuthTokenResponse) -> Self {
        Self {
            token,
            organization_id: None,
            runner_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub slug: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runner {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub runner_version: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerUpsertRequest {
    pub organization_id: String,
    pub display_name: String,
    pub machine_fingerprint_hash: String,
    pub os: String,
    pub arch: String,
    pub runner_version: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRunStartRequest {
    pub organization_id: String,
    pub workflow_id: String,
    pub inputs: Value,
    #[serde(skip_serializing_if = "Option::is_none", rename = "workspacePath")]
    pub workspace_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "idempotencyKey")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRunStartResponse {
    pub id: String,
    pub status: String,
    #[serde(default, rename = "uiUrl", alias = "ui_url")]
    pub ui_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowBuilderStartRequest {
    pub prompt: String,
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "workspacePath")]
    pub workspace_path: Option<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanRequestSummary {
    pub id: String,
    pub status: String,
    pub title: String,
    #[serde(default)]
    pub execution: Option<HumanRequestExecution>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub blocking: bool,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerWorkflowSummary {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, rename = "activeVersionId", alias = "active_version_id")]
    pub active_version_id: Option<String>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerWorkflowExecutionResponse {
    pub execution: Value,
    #[serde(default, rename = "humanRequest", alias = "human_request")]
    pub human_request: Option<Value>,
    #[serde(default)]
    pub runner: Option<Value>,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default, rename = "aiTrace", alias = "ai_trace")]
    pub ai_trace: Option<Value>,
    #[serde(default, rename = "latestSequence", alias = "latest_sequence")]
    pub latest_sequence: u64,
    #[serde(default, rename = "timedOut", alias = "timed_out")]
    pub timed_out: bool,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerWorkflowExecutionListResponse {
    #[serde(default)]
    pub executions: Vec<Value>,
    #[serde(default, rename = "nextCursor", alias = "next_cursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunnerWorkflowExecutionStartOptions<'a> {
    pub workflow_id: &'a str,
    pub inputs: Value,
    pub workspace_path: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub version: Option<&'a str>,
    pub execution_mode: Option<&'a str>,
    pub idempotency_key: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerHumanRequestListQuery<'a> {
    pub workflow_id: &'a str,
    pub execution_id: Option<&'a str>,
    pub request_type: Option<&'a str>,
    pub status: Option<&'a str>,
    pub cursor: Option<&'a str>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerWorkflowInputSchemaResponse {
    #[serde(default)]
    pub workflow: Option<Value>,
    #[serde(default, rename = "inputSchema", alias = "input_schema")]
    pub input_schema: Option<Value>,
    #[serde(default, rename = "activeVersion", alias = "active_version")]
    pub active_version: Option<Value>,
    #[serde(default, rename = "selectedVersion", alias = "selected_version")]
    pub selected_version: Option<Value>,
    #[serde(default)]
    pub versions: Vec<Value>,
    #[serde(default, rename = "firstHumanInput", alias = "first_human_input")]
    pub first_human_input: Option<Value>,
    #[serde(default)]
    pub nodes: Vec<Value>,
    #[serde(default)]
    pub capabilities: serde_json::Map<String, Value>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerSessionResponse {
    pub runner: Value,
    pub session: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerJobResponse {
    pub job: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerJobEventCreateResponse {
    #[serde(default)]
    pub events: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanRequestExecution {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HumanRequestResolveResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "requestStatus")]
    pub request_status: String,
    #[serde(default, rename = "executionId")]
    pub execution_id: Option<String>,
    #[serde(default, rename = "executionStatus")]
    pub execution_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RunnerWorkflowListResponse {
    workflows: Vec<RunnerWorkflowSummary>,
}

fn runner_workflow_execution_mode(workflow: &RunnerWorkflowSummary) -> String {
    let raw = workflow
        .extra
        .get("executionMode")
        .or_else(|| workflow.extra.get("execution_mode"))
        .and_then(Value::as_str)
        .unwrap_or("app")
        .trim();
    match raw {
        "local" | "local_runner" | "runner" => "app".to_string(),
        "server" | "app" | "plugin" => raw.to_string(),
        _ => "app".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerHumanRequestListResponse {
    #[serde(default)]
    pub human_requests: Vec<HumanRequestSummary>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RunnerWorkflowExecutionStartRequest {
    inputs: Value,
    #[serde(skip_serializing_if = "Option::is_none", rename = "workspacePath")]
    workspace_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "sessionId")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "executionMode")]
    execution_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerAuthExchangeData {
    runner: RunnerAuthRunner,
    runner_token: String,
    token_type: String,
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceLoginData {
    token: String,
    #[serde(default)]
    organization: Option<WorkspaceOrganizationData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceRegistrationData {
    challenge_id: String,
    email: String,
    status: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    resend_available_at: Option<String>,
    #[serde(default)]
    reused: bool,
}

#[derive(Debug, Deserialize)]
struct WorkspacePasswordResetData {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceOrganizationData {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerAuthRunner {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerSelfData {
    runner: RunnerSelfRunner,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerSelfRunner {
    id: String,
    organization_id: String,
    status: String,
    #[serde(default)]
    capabilities: Value,
}

impl RunnerSelfRunner {
    fn into_runner(self) -> Runner {
        let runner_version = self
            .capabilities
            .get("runnerVersion")
            .and_then(Value::as_str)
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string();
        let protocol_version = self
            .capabilities
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(crate::protocol::PROTOCOL_VERSION)
            .to_string();
        let capabilities = match self.capabilities {
            Value::Array(values) => values
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect(),
            Value::Object(values) => values
                .into_iter()
                .filter_map(|(name, enabled)| (enabled == Value::Bool(true)).then_some(name))
                .collect(),
            _ => Vec::new(),
        };
        Runner {
            id: self.id,
            organization_id: self.organization_id,
            status: self.status,
            runner_version,
            protocol_version,
            capabilities,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientWorkflowDetailResponse {
    #[serde(default, rename = "activeVersion")]
    active_version: Option<ClientWorkflowVersion>,
}

#[derive(Debug, Deserialize)]
struct ClientWorkflowVersion {
    #[serde(default)]
    definition: Value,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ManagementCredential {
    pub profile: String,
    pub organization_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: String,
    pub storage_backend: CredentialStorageBackend,
    pub storage_warning: Option<String>,
    pub kind: CredentialKind,
}

impl std::fmt::Debug for ManagementCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementCredential")
            .field("profile", &self.profile)
            .field("organization_id", &self.organization_id)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .field("storage_backend", &self.storage_backend)
            .field("storage_warning", &self.storage_warning)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialStorageBackend {
    MacOsKeychain,
    LocalFileFallback,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialKind {
    #[default]
    LegacyUnknown,
    User,
    RunnerControlV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStorageOutcome {
    pub backend: CredentialStorageBackend,
    pub warning: Option<String>,
}

impl CredentialStorageOutcome {
    pub fn for_backend(backend: CredentialStorageBackend) -> Self {
        Self {
            backend,
            warning: storage_warning_for_backend(backend),
        }
    }
}

impl ManagementCredential {
    pub fn from_token_response(
        profile: impl Into<String>,
        organization_id: impl Into<String>,
        token: AuthTokenResponse,
        storage_backend: CredentialStorageBackend,
    ) -> CoreResult<Self> {
        validate_auth_token(&token)?;
        let storage_warning = storage_warning_for_backend(storage_backend);
        Ok(Self {
            profile: profile.into(),
            organization_id: organization_id.into(),
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            token_type: token.token_type,
            expires_at: token.expires_at,
            storage_backend,
            storage_warning,
            kind: CredentialKind::LegacyUnknown,
        })
    }

    pub fn from_user_token_response(
        profile: impl Into<String>,
        organization_id: impl Into<String>,
        token: AuthTokenResponse,
        storage_backend: CredentialStorageBackend,
    ) -> CoreResult<Self> {
        let mut credential =
            Self::from_token_response(profile, organization_id, token, storage_backend)?;
        credential.kind = CredentialKind::User;
        Ok(credential)
    }

    pub fn from_runner_token_response(
        profile: impl Into<String>,
        organization_id: impl Into<String>,
        token: AuthTokenResponse,
        storage_backend: CredentialStorageBackend,
    ) -> CoreResult<Self> {
        let mut credential =
            Self::from_token_response(profile, organization_id, token, storage_backend)?;
        credential.kind = CredentialKind::RunnerControlV1;
        Ok(credential)
    }

    pub fn validate_not_expiring(
        &self,
        now_epoch_seconds: u64,
        clock_skew_seconds: u64,
    ) -> CoreResult<()> {
        let expires_at = parse_rfc3339_utc_epoch_seconds(&self.expires_at)?;
        if expires_at <= now_epoch_seconds.saturating_add(clock_skew_seconds) {
            return Err(CoreError::new(
                "AUTH_TOKEN_EXPIRED",
                "management token is expired or too close to expiry; refresh endpoint is not available in the current management API contract",
            ));
        }
        Ok(())
    }
}

fn storage_warning_for_backend(backend: CredentialStorageBackend) -> Option<String> {
    match backend {
        CredentialStorageBackend::MacOsKeychain => None,
        CredentialStorageBackend::LocalFileFallback => Some(
            "secure OS credential storage unavailable; token stored in restricted local fallback"
                .to_string(),
        ),
    }
}

fn validate_auth_token(token: &AuthTokenResponse) -> CoreResult<()> {
    if token.access_token.trim().is_empty() {
        return Err(CoreError::new(
            "AUTH_TOKEN_INVALID",
            "access_token is required",
        ));
    }
    if token.token_type != "Bearer" {
        return Err(CoreError::new(
            "AUTH_TOKEN_INVALID",
            "token_type must be Bearer",
        ));
    }
    if token.expires_at.trim().is_empty() {
        return Err(CoreError::new(
            "AUTH_TOKEN_INVALID",
            "expires_at is required",
        ));
    }
    Ok(())
}

pub trait CredentialStore {
    fn save(&self, credential: &ManagementCredential) -> CoreResult<CredentialStorageOutcome>;
    fn load(&self, profile: &str) -> CoreResult<Option<ManagementCredential>>;
    fn delete(&self, profile: &str) -> CoreResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCredentialStore {
    root_dir: PathBuf,
}

impl LocalCredentialStore {
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    fn path_for_profile(&self, profile: &str) -> CoreResult<PathBuf> {
        if profile.trim().is_empty() || profile.contains('/') || profile.contains('\\') {
            return Err(CoreError::new("CREDENTIAL_PROFILE_INVALID", profile));
        }
        Ok(self.root_dir.join(format!("{profile}.json")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCredentialStore {
    keychain: Option<MacOsKeychainCredentialStore>,
    fallback: LocalCredentialStore,
}

impl SystemCredentialStore {
    pub fn new(fallback_root_dir: PathBuf) -> Self {
        Self {
            keychain: MacOsKeychainCredentialStore::available(),
            fallback: LocalCredentialStore::new(fallback_root_dir),
        }
    }

    pub fn storage_backend(&self) -> CredentialStorageBackend {
        if self.keychain.is_some() {
            CredentialStorageBackend::MacOsKeychain
        } else {
            CredentialStorageBackend::LocalFileFallback
        }
    }
}

impl CredentialStore for SystemCredentialStore {
    fn save(&self, credential: &ManagementCredential) -> CoreResult<CredentialStorageOutcome> {
        if let Some(keychain) = &self.keychain {
            let mut keychain_credential = credential.clone();
            keychain_credential.storage_backend = CredentialStorageBackend::MacOsKeychain;
            keychain_credential.storage_warning = None;
            if let Ok(outcome) = keychain.save(&keychain_credential) {
                let _ = self.fallback.delete(&credential.profile);
                return Ok(outcome);
            }
        }
        let mut fallback_credential = credential.clone();
        fallback_credential.storage_backend = CredentialStorageBackend::LocalFileFallback;
        fallback_credential.storage_warning =
            storage_warning_for_backend(CredentialStorageBackend::LocalFileFallback);
        self.fallback.save(&fallback_credential)
    }

    fn load(&self, profile: &str) -> CoreResult<Option<ManagementCredential>> {
        if let Some(keychain) = &self.keychain {
            match keychain.load(profile) {
                Ok(Some(credential)) => return Ok(Some(credential)),
                Ok(None) => {}
                Err(_) => {}
            }
        }
        self.fallback.load(profile)
    }

    fn delete(&self, profile: &str) -> CoreResult<()> {
        if let Some(keychain) = &self.keychain {
            let _ = keychain.delete(profile);
        }
        self.fallback.delete(profile)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacOsKeychainCredentialStore {
    service: String,
}

impl MacOsKeychainCredentialStore {
    fn available() -> Option<Self> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let Ok(output) = Command::new("security").arg("help").output() else {
            return None;
        };
        if !output.status.success() {
            return None;
        }
        Some(Self {
            service: "app.loomex.cli.management".to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalCredentialDocument {
    schema_version: String,
    profile: String,
    organization_id: String,
    access_token_b64: String,
    refresh_token_b64: Option<String>,
    token_type: String,
    expires_at: String,
    storage_backend: CredentialStorageBackend,
    #[serde(default)]
    kind: CredentialKind,
}

fn credential_to_document(credential: &ManagementCredential) -> LocalCredentialDocument {
    LocalCredentialDocument {
        schema_version: "loomex.cli.credential/v2".to_string(),
        profile: credential.profile.clone(),
        organization_id: credential.organization_id.clone(),
        access_token_b64: BASE64.encode(credential.access_token.as_bytes()),
        refresh_token_b64: credential
            .refresh_token
            .as_ref()
            .map(|value| BASE64.encode(value.as_bytes())),
        token_type: credential.token_type.clone(),
        expires_at: credential.expires_at.clone(),
        storage_backend: credential.storage_backend,
        kind: credential.kind,
    }
}

fn credential_from_document(document: LocalCredentialDocument) -> CoreResult<ManagementCredential> {
    let access_token = decode_secret(&document.access_token_b64)?;
    let refresh_token = document
        .refresh_token_b64
        .as_deref()
        .map(decode_secret)
        .transpose()?;
    Ok(ManagementCredential {
        profile: document.profile,
        organization_id: document.organization_id,
        access_token,
        refresh_token,
        token_type: document.token_type,
        expires_at: document.expires_at,
        storage_backend: document.storage_backend,
        storage_warning: storage_warning_for_backend(document.storage_backend),
        kind: document.kind,
    })
}

impl CredentialStore for LocalCredentialStore {
    fn save(&self, credential: &ManagementCredential) -> CoreResult<CredentialStorageOutcome> {
        fs::create_dir_all(&self.root_dir)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        set_private_dir_permissions(&self.root_dir)?;
        let document = credential_to_document(credential);
        let payload = serde_json::to_vec_pretty(&document)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        let path = self.path_for_profile(&credential.profile)?;
        let temp_path = path.with_extension("json.tmp");
        fs::write(&temp_path, payload)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        set_private_file_permissions(&temp_path)?;
        fs::rename(&temp_path, &path)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        Ok(CredentialStorageOutcome::for_backend(
            credential.storage_backend,
        ))
    }

    fn load(&self, profile: &str) -> CoreResult<Option<ManagementCredential>> {
        let path = self.path_for_profile(profile)?;
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read(&path)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_READ_FAILED", err.to_string()))?;
        let document: LocalCredentialDocument = serde_json::from_slice(&content)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_PARSE_FAILED", err.to_string()))?;
        credential_from_document(document).map(Some)
    }

    fn delete(&self, profile: &str) -> CoreResult<()> {
        let path = self.path_for_profile(profile)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(CoreError::new(
                "CREDENTIAL_STORE_DELETE_FAILED",
                err.to_string(),
            )),
        }
    }
}

impl CredentialStore for MacOsKeychainCredentialStore {
    fn save(&self, credential: &ManagementCredential) -> CoreResult<CredentialStorageOutcome> {
        let document = credential_to_document(credential);
        let payload = serde_json::to_string(&document)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                &self.service,
                "-a",
                &credential.profile,
                "-w",
                &payload,
            ])
            .output()
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))?;
        if output.status.success() {
            Ok(CredentialStorageOutcome::for_backend(
                CredentialStorageBackend::MacOsKeychain,
            ))
        } else {
            Err(CoreError::new(
                "CREDENTIAL_STORE_WRITE_FAILED",
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }

    fn load(&self, profile: &str) -> CoreResult<Option<ManagementCredential>> {
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                &self.service,
                "-a",
                profile,
                "-w",
            ])
            .output()
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_READ_FAILED", err.to_string()))?;
        if !output.status.success() {
            return Ok(None);
        }
        let document: LocalCredentialDocument = serde_json::from_slice(&output.stdout)
            .map_err(|err| CoreError::new("CREDENTIAL_STORE_PARSE_FAILED", err.to_string()))?;
        credential_from_document(document).map(Some)
    }

    fn delete(&self, profile: &str) -> CoreResult<()> {
        let _ = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                &self.service,
                "-a",
                profile,
            ])
            .output();
        Ok(())
    }
}

fn decode_secret(value: &str) -> CoreResult<String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|err| CoreError::new("CREDENTIAL_STORE_PARSE_FAILED", err.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|err| CoreError::new("CREDENTIAL_STORE_PARSE_FAILED", err.to_string()))
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| CoreError::new("CREDENTIAL_STORE_WRITE_FAILED", err.to_string()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

pub trait ManagementApiClient {
    fn start_device_login(&mut self) -> CoreResult<DeviceLoginChallenge>;
    fn poll_device_token(&mut self, device_code: &str) -> CoreResult<Option<AuthTokenResponse>>;
    fn exchange_api_key(
        &mut self,
        api_key: &str,
        api_secret: &str,
        organization_id: &str,
    ) -> CoreResult<ApiKeyExchangeResult>;
    fn login_workspace(&mut self, email: &str, password: &str) -> CoreResult<WorkspaceLoginResult>;
    fn login_or_register_workspace(
        &mut self,
        email: &str,
        first_name: &str,
        last_name: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspaceLoginOrRegisterResult>;
    fn register_workspace(
        &mut self,
        email: &str,
        first_name: &str,
        last_name: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspaceRegistrationChallenge>;
    fn verify_workspace_registration(
        &mut self,
        challenge_id: &str,
        email: &str,
        code: &str,
    ) -> CoreResult<WorkspaceLoginResult>;
    fn request_workspace_password_reset(
        &mut self,
        email: &str,
    ) -> CoreResult<WorkspaceRegistrationChallenge>;
    fn reset_workspace_password(
        &mut self,
        challenge_id: &str,
        email: &str,
        code: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspacePasswordResetResult>;
    fn create_organization(
        &mut self,
        credential: &ManagementCredential,
        name: &str,
        slug: Option<&str>,
    ) -> CoreResult<Organization>;
    fn bootstrap_runner_with_workspace_token(
        &mut self,
        workspace_token: &str,
        organization_id: &str,
    ) -> CoreResult<ApiKeyExchangeResult>;
    fn list_organizations(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<Organization>>;
    fn get_current_runner(
        &mut self,
        credential: &ManagementCredential,
        organization_id: &str,
    ) -> CoreResult<Runner>;
    fn get_runner_self_status(&mut self, _credential: &ManagementCredential) -> CoreResult<Value> {
        Err(CoreError::new(
            "RUNNER_SELF_STATUS_UNSUPPORTED",
            "management client does not support runner self status",
        ))
    }
    fn revoke_current_runner_token(
        &mut self,
        _credential: &ManagementCredential,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "RUNNER_TOKEN_REVOKE_UNSUPPORTED",
            "management client does not support runner token revocation",
        ))
    }
    fn upsert_current_runner(
        &mut self,
        credential: &ManagementCredential,
        request: &RunnerUpsertRequest,
        idempotency_key: &str,
    ) -> CoreResult<Runner>;
    fn start_workflow_run(
        &mut self,
        credential: &ManagementCredential,
        request: &WorkflowRunStartRequest,
    ) -> CoreResult<WorkflowRunStartResponse>;
    fn start_workflow_builder(
        &mut self,
        _credential: &ManagementCredential,
        _request: &WorkflowBuilderStartRequest,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "WORKFLOW_BUILDER_UNSUPPORTED",
            "management client does not support the workflow builder",
        ))
    }
    fn respond_workflow_builder(
        &mut self,
        _credential: &ManagementCredential,
        _session_id: &str,
        _response: &Value,
        _idempotency_key: &str,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "WORKFLOW_BUILDER_UNSUPPORTED",
            "management client does not support the workflow builder",
        ))
    }
    fn finalize_workflow_builder(
        &mut self,
        _credential: &ManagementCredential,
        _session_id: &str,
        _idempotency_key: &str,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "WORKFLOW_BUILDER_UNSUPPORTED",
            "management client does not support finalizing the workflow builder",
        ))
    }
    fn list_runner_workflows(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<RunnerWorkflowSummary>>;
    fn validate_runner_workflow_definition(
        &mut self,
        _credential: &ManagementCredential,
        _definition: &Value,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "WORKFLOW_VALIDATION_UNSUPPORTED",
            "management client does not support workflow validation",
        ))
    }
    fn list_runner_workflows_filtered(
        &mut self,
        credential: &ManagementCredential,
        execution_mode: Option<&str>,
        system_key: Option<&str>,
        query: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<Value> {
        let mut workflows = self.list_runner_workflows(credential)?;
        if let Some(execution_mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            workflows.retain(|workflow| runner_workflow_execution_mode(workflow) == execution_mode);
        }
        if let Some(system_key) = system_key.filter(|value| !value.trim().is_empty()) {
            workflows.retain(|workflow| {
                workflow
                    .extra
                    .get("systemKey")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == system_key)
            });
        }
        if let Some(query) = query.filter(|value| !value.trim().is_empty()) {
            let query = query.to_ascii_lowercase();
            workflows.retain(|workflow| {
                workflow.name.to_ascii_lowercase().contains(&query)
                    || workflow
                        .title
                        .as_deref()
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&query))
            });
        }
        let offset = cursor
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let limit = limit.clamp(1, 200);
        let total = workflows.len();
        let page = workflows
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        let next_cursor = (offset + page.len() < total).then(|| (offset + page.len()).to_string());
        Ok(serde_json::json!({"workflows": page, "nextCursor": next_cursor}))
    }
    fn start_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        inputs: Value,
        session_id: Option<&str>,
        version: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse>;
    fn start_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        options: RunnerWorkflowExecutionStartOptions<'_>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        if let Some(mode) = options
            .execution_mode
            .filter(|value| !value.trim().is_empty())
        {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!("management client does not support {mode} workflow execution"),
            ));
        }
        self.start_runner_workflow_execution(
            credential,
            options.workflow_id,
            options.inputs,
            options.session_id,
            options.version,
        )
    }
    fn list_runner_workflow_executions(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse>;
    fn list_runner_workflow_executions_filtered(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        status: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse> {
        let mut response =
            self.list_runner_workflow_executions(credential, workflow_id, limit.clamp(1, 200))?;
        if let Some(status) = status.filter(|value| !value.trim().is_empty()) {
            response.executions.retain(|execution| {
                execution.get("status").and_then(Value::as_str) == Some(status)
            });
        }
        let offset = cursor
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let total = response.executions.len();
        response.executions = response
            .executions
            .into_iter()
            .skip(offset)
            .take(limit.clamp(1, 200))
            .collect();
        response.next_cursor = (offset + response.executions.len() < total)
            .then(|| (offset + response.executions.len()).to_string());
        Ok(response)
    }
    fn list_runner_workflow_executions_filtered_scoped(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_mode: Option<&str>,
        status: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse> {
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!("management client does not support {mode} workflow execution lists"),
            ));
        }
        self.list_runner_workflow_executions_filtered(
            credential,
            workflow_id,
            status,
            cursor,
            limit,
        )
    }
    fn get_runner_workflow_input_schema(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        version: Option<&str>,
    ) -> CoreResult<RunnerWorkflowInputSchemaResponse>;
    fn get_runner_workflow_input_schema_scoped(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        version: Option<&str>,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowInputSchemaResponse> {
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!("management client does not support {mode} workflow schemas"),
            ));
        }
        self.get_runner_workflow_input_schema(credential, workflow_id, version)
    }
    fn get_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
    ) -> CoreResult<RunnerWorkflowExecutionResponse>;
    fn get_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!("management client does not support {mode} workflow execution details"),
            ));
        }
        self.get_runner_workflow_execution(credential, execution_id)
    }
    fn wait_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        _after_sequence: u64,
        _timeout_seconds: u64,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        self.get_runner_workflow_execution(credential, execution_id)
    }
    fn wait_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        after_sequence: u64,
        timeout_seconds: u64,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!(
                    "management client does not support waiting for {mode} workflow executions"
                ),
            ));
        }
        self.wait_runner_workflow_execution(
            credential,
            execution_id,
            after_sequence,
            timeout_seconds,
        )
    }
    fn cancel_runner_workflow_execution(
        &mut self,
        _credential: &ManagementCredential,
        _execution_id: &str,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "RUNNER_EXECUTION_CANCEL_UNSUPPORTED",
            "management client does not support execution cancellation",
        ))
    }
    fn cancel_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        _reason: &str,
        _idempotency_key: &str,
    ) -> CoreResult<Value> {
        self.cancel_runner_workflow_execution(credential, execution_id)
    }
    fn cancel_runner_workflow_execution_mode_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        reason: &str,
        idempotency_key: &str,
        execution_mode: Option<&str>,
    ) -> CoreResult<Value> {
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_MODE_UNSUPPORTED",
                format!("management client does not support cancelling {mode} workflow executions"),
            ));
        }
        self.cancel_runner_workflow_execution_scoped(
            credential,
            execution_id,
            reason,
            idempotency_key,
        )
    }
    fn get_workflow_input_schema(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
    ) -> CoreResult<Option<Value>>;
    fn list_human_requests(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
    ) -> CoreResult<Vec<HumanRequestSummary>>;
    fn list_human_requests_filtered(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
        _request_type: Option<&str>,
    ) -> CoreResult<Vec<HumanRequestSummary>> {
        self.list_human_requests(credential, workflow_id, execution_id)
    }
    fn list_human_requests_query(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
        request_type: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> CoreResult<Vec<HumanRequestSummary>> {
        let mut requests =
            self.list_human_requests_filtered(credential, workflow_id, execution_id, request_type)?;
        if let Some(status) = status.filter(|value| *value != "all") {
            requests.retain(|request| request.status == status);
        }
        requests.truncate(limit.clamp(1, 200));
        Ok(requests)
    }
    fn list_human_requests_page(
        &mut self,
        credential: &ManagementCredential,
        query: &RunnerHumanRequestListQuery<'_>,
    ) -> CoreResult<RunnerHumanRequestListResponse> {
        Ok(RunnerHumanRequestListResponse {
            human_requests: self.list_human_requests_query(
                credential,
                query.workflow_id,
                query.execution_id,
                query.request_type,
                query.status,
                query.limit,
            )?,
            next_cursor: None,
        })
    }
    fn resolve_human_request(
        &mut self,
        credential: &ManagementCredential,
        request_id: &str,
        payload: &Value,
    ) -> CoreResult<HumanRequestResolveResponse>;
    fn resolve_human_request_idempotent(
        &mut self,
        credential: &ManagementCredential,
        request_id: &str,
        payload: &Value,
        _idempotency_key: Option<&str>,
    ) -> CoreResult<HumanRequestResolveResponse> {
        self.resolve_human_request(credential, request_id, payload)
    }
    fn create_runner_session(
        &mut self,
        credential: &ManagementCredential,
        manifest: Value,
        transport: &str,
    ) -> CoreResult<RunnerSessionResponse>;
    fn heartbeat_runner_session(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        manifest: Value,
    ) -> CoreResult<RunnerSessionResponse>;
    fn list_runner_job_cancellations(
        &mut self,
        _credential: &ManagementCredential,
        _session_id: &str,
    ) -> CoreResult<Vec<Value>> {
        Ok(Vec::new())
    }
    fn lease_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
    ) -> CoreResult<RunnerJobResponse>;
    fn get_runner_job(
        &mut self,
        _credential: &ManagementCredential,
        _job_id: &str,
    ) -> CoreResult<RunnerJobResponse> {
        Err(CoreError::new(
            "RUNNER_JOB_RECOVERY_UNSUPPORTED",
            "management client does not support runner job recovery",
        ))
    }
    fn renew_runner_job(
        &mut self,
        _credential: &ManagementCredential,
        _session_id: &str,
        _job_id: &str,
        _lease_version: u64,
    ) -> CoreResult<RunnerJobResponse> {
        Err(CoreError::new(
            "RUNNER_JOB_RENEW_UNSUPPORTED",
            "management client does not support runner job lease renewal",
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn reclaim_runner_job(
        &mut self,
        _credential: &ManagementCredential,
        _session_id: &str,
        _job_id: &str,
        _expected_lease_version: u64,
        _payload_digest: &str,
        _idempotency_key: &str,
        _terminal_submission: Option<&Value>,
    ) -> CoreResult<RunnerJobResponse> {
        Err(CoreError::new(
            "RUNNER_JOB_RECLAIM_UNSUPPORTED",
            "management client does not support runner job reclaim",
        ))
    }
    fn start_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
    ) -> CoreResult<RunnerJobResponse>;
    fn start_runner_job_leased(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        _lease_version: u64,
    ) -> CoreResult<RunnerJobResponse> {
        self.start_runner_job(credential, session_id, job_id)
    }
    fn append_runner_job_events(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        events: Vec<Value>,
    ) -> CoreResult<RunnerJobEventCreateResponse>;
    fn append_runner_job_events_leased(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        _lease_version: u64,
        events: Vec<Value>,
    ) -> CoreResult<RunnerJobEventCreateResponse> {
        self.append_runner_job_events(credential, session_id, job_id, events)
    }
    fn complete_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        result: Value,
    ) -> CoreResult<RunnerJobResponse>;
    #[allow(clippy::too_many_arguments)]
    fn complete_runner_job_idempotent(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        _lease_version: u64,
        _idempotency_key: &str,
        result: Value,
    ) -> CoreResult<RunnerJobResponse> {
        self.complete_runner_job(credential, session_id, job_id, result)
    }
    fn fail_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        error: Value,
    ) -> CoreResult<RunnerJobResponse>;
    #[allow(clippy::too_many_arguments)]
    fn fail_runner_job_idempotent(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        _lease_version: u64,
        _idempotency_key: &str,
        error: Value,
    ) -> CoreResult<RunnerJobResponse> {
        self.fail_runner_job(credential, session_id, job_id, error)
    }
}

#[derive(Debug, Clone)]
pub struct HttpManagementApiClient {
    base_url: String,
    host_header: Option<String>,
    client: Client,
}

impl HttpManagementApiClient {
    pub fn new(server_url: impl Into<String>, host_header: Option<String>) -> CoreResult<Self> {
        let mut base_url = server_url.into().trim_end_matches('/').to_string();
        if !base_url.ends_with("/api/v1") {
            base_url.push_str("/api/v1");
        }
        Ok(Self {
            base_url,
            host_header,
            client: Client::builder()
                .connect_timeout(MANAGEMENT_CONNECT_TIMEOUT)
                .timeout(MANAGEMENT_REQUEST_TIMEOUT)
                .pool_idle_timeout(MANAGEMENT_IDLE_TIMEOUT)
                .build()
                .map_err(|err| CoreError::new("MANAGEMENT_HTTP_CLIENT_FAILED", err.to_string()))?,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn apply_common_headers(
        &self,
        mut request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(host_header) = &self.host_header {
            request = request.header("Host", host_header);
        }
        request
    }

    fn get_with_auth(
        &self,
        path: &str,
        credential: &ManagementCredential,
    ) -> reqwest::blocking::RequestBuilder {
        self.apply_common_headers(
            self.client
                .get(self.url(path))
                .bearer_auth(&credential.access_token),
        )
    }

    fn post_with_auth(
        &self,
        path: &str,
        credential: &ManagementCredential,
    ) -> reqwest::blocking::RequestBuilder {
        self.apply_common_headers(
            self.client
                .post(self.url(path))
                .bearer_auth(&credential.access_token),
        )
    }
}

impl ManagementApiClient for HttpManagementApiClient {
    fn start_device_login(&mut self) -> CoreResult<DeviceLoginChallenge> {
        let response = self
            .apply_common_headers(self.client.post(self.url("/auth/device/start")))
            .json(&DeviceLoginStartRequest {
                client_name: "loomex-cli".to_string(),
            })
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        parse_json_response(response)
    }

    fn poll_device_token(&mut self, device_code: &str) -> CoreResult<Option<AuthTokenResponse>> {
        let response = self
            .apply_common_headers(self.client.post(self.url("/auth/device/token")))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        if response.status() == StatusCode::ACCEPTED {
            return Ok(None);
        }
        parse_json_response(response).map(Some)
    }

    fn exchange_api_key(
        &mut self,
        api_key: &str,
        api_secret: &str,
        organization_id: &str,
    ) -> CoreResult<ApiKeyExchangeResult> {
        let response = self
            .apply_common_headers(self.client.post(self.url(RUNNER_AUTH_EXCHANGE_PATH)))
            .json(&serde_json::json!({
                "api_key": api_key,
                "api_secret": api_secret,
                "organization_id": organization_id,
                "runnerName": "Local runner"
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerAuthExchangeData> = parse_json_response(response)?;
        Ok(ApiKeyExchangeResult {
            token: AuthTokenResponse {
                access_token: envelope.data.runner_token,
                refresh_token: None,
                token_type: envelope.data.token_type,
                expires_at: RUNNER_TOKEN_NON_EXPIRING_EXPIRES_AT.to_string(),
            },
            organization_id: Some(envelope.data.organization_id),
            runner_id: Some(envelope.data.runner.id.clone()),
        })
    }

    fn login_workspace(&mut self, email: &str, password: &str) -> CoreResult<WorkspaceLoginResult> {
        let response = self
            .apply_common_headers(self.client.post(self.url("/workspace/auth/login/")))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkspaceLoginData> = parse_json_response(response)?;
        let organization_id = envelope.data.organization.map(|item| item.id);
        Ok(WorkspaceLoginResult {
            token: envelope.data.token,
            organization_id,
        })
    }

    fn login_or_register_workspace(
        &mut self,
        email: &str,
        first_name: &str,
        last_name: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspaceLoginOrRegisterResult> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url("/workspace/auth/login-or-register/")),
            )
            .json(&serde_json::json!({
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "password": password,
                "confirmPassword": confirm_password,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        if envelope.data.get("token").and_then(Value::as_str).is_some() {
            let data: WorkspaceLoginData = serde_json::from_value(envelope.data)
                .map_err(|err| CoreError::new("MANAGEMENT_RESPONSE_INVALID", err.to_string()))?;
            let organization_id = data.organization.map(|item| item.id);
            return Ok(WorkspaceLoginOrRegisterResult::Authenticated(
                WorkspaceLoginResult {
                    token: data.token,
                    organization_id,
                },
            ));
        }
        let challenge: WorkspaceRegistrationData = serde_json::from_value(envelope.data)
            .map_err(|err| CoreError::new("MANAGEMENT_RESPONSE_INVALID", err.to_string()))?;
        Ok(WorkspaceLoginOrRegisterResult::RegistrationChallenge(
            WorkspaceRegistrationChallenge {
                challenge_id: challenge.challenge_id,
                email: challenge.email,
                status: challenge.status,
                purpose: challenge.purpose,
                expires_at: challenge.expires_at,
                resend_available_at: challenge.resend_available_at,
                reused: challenge.reused,
            },
        ))
    }

    fn register_workspace(
        &mut self,
        email: &str,
        first_name: &str,
        last_name: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspaceRegistrationChallenge> {
        let response = self
            .apply_common_headers(self.client.post(self.url("/workspace/auth/register/")))
            .json(&serde_json::json!({
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "password": password,
                "confirmPassword": confirm_password,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkspaceRegistrationData> = parse_json_response(response)?;
        Ok(WorkspaceRegistrationChallenge {
            challenge_id: envelope.data.challenge_id,
            email: envelope.data.email,
            status: envelope.data.status,
            purpose: envelope.data.purpose,
            expires_at: envelope.data.expires_at,
            resend_available_at: envelope.data.resend_available_at,
            reused: envelope.data.reused,
        })
    }

    fn verify_workspace_registration(
        &mut self,
        challenge_id: &str,
        email: &str,
        code: &str,
    ) -> CoreResult<WorkspaceLoginResult> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url("/workspace/auth/register/verify/")),
            )
            .json(&serde_json::json!({
                "challengeId": challenge_id,
                "email": email,
                "code": code,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkspaceLoginData> = parse_json_response(response)?;
        let organization_id = envelope.data.organization.map(|item| item.id);
        Ok(WorkspaceLoginResult {
            token: envelope.data.token,
            organization_id,
        })
    }

    fn request_workspace_password_reset(
        &mut self,
        email: &str,
    ) -> CoreResult<WorkspaceRegistrationChallenge> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url("/workspace/auth/password/forgot/")),
            )
            .json(&serde_json::json!({"email": email}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkspaceRegistrationData> = parse_json_response(response)?;
        Ok(WorkspaceRegistrationChallenge {
            challenge_id: envelope.data.challenge_id,
            email: envelope.data.email,
            status: envelope.data.status,
            purpose: envelope.data.purpose,
            expires_at: envelope.data.expires_at,
            resend_available_at: envelope.data.resend_available_at,
            reused: envelope.data.reused,
        })
    }

    fn reset_workspace_password(
        &mut self,
        challenge_id: &str,
        email: &str,
        code: &str,
        password: &str,
        confirm_password: &str,
    ) -> CoreResult<WorkspacePasswordResetResult> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url("/workspace/auth/password/reset/")),
            )
            .json(&serde_json::json!({
                "challengeId": challenge_id,
                "email": email,
                "code": code,
                "password": password,
                "confirmPassword": confirm_password,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkspacePasswordResetData> = parse_json_response(response)?;
        Ok(WorkspacePasswordResetResult {
            status: envelope.data.status,
        })
    }

    fn create_organization(
        &mut self,
        credential: &ManagementCredential,
        name: &str,
        slug: Option<&str>,
    ) -> CoreResult<Organization> {
        let mut body = serde_json::json!({"name": name});
        if let Some(slug) = slug.filter(|value| !value.trim().is_empty()) {
            body["slug"] = Value::String(slug.to_string());
        }
        let response = self
            .post_with_auth("/organizations/", credential)
            .json(&body)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Organization> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn bootstrap_runner_with_workspace_token(
        &mut self,
        workspace_token: &str,
        organization_id: &str,
    ) -> CoreResult<ApiKeyExchangeResult> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url(RUNNER_AUTH_BOOTSTRAP_PATH))
                    .bearer_auth(workspace_token),
            )
            .json(&serde_json::json!({
                "organizationId": organization_id,
                "runnerName": "Local runner",
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerAuthExchangeData> = parse_json_response(response)?;
        Ok(ApiKeyExchangeResult {
            token: AuthTokenResponse {
                access_token: envelope.data.runner_token,
                refresh_token: None,
                token_type: envelope.data.token_type,
                expires_at: RUNNER_TOKEN_NON_EXPIRING_EXPIRES_AT.to_string(),
            },
            organization_id: Some(envelope.data.organization_id),
            runner_id: Some(envelope.data.runner.id.clone()),
        })
    }

    fn list_organizations(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<Organization>> {
        let response = self
            .get_with_auth("/organizations/", credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Vec<Organization>> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let mut path = format!(
            "/runner-control/runner/v1/executions/{}/",
            encode_path(execution_id)
        );
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            path.push_str("?executionMode=");
            path.push_str(&encode_query(mode.trim()));
        }
        let response = self
            .get_with_auth(&path, credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_current_runner(
        &mut self,
        credential: &ManagementCredential,
        organization_id: &str,
    ) -> CoreResult<Runner> {
        let response = self
            .get_with_auth("/runner-control/runner/v1/self/", credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerSelfData> = parse_json_response(response)?;
        let runner = envelope.data.runner.into_runner();
        if runner.organization_id != organization_id {
            return Err(CoreError::new(
                "RUNNER_ORGANIZATION_MISMATCH",
                "authenticated runner does not belong to the selected organization",
            ));
        }
        Ok(runner)
    }

    fn upsert_current_runner(
        &mut self,
        credential: &ManagementCredential,
        request: &RunnerUpsertRequest,
        _idempotency_key: &str,
    ) -> CoreResult<Runner> {
        // Runner-control creates a runner during auth exchange/bootstrap. There is no
        // mutable "current runner" resource in the v1 contract, so legacy callers
        // resolve the already-authenticated runner instead of issuing an obsolete PUT.
        self.get_current_runner(credential, &request.organization_id)
    }

    fn start_workflow_run(
        &mut self,
        credential: &ManagementCredential,
        request: &WorkflowRunStartRequest,
    ) -> CoreResult<WorkflowRunStartResponse> {
        if request
            .workspace_path
            .as_deref()
            .is_none_or(|path| path.trim().is_empty())
        {
            return Err(CoreError::new(
                "RUNNER_EXECUTION_WORKSPACE_REQUIRED",
                "workflow execution requires workspacePath",
            ));
        }
        let idempotency_key = request
            .idempotency_key
            .clone()
            .unwrap_or_else(|| format!("workflow-run:{}", request.workflow_id));
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflows/{}/executions/",
                    encode_path(&request.workflow_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&RunnerWorkflowExecutionStartRequest {
                inputs: request.inputs.clone(),
                workspace_path: request.workspace_path.clone(),
                session_id: None,
                version: None,
                execution_mode: Some("plugin".to_string()),
            })
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        let execution =
            envelope.data.execution.as_object().ok_or_else(|| {
                CoreError::new("MANAGEMENT_RESPONSE_INVALID", "execution is missing")
            })?;
        let id = execution
            .get("id")
            .or_else(|| execution.get("executionId"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CoreError::new("MANAGEMENT_RESPONSE_INVALID", "execution id is missing")
            })?;
        Ok(WorkflowRunStartResponse {
            id: id.to_string(),
            status: execution
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("queued")
                .to_string(),
            ui_url: execution
                .get("uiUrl")
                .or_else(|| execution.get("ui_url"))
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    fn start_workflow_builder(
        &mut self,
        credential: &ManagementCredential,
        request: &WorkflowBuilderStartRequest,
    ) -> CoreResult<Value> {
        let response = self
            .post_with_auth(
                "/runner-control/runner/v1/workflow-builder/sessions/",
                credential,
            )
            .header("Idempotency-Key", &request.idempotency_key)
            .json(&serde_json::json!({
                "prompt": request.prompt,
                "model": request.model,
                "workspacePath": request.workspace_path,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn finalize_workflow_builder(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<Value> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflow-builder/sessions/{}/finalize/",
                    encode_path(session_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn respond_workflow_builder(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        response: &Value,
        idempotency_key: &str,
    ) -> CoreResult<Value> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflow-builder/sessions/{}/responses/",
                    encode_path(session_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({"response": response}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_job(
        &mut self,
        credential: &ManagementCredential,
        job_id: &str,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .get_with_auth(
                &format!("/runner-control/runner/v1/jobs/{}/", encode_path(job_id)),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn renew_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        lease_version: u64,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/renew/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "leaseVersion": lease_version,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn reclaim_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        expected_lease_version: u64,
        payload_digest: &str,
        idempotency_key: &str,
        terminal_submission: Option<&Value>,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/reclaim/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "expectedLeaseVersion": expected_lease_version,
                "payloadDigest": payload_digest,
                "idempotencyKey": idempotency_key,
                "terminalSubmission": terminal_submission.is_some(),
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_self_status(&mut self, credential: &ManagementCredential) -> CoreResult<Value> {
        let response = self
            .get_with_auth("/runner-control/runner/v1/self/", credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn revoke_current_runner_token(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Value> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/auth/logout/", credential)
            .json(&serde_json::json!({}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_workflows(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<RunnerWorkflowSummary>> {
        let response = self
            .get_with_auth("/runner-control/runner/v1/workflows/", credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowListResponse> = parse_json_response(response)?;
        Ok(envelope.data.workflows)
    }

    fn validate_runner_workflow_definition(
        &mut self,
        credential: &ManagementCredential,
        definition: &Value,
    ) -> CoreResult<Value> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/workflows/validate/", credential)
            .json(&serde_json::json!({"definition": definition}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_workflows_filtered(
        &mut self,
        credential: &ManagementCredential,
        execution_mode: Option<&str>,
        system_key: Option<&str>,
        query: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<Value> {
        let mut params = vec![format!("limit={}", limit.clamp(1, 200))];
        if let Some(value) = execution_mode.filter(|value| !value.trim().is_empty()) {
            params.push(format!("executionMode={}", encode_query(value)));
        }
        if let Some(value) = system_key.filter(|value| !value.trim().is_empty()) {
            params.push(format!("systemKey={}", encode_query(value)));
        }
        if let Some(value) = query.filter(|value| !value.trim().is_empty()) {
            params.push(format!("query={}", encode_query(value)));
        }
        if let Some(value) = cursor.filter(|value| !value.trim().is_empty()) {
            params.push(format!("cursor={}", encode_query(value)));
        }
        let response = self
            .get_with_auth(
                &format!("/runner-control/runner/v1/workflows/?{}", params.join("&")),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn start_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        inputs: Value,
        session_id: Option<&str>,
        version: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let body = RunnerWorkflowExecutionStartRequest {
            inputs,
            workspace_path: None,
            session_id: session_id.map(str::to_string),
            version: version.map(str::to_string),
            execution_mode: None,
        };
        let idempotency_key = default_runner_operation_idempotency_key(
            "workflow.run",
            &serde_json::json!({"workflowId": workflow_id, "request": body}),
        )?;
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflows/{}/executions/",
                    encode_path(workflow_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&body)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn start_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        options: RunnerWorkflowExecutionStartOptions<'_>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let idempotency_key = validate_runner_operation_idempotency_key(options.idempotency_key)?;
        let mut request = self.post_with_auth(
            &format!(
                "/runner-control/runner/v1/workflows/{}/executions/",
                encode_path(options.workflow_id)
            ),
            credential,
        );
        request = request.header("Idempotency-Key", idempotency_key);
        let response = request
            .json(&RunnerWorkflowExecutionStartRequest {
                inputs: options.inputs,
                workspace_path: options.workspace_path.map(str::to_string),
                session_id: options.session_id.map(str::to_string),
                version: options.version.map(str::to_string),
                execution_mode: options.execution_mode.map(str::to_string),
            })
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/executions/{}/",
                    encode_path(execution_id)
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn wait_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        after_sequence: u64,
        timeout_seconds: u64,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/executions/{}/?afterSequence={}&timeoutSeconds={}",
                    encode_path(execution_id),
                    after_sequence,
                    timeout_seconds.min(45),
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn wait_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        after_sequence: u64,
        timeout_seconds: u64,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowExecutionResponse> {
        let mut params = vec![
            format!("afterSequence={after_sequence}"),
            format!("timeoutSeconds={}", timeout_seconds.min(45)),
        ];
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            params.push(format!("executionMode={}", encode_query(mode.trim())));
        }
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/executions/{}/?{}",
                    encode_path(execution_id),
                    params.join("&")
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn cancel_runner_workflow_execution(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
    ) -> CoreResult<Value> {
        let reason = "Requested by legacy Loomex client";
        let idempotency_key = default_runner_operation_idempotency_key(
            "workflow.cancel",
            &serde_json::json!({"executionId": execution_id, "reason": reason}),
        )?;
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/executions/{}/cancel/",
                    encode_path(execution_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({"reason": reason}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn cancel_runner_workflow_execution_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        reason: &str,
        idempotency_key: &str,
    ) -> CoreResult<Value> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(CoreError::new(
                "CANCELLATION_REASON_REQUIRED",
                "cancellation reason is required",
            ));
        }
        let idempotency_key = validate_runner_operation_idempotency_key(idempotency_key)?;
        let mut request = self.post_with_auth(
            &format!(
                "/runner-control/runner/v1/executions/{}/cancel/",
                encode_path(execution_id)
            ),
            credential,
        );
        request = request.header("Idempotency-Key", idempotency_key);
        let response = request
            .json(&serde_json::json!({"reason": reason}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn cancel_runner_workflow_execution_mode_scoped(
        &mut self,
        credential: &ManagementCredential,
        execution_id: &str,
        reason: &str,
        idempotency_key: &str,
        execution_mode: Option<&str>,
    ) -> CoreResult<Value> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(CoreError::new(
                "CANCELLATION_REASON_REQUIRED",
                "cancellation reason is required",
            ));
        }
        let idempotency_key = validate_runner_operation_idempotency_key(idempotency_key)?;
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/executions/{}/cancel/",
                    encode_path(execution_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({
                "reason": reason,
                "executionMode": execution_mode.filter(|value| !value.trim().is_empty()),
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_workflow_executions(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse> {
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflows/{}/executions/?limit={}",
                    encode_path(workflow_id),
                    limit.clamp(1, 50)
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionListResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_workflow_executions_filtered(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        status: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse> {
        let mut params = vec![format!("limit={}", limit.clamp(1, 200))];
        if let Some(value) = status.filter(|value| !value.trim().is_empty()) {
            params.push(format!("status={}", encode_query(value)));
        }
        if let Some(value) = cursor.filter(|value| !value.trim().is_empty()) {
            params.push(format!("cursor={}", encode_query(value)));
        }
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflows/{}/executions/?{}",
                    encode_path(workflow_id),
                    params.join("&")
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionListResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_workflow_executions_filtered_scoped(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_mode: Option<&str>,
        status: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<RunnerWorkflowExecutionListResponse> {
        let mut params = vec![format!("limit={}", limit.clamp(1, 200))];
        if let Some(value) = execution_mode.filter(|value| !value.trim().is_empty()) {
            params.push(format!("executionMode={}", encode_query(value)));
        }
        if let Some(value) = status.filter(|value| !value.trim().is_empty()) {
            params.push(format!("status={}", encode_query(value)));
        }
        if let Some(value) = cursor.filter(|value| !value.trim().is_empty()) {
            params.push(format!("cursor={}", encode_query(value)));
        }
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/workflows/{}/executions/?{}",
                    encode_path(workflow_id),
                    params.join("&")
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowExecutionListResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_workflow_input_schema(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        version: Option<&str>,
    ) -> CoreResult<RunnerWorkflowInputSchemaResponse> {
        let mut path = format!(
            "/runner-control/runner/v1/workflows/{}/",
            encode_path(workflow_id)
        );
        if let Some(version) = version.filter(|value| !value.trim().is_empty()) {
            path.push_str("?version=");
            path.push_str(&encode_query(version.trim()));
        }
        let response = self
            .get_with_auth(&path, credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowInputSchemaResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_runner_workflow_input_schema_scoped(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        version: Option<&str>,
        execution_mode: Option<&str>,
    ) -> CoreResult<RunnerWorkflowInputSchemaResponse> {
        let mut params = Vec::new();
        if let Some(version) = version.filter(|value| !value.trim().is_empty()) {
            params.push(format!("version={}", encode_query(version.trim())));
        }
        if let Some(mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            params.push(format!("executionMode={}", encode_query(mode.trim())));
        }
        let mut path = format!(
            "/runner-control/runner/v1/workflows/{}/",
            encode_path(workflow_id)
        );
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        let response = self
            .get_with_auth(&path, credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerWorkflowInputSchemaResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_workflow_input_schema(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
    ) -> CoreResult<Option<Value>> {
        let response = self
            .get_with_auth(
                &format!("/client/workflows/{}/", encode_path(workflow_id)),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<ClientWorkflowDetailResponse> = parse_json_response(response)?;
        Ok(envelope
            .data
            .active_version
            .and_then(|version| version.definition.get("inputSchema").cloned())
            .filter(|schema| schema.is_object()))
    }

    fn list_human_requests(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
    ) -> CoreResult<Vec<HumanRequestSummary>> {
        self.list_human_requests_filtered(credential, workflow_id, execution_id, None)
    }

    fn list_human_requests_filtered(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
        request_type: Option<&str>,
    ) -> CoreResult<Vec<HumanRequestSummary>> {
        let mut query = vec!["status=pending".to_string(), "limit=100".to_string()];
        if !workflow_id.trim().is_empty() {
            query.push(format!("workflowId={}", encode_query(workflow_id.trim())));
        }
        if let Some(execution_id) = execution_id.filter(|value| !value.trim().is_empty()) {
            query.push(format!("executionId={}", encode_query(execution_id.trim())));
        }
        if let Some(request_type) = request_type.filter(|value| !value.trim().is_empty()) {
            query.push(format!("requestType={}", encode_query(request_type.trim())));
        }
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/human-requests/?{}",
                    query.join("&")
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerHumanRequestListResponse> =
            parse_json_response(response)?;
        Ok(envelope.data.human_requests)
    }

    fn list_human_requests_query(
        &mut self,
        credential: &ManagementCredential,
        workflow_id: &str,
        execution_id: Option<&str>,
        request_type: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> CoreResult<Vec<HumanRequestSummary>> {
        Ok(self
            .list_human_requests_page(
                credential,
                &RunnerHumanRequestListQuery {
                    workflow_id,
                    execution_id,
                    request_type,
                    status,
                    cursor: None,
                    limit,
                },
            )?
            .human_requests)
    }

    fn list_human_requests_page(
        &mut self,
        credential: &ManagementCredential,
        list_query: &RunnerHumanRequestListQuery<'_>,
    ) -> CoreResult<RunnerHumanRequestListResponse> {
        let mut query = vec![
            format!(
                "status={}",
                encode_query(list_query.status.unwrap_or("pending"))
            ),
            format!("limit={}", list_query.limit.clamp(1, 200)),
        ];
        if !list_query.workflow_id.trim().is_empty() {
            query.push(format!(
                "workflowId={}",
                encode_query(list_query.workflow_id.trim())
            ));
        }
        if let Some(value) = list_query
            .execution_id
            .filter(|value| !value.trim().is_empty())
        {
            query.push(format!("executionId={}", encode_query(value)));
        }
        if let Some(value) = list_query
            .request_type
            .filter(|value| !value.trim().is_empty())
        {
            query.push(format!("requestType={}", encode_query(value)));
        }
        if let Some(value) = list_query.cursor.filter(|value| !value.trim().is_empty()) {
            query.push(format!("cursor={}", encode_query(value)));
        }
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/human-requests/?{}",
                    query.join("&")
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerHumanRequestListResponse> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn resolve_human_request(
        &mut self,
        credential: &ManagementCredential,
        request_id: &str,
        payload: &Value,
    ) -> CoreResult<HumanRequestResolveResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/human-requests/{}/resolve/",
                    encode_path(request_id)
                ),
                credential,
            )
            .json(payload)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<HumanRequestResolveResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn resolve_human_request_idempotent(
        &mut self,
        credential: &ManagementCredential,
        request_id: &str,
        payload: &Value,
        idempotency_key: Option<&str>,
    ) -> CoreResult<HumanRequestResolveResponse> {
        let mut request = self.post_with_auth(
            &format!(
                "/runner-control/runner/v1/human-requests/{}/resolve/",
                encode_path(request_id)
            ),
            credential,
        );
        if let Some(key) = idempotency_key.filter(|value| !value.trim().is_empty()) {
            request = request.header("Idempotency-Key", key);
        }
        let response = request
            .json(payload)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<HumanRequestResolveResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn create_runner_session(
        &mut self,
        credential: &ManagementCredential,
        manifest: Value,
        transport: &str,
    ) -> CoreResult<RunnerSessionResponse> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/sessions/", credential)
            .json(&serde_json::json!({
                "manifest": manifest,
                "transport": transport,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerSessionResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn heartbeat_runner_session(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        manifest: Value,
    ) -> CoreResult<RunnerSessionResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/sessions/{}/heartbeat/",
                    encode_path(session_id)
                ),
                credential,
            )
            .json(&serde_json::json!({ "manifest": manifest }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerSessionResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_runner_job_cancellations(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
    ) -> CoreResult<Vec<Value>> {
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/cancellations/?sessionId={}",
                    encode_query(session_id)
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(envelope
            .data
            .get("jobs")
            .or_else(|| envelope.data.get("cancellations"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn lease_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/jobs/lease/", credential)
            .json(&serde_json::json!({ "sessionId": session_id }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn start_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/start/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({ "sessionId": session_id }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn start_runner_job_leased(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        lease_version: u64,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/start/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "leaseVersion": lease_version,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn append_runner_job_events(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        events: Vec<Value>,
    ) -> CoreResult<RunnerJobEventCreateResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/events/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({ "sessionId": session_id, "events": events }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobEventCreateResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn append_runner_job_events_leased(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        lease_version: u64,
        events: Vec<Value>,
    ) -> CoreResult<RunnerJobEventCreateResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/events/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "leaseVersion": lease_version,
                "events": events,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobEventCreateResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn complete_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        result: Value,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/complete/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({ "sessionId": session_id, "result": result }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn complete_runner_job_idempotent(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        lease_version: u64,
        idempotency_key: &str,
        result: Value,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/complete/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "leaseVersion": lease_version,
                "idempotencyKey": idempotency_key,
                "result": result,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn fail_runner_job(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        error: Value,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/fail/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({ "sessionId": session_id, "error": error }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn fail_runner_job_idempotent(
        &mut self,
        credential: &ManagementCredential,
        session_id: &str,
        job_id: &str,
        lease_version: u64,
        idempotency_key: &str,
        error: Value,
    ) -> CoreResult<RunnerJobResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/jobs/{}/fail/",
                    encode_path(job_id)
                ),
                credential,
            )
            .json(&serde_json::json!({
                "sessionId": session_id,
                "leaseVersion": lease_version,
                "idempotencyKey": idempotency_key,
                "error": error,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerJobResponse> = parse_json_response(response)?;
        Ok(envelope.data)
    }
}

fn parse_json_response<T: for<'de> Deserialize<'de>>(
    mut response: reqwest::blocking::Response,
) -> CoreResult<T> {
    if management_breaker_is_open() {
        management_metrics()
            .breaker_rejected
            .fetch_add(1, Ordering::Relaxed);
        return Err(CoreError::new(
            "MANAGEMENT_CIRCUIT_OPEN",
            "management API circuit breaker is open",
        ));
    }
    let status = response.status();
    let body = read_bounded_response(&mut response)?;
    if !status.is_success() {
        if status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
        {
            record_management_failure();
        }
        let body = String::from_utf8_lossy(&body);
        return Err(management_error_from_status_and_body(
            status.as_u16(),
            &body,
        ));
    }
    record_management_success();
    serde_json::from_slice::<T>(&body)
        .map_err(|err| CoreError::new("MANAGEMENT_RESPONSE_INVALID", err.to_string()))
}

fn read_bounded_response(response: &mut reqwest::blocking::Response) -> CoreResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MANAGEMENT_MAX_RESPONSE_BYTES)
    {
        management_metrics()
            .oversize
            .fetch_add(1, Ordering::Relaxed);
        record_management_failure();
        return Err(CoreError::new(
            "MANAGEMENT_RESPONSE_TOO_LARGE",
            format!(
                "management API response exceeds {} bytes",
                MANAGEMENT_MAX_RESPONSE_BYTES
            ),
        ));
    }

    let capacity = response
        .content_length()
        .unwrap_or(0)
        .min(MANAGEMENT_MAX_RESPONSE_BYTES) as usize;
    let mut body = Vec::with_capacity(capacity);
    response
        .take(MANAGEMENT_MAX_RESPONSE_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                management_metrics().timeout.fetch_add(1, Ordering::Relaxed);
            }
            record_management_failure();
            CoreError::new(
                if err.kind() == std::io::ErrorKind::TimedOut {
                    "MANAGEMENT_HTTP_TIMEOUT"
                } else {
                    "MANAGEMENT_HTTP_FAILED"
                },
                err.to_string(),
            )
        })?;
    if body.len() as u64 > MANAGEMENT_MAX_RESPONSE_BYTES {
        management_metrics()
            .oversize
            .fetch_add(1, Ordering::Relaxed);
        record_management_failure();
        return Err(CoreError::new(
            "MANAGEMENT_RESPONSE_TOO_LARGE",
            format!(
                "management API response exceeds {} bytes",
                MANAGEMENT_MAX_RESPONSE_BYTES
            ),
        ));
    }
    Ok(body)
}

fn management_breaker() -> &'static Mutex<(u32, Option<Instant>)> {
    MANAGEMENT_BREAKER.get_or_init(|| Mutex::new((0, None)))
}

fn management_breaker_is_open() -> bool {
    let Ok(mut breaker) = management_breaker().lock() else {
        return false;
    };
    let Some(reopens_at) = breaker.1 else {
        return false;
    };
    if Instant::now() >= reopens_at {
        breaker.0 = 0;
        breaker.1 = None;
        return false;
    }
    true
}

fn record_management_failure() {
    let Ok(mut breaker) = management_breaker().lock() else {
        return;
    };
    breaker.0 = breaker.0.saturating_add(1);
    if breaker.0 >= MANAGEMENT_BREAKER_FAILURE_THRESHOLD && breaker.1.is_none() {
        breaker.1 = Some(Instant::now() + MANAGEMENT_BREAKER_COOLDOWN);
        management_metrics()
            .breaker_open
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn record_management_success() {
    if let Ok(mut breaker) = management_breaker().lock() {
        breaker.0 = 0;
        breaker.1 = None;
    }
}

#[allow(dead_code)]
fn management_retry_delay(attempt: u8) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or_default();
    let jitter = nanos % 100;
    Duration::from_millis((50_u64 << attempt.min(MANAGEMENT_RETRY_BUDGET)) + jitter)
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
    #[serde(default)]
    request_id: String,
    details: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelopeResponse {
    error: ErrorResponse,
    #[serde(default)]
    meta: ErrorEnvelopeMeta,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelopeMeta {
    #[serde(default)]
    correlation_id: String,
}

fn management_error_from_status_and_body(status: u16, body: &str) -> CoreError {
    let parsed = serde_json::from_str::<ErrorResponse>(body)
        .ok()
        .or_else(|| {
            serde_json::from_str::<ErrorEnvelopeResponse>(body)
                .ok()
                .map(|envelope| {
                    let mut error = envelope.error;
                    if error.request_id.is_empty() {
                        error.request_id = envelope.meta.correlation_id;
                    }
                    error
                })
        });
    if let Some(error) = parsed {
        let code: &'static str = Box::leak(error.code.into_boxed_str());
        let mut message = error.message;
        if !error.request_id.is_empty() {
            message.push_str(&format!(" request_id={}", error.request_id));
        }
        if let Some(details) = error.details {
            message.push_str(&format!(" details={details}"));
        }
        return CoreError::new(code, message);
    }
    CoreError::new(
        match status {
            401 => "MANAGEMENT_AUTH_FAILED",
            403 => "MANAGEMENT_PERMISSION_DENIED",
            _ => "MANAGEMENT_HTTP_STATUS",
        },
        format!("management API returned HTTP {status}"),
    )
}

pub fn parse_rfc3339_utc_epoch_seconds(value: &str) -> CoreResult<u64> {
    let Some((date, time)) = value.strip_suffix('Z').and_then(|v| v.split_once('T')) else {
        return Err(CoreError::new(
            "AUTH_TOKEN_EXPIRY_INVALID",
            "expires_at must be an RFC3339 UTC timestamp",
        ));
    };
    let mut date_parts = date.split('-');
    let year = parse_i64(date_parts.next(), "year")?;
    let month = parse_i64(date_parts.next(), "month")?;
    let day = parse_i64(date_parts.next(), "day")?;
    if date_parts.next().is_some() {
        return Err(CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", "invalid date"));
    }
    let mut time_parts = time.split(':');
    let hour = parse_i64(time_parts.next(), "hour")?;
    let minute = parse_i64(time_parts.next(), "minute")?;
    let second = parse_i64(time_parts.next(), "second")?;
    if time_parts.next().is_some() {
        return Err(CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", "invalid time"));
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(CoreError::new(
            "AUTH_TOKEN_EXPIRY_INVALID",
            "expires_at contains an out-of-range timestamp component",
        ));
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", "timestamp overflow"))?;
    u64::try_from(seconds)
        .map_err(|_| CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", "timestamp is before epoch"))
}

fn parse_i64(value: Option<&str>, field: &'static str) -> CoreResult<i64> {
    value
        .ok_or_else(|| CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", field))?
        .parse::<i64>()
        .map_err(|_| CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", field))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> CoreResult<i64> {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    if !(0..=365).contains(&day_of_year) {
        return Err(CoreError::new("AUTH_TOKEN_EXPIRY_INVALID", "invalid date"));
    }
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(era * 146_097 + day_of_era - 719_468)
}

fn encode_path(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn encode_query(value: &str) -> String {
    encode_path(value)
}

fn validate_runner_operation_idempotency_key(value: &str) -> CoreResult<&str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CoreError::new(
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key is required",
        ));
    }
    if value.len() > 160 {
        return Err(CoreError::new(
            "IDEMPOTENCY_KEY_INVALID",
            "Idempotency-Key must not exceed 160 bytes",
        ));
    }
    Ok(value)
}

fn default_runner_operation_idempotency_key(
    operation: &str,
    payload: &Value,
) -> CoreResult<String> {
    let encoded = serde_json::to_vec(payload)
        .map_err(|error| CoreError::new("IDEMPOTENCY_PAYLOAD_INVALID", error.to_string()))?;
    let digest = Sha256::digest(encoded);
    Ok(format!("loomex-legacy-{operation}-{digest:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn serve_one_http_response(
        response_body: &'static str,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        serve_one_http_response_with_status("200 OK", response_body)
    }

    fn serve_one_http_response_with_status(
        response_status: &'static str,
        response_body: &'static str,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
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
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            while bytes.len() < header_end + content_length {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "client closed before sending request body");
                bytes.extend_from_slice(&buffer[..count]);
            }
            request_sender
                .send(String::from_utf8(bytes).unwrap())
                .unwrap();
            let response = format!(
                "HTTP/1.1 {response_status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), request_receiver, handle)
    }

    fn test_credential(access_token: &str) -> ManagementCredential {
        ManagementCredential::from_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: access_token.to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap()
    }

    fn captured_request(
        receiver: mpsc::Receiver<String>,
        server: std::thread::JoinHandle<()>,
    ) -> String {
        let request = receiver.recv().unwrap();
        server.join().unwrap();
        request
    }

    #[test]
    fn device_authorization_http_contracts_are_exact() {
        let (server_url, request, server) = serve_one_http_response(
            r#"{"device_code":"device-1","user_code":"ABCD-EFGH","verification_uri":"https://loomex.test/verify","expires_in_seconds":600,"interval_seconds":5}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let challenge = client.start_device_login().unwrap();
        let raw = captured_request(request, server);
        assert_eq!(challenge.device_code, "device-1");
        assert!(raw.starts_with("POST /api/v1/auth/device/start HTTP/1.1\r\n"));
        assert!(raw.contains(r#"{"client_name":"loomex-cli"}"#));
        assert!(!raw.to_ascii_lowercase().contains("authorization:"));

        let (server_url, request, server) = serve_one_http_response(
            r#"{"access_token":"user.jwt","refresh_token":null,"token_type":"Bearer","expires_at":"2099-01-01T00:00:00Z"}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let token = client.poll_device_token("device-1").unwrap().unwrap();
        let raw = captured_request(request, server);
        assert_eq!(token.access_token, "user.jwt");
        assert!(raw.starts_with("POST /api/v1/auth/device/token HTTP/1.1\r\n"));
        assert!(raw.contains(r#"{"device_code":"device-1"}"#));
        assert!(!raw.to_ascii_lowercase().contains("authorization:"));
    }

    #[test]
    fn workspace_combined_auth_and_password_reset_http_contracts_are_exact() {
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"challengeId":"challenge-1","email":"new@example.com","status":"pending","expiresAt":"2099-01-01T00:00:00Z","resendAvailableAt":null,"reused":false}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let result = client
            .login_or_register_workspace(
                "new@example.com",
                "Ada",
                "Lovelace",
                "Password1!",
                "Password1!",
            )
            .unwrap();
        assert!(matches!(
            result,
            WorkspaceLoginOrRegisterResult::RegistrationChallenge(_)
        ));
        let raw = captured_request(request, server);
        assert!(raw.starts_with("POST /api/v1/workspace/auth/login-or-register/ HTTP/1.1\r\n"));
        assert!(raw.contains(r#""firstName":"Ada""#));
        assert!(raw.contains(r#""confirmPassword":"Password1!""#));

        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"challengeId":"reset-1","email":"user@example.com","status":"pending"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let challenge = client
            .request_workspace_password_reset("user@example.com")
            .unwrap();
        assert_eq!(challenge.challenge_id, "reset-1");
        let raw = captured_request(request, server);
        assert!(raw.starts_with("POST /api/v1/workspace/auth/password/forgot/ HTTP/1.1\r\n"));
        assert!(raw.contains(r#""email":"user@example.com""#));

        let (server_url, request, server) =
            serve_one_http_response(r#"{"data":{"status":"password_reset"}}"#);
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let reset = client
            .reset_workspace_password(
                "reset-1",
                "user@example.com",
                "123456",
                "Password2!",
                "Password2!",
            )
            .unwrap();
        assert_eq!(reset.status, "password_reset");
        let raw = captured_request(request, server);
        assert!(raw.starts_with("POST /api/v1/workspace/auth/password/reset/ HTTP/1.1\r\n"));
        assert!(raw.contains(r#""challengeId":"reset-1""#));
    }

    #[test]
    fn org_scoped_runner_bootstrap_http_contract_is_exact() {
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"runner":{"id":"runner-1"},"runnerToken":"runner.jwt","tokenType":"Bearer","organizationId":"org-1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let exchange = client
            .bootstrap_runner_with_workspace_token("user.jwt", "org-1")
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(exchange.runner_id.as_deref(), Some("runner-1"));
        assert!(
            raw.starts_with("POST /api/v1/runner-control/runner/v1/auth/bootstrap/ HTTP/1.1\r\n")
        );
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer user.jwt\r\n"));
        assert!(raw.contains(r#""organizationId":"org-1""#));
    }

    #[test]
    fn runner_workflow_read_http_contracts_are_exact() {
        let credential = test_credential("runner.jwt");

        let (server_url, request, server) =
            serve_one_http_response(r#"{"data":{"workflows":[],"nextCursor":"next-1"}}"#);
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let page = client
            .list_runner_workflows_filtered(
                &credential,
                Some("plugin"),
                None,
                Some("review me"),
                Some("cursor-1"),
                200,
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(page["nextCursor"], "next-1");
        assert!(raw.starts_with("GET /api/v1/runner-control/runner/v1/workflows/?"));
        for query in [
            "limit=200",
            "executionMode=plugin",
            "query=review%20me",
            "cursor=cursor-1",
        ] {
            assert!(raw.contains(query), "missing {query}: {raw}");
        }

        let (server_url, request, server) =
            serve_one_http_response(r#"{"data":{"inputSchema":{"type":"object"}}}"#);
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        client
            .get_runner_workflow_input_schema_scoped(
                &credential,
                "workflow / one",
                Some("version 2"),
                Some("plugin"),
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert!(raw.starts_with(
            "GET /api/v1/runner-control/runner/v1/workflows/workflow%20%2F%20one/?version=version%202&executionMode=plugin HTTP/1.1\r\n"
        ));

        let (server_url, request, server) =
            serve_one_http_response(r#"{"data":{"executions":[],"nextCursor":"cursor-2"}}"#);
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let page = client
            .list_runner_workflow_executions_filtered_scoped(
                &credential,
                "workflow-1",
                Some("plugin"),
                Some("waiting_for_human"),
                Some("cursor-1"),
                200,
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));
        assert!(raw
            .starts_with("GET /api/v1/runner-control/runner/v1/workflows/workflow-1/executions/?"));
        for query in [
            "limit=200",
            "executionMode=plugin",
            "status=waiting_for_human",
            "cursor=cursor-1",
        ] {
            assert!(raw.contains(query), "missing {query}: {raw}");
        }

        for (wait, expected_path) in [
            (
                false,
                "GET /api/v1/runner-control/runner/v1/executions/execution%20%2F%20one/?executionMode=plugin HTTP/1.1\r\n",
            ),
            (
                true,
                "GET /api/v1/runner-control/runner/v1/executions/execution%20%2F%20one/?afterSequence=9&timeoutSeconds=45&executionMode=plugin HTTP/1.1\r\n",
            ),
        ] {
            let (server_url, request, server) = serve_one_http_response(
                r#"{"data":{"execution":{"id":"execution-1","status":"running"},"events":[],"latestSequence":9,"timedOut":false}}"#,
            );
            let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
            if wait {
                client
                    .wait_runner_workflow_execution_scoped(
                        &credential,
                        "execution / one",
                        9,
                        99,
                        Some("plugin"),
                    )
                    .unwrap();
            } else {
                client
                    .get_runner_workflow_execution_scoped(
                        &credential,
                        "execution / one",
                        Some("plugin"),
                    )
                    .unwrap();
            }
            let raw = captured_request(request, server);
            assert!(raw.starts_with(expected_path), "unexpected request: {raw}");
        }
    }

    #[test]
    fn human_resolution_and_runner_status_http_contracts_are_exact() {
        let credential = test_credential("runner.jwt");
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"requestId":"request-1","requestStatus":"resolved","executionId":"execution-1","executionStatus":"running"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let response = client
            .resolve_human_request_idempotent(
                &credential,
                "request / one",
                &json!({"decision":"approve","reason":"looks good"}),
                Some("human-response-1"),
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(response.request_status, "resolved");
        assert!(raw.starts_with(
            "POST /api/v1/runner-control/runner/v1/human-requests/request%20%2F%20one/resolve/ HTTP/1.1\r\n"
        ));
        let lowered = raw.to_ascii_lowercase();
        assert!(lowered.contains("authorization: bearer runner.jwt\r\n"));
        assert!(lowered.contains("idempotency-key: human-response-1\r\n"));
        assert!(raw.contains(r#"{"decision":"approve","reason":"looks good"}"#));
    }

    #[test]
    fn current_runner_uses_runner_control_self_contract() {
        let credential = test_credential("runner.jwt");
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"runner":{"id":"runner-1","organizationId":"org-1","status":"online","capabilities":{"runnerVersion":"0.1.0","protocolVersion":"runner.v1","localFiles":true,"disabledFeature":false}}}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let runner = client.get_current_runner(&credential, "org-1").unwrap();
        let raw = captured_request(request, server);

        assert!(raw.starts_with("GET /api/v1/runner-control/runner/v1/self/ HTTP/1.1\r\n"));
        assert!(!raw.contains("/runners/current"));
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer runner.jwt\r\n"));
        assert_eq!(runner.id, "runner-1");
        assert_eq!(runner.organization_id, "org-1");
        assert_eq!(runner.runner_version, "0.1.0");
        assert_eq!(runner.protocol_version, "runner.v1");
        assert_eq!(runner.capabilities, vec!["localFiles"]);
    }

    #[test]
    fn legacy_upsert_callers_resolve_bootstrapped_runner_without_legacy_put() {
        let credential = test_credential("runner.jwt");
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"runner":{"id":"runner-1","organizationId":"org-1","status":"offline","capabilities":{}}}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let runner = client
            .upsert_current_runner(
                &credential,
                &RunnerUpsertRequest {
                    organization_id: "org-1".to_string(),
                    display_name: "Local runner".to_string(),
                    machine_fingerprint_hash: "machine-1".to_string(),
                    os: "macos".to_string(),
                    arch: "aarch64".to_string(),
                    runner_version: "0.1.0".to_string(),
                    protocol_version: "runner.v1".to_string(),
                    capabilities: vec!["localFiles".to_string()],
                },
                "ignored-by-runner-control-v1",
            )
            .unwrap();
        let raw = captured_request(request, server);

        assert!(raw.starts_with("GET /api/v1/runner-control/runner/v1/self/ HTTP/1.1\r\n"));
        assert!(!raw.contains("PUT "));
        assert!(!raw.contains("/runners/current"));
        assert_eq!(runner.id, "runner-1");
    }

    #[test]
    fn current_runner_preserves_runner_control_scope_error() {
        let credential = test_credential("runner.without-read-scope");
        let (server_url, request, server) = serve_one_http_response_with_status(
            "403 Forbidden",
            r#"{"error":{"code":"AUTHORIZATION_FAILED","message":"Runner token must include runner.read scope","details":{"requiredScope":"runner.read"}},"meta":{"correlationId":"req-scope-1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let error = client.get_current_runner(&credential, "org-1").unwrap_err();
        let raw = captured_request(request, server);

        assert!(raw.starts_with("GET /api/v1/runner-control/runner/v1/self/ HTTP/1.1\r\n"));
        assert_eq!(error.code, "AUTHORIZATION_FAILED");
        assert!(error.message.contains("runner.read scope"));
        assert!(error.message.contains("request_id=req-scope-1"));
        assert!(error.message.contains("requiredScope"));
    }

    #[test]
    fn runner_logout_revokes_the_presented_runner_token() {
        let (server_url, request, server) = serve_one_http_response(r#"{"data":{"revoked":true}}"#);
        let mut client = HttpManagementApiClient::new(&server_url, None).unwrap();
        let credential = test_credential("runner.logout.secret");

        let response = client.revoke_current_runner_token(&credential).unwrap();
        let raw_request = request.recv().unwrap();
        server.join().unwrap();

        assert_eq!(response["revoked"], true);
        assert!(raw_request
            .starts_with("POST /api/v1/runner-control/runner/v1/auth/logout/ HTTP/1.1\r\n"));
        assert!(raw_request
            .to_ascii_lowercase()
            .contains("authorization: bearer runner.logout.secret\r\n"));
    }

    #[test]
    fn api_key_exchange_uses_runner_control_endpoint() {
        let client = HttpManagementApiClient::new("http://loomex.localhost:28080", None).unwrap();

        assert_eq!(
            "http://loomex.localhost:28080/api/v1/runner-control/runner/v1/auth/exchange/",
            client.url(RUNNER_AUTH_EXCHANGE_PATH)
        );
    }

    #[test]
    fn organization_list_uses_signed_user_contract() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":[{"id":"org_123","name":"Acme"}],"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let organizations = client
            .list_organizations(&test_credential("user.jwt"))
            .unwrap();
        let request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(organizations[0].id, "org_123");
        assert!(request.starts_with("GET /api/v1/organizations/ HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer user.jwt\r\n"));
    }

    #[test]
    fn human_request_page_forwards_cursor_and_preserves_next_cursor() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"humanRequests":[{"id":"human-1","status":"resolved","title":"Review","answer":{"decision":"approve"}}],"nextCursor":"cursor-3"},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let page = client
            .list_human_requests_page(
                &test_credential("runner.secret"),
                &RunnerHumanRequestListQuery {
                    workflow_id: "workflow-1",
                    execution_id: Some("execution-1"),
                    request_type: Some("approval"),
                    status: Some("approved"),
                    cursor: Some("cursor-2"),
                    limit: 1,
                },
            )
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(page.human_requests[0].id, "human-1");
        assert_eq!(page.next_cursor.as_deref(), Some("cursor-3"));
        assert!(raw_request.starts_with("GET /api/v1/runner-control/runner/v1/human-requests/?"));
        for query in [
            "status=approved",
            "limit=1",
            "workflowId=workflow-1",
            "executionId=execution-1",
            "requestType=approval",
            "cursor=cursor-2",
        ] {
            assert!(
                raw_request.contains(query),
                "missing {query}: {raw_request}"
            );
        }
    }

    #[test]
    fn workflow_run_sends_required_idempotency_key_and_execution_root_payload() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"execution":{"id":"run-1","status":"queued"},"events":[],"latestSequence":0,"timedOut":false},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let response = client
            .start_runner_workflow_execution_scoped(
                &test_credential("runner.secret"),
                RunnerWorkflowExecutionStartOptions {
                    workflow_id: "workflow-1",
                    inputs: json!({"prompt":"hello"}),
                    workspace_path: Some("/repo"),
                    session_id: Some("session-1"),
                    version: Some("3"),
                    execution_mode: Some("plugin"),
                    idempotency_key: "run-attempt-1",
                },
            )
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(response.execution["id"], "run-1");
        assert!(raw_request
            .to_ascii_lowercase()
            .contains("idempotency-key: run-attempt-1\r\n"));
        assert!(raw_request.contains("\"workspacePath\":\"/repo\""));
        assert!(raw_request.contains("\"sessionId\":\"session-1\""));
        assert!(raw_request.contains("\"version\":\"3\""));
        assert!(raw_request.contains("\"executionMode\":\"plugin\""));
        assert!(raw_request.contains("\"inputs\":{\"prompt\":\"hello\"}"));
    }

    #[test]
    fn workflow_cancel_sends_required_reason_and_idempotency_key() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"execution":{"id":"run-1","status":"canceled"},"jobs":[]},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let response = client
            .cancel_runner_workflow_execution_mode_scoped(
                &test_credential("runner.secret"),
                "run-1",
                "No longer needed",
                "cancel-attempt-1",
                Some("plugin"),
            )
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(response["execution"]["status"], "canceled");
        assert!(raw_request
            .to_ascii_lowercase()
            .contains("idempotency-key: cancel-attempt-1\r\n"));
        assert!(raw_request.contains("\"reason\":\"No longer needed\""));
        assert!(raw_request.contains("\"executionMode\":\"plugin\""));
    }

    #[test]
    fn legacy_workflow_run_generates_bounded_deterministic_idempotency_key() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"execution":{"id":"run-legacy","status":"queued"},"events":[],"latestSequence":0,"timedOut":false},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        client
            .start_runner_workflow_execution(
                &test_credential("runner.secret"),
                "workflow-legacy",
                json!({"prompt":"hello"}),
                Some("session-legacy"),
                None,
            )
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        let header = raw_request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
            .unwrap();
        let key = header.split_once(':').unwrap().1.trim();
        assert!(key.starts_with("loomex-legacy-workflow.run-"));
        assert!(key.len() <= 160);
        assert_eq!(
            key,
            default_runner_operation_idempotency_key(
                "workflow.run",
                &json!({
                    "workflowId":"workflow-legacy",
                    "request": {
                        "inputs":{"prompt":"hello"},
                        "sessionId":"session-legacy"
                    }
                })
            )
            .unwrap()
        );
    }

    #[test]
    fn legacy_workflow_cancel_supplies_backend_required_reason_and_key() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"execution":{"id":"run-legacy","status":"canceled"},"jobs":[]},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        client
            .cancel_runner_workflow_execution(&test_credential("runner.secret"), "run-legacy")
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert!(raw_request
            .to_ascii_lowercase()
            .contains("idempotency-key: loomex-legacy-workflow.cancel-"));
        assert!(raw_request.contains("\"reason\":\"Requested by legacy Loomex client\""));
    }

    #[test]
    fn local_store_does_not_write_plain_token_and_round_trips() {
        let root = std::env::temp_dir().join(format!(
            "loomex-credentials-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        let store = LocalCredentialStore::new(root.clone());
        let credential = ManagementCredential::from_runner_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "management_secret".to_string(),
                refresh_token: Some("refresh_secret".to_string()),
                token_type: "Bearer".to_string(),
                expires_at: "2026-06-29T00:00:00Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();

        store.save(&credential).unwrap();
        let raw = fs::read_to_string(root.join("default.json")).unwrap();
        let loaded = store.load("default").unwrap().unwrap();
        let _ = fs::remove_dir_all(&root);

        assert!(!raw.contains("management_secret"));
        assert!(!raw.contains("refresh_secret"));
        assert!(raw.contains("loomex.cli.credential/v2"));
        assert_eq!(credential.access_token, loaded.access_token);
        assert_eq!(credential.refresh_token, loaded.refresh_token);
        assert_eq!(CredentialKind::RunnerControlV1, loaded.kind);
        assert!(loaded.storage_warning.unwrap().contains("fallback"));
    }

    #[test]
    fn legacy_credential_document_defaults_to_unknown_kind() {
        let document: LocalCredentialDocument = serde_json::from_str(
            r#"{
                "schema_version":"loomex.cli.credential/v1",
                "profile":"default",
                "organization_id":"org_123",
                "access_token_b64":"bGVnYWN5LXRva2Vu",
                "refresh_token_b64":null,
                "token_type":"Bearer",
                "expires_at":"9999-12-31T23:59:59Z",
                "storage_backend":"LocalFileFallback"
            }"#,
        )
        .unwrap();

        let credential = credential_from_document(document).unwrap();

        assert_eq!(CredentialKind::LegacyUnknown, credential.kind);
        assert_eq!("legacy-token", credential.access_token);
    }

    #[test]
    fn credential_debug_redacts_token() {
        let credential = ManagementCredential::from_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "management_secret".to_string(),
                refresh_token: Some("refresh_secret".to_string()),
                token_type: "Bearer".to_string(),
                expires_at: "2026-06-29T00:00:00Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();

        let debug = format!("{credential:?}");

        assert!(!debug.contains("management_secret"));
        assert!(!debug.contains("refresh_secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_auth_token_shape_is_rejected() {
        let err = ManagementCredential::from_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: String::new(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "2026-06-29T00:00:00Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap_err();

        assert_eq!("AUTH_TOKEN_INVALID", err.code);
    }

    #[test]
    fn expired_and_near_expiry_management_tokens_fail_deterministically() {
        let credential = ManagementCredential::from_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "management_secret".to_string(),
                refresh_token: Some("refresh_secret".to_string()),
                token_type: "Bearer".to_string(),
                expires_at: "2026-06-29T00:00:00Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();

        assert_eq!(
            "AUTH_TOKEN_EXPIRED",
            credential
                .validate_not_expiring(1_782_691_200, 300)
                .unwrap_err()
                .code
        );
        assert_eq!(
            "AUTH_TOKEN_EXPIRED",
            credential
                .validate_not_expiring(1_782_690_950, 300)
                .unwrap_err()
                .code
        );
        credential
            .validate_not_expiring(1_782_690_000, 300)
            .unwrap();
    }

    #[test]
    fn management_error_envelope_preserves_code_message_and_request_id() {
        let err = management_error_from_status_and_body(
            403,
            r#"{"code":"ORGANIZATION_FORBIDDEN","message":"No access","details":{"organization_id":"org_123"},"request_id":"req_123"}"#,
        );

        assert_eq!("ORGANIZATION_FORBIDDEN", err.code);
        assert!(err.message.contains("No access"));
        assert!(err.message.contains("request_id=req_123"));
        assert!(err.message.contains("organization_id"));
    }

    #[test]
    fn runner_workflow_execution_response_preserves_ai_trace() {
        let response = serde_json::from_str::<RunnerWorkflowExecutionResponse>(
            r#"{
                "execution": {"id": "exec_123", "status": "running"},
                "aiTrace": {
                    "schemaVersion": "loomex.runner.aiTrace/v1",
                    "events": [{"sequence": 1, "type": "ai.message.completed", "content": "done"}]
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            response
                .ai_trace
                .as_ref()
                .and_then(|trace| trace.get("events"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn runner_workflow_detail_deserializes_backend_capability_flags() {
        let envelope = serde_json::from_str::<ClientEnvelope<RunnerWorkflowInputSchemaResponse>>(
            r#"{
                "data": {
                    "workflow": {"id": "workflow_123"},
                    "inputSchema": {"type": "object"},
                    "nodes": [{"key": "review", "type": "human"}],
                    "capabilities": {
                        "hasHumanInput": true,
                        "hasSubWorkflow": false,
                        "hasAiAgent": true,
                        "hasGitTool": false,
                        "hasHttpRequest": false,
                        "hasCondition": false,
                        "hasSwitch": false
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            envelope.data.capabilities.get("hasHumanInput"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            envelope.data.capabilities.get("hasSubWorkflow"),
            Some(&Value::Bool(false))
        );
        let serialized = serde_json::to_value(envelope.data).unwrap();
        assert!(serialized["capabilities"].is_object());
        assert_eq!(serialized["capabilities"]["hasAiAgent"], true);
    }

    #[test]
    fn unauthorized_error_envelope_preserves_contract_code() {
        let err = management_error_from_status_and_body(
            401,
            r#"{"code":"AUTH_TOKEN_EXPIRED","message":"Token expired","request_id":"req_auth","details":{"profile":"default"}}"#,
        );

        assert_eq!("AUTH_TOKEN_EXPIRED", err.code);
        assert!(err.message.contains("Token expired"));
        assert!(err.message.contains("request_id=req_auth"));
    }

    #[test]
    fn nested_management_error_envelope_preserves_contract_code() {
        let err = management_error_from_status_and_body(
            422,
            r#"{"error":{"code":"LOCAL_RUNNER_REQUIRED","message":"Local workflow execution requires an online runner.","details":{}},"meta":{"correlationId":"req_nested","version":"v1"}}"#,
        );

        assert_eq!("LOCAL_RUNNER_REQUIRED", err.code);
        assert!(err
            .message
            .contains("Local workflow execution requires an online runner."));
        assert!(!err.message.contains("management API returned HTTP 422"));
    }
}
