use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    pub project_id: Option<String>,
    pub runner_id: Option<String>,
    pub binding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLoginResult {
    pub token: String,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
}

impl ApiKeyExchangeResult {
    pub fn from_token(token: AuthTokenResponse) -> Self {
        Self {
            token,
            organization_id: None,
            project_id: None,
            runner_id: None,
            binding_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub status: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRunnerBindingCreateRequest {
    pub organization_id: String,
    pub runner_id: String,
    pub local_root_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_root_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagementProjectRunnerBinding {
    pub id: String,
    pub organization_id: String,
    pub project_id: String,
    pub runner_id: String,
    #[serde(alias = "workspaceRoot", alias = "workspacePath")]
    pub local_root_path: String,
    pub status: String,
    #[serde(default)]
    pub local_root_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRunStartRequest {
    pub organization_id: String,
    pub project_id: String,
    pub workflow_id: String,
    pub inputs: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_runner_binding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRunStartResponse {
    pub id: String,
    pub status: String,
    #[serde(default, rename = "uiUrl", alias = "ui_url")]
    pub ui_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCredentialRequest {
    pub organization_id: String,
    pub project_id: String,
    pub runner_id: String,
    pub project_runner_binding_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_session_id: Option<String>,
    pub protocol_version: String,
    pub runner_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCredentialResponse {
    pub stream_token: String,
    pub token_type: String,
    pub audience: String,
    pub runner_session_id: String,
    pub expires_at: String,
    pub grpc_endpoint: String,
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
    pub binding_id: &'a str,
    pub inputs: Value,
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
struct ClientWorkflowRunStartRequest {
    input: Value,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "projectRunnerBindingId"
    )]
    project_runner_binding_id: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none", rename = "sessionId")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "bindingId")]
    binding_id: Option<String>,
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
    #[serde(default)]
    project_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceLoginData {
    token: String,
    #[serde(default)]
    organization: Option<WorkspaceOrganizationData>,
    #[serde(default)]
    projects: Vec<WorkspaceProjectData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceOrganizationData {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceProjectData {
    id: String,
    #[serde(default)]
    organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerAuthRunner {
    id: String,
    #[serde(default)]
    project_id: Option<String>,
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
    fn bootstrap_runner_with_workspace_token(
        &mut self,
        workspace_token: &str,
        organization_id: &str,
        project_id: Option<&str>,
        workspace_root: Option<&str>,
    ) -> CoreResult<ApiKeyExchangeResult>;
    fn list_organizations(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<Organization>>;
    fn list_projects(
        &mut self,
        credential: &ManagementCredential,
        organization_id: &str,
    ) -> CoreResult<Vec<Project>>;
    fn get_project(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
    ) -> CoreResult<Project>;
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
    fn list_runner_binding_statuses(
        &mut self,
        _credential: &ManagementCredential,
    ) -> CoreResult<Value> {
        Err(CoreError::new(
            "RUNNER_BINDING_STATUS_UNSUPPORTED",
            "management client does not support runner binding status",
        ))
    }
    fn list_runner_binding_statuses_filtered(
        &mut self,
        credential: &ManagementCredential,
        project_id: Option<&str>,
        status: Option<&str>,
    ) -> CoreResult<Value> {
        let mut value = self.list_runner_binding_statuses(credential)?;
        if let Some(bindings) = value.get_mut("bindings").and_then(Value::as_array_mut) {
            bindings.retain(|binding| {
                project_id.is_none_or(|expected| {
                    binding.get("projectId").and_then(Value::as_str) == Some(expected)
                }) && status.is_none_or(|expected| {
                    expected == "all"
                        || binding.get("status").and_then(Value::as_str) == Some(expected)
                })
            });
        }
        Ok(value)
    }
    fn upsert_current_runner(
        &mut self,
        credential: &ManagementCredential,
        request: &RunnerUpsertRequest,
        idempotency_key: &str,
    ) -> CoreResult<Runner>;
    fn create_project_runner_binding(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
        request: &ProjectRunnerBindingCreateRequest,
        idempotency_key: &str,
    ) -> CoreResult<ManagementProjectRunnerBinding>;
    fn list_project_runner_bindings(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
    ) -> CoreResult<Vec<ManagementProjectRunnerBinding>>;
    fn revoke_project_runner_binding(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
        binding_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<()>;
    fn start_workflow_run(
        &mut self,
        credential: &ManagementCredential,
        request: &WorkflowRunStartRequest,
    ) -> CoreResult<WorkflowRunStartResponse>;
    fn list_runner_workflows(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Vec<RunnerWorkflowSummary>>;
    fn list_runner_workflows_filtered(
        &mut self,
        credential: &ManagementCredential,
        _project_id: Option<&str>,
        execution_mode: Option<&str>,
        query: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<Value> {
        let mut workflows = self.list_runner_workflows(credential)?;
        if let Some(execution_mode) = execution_mode.filter(|value| !value.trim().is_empty()) {
            workflows.retain(|workflow| runner_workflow_execution_mode(workflow) == execution_mode);
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
        if options.binding_id.trim().is_empty() {
            return Err(CoreError::new(
                "RUNNER_BINDING_REQUIRED",
                "bindingId is required for local workflow execution",
            ));
        }
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
        workspace_root: &str,
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
    fn issue_stream_credential(
        &mut self,
        credential: &ManagementCredential,
        request: &StreamCredentialRequest,
        idempotency_key: &str,
    ) -> CoreResult<StreamCredentialResponse>;
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
        let project_id = envelope.data.project_id.or(envelope.data.runner.project_id);
        Ok(ApiKeyExchangeResult {
            token: AuthTokenResponse {
                access_token: envelope.data.runner_token,
                refresh_token: None,
                token_type: envelope.data.token_type,
                expires_at: RUNNER_TOKEN_NON_EXPIRING_EXPIRES_AT.to_string(),
            },
            organization_id: Some(envelope.data.organization_id),
            project_id: project_id.clone(),
            runner_id: Some(envelope.data.runner.id.clone()),
            binding_id: project_id.map(|_| envelope.data.runner.id),
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
        let project_id = envelope
            .data
            .projects
            .into_iter()
            .find(|project| {
                organization_id
                    .as_deref()
                    .map(|org| project.organization_id.as_deref() == Some(org))
                    .unwrap_or(true)
            })
            .map(|project| project.id);
        Ok(WorkspaceLoginResult {
            token: envelope.data.token,
            organization_id,
            project_id,
        })
    }

    fn bootstrap_runner_with_workspace_token(
        &mut self,
        workspace_token: &str,
        organization_id: &str,
        project_id: Option<&str>,
        workspace_root: Option<&str>,
    ) -> CoreResult<ApiKeyExchangeResult> {
        let response = self
            .apply_common_headers(
                self.client
                    .post(self.url(RUNNER_AUTH_BOOTSTRAP_PATH))
                    .bearer_auth(workspace_token),
            )
            .json(&serde_json::json!({
                "organizationId": organization_id,
                "projectId": project_id,
                "workspaceRoot": workspace_root.unwrap_or(""),
                "runnerName": "Local runner",
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<RunnerAuthExchangeData> = parse_json_response(response)?;
        let project_id = envelope.data.project_id.or(envelope.data.runner.project_id);
        Ok(ApiKeyExchangeResult {
            token: AuthTokenResponse {
                access_token: envelope.data.runner_token,
                refresh_token: None,
                token_type: envelope.data.token_type,
                expires_at: RUNNER_TOKEN_NON_EXPIRING_EXPIRES_AT.to_string(),
            },
            organization_id: Some(envelope.data.organization_id),
            project_id: project_id.clone(),
            runner_id: Some(envelope.data.runner.id.clone()),
            binding_id: project_id.map(|_| envelope.data.runner.id),
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

    fn list_projects(
        &mut self,
        credential: &ManagementCredential,
        organization_id: &str,
    ) -> CoreResult<Vec<Project>> {
        let response = self
            .get_with_auth(
                &format!(
                    "/projects/?organization_id={}",
                    encode_query(organization_id)
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Vec<Project>> = parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn get_project(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
    ) -> CoreResult<Project> {
        let response = self
            .get_with_auth("/projects/", credential)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Vec<Project>> = parse_json_response(response)?;
        envelope
            .data
            .into_iter()
            .find(|project| project.id == project_id)
            .ok_or_else(|| CoreError::new("PROJECT_NOT_FOUND", project_id))
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

    fn create_project_runner_binding(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
        request: &ProjectRunnerBindingCreateRequest,
        idempotency_key: &str,
    ) -> CoreResult<ManagementProjectRunnerBinding> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/bindings/", credential)
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({
                "projectId": project_id,
                "organizationId": request.organization_id,
                "runnerId": request.runner_id,
                "localRootPath": request.local_root_path,
                "localRootFingerprint": request.local_root_fingerprint,
            }))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<ManagementProjectRunnerBinding> =
            parse_json_response(response)?;
        Ok(envelope.data)
    }

    fn list_project_runner_bindings(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
    ) -> CoreResult<Vec<ManagementProjectRunnerBinding>> {
        let response = self
            .get_with_auth(
                &format!(
                    "/runner-control/runner/v1/bindings/?projectId={}",
                    encode_query(project_id)
                ),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
        serde_json::from_value(
            envelope
                .data
                .get("bindings")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )
        .map_err(|err| CoreError::new("MANAGEMENT_RESPONSE_INVALID", err.to_string()))
    }

    fn revoke_project_runner_binding(
        &mut self,
        credential: &ManagementCredential,
        project_id: &str,
        binding_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<()> {
        let response = self
            .post_with_auth(
                &format!(
                    "/runner-control/runner/v1/bindings/{}/revoke/",
                    encode_path(binding_id)
                ),
                credential,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({"projectId": project_id}))
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let _: ClientEnvelope<Value> = parse_json_response(response)?;
        Ok(())
    }

    fn start_workflow_run(
        &mut self,
        credential: &ManagementCredential,
        request: &WorkflowRunStartRequest,
    ) -> CoreResult<WorkflowRunStartResponse> {
        let response = self
            .post_with_auth(
                &format!(
                    "/client/workflows/{}/runs/",
                    encode_path(&request.workflow_id)
                ),
                credential,
            )
            .json(&ClientWorkflowRunStartRequest {
                input: request.inputs.clone(),
                project_runner_binding_id: request.project_runner_binding_id.clone(),
            })
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<WorkflowRunStartResponse> = parse_json_response(response)?;
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

    fn list_runner_binding_statuses_filtered(
        &mut self,
        credential: &ManagementCredential,
        project_id: Option<&str>,
        status: Option<&str>,
    ) -> CoreResult<Value> {
        let mut query = Vec::new();
        if let Some(project_id) = project_id.filter(|value| !value.trim().is_empty()) {
            query.push(format!("projectId={}", encode_query(project_id)));
        }
        if let Some(status) = status.filter(|value| !value.trim().is_empty()) {
            query.push(format!("status={}", encode_query(status)));
        }
        let suffix = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        let response = self
            .get_with_auth(
                &format!("/runner-control/runner/v1/bindings/{suffix}"),
                credential,
            )
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        let envelope: ClientEnvelope<Value> = parse_json_response(response)?;
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

    fn list_runner_binding_statuses(
        &mut self,
        credential: &ManagementCredential,
    ) -> CoreResult<Value> {
        let response = self
            .get_with_auth("/runner-control/runner/v1/bindings/status/", credential)
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

    fn list_runner_workflows_filtered(
        &mut self,
        credential: &ManagementCredential,
        project_id: Option<&str>,
        execution_mode: Option<&str>,
        query: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> CoreResult<Value> {
        let mut params = vec![format!("limit={}", limit.clamp(1, 200))];
        if let Some(value) = project_id.filter(|value| !value.trim().is_empty()) {
            params.push(format!("projectId={}", encode_query(value)));
        }
        if let Some(value) = execution_mode.filter(|value| !value.trim().is_empty()) {
            params.push(format!("executionMode={}", encode_query(value)));
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
            session_id: session_id.map(str::to_string),
            version: version.map(str::to_string),
            binding_id: None,
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
                session_id: options.session_id.map(str::to_string),
                version: options.version.map(str::to_string),
                binding_id: Some(options.binding_id.to_string()),
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
        workspace_root: &str,
        manifest: Value,
        transport: &str,
    ) -> CoreResult<RunnerSessionResponse> {
        let response = self
            .post_with_auth("/runner-control/runner/v1/sessions/", credential)
            .json(&serde_json::json!({
                "workspaceRoot": workspace_root,
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

    fn issue_stream_credential(
        &mut self,
        credential: &ManagementCredential,
        request: &StreamCredentialRequest,
        idempotency_key: &str,
    ) -> CoreResult<StreamCredentialResponse> {
        let response = self
            .post_with_auth("/runners/current/stream-credential", credential)
            .header("Idempotency-Key", idempotency_key)
            .json(request)
            .send()
            .map_err(|err| CoreError::new("MANAGEMENT_HTTP_FAILED", err.to_string()))?;
        parse_json_response(response)
    }
}

fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
) -> CoreResult<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(management_error_from_status_and_body(
            status.as_u16(),
            &body,
        ));
    }
    response
        .json::<T>()
        .map_err(|err| CoreError::new("MANAGEMENT_RESPONSE_INVALID", err.to_string()))
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
    fn user_project_and_runner_bootstrap_http_contracts_are_exact() {
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":[{"id":"project-1","organizationId":"org-1","name":"Demo","status":"active"}]}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let projects = client
            .list_projects(&test_credential("user.jwt"), "org / one")
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(projects[0].id, "project-1");
        assert!(
            raw.starts_with("GET /api/v1/projects/?organization_id=org%20%2F%20one HTTP/1.1\r\n")
        );
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer user.jwt\r\n"));

        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"runner":{"id":"runner-1","projectId":"project-1"},"runnerToken":"runner.jwt","tokenType":"Bearer","organizationId":"org-1","projectId":"project-1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let exchange = client
            .bootstrap_runner_with_workspace_token(
                "user.jwt",
                "org-1",
                Some("project-1"),
                Some("/repo"),
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(exchange.runner_id.as_deref(), Some("runner-1"));
        assert!(
            raw.starts_with("POST /api/v1/runner-control/runner/v1/auth/bootstrap/ HTTP/1.1\r\n")
        );
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer user.jwt\r\n"));
        for body in [
            r#""organizationId":"org-1""#,
            r#""projectId":"project-1""#,
            r#""workspaceRoot":"/repo""#,
        ] {
            assert!(raw.contains(body), "missing {body}: {raw}");
        }
    }

    #[test]
    fn binding_list_and_revoke_http_contracts_are_exact() {
        let (server_url, request, server) = serve_one_http_response(
            r#"{"data":{"bindings":[{"id":"binding-1","organizationId":"org-1","projectId":"project-1","runnerId":"runner-1","localRootPath":"/repo","status":"active"}]}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let bindings = client
            .list_project_runner_bindings(&test_credential("runner.jwt"), "project / one")
            .unwrap();
        let raw = captured_request(request, server);
        assert_eq!(bindings[0].id, "binding-1");
        assert!(raw.starts_with(
            "GET /api/v1/runner-control/runner/v1/bindings/?projectId=project%20%2F%20one HTTP/1.1\r\n"
        ));
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer runner.jwt\r\n"));

        let (server_url, request, server) = serve_one_http_response(r#"{"data":{"revoked":true}}"#);
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        client
            .revoke_project_runner_binding(
                &test_credential("runner.jwt"),
                "project-1",
                "binding / one",
                "binding-revoke-1",
            )
            .unwrap();
        let raw = captured_request(request, server);
        assert!(raw.starts_with(
            "POST /api/v1/runner-control/runner/v1/bindings/binding%20%2F%20one/revoke/ HTTP/1.1\r\n"
        ));
        let lowered = raw.to_ascii_lowercase();
        assert!(lowered.contains("authorization: bearer runner.jwt\r\n"));
        assert!(lowered.contains("idempotency-key: binding-revoke-1\r\n"));
        assert!(raw.contains(r#"{"projectId":"project-1"}"#));
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
                Some("project-1"),
                Some("plugin"),
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
            "projectId=project-1",
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

        let cases = [
            ("self", "/api/v1/runner-control/runner/v1/self/", None, None),
            (
                "bindings-status",
                "/api/v1/runner-control/runner/v1/bindings/status/",
                None,
                None,
            ),
            (
                "bindings-filtered",
                "/api/v1/runner-control/runner/v1/bindings/?projectId=project-1&status=all",
                Some("project-1"),
                Some("all"),
            ),
        ];
        for (operation, path, project_id, status) in cases {
            let (server_url, request, server) =
                serve_one_http_response(r#"{"data":{"bindings":[]}}"#);
            let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
            match operation {
                "self" => {
                    client.get_runner_self_status(&credential).unwrap();
                }
                "bindings-status" => {
                    client.list_runner_binding_statuses(&credential).unwrap();
                }
                "bindings-filtered" => {
                    client
                        .list_runner_binding_statuses_filtered(&credential, project_id, status)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let raw = captured_request(request, server);
            assert!(
                raw.starts_with(&format!("GET {path} HTTP/1.1\r\n")),
                "unexpected {operation} request: {raw}"
            );
            assert!(raw
                .to_ascii_lowercase()
                .contains("authorization: bearer runner.jwt\r\n"));
        }
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
    fn project_lookup_uses_collection_contract_instead_of_missing_detail_route() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":[{"id":"prj_other","organizationId":"org_123","name":"Other","status":"active"},{"id":"prj_123","organizationId":"org_123","name":"Demo","status":"active"}],"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let project = client
            .get_project(&test_credential("user.jwt"), "prj_123")
            .unwrap();
        let request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(project.name, "Demo");
        assert!(request.starts_with("GET /api/v1/projects/ HTTP/1.1\r\n"));
        assert!(!request.contains("/projects/prj_123"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer user.jwt\r\n"));
    }

    #[test]
    fn binding_create_uses_runner_token_contract_and_unwraps_envelope() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"id":"11111111-1111-1111-1111-111111111111","organizationId":"22222222-2222-2222-2222-222222222222","projectId":"33333333-3333-3333-3333-333333333333","runnerId":"11111111-1111-1111-1111-111111111111","localRootPath":"/tmp/workspace","status":"active","localRootFingerprint":"fp"},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();
        let request = ProjectRunnerBindingCreateRequest {
            organization_id: "22222222-2222-2222-2222-222222222222".to_string(),
            runner_id: "11111111-1111-1111-1111-111111111111".to_string(),
            local_root_path: "/tmp/workspace".to_string(),
            local_root_fingerprint: Some("fp".to_string()),
        };

        let binding = client
            .create_project_runner_binding(
                &test_credential("runner.secret"),
                "33333333-3333-3333-3333-333333333333",
                &request,
                "binding-key",
            )
            .unwrap();
        let raw_request = request_receiver.recv().unwrap();
        server.join().unwrap();

        assert_eq!(binding.runner_id, request.runner_id);
        assert!(
            raw_request.starts_with("POST /api/v1/runner-control/runner/v1/bindings/ HTTP/1.1\r\n")
        );
        let lowered = raw_request.to_ascii_lowercase();
        assert!(lowered.contains("authorization: bearer runner.secret\r\n"));
        assert!(lowered.contains("idempotency-key: binding-key\r\n"));
        assert!(raw_request.contains("\"projectId\":\"33333333-3333-3333-3333-333333333333\""));
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
    fn workflow_run_sends_required_idempotency_key_and_bound_payload() {
        let (server_url, request_receiver, server) = serve_one_http_response(
            r#"{"data":{"execution":{"id":"run-1","status":"queued"},"events":[],"latestSequence":0,"timedOut":false},"meta":{"version":"v1"}}"#,
        );
        let mut client = HttpManagementApiClient::new(server_url, None).unwrap();

        let response = client
            .start_runner_workflow_execution_scoped(
                &test_credential("runner.secret"),
                RunnerWorkflowExecutionStartOptions {
                    workflow_id: "workflow-1",
                    binding_id: "binding-1",
                    inputs: json!({"prompt":"hello"}),
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
        assert!(raw_request.contains("\"bindingId\":\"binding-1\""));
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
            r#"{"code":"PROJECT_FORBIDDEN","message":"No access","details":{"project_id":"prj_123"},"request_id":"req_123"}"#,
        );

        assert_eq!("PROJECT_FORBIDDEN", err.code);
        assert!(err.message.contains("No access"));
        assert!(err.message.contains("request_id=req_123"));
        assert!(err.message.contains("project_id"));
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
            r#"{"error":{"code":"LOCAL_RUNNER_REQUIRED","message":"Local workflow execution requires an online project runner.","details":{}},"meta":{"correlationId":"req_nested","version":"v1"}}"#,
        );

        assert_eq!("LOCAL_RUNNER_REQUIRED", err.code);
        assert!(err
            .message
            .contains("Local workflow execution requires an online project runner."));
        assert!(!err.message.contains("management API returned HTTP 422"));
    }
}
