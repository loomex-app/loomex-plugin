use std::collections::{BTreeMap, BTreeSet};

use crate::grpc::StreamCredential;
use crate::{CoreError, CoreResult};

pub const STREAM_TOKEN_AUDIENCE: &str = "runner_stream";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDeviceMetadata {
    pub organization_id: String,
    pub user_id: String,
    pub machine_id: String,
    pub os: String,
    pub arch: String,
    pub runner_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDeviceRecord {
    pub runner_device_id: String,
    pub metadata: RunnerDeviceMetadata,
    pub revoked: bool,
}

impl RunnerDeviceRecord {
    pub fn upsert(existing: Option<Self>, metadata: RunnerDeviceMetadata) -> CoreResult<Self> {
        validate_device_metadata(&metadata)?;
        if let Some(record) = existing {
            if same_device_tuple(&record.metadata, &metadata) {
                if record.revoked {
                    return Err(CoreError::new(
                        "RUNNER_DEVICE_REVOKED",
                        "revoked runner device cannot be restored by normal upsert",
                    ));
                }
                return Ok(Self {
                    runner_device_id: record.runner_device_id,
                    metadata,
                    revoked: false,
                });
            }
        }

        Ok(Self {
            runner_device_id: stable_device_id(&metadata),
            metadata,
            revoked: false,
        })
    }
}

fn same_device_tuple(left: &RunnerDeviceMetadata, right: &RunnerDeviceMetadata) -> bool {
    left.organization_id == right.organization_id
        && left.user_id == right.user_id
        && left.machine_id == right.machine_id
}

pub fn stable_device_id(metadata: &RunnerDeviceMetadata) -> String {
    let seed = [
        metadata.organization_id.as_str(),
        metadata.user_id.as_str(),
        metadata.machine_id.as_str(),
        metadata.os.as_str(),
        metadata.arch.as_str(),
    ]
    .join("\0");
    format!("device_{:016x}", fnv1a64(seed.as_bytes()))
}

fn validate_device_metadata(metadata: &RunnerDeviceMetadata) -> CoreResult<()> {
    for (field, value) in [
        ("organization_id", &metadata.organization_id),
        ("user_id", &metadata.user_id),
        ("machine_id", &metadata.machine_id),
        ("os", &metadata.os),
        ("arch", &metadata.arch),
        ("runner_version", &metadata.runner_version),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("DEVICE_METADATA_MISSING_FIELD", field));
        }
    }
    Ok(())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TokenScope {
    Management,
    Stream,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredToken {
    pub scope: TokenScope,
    pub organization_id: String,
    pub project_id: Option<String>,
    pub runner_device_id: Option<String>,
    pub audience: Option<String>,
    pub token: String,
    pub expires_at_epoch_ms: Option<u64>,
    pub generation: u64,
    pub revoked: bool,
}

impl std::fmt::Debug for StoredToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredToken")
            .field("scope", &self.scope)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("runner_device_id", &self.runner_device_id)
            .field("audience", &self.audience)
            .field("token", &"[REDACTED]")
            .field("expires_at_epoch_ms", &self.expires_at_epoch_ms)
            .field("generation", &self.generation)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl StoredToken {
    pub fn management(
        organization_id: impl Into<String>,
        token: impl Into<String>,
        expires_at_epoch_ms: Option<u64>,
    ) -> Self {
        Self {
            scope: TokenScope::Management,
            organization_id: organization_id.into(),
            project_id: None,
            runner_device_id: None,
            audience: None,
            token: token.into(),
            expires_at_epoch_ms,
            generation: 1,
            revoked: false,
        }
    }

    pub fn stream(
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        runner_device_id: impl Into<String>,
        token: impl Into<String>,
        expires_at_epoch_ms: u64,
    ) -> Self {
        Self {
            scope: TokenScope::Stream,
            organization_id: organization_id.into(),
            project_id: Some(project_id.into()),
            runner_device_id: Some(runner_device_id.into()),
            audience: Some(STREAM_TOKEN_AUDIENCE.to_string()),
            token: token.into(),
            expires_at_epoch_ms: Some(expires_at_epoch_ms),
            generation: 1,
            revoked: false,
        }
    }

    pub fn is_expired(&self, now_epoch_ms: u64) -> bool {
        match self.expires_at_epoch_ms {
            Some(expires_at) => now_epoch_ms >= expires_at,
            None => false,
        }
    }

    pub fn rotate(
        &self,
        token: impl Into<String>,
        expires_at_epoch_ms: Option<u64>,
    ) -> CoreResult<Self> {
        if self.revoked {
            return Err(CoreError::new(
                "TOKEN_REVOKED",
                "revoked token cannot be rotated locally",
            ));
        }
        if self.scope == TokenScope::Stream && expires_at_epoch_ms.is_none() {
            return Err(CoreError::new(
                "STREAM_AUTH_MISSING_EXPIRY",
                "stream token expiry is required",
            ));
        }
        let mut rotated = self.clone();
        rotated.token = token.into();
        rotated.expires_at_epoch_ms = expires_at_epoch_ms;
        rotated.generation += 1;
        Ok(rotated)
    }
}

pub trait TokenStore {
    fn save(&mut self, token: StoredToken) -> CoreResult<()>;
    fn load(&self, scope: TokenScope) -> CoreResult<Option<StoredToken>>;
    fn delete(&mut self, scope: TokenScope) -> CoreResult<()>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryTokenStore {
    tokens: BTreeMap<TokenScope, StoredToken>,
}

impl TokenStore for MemoryTokenStore {
    fn save(&mut self, token: StoredToken) -> CoreResult<()> {
        validate_token_material(&token)?;
        self.tokens.insert(token.scope, token);
        Ok(())
    }

    fn load(&self, scope: TokenScope) -> CoreResult<Option<StoredToken>> {
        Ok(self.tokens.get(&scope).cloned())
    }

    fn delete(&mut self, scope: TokenScope) -> CoreResult<()> {
        self.tokens.remove(&scope);
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TokenStorageBackend {
    MacOsKeychain,
    DevSecureFileFallback,
}

pub fn select_token_storage_backend(
    os: &str,
    keychain_available: bool,
    allow_dev_file_fallback: bool,
) -> CoreResult<TokenStorageBackend> {
    if os == "macos" && keychain_available {
        return Ok(TokenStorageBackend::MacOsKeychain);
    }
    if allow_dev_file_fallback {
        return Ok(TokenStorageBackend::DevSecureFileFallback);
    }
    Err(CoreError::new(
        "TOKEN_STORE_UNAVAILABLE",
        "macOS keychain is unavailable and dev secure-file fallback is disabled",
    ))
}

pub fn validate_management_api_token(
    token: &StoredToken,
    organization_id: &str,
    now_epoch_ms: u64,
) -> CoreResult<()> {
    validate_token_material(token)?;
    if token.scope != TokenScope::Management {
        return Err(CoreError::new(
            "TOKEN_SCOPE_MISMATCH",
            "stream token cannot call management APIs",
        ));
    }
    validate_common_token(token, organization_id, now_epoch_ms)
}

pub fn reusable_management_token_generation(
    token: &StoredToken,
    organization_id: &str,
    now_epoch_ms: u64,
) -> CoreResult<u64> {
    validate_management_api_token(token, organization_id, now_epoch_ms)?;
    Ok(token.generation)
}

pub fn validate_stream_token_for_stream(
    token: &StoredToken,
    organization_id: &str,
    project_id: &str,
    runner_device_id: &str,
    now_epoch_ms: u64,
) -> CoreResult<()> {
    validate_token_material(token)?;
    if token.scope != TokenScope::Stream {
        return Err(CoreError::new(
            "TOKEN_SCOPE_MISMATCH",
            "management token cannot open runner stream",
        ));
    }
    if token.expires_at_epoch_ms.is_none() {
        return Err(CoreError::new(
            "STREAM_AUTH_MISSING_EXPIRY",
            "stream token expiry is required",
        ));
    }
    validate_common_token(token, organization_id, now_epoch_ms)?;
    if token.audience.as_deref() != Some(STREAM_TOKEN_AUDIENCE) {
        return Err(CoreError::new(
            "STREAM_TOKEN_AUDIENCE_INVALID",
            "stream token audience must be runner_stream",
        ));
    }
    if token.project_id.as_deref() != Some(project_id) {
        return Err(CoreError::new(
            "STREAM_TOKEN_PROJECT_MISMATCH",
            "stream token project does not match request",
        ));
    }
    if token.runner_device_id.as_deref() != Some(runner_device_id) {
        return Err(CoreError::new(
            "STREAM_TOKEN_DEVICE_MISMATCH",
            "stream token device does not match request",
        ));
    }
    Ok(())
}

pub fn should_refresh_stream_token(
    token: &StoredToken,
    now_epoch_ms: u64,
    refresh_before_ms: u64,
) -> CoreResult<bool> {
    if token.scope != TokenScope::Stream {
        return Err(CoreError::new(
            "TOKEN_SCOPE_MISMATCH",
            "refresh applies only to stream tokens",
        ));
    }
    let Some(expires_at) = token.expires_at_epoch_ms else {
        return Err(CoreError::new(
            "STREAM_AUTH_MISSING_EXPIRY",
            "stream token expiry is required",
        ));
    };
    Ok(now_epoch_ms.saturating_add(refresh_before_ms) >= expires_at)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCredentialRequest {
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub runner_session_id: String,
    pub nonce: String,
    pub runner_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCredentialGrant {
    pub credential: StreamCredential,
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub runner_session_id: String,
    pub nonce: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplayNonceStore {
    seen: BTreeSet<(String, String)>,
}

impl ReplayNonceStore {
    pub fn accept(&mut self, runner_session_id: &str, nonce: &str) -> CoreResult<()> {
        if runner_session_id.trim().is_empty() || nonce.trim().is_empty() {
            return Err(CoreError::new(
                "STREAM_NONCE_MISSING",
                "runner session id and nonce are required",
            ));
        }
        let key = (runner_session_id.to_string(), nonce.to_string());
        if !self.seen.insert(key) {
            return Err(CoreError::new(
                "STREAM_REPLAY_DETECTED",
                "duplicate runner session nonce rejected",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RevocationState {
    pub device_revoked: bool,
    pub binding_revoked: bool,
    pub token_revoked: bool,
}

impl RevocationState {
    pub fn validate_stream_allowed(&self) -> CoreResult<()> {
        if self.device_revoked {
            return Err(CoreError::new(
                "RUNNER_DEVICE_REVOKED",
                "runner device has been revoked",
            ));
        }
        if self.binding_revoked {
            return Err(CoreError::new(
                "RUNNER_BINDING_REVOKED",
                "runner binding has been revoked",
            ));
        }
        if self.token_revoked {
            return Err(CoreError::new(
                "RUNNER_TOKEN_REVOKED",
                "runner token has been revoked",
            ));
        }
        Ok(())
    }
}

pub fn issue_stream_credential(
    management_token: &StoredToken,
    request: &StreamCredentialRequest,
    nonce_store: &mut ReplayNonceStore,
    revocation: &RevocationState,
    now_epoch_ms: u64,
    lifetime_ms: u64,
) -> CoreResult<StreamCredentialGrant> {
    validate_request(request)?;
    revocation.validate_stream_allowed()?;
    validate_management_api_token(management_token, &request.organization_id, now_epoch_ms)?;
    nonce_store.accept(&request.runner_session_id, &request.nonce)?;

    let expires_at = now_epoch_ms.saturating_add(lifetime_ms);
    Ok(StreamCredentialGrant {
        credential: StreamCredential {
            stream_token: format!(
                "stream_{}_{}_{}",
                request.runner_device_id, request.runner_session_id, expires_at
            ),
            audience: STREAM_TOKEN_AUDIENCE.to_string(),
            expires_at_epoch_ms: expires_at,
        },
        organization_id: request.organization_id.clone(),
        project_id: request.project_id.clone(),
        runner_device_id: request.runner_device_id.clone(),
        runner_session_id: request.runner_session_id.clone(),
        nonce: request.nonce.clone(),
    })
}

fn validate_request(request: &StreamCredentialRequest) -> CoreResult<()> {
    for (field, value) in [
        ("organization_id", &request.organization_id),
        ("project_id", &request.project_id),
        ("runner_device_id", &request.runner_device_id),
        ("runner_session_id", &request.runner_session_id),
        ("nonce", &request.nonce),
        ("runner_version", &request.runner_version),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new(
                "STREAM_CREDENTIAL_REQUEST_MISSING_FIELD",
                field,
            ));
        }
    }
    Ok(())
}

fn validate_common_token(
    token: &StoredToken,
    organization_id: &str,
    now_epoch_ms: u64,
) -> CoreResult<()> {
    if token.organization_id != organization_id {
        return Err(CoreError::new(
            "TOKEN_ORG_MISMATCH",
            "token organization does not match request",
        ));
    }
    if token.revoked {
        return Err(CoreError::new("TOKEN_REVOKED", "token has been revoked"));
    }
    if token.is_expired(now_epoch_ms) {
        return Err(CoreError::new("TOKEN_EXPIRED", "token has expired"));
    }
    Ok(())
}

fn validate_token_material(token: &StoredToken) -> CoreResult<()> {
    if token.token.trim().is_empty() {
        return Err(CoreError::new("TOKEN_MISSING", "token value is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> RunnerDeviceMetadata {
        RunnerDeviceMetadata {
            organization_id: "org_123".to_string(),
            user_id: "user_123".to_string(),
            machine_id: "machine_123".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            runner_version: "0.1.0".to_string(),
        }
    }

    fn request() -> StreamCredentialRequest {
        StreamCredentialRequest {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            runner_device_id: "device_123".to_string(),
            runner_session_id: "session_123".to_string(),
            nonce: "nonce_123".to_string(),
            runner_version: "0.1.0".to_string(),
        }
    }

    #[test]
    fn device_id_stable_across_restarts() {
        let first = stable_device_id(&metadata());
        let second = stable_device_id(&metadata());

        assert_eq!(first, second);
        assert!(first.starts_with("device_"));
    }

    #[test]
    fn device_upsert_reuses_existing_device() {
        let created = RunnerDeviceRecord::upsert(None, metadata()).unwrap();
        let updated = RunnerDeviceRecord::upsert(Some(created.clone()), metadata()).unwrap();

        assert_eq!(created.runner_device_id, updated.runner_device_id);
    }

    #[test]
    fn revoked_device_is_not_resurrected_by_normal_upsert() {
        let mut revoked = RunnerDeviceRecord::upsert(None, metadata()).unwrap();
        revoked.revoked = true;

        let err = RunnerDeviceRecord::upsert(Some(revoked), metadata()).unwrap_err();

        assert_eq!("RUNNER_DEVICE_REVOKED", err.code);
    }

    #[test]
    fn management_token_cannot_open_stream() {
        let token = StoredToken::management("org_123", "management_token", Some(10_000));

        let err = validate_stream_token_for_stream(&token, "org_123", "prj_123", "device_123", 1)
            .unwrap_err();

        assert_eq!("TOKEN_SCOPE_MISMATCH", err.code);
    }

    #[test]
    fn stream_token_cannot_call_management_api() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "stream_token", 10_000);

        let err = validate_management_api_token(&token, "org_123", 1).unwrap_err();

        assert_eq!("TOKEN_SCOPE_MISMATCH", err.code);
    }

    #[test]
    fn stream_token_wrong_org_rejected() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "stream_token", 10_000);

        let err = validate_stream_token_for_stream(&token, "org_other", "prj_123", "device_123", 1)
            .unwrap_err();

        assert_eq!("TOKEN_ORG_MISMATCH", err.code);
    }

    #[test]
    fn stream_token_wrong_device_rejected() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "stream_token", 10_000);

        let err = validate_stream_token_for_stream(&token, "org_123", "prj_123", "device_other", 1)
            .unwrap_err();

        assert_eq!("STREAM_TOKEN_DEVICE_MISMATCH", err.code);
    }

    #[test]
    fn expired_stream_token_refreshes() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "stream_token", 10_000);

        assert!(should_refresh_stream_token(&token, 9_500, 1_000).unwrap());
    }

    #[test]
    fn revoked_device_disconnects() {
        let revocation = RevocationState {
            device_revoked: true,
            binding_revoked: false,
            token_revoked: false,
        };

        let err = revocation.validate_stream_allowed().unwrap_err();

        assert_eq!("RUNNER_DEVICE_REVOKED", err.code);
    }

    #[test]
    fn replayed_nonce_rejected() {
        let mut nonce_store = ReplayNonceStore::default();
        nonce_store.accept("session_123", "nonce_123").unwrap();

        let err = nonce_store.accept("session_123", "nonce_123").unwrap_err();

        assert_eq!("STREAM_REPLAY_DETECTED", err.code);
    }

    #[test]
    fn stream_credential_requires_management_scope_and_nonce() {
        let mut nonce_store = ReplayNonceStore::default();
        let management = StoredToken::management("org_123", "management_token", Some(100_000));
        let grant = issue_stream_credential(
            &management,
            &request(),
            &mut nonce_store,
            &RevocationState::default(),
            1_000,
            60_000,
        )
        .unwrap();

        assert_eq!(STREAM_TOKEN_AUDIENCE, grant.credential.audience);
        assert_eq!(61_000, grant.credential.expires_at_epoch_ms);
    }

    #[test]
    fn token_rotation_increments_generation_without_changing_scope() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "old", 10_000);
        let rotated = token.rotate("new", Some(20_000)).unwrap();

        assert_eq!(TokenScope::Stream, rotated.scope);
        assert_eq!(2, rotated.generation);
        assert_eq!(Some(20_000), rotated.expires_at_epoch_ms);
    }

    #[test]
    fn rotated_stream_token_without_expiry_is_rejected() {
        let token = StoredToken::stream("org_123", "prj_123", "device_123", "old", 10_000);

        let err = token.rotate("new", None).unwrap_err();

        assert_eq!("STREAM_AUTH_MISSING_EXPIRY", err.code);
    }

    #[test]
    fn stream_token_without_expiry_is_rejected() {
        let mut token =
            StoredToken::stream("org_123", "prj_123", "device_123", "stream_token", 10_000);
        token.expires_at_epoch_ms = None;

        let err = validate_stream_token_for_stream(&token, "org_123", "prj_123", "device_123", 1)
            .unwrap_err();

        assert_eq!("STREAM_AUTH_MISSING_EXPIRY", err.code);
    }

    #[test]
    fn management_token_without_expiry_can_rotate_and_validate() {
        let token = StoredToken::management("org_123", "old", None);
        let rotated = token.rotate("new", None).unwrap();

        assert_eq!(TokenScope::Management, rotated.scope);
        assert_eq!(None, rotated.expires_at_epoch_ms);
        validate_management_api_token(&rotated, "org_123", 1).unwrap();
    }

    #[test]
    fn bind_and_run_reuse_same_management_token_generation() {
        let token = StoredToken::management("org_123", "management_token", Some(10_000));

        let bind_generation =
            reusable_management_token_generation(&token, "org_123", 1_000).unwrap();
        let run_generation =
            reusable_management_token_generation(&token, "org_123", 2_000).unwrap();

        assert_eq!(bind_generation, run_generation);
        assert_eq!(1, run_generation);
    }

    #[test]
    fn management_token_rotation_changes_generation_without_changing_session_rule() {
        let token = StoredToken::management("org_123", "old", Some(10_000));
        let rotated = token.rotate("new", Some(20_000)).unwrap();

        assert_eq!(
            2,
            reusable_management_token_generation(&rotated, "org_123", 1_000).unwrap()
        );
    }

    #[test]
    fn revoked_management_token_cannot_be_unrevoked_by_rotation() {
        let mut token = StoredToken::management("org_123", "old", Some(10_000));
        token.revoked = true;

        let err = token.rotate("new", Some(20_000)).unwrap_err();

        assert_eq!("TOKEN_REVOKED", err.code);
        assert!(token.revoked);
    }

    #[test]
    fn revoked_stream_token_cannot_be_unrevoked_by_rotation() {
        let mut token = StoredToken::stream("org_123", "prj_123", "device_123", "old", 10_000);
        token.revoked = true;

        let err = token.rotate("new", Some(20_000)).unwrap_err();

        assert_eq!("TOKEN_REVOKED", err.code);
        assert!(token.revoked);
    }

    #[test]
    fn token_debug_does_not_print_secret() {
        let token = StoredToken::management("org_123", "management_secret", Some(10_000));

        assert!(!format!("{token:?}").contains("management_secret"));
    }

    #[test]
    fn missing_keychain_uses_dev_fallback_when_allowed() {
        let backend = select_token_storage_backend("macos", false, true).unwrap();

        assert_eq!(TokenStorageBackend::DevSecureFileFallback, backend);
    }

    #[test]
    fn missing_keychain_without_dev_fallback_errors() {
        let err = select_token_storage_backend("macos", false, false).unwrap_err();

        assert_eq!("TOKEN_STORE_UNAVAILABLE", err.code);
    }
}
