use std::collections::BTreeMap;

use crate::{CoreError, CoreResult};

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
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredToken {
    pub scope: TokenScope,
    pub organization_id: String,
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
            runner_device_id: None,
            audience: None,
            token: token.into(),
            expires_at_epoch_ms,
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

    #[test]
    fn management_token_without_expiry_can_rotate_and_validate() {
        let token = StoredToken::management("org_123", "old", None);
        let rotated = token.rotate("new", None).unwrap();

        assert_eq!(TokenScope::Management, rotated.scope);
        assert_eq!(None, rotated.expires_at_epoch_ms);
        validate_management_api_token(&rotated, "org_123", 1).unwrap();
    }

    #[test]
    fn management_token_reuse_keeps_same_generation() {
        let token = StoredToken::management("org_123", "management_token", Some(10_000));

        let first_generation =
            reusable_management_token_generation(&token, "org_123", 1_000).unwrap();
        let second_generation =
            reusable_management_token_generation(&token, "org_123", 2_000).unwrap();

        assert_eq!(first_generation, second_generation);
        assert_eq!(1, second_generation);
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
