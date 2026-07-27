use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

pub const AGENT_EXECUTABLE_CONFIG_FILE_NAME: &str = "agent-executables.json";
pub const AGENT_EXECUTABLE_CONFIG_VERSION: u32 = 2;

const OBSERVATION_SOURCE: &str = "interactive_path";
const APPROVED_EXPLICIT_PATH_SOURCE: &str = "approved_explicit_path";
const TEMP_FILE_ATTEMPTS: u32 = 16;

/// Agent providers whose native executable may be discovered by Loomex.
///
/// This allowlist is intentionally closed. In particular, Gemini is launched by
/// the `agy` executable and Loomex must never silently fall back to a `gemini`
/// binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentExecutableProvider {
    Codex,
    Claude,
    Agy,
}

impl AgentExecutableProvider {
    pub const ALL: [Self; 3] = [Self::Codex, Self::Claude, Self::Agy];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Agy => "agy",
        }
    }

    pub fn from_executable_name(value: &str) -> CoreResult<Self> {
        Self::parse(value)
    }

    fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            "agy" => Ok(Self::Agy),
            _ => Err(CoreError::new(
                "AGENT_EXECUTABLE_PROVIDER_UNSUPPORTED",
                format!("unsupported agent executable provider: {value}"),
            )),
        }
    }

    #[cfg(not(windows))]
    fn executable_file_names(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["codex"],
            Self::Claude => &["claude"],
            Self::Agy => &["agy"],
        }
    }

    #[cfg(windows)]
    fn executable_file_names(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["codex.exe"],
            Self::Claude => &["claude.exe"],
            Self::Agy => &["agy.exe"],
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct AgentExecutableObservation {
    canonical_path: PathBuf,
    observed_at_epoch_ms: u64,
    source: &'static str,
}

/// Private local configuration used to launch native agent runtimes.
///
/// Paths are deliberately not exposed as public fields and this type has a
/// redacted `Debug` implementation. Use [`Self::resolve_executable`] at the
/// execution boundary; it reads only persisted configuration and never PATH.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentExecutableConfig {
    config_version: u32,
    observed_at_epoch_ms: u64,
    executables: BTreeMap<AgentExecutableProvider, AgentExecutableObservation>,
}

impl fmt::Debug for AgentExecutableConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentExecutableConfig")
            .field("config_version", &self.config_version)
            .field("observed_at_epoch_ms", &self.observed_at_epoch_ms)
            .field(
                "configured_providers",
                &self
                    .executables
                    .keys()
                    .map(|provider| provider.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for AgentExecutableConfig {
    fn default() -> Self {
        Self {
            config_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms: 0,
            executables: BTreeMap::new(),
        }
    }
}

/// Safe status for UI, MCP, heartbeat, and diagnostics serialization.
///
/// It intentionally contains neither executable paths nor command output,
/// tokens, accounts, or model names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutablePublicStatus {
    pub provider: AgentExecutableProvider,
    pub configured: bool,
    pub observed_at_epoch_ms: u64,
}

pub fn agent_executable_config_path(cli_config_path: &Path) -> PathBuf {
    cli_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(AGENT_EXECUTABLE_CONFIG_FILE_NAME)
}

impl AgentExecutableConfig {
    pub fn load_or_default(path: &Path) -> CoreResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path).map_err(|error| {
            CoreError::new("AGENT_EXECUTABLE_CONFIG_READ_FAILED", error.to_string())
        })?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        Self::parse(&bytes)
    }

    /// Discovers the allowlisted executables from a PATH captured once from the
    /// user's interactive bootstrap environment.
    ///
    /// Relative PATH entries are ignored because their meaning would change
    /// when the durable service changes its working directory.
    pub fn discover_from_interactive_path(
        interactive_path: Option<&OsStr>,
        observed_at_epoch_ms: u64,
    ) -> Self {
        let path_directories = interactive_path
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .filter(|directory| directory.is_absolute())
            .collect::<Vec<_>>();
        let mut executables = BTreeMap::new();

        for provider in AgentExecutableProvider::ALL {
            let discovered = path_directories.iter().find_map(|directory| {
                provider
                    .executable_file_names()
                    .iter()
                    .find_map(|file_name| {
                        validate_discovered_candidate(&directory.join(file_name), directory).ok()
                    })
            });
            if let Some(canonical_path) = discovered {
                executables.insert(
                    provider,
                    AgentExecutableObservation {
                        canonical_path,
                        observed_at_epoch_ms,
                        source: OBSERVATION_SOURCE,
                    },
                );
            }
        }

        Self {
            config_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms,
            executables,
        }
    }

    /// Performs one discovery snapshot and persists it atomically.
    pub fn discover_and_save(
        path: &Path,
        interactive_path: Option<&OsStr>,
        observed_at_epoch_ms: u64,
    ) -> CoreResult<Self> {
        let config = Self::discover_from_interactive_path(interactive_path, observed_at_epoch_ms);
        config.save(path)?;
        Ok(config)
    }

    /// Refreshes executable discovery from the PATH of a user-invoked local
    /// CLI process and persists the merged snapshot.
    ///
    /// Existing still-valid entries are retained when the interactive PATH is
    /// restricted (for example when the CLI was launched from a GUI). This
    /// method must never be called by the durable daemon or with data received
    /// from Backend, task, or MCP payloads.
    pub fn refresh_and_save_from_interactive_path(
        path: &Path,
        interactive_path: Option<&OsStr>,
        observed_at_epoch_ms: u64,
    ) -> CoreResult<Self> {
        let current = Self::load_or_default(path)?;
        let discovered =
            Self::discover_from_interactive_path(interactive_path, observed_at_epoch_ms);
        let mut executables = current.valid_observations();
        executables.extend(discovered.executables);
        let refreshed = Self {
            config_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms,
            executables,
        };
        refreshed.save(path)?;
        Ok(refreshed)
    }

    /// Persists one user-approved local executable override.
    ///
    /// The provider is a closed allowlist and the supplied path must already
    /// be canonical, absolute, regular, executable, and named for that
    /// provider. Requiring a canonical path also rejects symlinks, including
    /// symlink escapes. Approval itself belongs to the local interactive CLI;
    /// this API performs validation and persistence only.
    pub fn refresh_and_save_approved_path(
        path: &Path,
        provider: AgentExecutableProvider,
        approved_path: &Path,
        observed_at_epoch_ms: u64,
    ) -> CoreResult<Self> {
        let canonical_path = validate_approved_explicit_path(provider, approved_path)?;
        let current = Self::load_or_default(path)?;
        let mut executables = current.valid_observations();
        executables.insert(
            provider,
            AgentExecutableObservation {
                canonical_path,
                observed_at_epoch_ms,
                source: APPROVED_EXPLICIT_PATH_SOURCE,
            },
        );
        let refreshed = Self {
            config_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms,
            executables,
        };
        refreshed.save(path)?;
        Ok(refreshed)
    }

    pub fn save(&self, path: &Path) -> CoreResult<()> {
        self.validate_document()?;
        let parent = path.parent().ok_or_else(|| {
            CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_PATH_INVALID",
                "agent executable config must have a parent directory",
            )
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_DIR_CREATE_FAILED",
                error.to_string(),
            )
        })?;
        set_private_directory_permissions(parent)?;

        let document = PersistedDocumentV2 {
            schema_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms: self.observed_at_epoch_ms,
            executables: self
                .executables
                .iter()
                .map(|(provider, observation)| {
                    (
                        provider.as_str().to_string(),
                        PersistedExecutableV2 {
                            path: observation.canonical_path.clone(),
                            observed_at_epoch_ms: observation.observed_at_epoch_ms,
                            source: observation.source.to_string(),
                        },
                    )
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&document).map_err(|error| {
            CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_SERIALIZE_FAILED",
                error.to_string(),
            )
        })?;
        atomic_private_write(path, &bytes)
    }

    /// Resolves a launch path exclusively from persisted configuration.
    ///
    /// The path is revalidated before every spawn so a removed, replaced, or
    /// permission-changed executable fails closed. No PATH lookup occurs here.
    pub fn resolve_executable(&self, provider: AgentExecutableProvider) -> CoreResult<PathBuf> {
        let observation = self.executables.get(&provider).ok_or_else(|| {
            CoreError::new(
                "AGENT_PROVIDER_NOT_INSTALLED",
                format!(
                    "{} is not configured; install it, then run `loomex setup agents refresh --confirm` locally, or approve its canonical path with `loomex setup agents refresh --confirm --provider {} --path ABSOLUTE_CANONICAL_PATH`",
                    provider.as_str(),
                    provider.as_str(),
                ),
            )
        })?;
        validate_persisted_executable(&observation.canonical_path)
    }

    pub fn public_status(&self) -> Vec<AgentExecutablePublicStatus> {
        AgentExecutableProvider::ALL
            .into_iter()
            .map(|provider| AgentExecutablePublicStatus {
                provider,
                configured: self.executables.contains_key(&provider),
                observed_at_epoch_ms: self
                    .executables
                    .get(&provider)
                    .map(|observation| observation.observed_at_epoch_ms)
                    .unwrap_or(self.observed_at_epoch_ms),
            })
            .collect()
    }

    pub fn observed_at_epoch_ms(&self) -> u64 {
        self.observed_at_epoch_ms
    }

    fn valid_observations(&self) -> BTreeMap<AgentExecutableProvider, AgentExecutableObservation> {
        self.executables
            .iter()
            .filter(|(_, observation)| {
                validate_persisted_executable(&observation.canonical_path).is_ok()
            })
            .map(|(provider, observation)| (*provider, observation.clone()))
            .collect()
    }

    fn parse(bytes: &[u8]) -> CoreResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
            CoreError::new("AGENT_EXECUTABLE_CONFIG_PARSE_FAILED", error.to_string())
        })?;
        let version = value
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1);

        match version {
            1 => Self::parse_v1(value),
            2 => {
                let document: PersistedDocumentV2 =
                    serde_json::from_value(value).map_err(|error| {
                        CoreError::new("AGENT_EXECUTABLE_CONFIG_PARSE_FAILED", error.to_string())
                    })?;
                let config = Self::from_v2(document)?;
                config.validate_document()?;
                Ok(config)
            }
            _ => Err(CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_VERSION_UNSUPPORTED",
                format!("unsupported agent executable config schema version: {version}"),
            )),
        }
    }

    fn parse_v1(value: serde_json::Value) -> CoreResult<Self> {
        let observed_at_epoch_ms = value
            .get("observedAtEpochMs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let mut legacy_paths = BTreeMap::<String, String>::new();

        if let Some(executables) = value
            .get("executables")
            .and_then(serde_json::Value::as_object)
        {
            for (provider, path) in executables {
                let path = path.as_str().ok_or_else(|| {
                    CoreError::new(
                        "AGENT_EXECUTABLE_CONFIG_PARSE_FAILED",
                        format!("legacy executable path for {provider} must be a string"),
                    )
                })?;
                legacy_paths.insert(provider.clone(), path.to_string());
            }
        }
        for (legacy_key, provider) in [
            ("codexPath", "codex"),
            ("claudePath", "claude"),
            ("agyPath", "agy"),
        ] {
            if let Some(path) = value.get(legacy_key).and_then(serde_json::Value::as_str) {
                legacy_paths.insert(provider.to_string(), path.to_string());
            }
        }

        let mut executables = BTreeMap::new();
        for (provider, path) in legacy_paths {
            // V1 was intentionally permissive and may contain executable
            // entries from older integrations (notably `gemini`). Preserve
            // backward-compatible loading without carrying those entries into
            // the closed V2 allowlist. In particular, never reinterpret a
            // legacy Gemini executable as `agy`.
            let Ok(provider) = AgentExecutableProvider::parse(&provider) else {
                continue;
            };
            let configured_path = PathBuf::from(path);
            validate_absolute_persisted_path(&configured_path)?;
            let canonical_path = fs::canonicalize(&configured_path).unwrap_or(configured_path);
            executables.insert(
                provider,
                AgentExecutableObservation {
                    canonical_path,
                    observed_at_epoch_ms,
                    source: OBSERVATION_SOURCE,
                },
            );
        }
        let config = Self {
            config_version: AGENT_EXECUTABLE_CONFIG_VERSION,
            observed_at_epoch_ms,
            executables,
        };
        config.validate_document()?;
        Ok(config)
    }

    fn from_v2(document: PersistedDocumentV2) -> CoreResult<Self> {
        let mut executables = BTreeMap::new();
        for (provider, executable) in document.executables {
            let provider = AgentExecutableProvider::parse(&provider)?;
            validate_absolute_persisted_path(&executable.path)?;
            let source = parse_observation_source(&executable.source)?;
            executables.insert(
                provider,
                AgentExecutableObservation {
                    canonical_path: executable.path,
                    observed_at_epoch_ms: executable.observed_at_epoch_ms,
                    source,
                },
            );
        }
        Ok(Self {
            config_version: document.schema_version,
            observed_at_epoch_ms: document.observed_at_epoch_ms,
            executables,
        })
    }

    fn validate_document(&self) -> CoreResult<()> {
        if self.config_version != AGENT_EXECUTABLE_CONFIG_VERSION {
            return Err(CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_VERSION_UNSUPPORTED",
                format!(
                    "unsupported agent executable config schema version: {}",
                    self.config_version
                ),
            ));
        }
        for observation in self.executables.values() {
            validate_absolute_persisted_path(&observation.canonical_path)?;
            parse_observation_source(observation.source)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedDocumentV2 {
    schema_version: u32,
    observed_at_epoch_ms: u64,
    executables: BTreeMap<String, PersistedExecutableV2>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedExecutableV2 {
    path: PathBuf,
    observed_at_epoch_ms: u64,
    source: String,
}

fn validate_discovered_candidate(candidate: &Path, path_directory: &Path) -> CoreResult<PathBuf> {
    let link_metadata = fs::symlink_metadata(candidate)
        .map_err(|error| CoreError::new("AGENT_EXECUTABLE_NOT_FOUND", error.to_string()))?;
    let canonical_path = fs::canonicalize(candidate).map_err(|error| {
        CoreError::new("AGENT_EXECUTABLE_CANONICALIZE_FAILED", error.to_string())
    })?;

    if link_metadata.file_type().is_symlink() {
        let canonical_directory = fs::canonicalize(path_directory).map_err(|error| {
            CoreError::new("AGENT_EXECUTABLE_CANONICALIZE_FAILED", error.to_string())
        })?;
        let trusted_installation_root =
            canonical_directory.parent().unwrap_or(&canonical_directory);
        if !canonical_path.starts_with(trusted_installation_root) {
            return Err(CoreError::new(
                "AGENT_EXECUTABLE_SYMLINK_ESCAPE",
                "agent executable symlink resolves outside its installation root",
            ));
        }
    }

    validate_persisted_executable(&canonical_path)
}

fn validate_approved_explicit_path(
    provider: AgentExecutableProvider,
    path: &Path,
) -> CoreResult<PathBuf> {
    validate_absolute_persisted_path(path)?;
    let expected_name = provider.executable_file_names();
    if !path.file_name().is_some_and(|name| {
        expected_name
            .iter()
            .any(|expected| name == OsStr::new(expected))
    }) {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_NAME_MISMATCH",
            format!(
                "approved path filename must identify the {} executable",
                provider.as_str()
            ),
        ));
    }
    validate_persisted_executable(path)
}

fn parse_observation_source(source: &str) -> CoreResult<&'static str> {
    match source {
        OBSERVATION_SOURCE => Ok(OBSERVATION_SOURCE),
        APPROVED_EXPLICIT_PATH_SOURCE => Ok(APPROVED_EXPLICIT_PATH_SOURCE),
        _ => Err(CoreError::new(
            "AGENT_EXECUTABLE_CONFIG_SOURCE_INVALID",
            "agent executable source must be interactive_path or approved_explicit_path",
        )),
    }
}

fn validate_absolute_persisted_path(path: &Path) -> CoreResult<()> {
    if !path.is_absolute() {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_PATH_INVALID",
            "agent executable path must be absolute",
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_PATH_INVALID",
            "agent executable path must be canonical",
        ));
    }
    Ok(())
}

fn validate_persisted_executable(path: &Path) -> CoreResult<PathBuf> {
    validate_absolute_persisted_path(path)?;
    let canonical_path = fs::canonicalize(path)
        .map_err(|error| CoreError::new("AGENT_PROVIDER_NOT_INSTALLED", error.to_string()))?;
    if canonical_path != path {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_PATH_CHANGED",
            "persisted agent executable path is no longer canonical",
        ));
    }
    let metadata = fs::metadata(&canonical_path)
        .map_err(|error| CoreError::new("AGENT_PROVIDER_NOT_INSTALLED", error.to_string()))?;
    if !metadata.is_file() {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_NOT_REGULAR_FILE",
            "agent executable must be a regular file",
        ));
    }
    if !is_executable(&metadata) {
        return Err(CoreError::new(
            "AGENT_EXECUTABLE_NOT_EXECUTABLE",
            "agent executable does not have executable permissions",
        ));
    }
    Ok(canonical_path)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(windows)]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(not(any(unix, windows)))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let parent = path.parent().ok_or_else(|| {
        CoreError::new(
            "AGENT_EXECUTABLE_CONFIG_PATH_INVALID",
            "agent executable config must have a parent directory",
        )
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string()))?
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(AGENT_EXECUTABLE_CONFIG_FILE_NAME);

    for attempt in 0..TEMP_FILE_ATTEMPTS {
        let temp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            nonce.saturating_add(u128::from(attempt))
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CoreError::new(
                    "AGENT_EXECUTABLE_CONFIG_WRITE_FAILED",
                    error.to_string(),
                ))
            }
        };
        let result = (|| {
            file.write_all(bytes).map_err(|error| {
                CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string())
            })?;
            file.sync_all().map_err(|error| {
                CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string())
            })?;
            set_private_file_permissions(&temp_path)?;
            drop(file);
            replace_file(&temp_path, path)?;
            set_private_file_permissions(path)?;
            sync_parent_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        return result;
    }

    Err(CoreError::new(
        "AGENT_EXECUTABLE_CONFIG_WRITE_FAILED",
        "could not create a unique temporary config file",
    ))
}

#[cfg(not(windows))]
fn replace_file(temp_path: &Path, path: &Path) -> CoreResult<()> {
    fs::rename(temp_path, path)
        .map_err(|error| CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string()))
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, path: &Path) -> CoreResult<()> {
    // std does not expose ReplaceFileW. Keep the new file owner-private and use
    // the closest available replacement semantics on Windows.
    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string())
        })?;
    }
    fs::rename(temp_path, path)
        .map_err(|error| CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string()))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        CoreError::new(
            "AGENT_EXECUTABLE_CONFIG_PERMISSION_FAILED",
            error.to_string(),
        )
    })
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        CoreError::new(
            "AGENT_EXECUTABLE_CONFIG_PERMISSION_FAILED",
            error.to_string(),
        )
    })
}

#[cfg(not(unix))]
fn set_private_file_permissions(path: &Path) -> CoreResult<()> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| {
            CoreError::new(
                "AGENT_EXECUTABLE_CONFIG_PERMISSION_FAILED",
                error.to_string(),
            )
        })?
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).map_err(|error| {
        CoreError::new(
            "AGENT_EXECUTABLE_CONFIG_PERMISSION_FAILED",
            error.to_string(),
        )
    })
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> CoreResult<()> {
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| CoreError::new("AGENT_EXECUTABLE_CONFIG_WRITE_FAILED", error.to_string()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "loomex-agent-executable-config-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    fn create_executable(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn joined_path(paths: &[&Path]) -> OsString {
        std::env::join_paths(paths).unwrap()
    }

    #[test]
    fn discovers_only_allowlisted_executables_from_one_path_snapshot() {
        let root = test_root("discovery");
        let bin = root.join("bin");
        create_executable(&bin.join("codex"));
        create_executable(&bin.join("claude"));
        create_executable(&bin.join("agy"));
        create_executable(&bin.join("gemini"));

        let config =
            AgentExecutableConfig::discover_from_interactive_path(Some(&joined_path(&[&bin])), 42);

        assert!(config
            .resolve_executable(AgentExecutableProvider::Codex)
            .is_ok());
        assert!(config
            .resolve_executable(AgentExecutableProvider::Claude)
            .is_ok());
        assert!(config
            .resolve_executable(AgentExecutableProvider::Agy)
            .is_ok());
        let persisted = serde_json::to_string(&config.public_status()).unwrap();
        assert!(!persisted.contains("gemini"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_executable_is_explicit_and_gemini_never_falls_back() {
        let root = test_root("missing");
        let bin = root.join("bin");
        create_executable(&bin.join("gemini"));

        let config =
            AgentExecutableConfig::discover_from_interactive_path(Some(&joined_path(&[&bin])), 43);
        let error = config
            .resolve_executable(AgentExecutableProvider::Agy)
            .unwrap_err();

        assert_eq!("AGENT_PROVIDER_NOT_INSTALLED", error.code);
        assert!(!format!("{config:?}").contains(&bin.display().to_string()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn install_after_setup_becomes_ready_after_local_interactive_refresh() {
        let root = test_root("install-after-setup");
        let config_path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        let initial_bin = root.join("initial-bin");
        fs::create_dir_all(&initial_bin).unwrap();
        let initial_path = joined_path(&[&initial_bin]);

        let initial =
            AgentExecutableConfig::discover_and_save(&config_path, Some(&initial_path), 100)
                .unwrap();
        assert_eq!(
            initial
                .resolve_executable(AgentExecutableProvider::Claude)
                .unwrap_err()
                .code,
            "AGENT_PROVIDER_NOT_INSTALLED"
        );

        let installed_bin = root.join("installed").join("bin");
        create_executable(&installed_bin.join("claude"));
        let refreshed_path = joined_path(&[&installed_bin]);
        let refreshed = AgentExecutableConfig::refresh_and_save_from_interactive_path(
            &config_path,
            Some(&refreshed_path),
            200,
        )
        .unwrap();
        assert_eq!(
            refreshed
                .resolve_executable(AgentExecutableProvider::Claude)
                .unwrap(),
            fs::canonicalize(installed_bin.join("claude")).unwrap()
        );

        let daemon_loaded = AgentExecutableConfig::load_or_default(&config_path).unwrap();
        assert!(daemon_loaded
            .resolve_executable(AgentExecutableProvider::Claude)
            .is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restricted_gui_path_accepts_only_approved_canonical_claude_path() {
        let root = test_root("restricted-gui-path");
        let config_path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        let restricted_bin = root.join("gui-bin");
        fs::create_dir_all(&restricted_bin).unwrap();
        let restricted_path = joined_path(&[&restricted_bin]);
        AgentExecutableConfig::discover_and_save(&config_path, Some(&restricted_path), 300)
            .unwrap();

        let approved = root.join("claude-install").join("bin").join("claude");
        create_executable(&approved);
        let approved = fs::canonicalize(approved).unwrap();
        let refreshed = AgentExecutableConfig::refresh_and_save_approved_path(
            &config_path,
            AgentExecutableProvider::Claude,
            &approved,
            400,
        )
        .unwrap();
        assert_eq!(
            refreshed
                .resolve_executable(AgentExecutableProvider::Claude)
                .unwrap(),
            approved
        );

        let persisted = fs::read_to_string(&config_path).unwrap();
        assert!(persisted.contains("\"source\": \"approved_explicit_path\""));
        assert!(!persisted.contains("gemini"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn approved_path_rejects_wrong_provider_name_and_symlink() {
        let root = test_root("approved-path-validation");
        let config_path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        let wrong_name = root.join("install").join("bin").join("other");
        create_executable(&wrong_name);
        let error = AgentExecutableConfig::refresh_and_save_approved_path(
            &config_path,
            AgentExecutableProvider::Claude,
            &wrong_name,
            500,
        )
        .unwrap_err();
        assert_eq!(error.code, "AGENT_EXECUTABLE_NAME_MISMATCH");

        #[cfg(unix)]
        {
            let canonical = root.join("install").join("bin").join("claude");
            create_executable(&canonical);
            let symlink_path = root.join("shim").join("claude");
            fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
            symlink(&canonical, &symlink_path).unwrap();
            let error = AgentExecutableConfig::refresh_and_save_approved_path(
                &config_path,
                AgentExecutableProvider::Claude,
                &symlink_path,
                501,
            )
            .unwrap_err();
            assert_eq!(error.code, "AGENT_EXECUTABLE_PATH_CHANGED");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restricted_refresh_preserves_existing_valid_observations() {
        let root = test_root("refresh-preserves-existing");
        let config_path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        let original_bin = root.join("original").join("bin");
        create_executable(&original_bin.join("codex"));
        AgentExecutableConfig::discover_and_save(
            &config_path,
            Some(&joined_path(&[&original_bin])),
            600,
        )
        .unwrap();

        let restricted_bin = root.join("restricted");
        fs::create_dir_all(&restricted_bin).unwrap();
        let refreshed = AgentExecutableConfig::refresh_and_save_from_interactive_path(
            &config_path,
            Some(&joined_path(&[&restricted_bin])),
            700,
        )
        .unwrap();
        assert!(refreshed
            .resolve_executable(AgentExecutableProvider::Codex)
            .is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn canonical_paths_are_persisted_and_relative_path_entries_are_ignored() {
        let root = test_root("canonical");
        let bin = root.join("install").join("bin");
        create_executable(&bin.join("codex"));
        let relative = Path::new("relative-bin");
        let path = joined_path(&[relative, &bin]);

        let config = AgentExecutableConfig::discover_from_interactive_path(Some(&path), 44);
        let resolved = config
            .resolve_executable(AgentExecutableProvider::Codex)
            .unwrap();

        assert_eq!(fs::canonicalize(bin.join("codex")).unwrap(), resolved);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_executable_and_symlink_escape() {
        let root = test_root("rejections");
        let bin = root.join("safe").join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("codex"), b"not executable").unwrap();
        let outside = root.join("outside").join("agy");
        create_executable(&outside);
        symlink(&outside, bin.join("agy")).unwrap();

        let config =
            AgentExecutableConfig::discover_from_interactive_path(Some(&joined_path(&[&bin])), 45);

        assert_eq!(
            "AGENT_PROVIDER_NOT_INSTALLED",
            config
                .resolve_executable(AgentExecutableProvider::Codex)
                .unwrap_err()
                .code
        );
        assert_eq!(
            "AGENT_PROVIDER_NOT_INSTALLED",
            config
                .resolve_executable(AgentExecutableProvider::Agy)
                .unwrap_err()
                .code
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn save_is_private_and_round_trips() {
        let root = test_root("permissions");
        let bin = root.join("install").join("bin");
        let path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        create_executable(&bin.join("codex"));
        let config =
            AgentExecutableConfig::discover_from_interactive_path(Some(&joined_path(&[&bin])), 46);

        config.save(&path).unwrap();
        let loaded = AgentExecutableConfig::load_or_default(&path).unwrap();

        assert_eq!(config, loaded);
        assert_eq!(
            0o600,
            fs::metadata(&path).unwrap().permissions().mode() & 0o777
        );
        assert_eq!(
            0o700,
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn v1_document_migrates_without_persisting_forbidden_fields() {
        let root = test_root("migration");
        let executable = root.join("install").join("bin").join("claude");
        let legacy_gemini = root.join("install").join("bin").join("gemini");
        create_executable(&executable);
        create_executable(&legacy_gemini);
        let legacy = serde_json::json!({
            "schemaVersion": 1,
            "observedAtEpochMs": 47,
            "claudePath": executable,
            "executables": {
                "gemini": legacy_gemini,
            },
            "token": "must-not-survive",
            "account": "must-not-survive",
            "models": ["must-not-survive"],
            "rawStderr": "must-not-survive",
        });

        let config =
            AgentExecutableConfig::parse(serde_json::to_string(&legacy).unwrap().as_bytes())
                .unwrap();
        let target = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        config.save(&target).unwrap();
        let persisted = fs::read_to_string(&target).unwrap();

        assert_eq!(47, config.observed_at_epoch_ms());
        assert!(config
            .resolve_executable(AgentExecutableProvider::Claude)
            .is_ok());
        assert_eq!(
            "AGENT_PROVIDER_NOT_INSTALLED",
            config
                .resolve_executable(AgentExecutableProvider::Agy)
                .unwrap_err()
                .code
        );
        assert!(persisted.contains("\"schemaVersion\": 2"));
        assert!(!persisted.contains("gemini"));
        assert!(!persisted.contains("must-not-survive"));
        assert!(!persisted.contains("token"));
        assert!(!persisted.contains("account"));
        assert!(!persisted.contains("model"));
        assert!(!persisted.contains("stderr"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn public_serialization_and_debug_never_expose_local_paths() {
        let root = test_root("public-redaction");
        let secret_named_path = root
            .join("account-secret-token-model-stderr")
            .join("bin")
            .join("codex");
        create_executable(&secret_named_path);
        let bin = secret_named_path.parent().unwrap();
        let config =
            AgentExecutableConfig::discover_from_interactive_path(Some(&joined_path(&[bin])), 48);

        let public = serde_json::to_string(&config.public_status()).unwrap();
        let debug = format!("{config:?}");

        assert!(AgentExecutableProvider::from_executable_name("gemini").is_err());
        assert!(!public.contains(&root.display().to_string()));
        assert!(!public.contains("\"path\""));
        assert!(!debug.contains(&root.display().to_string()));
        assert!(!public.contains("secret"));
        assert!(!public.contains("token"));
        assert!(!public.contains("model"));
        assert!(!public.contains("stderr"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_resolution_does_not_consult_path() {
        let root = test_root("no-runtime-path");
        let persisted_bin = root.join("persisted").join("bin");
        let other_bin = root.join("other").join("bin");
        let config_path = root.join("config").join(AGENT_EXECUTABLE_CONFIG_FILE_NAME);
        create_executable(&persisted_bin.join("agy"));
        create_executable(&other_bin.join("agy"));
        let config = AgentExecutableConfig::discover_from_interactive_path(
            Some(&joined_path(&[&persisted_bin])),
            49,
        );
        config.save(&config_path).unwrap();
        let loaded = AgentExecutableConfig::load_or_default(&config_path).unwrap();

        let resolved = loaded
            .resolve_executable(AgentExecutableProvider::Agy)
            .unwrap();

        assert_eq!(
            fs::canonicalize(persisted_bin.join("agy")).unwrap(),
            resolved
        );
        assert_ne!(fs::canonicalize(other_bin.join("agy")).unwrap(), resolved);
        let _ = fs::remove_dir_all(root);
    }
}
