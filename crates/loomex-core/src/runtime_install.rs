//! Secure, versioned installation primitives for the per-user Loomex runtime.
//!
//! The installer deliberately accepts bytes that have already been downloaded by
//! a caller. Network policy, release selection, and user consent stay outside of
//! this module; manifest and artifact authenticity do not. A successful install
//! has the following layout:
//!
//! ```text
//! runtime/
//!   versions/<version>/bin/<executable>
//!   versions/<version>/install.json
//!   current -> versions/<version>       # Unix
//!   previous -> versions/<version>      # Unix, when available
//! ```
//!
//! New versions are written below `.staging` and renamed into `versions` only
//! after verification and durable writes. On Unix, activation replaces a
//! temporary symlink with `current` using `rename(2)`, so readers observe either
//! the old version or the new version.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::release_security::{
    sha256_hex, verify_release_artifact, verify_release_manifest, ReleaseArtifact, ReleaseManifest,
};
use crate::{CoreError, CoreResult};

pub const RUNTIME_INSTALL_METADATA_SCHEMA_VERSION: &str = "loomex.runtime.install/v1";
pub const RUNTIME_HOME_ENV: &str = "LOOMEX_RUNTIME_HOME";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInstallLayout {
    pub root: PathBuf,
    pub versions: PathBuf,
    pub staging: PathBuf,
    pub current: PathBuf,
    pub previous: PathBuf,
}

impl RuntimeInstallLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            versions: root.join("versions"),
            staging: root.join(".staging"),
            current: root.join("current"),
            previous: root.join("previous"),
            root,
        }
    }

    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.versions.join(version)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedRuntimeInstall<'a> {
    pub manifest: &'a ReleaseManifest,
    pub artifact: &'a ReleaseArtifact,
    pub artifact_bytes: &'a [u8],
    pub public_key_hex: &'a str,
    /// A single file name, such as `loomex-runner` or `loomex-runner.exe`.
    pub executable_name: &'a str,
}

/// A runtime executable carried by an already integrity-checked plugin package.
///
/// The caller must obtain `artifact_sha256` from the plugin package manifest,
/// not from user input. This layer independently checks the digest again before
/// anything is written to the stable runtime directory.
#[derive(Debug, Clone)]
pub struct BundledRuntimeInstall<'a> {
    pub version: &'a str,
    pub artifact_name: &'a str,
    pub artifact_sha256: &'a str,
    pub artifact_os: &'a str,
    pub artifact_arch: &'a str,
    pub artifact_bytes: &'a [u8],
    /// A single file name, such as `loomex` or `loomex.exe`.
    pub executable_name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRuntime {
    pub schema_version: String,
    pub version: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub artifact_os: String,
    pub artifact_arch: String,
    pub executable_name: String,
    pub installed_at_epoch_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeActivation {
    pub active: InstalledRuntime,
    pub previous_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInstallOutcome {
    pub activation: RuntimeActivation,
    /// True when the exact immutable version was already present and validated.
    pub reused_existing_version: bool,
}

#[derive(Debug, Clone)]
pub struct RuntimeInstaller {
    layout: RuntimeInstallLayout,
}

impl RuntimeInstaller {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            layout: RuntimeInstallLayout::new(root),
        }
    }

    pub fn for_current_user() -> CoreResult<Self> {
        Ok(Self::new(default_runtime_root()?))
    }

    pub fn layout(&self) -> &RuntimeInstallLayout {
        &self.layout
    }

    /// Verify, stage, atomically publish, and activate one runtime version.
    pub fn install_verified(
        &self,
        request: VerifiedRuntimeInstall<'_>,
    ) -> CoreResult<RuntimeInstallOutcome> {
        validate_safe_component(&request.manifest.version, "RUNTIME_VERSION_INVALID")?;
        validate_safe_component(request.executable_name, "RUNTIME_EXECUTABLE_NAME_INVALID")?;
        verify_release_manifest(request.manifest, request.public_key_hex)?;

        if !request
            .manifest
            .artifacts
            .iter()
            .any(|candidate| candidate == request.artifact)
        {
            return Err(CoreError::new(
                "RUNTIME_ARTIFACT_NOT_IN_MANIFEST",
                "runtime artifact is not an exact entry in the verified release manifest",
            ));
        }
        verify_release_artifact(
            request.artifact,
            request.artifact_bytes,
            request.public_key_hex,
        )?;
        validate_current_target(request.artifact)?;

        self.install_preverified(
            InstalledRuntime {
                schema_version: RUNTIME_INSTALL_METADATA_SCHEMA_VERSION.to_string(),
                version: request.manifest.version.clone(),
                artifact_name: request.artifact.name.clone(),
                artifact_sha256: request.artifact.sha256.clone(),
                artifact_os: request.artifact.os.clone(),
                artifact_arch: request.artifact.arch.clone(),
                executable_name: request.executable_name.to_string(),
                installed_at_epoch_ms: 0,
            },
            request.artifact_bytes,
        )
    }

    /// Install a runtime bundled in a verified Codex plugin package.
    ///
    /// This intentionally does not accept a path. The caller reads a regular,
    /// non-symlink artifact from inside its trusted package root and supplies
    /// the bytes plus the digest recorded in that package's integrity manifest.
    pub fn install_bundled(
        &self,
        request: BundledRuntimeInstall<'_>,
    ) -> CoreResult<RuntimeInstallOutcome> {
        validate_safe_component(request.version, "RUNTIME_VERSION_INVALID")?;
        validate_safe_component(request.artifact_name, "RUNTIME_ARTIFACT_NAME_INVALID")?;
        validate_safe_component(request.executable_name, "RUNTIME_EXECUTABLE_NAME_INVALID")?;
        validate_sha256(request.artifact_sha256)?;
        validate_target(request.artifact_os, request.artifact_arch)?;
        if sha256_hex(request.artifact_bytes) != request.artifact_sha256 {
            return Err(CoreError::new(
                "RUNTIME_BUNDLED_CHECKSUM_MISMATCH",
                "bundled runtime executable does not match the package integrity manifest",
            ));
        }

        self.install_preverified(
            InstalledRuntime {
                schema_version: RUNTIME_INSTALL_METADATA_SCHEMA_VERSION.to_string(),
                version: request.version.to_string(),
                artifact_name: request.artifact_name.to_string(),
                artifact_sha256: request.artifact_sha256.to_string(),
                artifact_os: request.artifact_os.to_string(),
                artifact_arch: request.artifact_arch.to_string(),
                executable_name: request.executable_name.to_string(),
                installed_at_epoch_ms: 0,
            },
            request.artifact_bytes,
        )
    }

    fn install_preverified(
        &self,
        mut metadata: InstalledRuntime,
        artifact_bytes: &[u8],
    ) -> CoreResult<RuntimeInstallOutcome> {
        self.prepare_layout()?;
        let version = metadata.version.as_str();
        let final_dir = self.layout.version_dir(version);
        match fs::symlink_metadata(&final_dir) {
            Ok(_) => {
                let existing = self.read_installed(version)?;
                ensure_existing_matches(&existing, &metadata)?;
                let activation = self.activate(version)?;
                return Ok(RuntimeInstallOutcome {
                    activation,
                    reused_existing_version: true,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(install_error("RUNTIME_PATH_INSPECTION_FAILED", error)),
        }

        let staging_dir = self
            .layout
            .staging
            .join(format!("{}-{}", version, unique_suffix()?));
        create_private_dir(&staging_dir)?;
        let staging_guard = StagingGuard::new(staging_dir.clone());
        let bin_dir = staging_dir.join("bin");
        create_private_dir(&bin_dir)?;

        let executable_path = bin_dir.join(&metadata.executable_name);
        write_private_executable(&executable_path, artifact_bytes)?;
        metadata.installed_at_epoch_ms = now_epoch_ms()?;
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| install_error("RUNTIME_METADATA_WRITE_FAILED", error))?;
        write_private_file(&staging_dir.join("install.json"), &metadata_bytes)?;
        sync_directory(&bin_dir)?;
        sync_directory(&staging_dir)?;

        fs::rename(&staging_dir, &final_dir)
            .map_err(|error| install_error("RUNTIME_PUBLISH_FAILED", error))?;
        staging_guard.disarm();
        sync_directory(&self.layout.versions)?;

        let activation = match self.activate(version) {
            Ok(activation) => activation,
            Err(error) => {
                // The version is safe but inactive. Keep it for a retry; never
                // delete a fully published runtime as part of activation failure.
                return Err(error);
            }
        };
        Ok(RuntimeInstallOutcome {
            activation,
            reused_existing_version: false,
        })
    }

    /// Activate an already installed version and remember the old version for rollback.
    pub fn activate(&self, version: &str) -> CoreResult<RuntimeActivation> {
        validate_safe_component(version, "RUNTIME_VERSION_INVALID")?;
        self.prepare_layout()?;
        let installed = self.read_installed(version)?;
        let previous_version = self.active_version()?;
        if previous_version.as_deref() == Some(version) {
            return Ok(RuntimeActivation {
                active: installed,
                previous_version,
            });
        }

        replace_pointer(&self.layout, &self.layout.current, version)?;
        if let Some(previous) = &previous_version {
            if let Err(error) = replace_pointer(&self.layout, &self.layout.previous, previous) {
                // Restore the old active pointer if maintaining rollback state failed.
                let _ = replace_pointer(&self.layout, &self.layout.current, previous);
                return Err(error);
            }
        }
        sync_directory(&self.layout.root)?;
        Ok(RuntimeActivation {
            active: installed,
            previous_version,
        })
    }

    /// Activate an explicit installed target. This is suitable for a server-directed rollback.
    pub fn rollback_to(&self, version: &str) -> CoreResult<RuntimeActivation> {
        self.activate(version)
    }

    /// Swap back to the version recorded during the last successful activation.
    pub fn rollback_to_previous(&self) -> CoreResult<RuntimeActivation> {
        let previous = read_pointer(&self.layout, &self.layout.previous)?.ok_or_else(|| {
            CoreError::new(
                "RUNTIME_ROLLBACK_UNAVAILABLE",
                "no previously active runtime is available for rollback",
            )
        })?;
        self.activate(&previous)
    }

    pub fn active_version(&self) -> CoreResult<Option<String>> {
        read_pointer(&self.layout, &self.layout.current)
    }

    /// Restore the active pointer captured before a higher-level transaction.
    ///
    /// Unlike `activate`, restoring `None` removes only a valid runtime pointer;
    /// a real file or directory at `current` is never removed. This is intended
    /// for setup compensation after the first runtime has been activated.
    pub fn restore_active_version(&self, version: Option<&str>) -> CoreResult<()> {
        self.restore_pointer_version(&self.layout.current, version)
    }

    /// Restore the rollback pointer captured before a higher-level transaction.
    pub fn restore_previous_version(&self, version: Option<&str>) -> CoreResult<()> {
        self.restore_pointer_version(&self.layout.previous, version)
    }

    fn restore_pointer_version(&self, pointer: &Path, version: Option<&str>) -> CoreResult<()> {
        self.prepare_layout()?;
        match version {
            Some(version) => {
                validate_safe_component(version, "RUNTIME_VERSION_INVALID")?;
                self.read_installed(version)?;
                replace_pointer(&self.layout, pointer, version)?;
            }
            None => {
                reject_non_pointer_path(pointer)?;
                match fs::remove_file(pointer) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(install_error("RUNTIME_ACTIVATION_FAILED", error));
                    }
                }
            }
        }
        sync_directory(&self.layout.root)
    }

    pub fn previous_version(&self) -> CoreResult<Option<String>> {
        read_pointer(&self.layout, &self.layout.previous)
    }

    pub fn active_runtime(&self) -> CoreResult<Option<InstalledRuntime>> {
        self.active_version()?
            .map(|version| self.read_installed(&version))
            .transpose()
    }

    pub fn read_installed(&self, version: &str) -> CoreResult<InstalledRuntime> {
        validate_safe_component(version, "RUNTIME_VERSION_INVALID")?;
        let version_dir = self.layout.version_dir(version);
        ensure_real_directory(&version_dir, "RUNTIME_VERSION_NOT_INSTALLED")?;
        let metadata_path = version_dir.join("install.json");
        ensure_regular_file(&metadata_path, "RUNTIME_METADATA_INVALID")?;
        let bytes = fs::read(&metadata_path)
            .map_err(|error| install_error("RUNTIME_METADATA_READ_FAILED", error))?;
        let installed: InstalledRuntime = serde_json::from_slice(&bytes)
            .map_err(|error| install_error("RUNTIME_METADATA_INVALID", error))?;
        if installed.schema_version != RUNTIME_INSTALL_METADATA_SCHEMA_VERSION
            || installed.version != version
        {
            return Err(CoreError::new(
                "RUNTIME_METADATA_INVALID",
                "installed runtime metadata does not match its version directory",
            ));
        }
        validate_safe_component(
            &installed.executable_name,
            "RUNTIME_EXECUTABLE_NAME_INVALID",
        )?;
        let executable_path = version_dir.join("bin").join(&installed.executable_name);
        ensure_regular_file(&executable_path, "RUNTIME_EXECUTABLE_MISSING")?;
        let executable_bytes = fs::read(&executable_path)
            .map_err(|error| install_error("RUNTIME_EXECUTABLE_READ_FAILED", error))?;
        if sha256_hex(&executable_bytes) != installed.artifact_sha256 {
            return Err(CoreError::new(
                "RUNTIME_EXECUTABLE_CHECKSUM_MISMATCH",
                "installed runtime executable does not match its verified artifact checksum",
            ));
        }
        Ok(installed)
    }

    /// Remove interrupted staging directories without touching published versions.
    pub fn clean_staging(&self) -> CoreResult<usize> {
        self.prepare_layout()?;
        let mut removed = 0;
        for entry in fs::read_dir(&self.layout.staging)
            .map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?
        {
            let entry =
                entry.map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?;
            if file_type.is_symlink() {
                fs::remove_file(entry.path())
                    .map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?;
            } else if file_type.is_dir() {
                fs::remove_dir_all(entry.path())
                    .map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?;
            } else {
                fs::remove_file(entry.path())
                    .map_err(|error| install_error("RUNTIME_STAGING_CLEANUP_FAILED", error))?;
            }
            removed += 1;
        }
        Ok(removed)
    }

    fn prepare_layout(&self) -> CoreResult<()> {
        create_private_dir(&self.layout.root)?;
        create_private_dir(&self.layout.versions)?;
        create_private_dir(&self.layout.staging)?;
        Ok(())
    }
}

pub fn default_runtime_root() -> CoreResult<PathBuf> {
    if let Some(override_root) = env::var_os(RUNTIME_HOME_ENV).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(override_root));
    }

    #[cfg(windows)]
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(local_app_data).join("Loomex").join("runtime"));
    }

    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CoreError::new(
                "RUNTIME_HOME_UNAVAILABLE",
                "cannot determine the per-user Loomex runtime directory",
            )
        })?;
    Ok(PathBuf::from(home).join(".loomex").join("runtime"))
}

fn ensure_existing_matches(
    installed: &InstalledRuntime,
    expected: &InstalledRuntime,
) -> CoreResult<()> {
    if installed.version != expected.version
        || installed.artifact_name != expected.artifact_name
        || installed.artifact_sha256 != expected.artifact_sha256
        || installed.artifact_os != expected.artifact_os
        || installed.artifact_arch != expected.artifact_arch
        || installed.executable_name != expected.executable_name
    {
        return Err(CoreError::new(
            "RUNTIME_IMMUTABLE_VERSION_CONFLICT",
            "installed version does not match the verified release artifact",
        ));
    }
    Ok(())
}

fn validate_current_target(artifact: &ReleaseArtifact) -> CoreResult<()> {
    validate_target(&artifact.os, &artifact.arch)
}

fn validate_target(os: &str, arch: &str) -> CoreResult<()> {
    if os != env::consts::OS || arch != env::consts::ARCH {
        return Err(CoreError::new(
            "RUNTIME_ARTIFACT_TARGET_MISMATCH",
            format!(
                "artifact targets {}/{}, but this host is {}/{}",
                os,
                arch,
                env::consts::OS,
                env::consts::ARCH
            ),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> CoreResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CoreError::new(
            "RUNTIME_BUNDLED_DIGEST_INVALID",
            "bundled runtime digest must be a lower-case SHA-256 hexadecimal value",
        ));
    }
    Ok(())
}

fn validate_safe_component(value: &str, code: &'static str) -> CoreResult<()> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !safe {
        return Err(CoreError::new(
            code,
            "value must be a non-empty portable path component",
        ));
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> CoreResult<()> {
    if path.exists() {
        ensure_real_directory(path, "RUNTIME_DIRECTORY_UNSAFE")?;
    } else {
        fs::create_dir_all(path)
            .map_err(|error| install_error("RUNTIME_DIRECTORY_CREATE_FAILED", error))?;
        ensure_real_directory(path, "RUNTIME_DIRECTORY_UNSAFE")?;
    }
    set_private_dir_permissions(path)
}

fn ensure_real_directory(path: &Path, missing_code: &'static str) -> CoreResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::new(missing_code, format!("{} does not exist", path.display()))
        } else {
            install_error("RUNTIME_PATH_INSPECTION_FAILED", error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoreError::new(
            "RUNTIME_DIRECTORY_UNSAFE",
            format!("{} must be a real directory", path.display()),
        ));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, code: &'static str) -> CoreResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CoreError::new(code, format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CoreError::new(
            code,
            format!("{} must be a regular file", path.display()),
        ));
    }
    Ok(())
}

fn write_private_executable(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    write_file_synced(path, bytes, "RUNTIME_EXECUTABLE_WRITE_FAILED")?;
    set_private_executable_permissions(path)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    write_file_synced(path, bytes, "RUNTIME_METADATA_WRITE_FAILED")?;
    set_private_file_permissions(path)
}

fn write_file_synced(path: &Path, bytes: &[u8], code: &'static str) -> CoreResult<()> {
    let mut file = File::create(path).map_err(|error| install_error(code, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| install_error(code, error))
}

#[cfg(unix)]
fn replace_pointer(layout: &RuntimeInstallLayout, pointer: &Path, version: &str) -> CoreResult<()> {
    use std::os::unix::fs::symlink;

    reject_non_pointer_path(pointer)?;
    let temporary = layout.root.join(format!(
        ".pointer-{}-{}",
        std::process::id(),
        unique_suffix()?
    ));
    let target = PathBuf::from("versions").join(version);
    symlink(&target, &temporary)
        .map_err(|error| install_error("RUNTIME_ACTIVATION_FAILED", error))?;
    if let Err(error) = fs::rename(&temporary, pointer) {
        let _ = fs::remove_file(&temporary);
        return Err(install_error("RUNTIME_ACTIVATION_FAILED", error));
    }
    Ok(())
}

#[cfg(not(unix))]
fn replace_pointer(layout: &RuntimeInstallLayout, pointer: &Path, version: &str) -> CoreResult<()> {
    reject_non_pointer_path(pointer)?;
    let temporary = layout.root.join(format!(
        ".pointer-{}-{}",
        std::process::id(),
        unique_suffix()?
    ));
    write_private_file(&temporary, version.as_bytes())?;
    if pointer.exists() {
        fs::remove_file(pointer)
            .map_err(|error| install_error("RUNTIME_ACTIVATION_FAILED", error))?;
    }
    fs::rename(&temporary, pointer)
        .map_err(|error| install_error("RUNTIME_ACTIVATION_FAILED", error))
}

fn reject_non_pointer_path(pointer: &Path) -> CoreResult<()> {
    let metadata = match fs::symlink_metadata(pointer) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(install_error("RUNTIME_PATH_INSPECTION_FAILED", error)),
    };
    #[cfg(unix)]
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    #[cfg(not(unix))]
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        return Ok(());
    }
    Err(CoreError::new(
        "RUNTIME_POINTER_UNSAFE",
        format!("refusing to replace non-pointer path {}", pointer.display()),
    ))
}

#[cfg(unix)]
fn read_pointer(layout: &RuntimeInstallLayout, pointer: &Path) -> CoreResult<Option<String>> {
    reject_non_pointer_path(pointer)?;
    let target = match fs::read_link(pointer) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(install_error("RUNTIME_POINTER_INVALID", error)),
    };
    parse_pointer_target(layout, &target).map(Some)
}

#[cfg(not(unix))]
fn read_pointer(layout: &RuntimeInstallLayout, pointer: &Path) -> CoreResult<Option<String>> {
    reject_non_pointer_path(pointer)?;
    let value = match fs::read_to_string(pointer) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(install_error("RUNTIME_POINTER_INVALID", error)),
    };
    let version = value.trim();
    validate_safe_component(version, "RUNTIME_POINTER_INVALID")?;
    ensure_real_directory(
        &layout.version_dir(version),
        "RUNTIME_VERSION_NOT_INSTALLED",
    )?;
    Ok(Some(version.to_string()))
}

#[cfg(unix)]
fn parse_pointer_target(layout: &RuntimeInstallLayout, target: &Path) -> CoreResult<String> {
    let relative_prefix = Path::new("versions");
    let version = target
        .strip_prefix(relative_prefix)
        .ok()
        .and_then(|rest| {
            let mut components = rest.components();
            let only = components.next()?;
            if components.next().is_some() {
                return None;
            }
            match only {
                std::path::Component::Normal(value) => value.to_str(),
                _ => None,
            }
        })
        .ok_or_else(|| {
            CoreError::new(
                "RUNTIME_POINTER_INVALID",
                "runtime pointer must target versions/<version>",
            )
        })?;
    validate_safe_component(version, "RUNTIME_POINTER_INVALID")?;
    ensure_real_directory(
        &layout.version_dir(version),
        "RUNTIME_VERSION_NOT_INSTALLED",
    )?;
    Ok(version.to_string())
}

fn unique_suffix() -> CoreResult<String> {
    Ok(format!("{}-{}", std::process::id(), now_epoch_nanos()?))
}

fn now_epoch_ms() -> CoreResult<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| install_error("RUNTIME_CLOCK_INVALID", error))
}

fn now_epoch_nanos() -> CoreResult<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| install_error("RUNTIME_CLOCK_INVALID", error))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> CoreResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| install_error("RUNTIME_SYNC_FAILED", error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> CoreResult<()> {
    // Windows does not support opening a directory with `std::fs::File`.
    // Individual file contents are still flushed before publication.
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| install_error("RUNTIME_PERMISSIONS_FAILED", error))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| install_error("RUNTIME_PERMISSIONS_FAILED", error))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_executable_permissions(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| install_error("RUNTIME_PERMISSIONS_FAILED", error))
}

#[cfg(not(unix))]
fn set_private_executable_permissions(_path: &Path) -> CoreResult<()> {
    Ok(())
}

fn install_error(code: &'static str, error: impl std::fmt::Display) -> CoreError {
    CoreError::new(code, error.to_string())
}

struct StagingGuard {
    path: PathBuf,
    armed: std::cell::Cell<bool>,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            armed: std::cell::Cell::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.set(false);
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed.get() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_security::{
        sign_release_artifact, sign_release_manifest, verifying_key_hex_from_signing_key,
        BuildProvenance, ReleaseChannel, SbomPackage, RELEASE_MANIFEST_SCHEMA_VERSION,
    };

    const SIGNING_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn verified_versions_install_activate_and_rollback() {
        let root = test_root("activate_rollback");
        let installer = RuntimeInstaller::new(&root);
        let first = signed_release("1.0.0", b"first");
        let second = signed_release("1.1.0", b"second");

        let first_outcome = installer
            .install_verified(first.request("loomex-runner"))
            .unwrap();
        assert_eq!("1.0.0", first_outcome.activation.active.version);
        assert_eq!(
            Some("1.0.0".to_string()),
            installer.active_version().unwrap()
        );

        let second_outcome = installer
            .install_verified(second.request("loomex-runner"))
            .unwrap();
        assert_eq!(
            Some("1.0.0".to_string()),
            second_outcome.activation.previous_version
        );
        assert_eq!(
            Some("1.1.0".to_string()),
            installer.active_version().unwrap()
        );

        let rolled_back = installer.rollback_to_previous().unwrap();
        assert_eq!("1.0.0", rolled_back.active.version);
        assert_eq!(
            Some("1.0.0".to_string()),
            installer.active_version().unwrap()
        );
        assert_eq!(
            b"first",
            fs::read(root.join("current/bin/loomex-runner"))
                .unwrap()
                .as_slice()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_artifact_never_reaches_staging() {
        let root = test_root("tampered");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("2.0.0", b"authentic");
        let request = VerifiedRuntimeInstall {
            artifact_bytes: b"tampered",
            ..signed.request("loomex-runner")
        };

        let error = installer.install_verified(request).unwrap_err();
        assert_eq!("RELEASE_ARTIFACT_CHECKSUM_MISMATCH", error.code);
        assert!(!root.exists());
    }

    #[test]
    fn bundled_plugin_runtime_installs_reuses_and_activates() {
        let root = test_root("bundled_plugin");
        let installer = RuntimeInstaller::new(&root);
        let bytes = b"bundled loomex executable";
        let digest = sha256_hex(bytes);
        let request = BundledRuntimeInstall {
            version: "0.1.0",
            artifact_name: "loomex-plugin-runtime",
            artifact_sha256: &digest,
            artifact_os: env::consts::OS,
            artifact_arch: env::consts::ARCH,
            artifact_bytes: bytes,
            executable_name: if cfg!(windows) {
                "loomex.exe"
            } else {
                "loomex"
            },
        };

        let first = installer.install_bundled(request.clone()).unwrap();
        assert!(!first.reused_existing_version);
        assert_eq!(
            Some("0.1.0".to_string()),
            installer.active_version().unwrap()
        );
        assert_eq!(
            bytes,
            fs::read(
                root.join("versions/0.1.0/bin")
                    .join(request.executable_name)
            )
            .unwrap()
            .as_slice()
        );

        let reused = installer.install_bundled(request).unwrap();
        assert!(reused.reused_existing_version);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_active_version_handles_present_and_absent_snapshots() {
        let root = test_root("restore_active_snapshot");
        let installer = RuntimeInstaller::new(&root);
        let first = signed_release("0.9.0", b"first");
        let second = signed_release("1.0.0", b"second");
        let third = signed_release("1.1.0", b"third");
        installer
            .install_verified(first.request("loomex-runner"))
            .unwrap();
        installer
            .install_verified(second.request("loomex-runner"))
            .unwrap();
        installer
            .install_verified(third.request("loomex-runner"))
            .unwrap();

        installer.restore_active_version(Some("1.0.0")).unwrap();
        installer.restore_previous_version(Some("0.9.0")).unwrap();
        assert_eq!(
            Some("1.0.0".to_string()),
            installer.active_version().unwrap()
        );
        assert_eq!(
            Some("0.9.0".to_string()),
            installer.previous_version().unwrap()
        );
        installer.restore_previous_version(None).unwrap();
        assert_eq!(None, installer.previous_version().unwrap());
        installer.restore_active_version(None).unwrap();
        assert_eq!(None, installer.active_version().unwrap());
        installer.restore_active_version(None).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn restore_absent_active_version_refuses_non_pointer_current_path() {
        let root = test_root("restore_absent_unsafe");
        let installer = RuntimeInstaller::new(&root);
        installer.prepare_layout().unwrap();
        fs::write(root.join("current"), b"do not remove").unwrap();

        let error = installer.restore_active_version(None).unwrap_err();
        assert_eq!("RUNTIME_POINTER_UNSAFE", error.code);
        assert_eq!(
            b"do not remove",
            fs::read(root.join("current")).unwrap().as_slice()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundled_plugin_runtime_rejects_tamper_and_wrong_target_before_writing() {
        let root = test_root("bundled_reject");
        let installer = RuntimeInstaller::new(&root);
        let digest = sha256_hex(b"trusted");
        let request = BundledRuntimeInstall {
            version: "0.1.0",
            artifact_name: "loomex-plugin-runtime",
            artifact_sha256: &digest,
            artifact_os: env::consts::OS,
            artifact_arch: env::consts::ARCH,
            artifact_bytes: b"tampered",
            executable_name: "loomex",
        };
        assert_eq!(
            "RUNTIME_BUNDLED_CHECKSUM_MISMATCH",
            installer.install_bundled(request.clone()).unwrap_err().code
        );
        assert!(!root.exists());

        let request = BundledRuntimeInstall {
            artifact_bytes: b"trusted",
            artifact_os: "not-this-host",
            ..request
        };
        assert_eq!(
            "RUNTIME_ARTIFACT_TARGET_MISMATCH",
            installer.install_bundled(request).unwrap_err().code
        );
        assert!(!root.exists());
    }

    #[test]
    fn existing_version_is_immutable_and_reusable() {
        let root = test_root("immutable");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("3.0.0", b"same");
        installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap();
        let reused = installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap();
        assert!(reused.reused_existing_version);

        let metadata_path = root.join("versions/3.0.0/install.json");
        let mut metadata: InstalledRuntime =
            serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
        metadata.artifact_name = "different".to_string();
        fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let error = installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap_err();
        assert_eq!("RUNTIME_IMMUTABLE_VERSION_CONFLICT", error.code);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_installed_executable_is_never_reused_or_activated() {
        let root = test_root("installed_tamper");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("3.1.0", b"trusted");
        installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap();
        fs::write(root.join("versions/3.1.0/bin/loomex-runner"), b"modified").unwrap();

        let error = installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap_err();
        assert_eq!("RUNTIME_EXECUTABLE_CHECKSUM_MISMATCH", error.code);
        let error = installer.activate("3.1.0").unwrap_err();
        assert_eq!("RUNTIME_EXECUTABLE_CHECKSUM_MISMATCH", error.code);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_version_and_executable_names_are_rejected() {
        let root = test_root("unsafe_names");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("../escape", b"binary");
        let error = installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap_err();
        assert_eq!("RUNTIME_VERSION_INVALID", error.code);

        let signed = signed_release("4.0.0", b"binary");
        let error = installer
            .install_verified(signed.request("../loomex-runner"))
            .unwrap_err();
        assert_eq!("RUNTIME_EXECUTABLE_NAME_INVALID", error.code);
        assert!(!root.exists());
    }

    #[test]
    #[cfg(unix)]
    fn activation_refuses_to_replace_non_symlink_current_path() {
        let root = test_root("unsafe_current");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("5.0.0", b"binary");
        installer.prepare_layout().unwrap();
        fs::write(root.join("current"), b"do not overwrite").unwrap();

        let error = installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap_err();
        assert_eq!("RUNTIME_POINTER_UNSAFE", error.code);
        assert_eq!(
            b"do not overwrite",
            fs::read(root.join("current")).unwrap().as_slice()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn runtime_directories_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("permissions");
        let installer = RuntimeInstaller::new(&root);
        let signed = signed_release("6.0.0", b"binary");
        installer
            .install_verified(signed.request("loomex-runner"))
            .unwrap();

        assert_eq!(
            0o700,
            fs::metadata(&root).unwrap().permissions().mode() & 0o777
        );
        assert_eq!(
            0o700,
            fs::metadata(root.join("versions/6.0.0/bin/loomex-runner"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );
        assert_eq!(
            0o600,
            fs::metadata(root.join("versions/6.0.0/install.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );

        fs::remove_dir_all(root).unwrap();
    }

    struct SignedRelease {
        manifest: ReleaseManifest,
        artifact: ReleaseArtifact,
        bytes: &'static [u8],
        public_key: String,
    }

    impl SignedRelease {
        fn request<'a>(&'a self, executable_name: &'a str) -> VerifiedRuntimeInstall<'a> {
            VerifiedRuntimeInstall {
                manifest: &self.manifest,
                artifact: &self.artifact,
                artifact_bytes: self.bytes,
                public_key_hex: &self.public_key,
                executable_name,
            }
        }
    }

    fn signed_release(version: &str, bytes: &'static [u8]) -> SignedRelease {
        let artifact = sign_release_artifact(
            "loomex-runner",
            env::consts::OS,
            env::consts::ARCH,
            bytes,
            SIGNING_KEY,
        )
        .unwrap();
        let manifest = sign_release_manifest(
            ReleaseManifest {
                schema_version: RELEASE_MANIFEST_SCHEMA_VERSION.to_string(),
                product: "loomex-runner".to_string(),
                version: version.to_string(),
                channel: ReleaseChannel::Stable,
                rollout_percent: 100,
                rollback_to_version: None,
                previous_versions: vec![],
                artifacts: vec![artifact.clone()],
                sbom: vec![SbomPackage {
                    name: "loomex-core".to_string(),
                    version: "0.1.0".to_string(),
                    license: None,
                }],
                provenance: BuildProvenance {
                    builder_id: "test".to_string(),
                    source_repository: "https://example.test/loomex".to_string(),
                    source_revision: "abcdef".to_string(),
                    build_started_at: "2026-07-20T00:00:00Z".to_string(),
                    build_finished_at: "2026-07-20T00:01:00Z".to_string(),
                    workflow_run_id: "test-run".to_string(),
                },
                created_at: "2026-07-20T00:02:00Z".to_string(),
                signature: None,
            },
            SIGNING_KEY,
        )
        .unwrap();
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        SignedRelease {
            manifest,
            artifact,
            bytes,
            public_key,
        }
    }

    fn test_root(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "loomex-runtime-install-{name}-{}-{}",
            std::process::id(),
            now_epoch_nanos().unwrap()
        ))
    }
}
