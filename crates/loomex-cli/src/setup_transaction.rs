use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const SETUP_TRANSACTION_SCHEMA_VERSION: &str = "loomex.cli.setupTransaction/v1";
const SETUP_TRANSACTION_FILE_NAME: &str = ".setup-transaction.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileSnapshot {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) missing_parent_directories: Vec<PathBuf>,
}

impl FileSnapshot {
    pub(crate) fn capture(path: PathBuf) -> Result<Self, String> {
        let (bytes, unix_mode) = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(format!(
                        "PLUGIN_SETUP_SNAPSHOT_UNSAFE: {} must be a regular non-symlink file",
                        path.display()
                    ));
                }
                let bytes = fs::read(&path).map_err(|error| {
                    format!(
                        "PLUGIN_SETUP_SNAPSHOT_READ_FAILED: {}: {error}",
                        path.display()
                    )
                })?;
                #[cfg(unix)]
                let unix_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(metadata.permissions().mode() & 0o7777)
                };
                #[cfg(not(unix))]
                let unix_mode = None;
                (Some(bytes), unix_mode)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
            Err(error) => {
                return Err(format!(
                    "PLUGIN_SETUP_SNAPSHOT_INSPECTION_FAILED: {}: {error}",
                    path.display()
                ));
            }
        };
        let missing_parent_directories = capture_missing_parent_directories(&path)?;
        Ok(Self {
            path,
            bytes,
            unix_mode,
            missing_parent_directories,
        })
    }

    pub(crate) fn restore(&self) -> Result<(), String> {
        match &self.bytes {
            Some(bytes) => {
                atomic_write_private(&self.path, bytes)?;
                restore_unix_mode(&self.path, self.unix_mode)
            }
            None => {
                remove_regular_file_if_present(&self.path)?;
                remove_created_empty_parents(&self.missing_parent_directories)
            }
        }
    }
}

fn capture_missing_parent_directories(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut missing = Vec::new();
    let mut current = path.parent();
    while let Some(parent) = current {
        match fs::symlink_metadata(parent) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "PLUGIN_SETUP_SNAPSHOT_UNSAFE: {} must be a real directory",
                        parent.display()
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(parent.to_path_buf());
                current = parent.parent();
            }
            Err(error) => {
                return Err(format!(
                    "PLUGIN_SETUP_SNAPSHOT_INSPECTION_FAILED: {}: {error}",
                    parent.display()
                ));
            }
        }
    }
    Ok(missing)
}

#[cfg(unix)]
fn restore_unix_mode(path: &Path, mode: Option<u32>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("PLUGIN_SETUP_RESTORE_FAILED: restore mode: {error}"))?;
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("PLUGIN_SETUP_RESTORE_FAILED: sync mode: {error}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_unix_mode(_path: &Path, _mode: Option<u32>) -> Result<(), String> {
    Ok(())
}

fn remove_created_empty_parents(paths: &[PathBuf]) -> Result<(), String> {
    for path in paths {
        match fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => break,
            Err(error) => {
                return Err(format!(
                    "PLUGIN_SETUP_RESTORE_FAILED: remove created directory {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupTransactionSnapshot {
    pub(crate) runtime_root: PathBuf,
    pub(crate) active_runtime_version: Option<String>,
    pub(crate) previous_runtime_version: Option<String>,
    pub(crate) config: FileSnapshot,
    pub(crate) service_file: FileSnapshot,
    pub(crate) service_installed: bool,
    pub(crate) service_enabled: bool,
    pub(crate) service_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupTransactionOperation {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupTransactionPhase {
    Prepared,
    RuntimeActivated,
    ConfigSaved,
    ServiceRegistered,
    ServiceStarted,
    HealthChecked,
    Committed,
    Compensated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetupTransactionJournal {
    schema_version: String,
    pub(crate) operation: SetupTransactionOperation,
    pub(crate) phase: SetupTransactionPhase,
    pub(crate) snapshot: SetupTransactionSnapshot,
    created_at_epoch_ms: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupTransactionStore {
    root: PathBuf,
    path: PathBuf,
}

impl SetupTransactionStore {
    pub(crate) fn new(runtime_root: &Path) -> Self {
        Self {
            root: runtime_root.to_path_buf(),
            path: runtime_root.join(SETUP_TRANSACTION_FILE_NAME),
        }
    }

    pub(crate) fn begin(
        &self,
        operation: SetupTransactionOperation,
        snapshot: SetupTransactionSnapshot,
    ) -> Result<SetupTransactionJournal, String> {
        if self.load()?.is_some() {
            return Err(
                "PLUGIN_SETUP_RECOVERY_REQUIRED: an unfinished setup transaction exists"
                    .to_string(),
            );
        }
        let journal = SetupTransactionJournal {
            schema_version: SETUP_TRANSACTION_SCHEMA_VERSION.to_string(),
            operation,
            phase: SetupTransactionPhase::Prepared,
            snapshot,
            created_at_epoch_ms: now_epoch_ms()?,
        };
        self.write(&journal)?;
        Ok(journal)
    }

    pub(crate) fn update_phase(
        &self,
        journal: &mut SetupTransactionJournal,
        phase: SetupTransactionPhase,
    ) -> Result<(), String> {
        journal.phase = phase;
        self.write(journal)
    }

    pub(crate) fn load(&self) -> Result<Option<SetupTransactionJournal>, String> {
        let Some(mut file) = self.open_journal()? else {
            return Ok(None);
        };
        Self::read_opened_journal(&mut file).map(Some)
    }

    fn open_journal(&self) -> Result<Option<File>, String> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = match options.open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            #[cfg(unix)]
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(
                    "PLUGIN_SETUP_JOURNAL_UNSAFE: journal must be a regular non-symlink file"
                        .to_string(),
                );
            }
            Err(error) => {
                return Err(format!("PLUGIN_SETUP_JOURNAL_OPEN_FAILED: {error}"));
            }
        };
        Ok(Some(file))
    }

    fn read_opened_journal(file: &mut File) -> Result<SetupTransactionJournal, String> {
        let metadata = file
            .metadata()
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_INSPECTION_FAILED: {error}"))?;
        if !metadata.is_file() {
            return Err(
                "PLUGIN_SETUP_JOURNAL_UNSAFE: journal must be a regular non-symlink file"
                    .to_string(),
            );
        }
        validate_private_file(&metadata)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_READ_FAILED: {error}"))?;
        Self::parse_journal(&bytes)
    }

    fn parse_journal(bytes: &[u8]) -> Result<SetupTransactionJournal, String> {
        let journal: SetupTransactionJournal = serde_json::from_slice(bytes)
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_INVALID: {error}"))?;
        if journal.schema_version != SETUP_TRANSACTION_SCHEMA_VERSION {
            return Err("PLUGIN_SETUP_JOURNAL_INVALID: unsupported schema version".to_string());
        }
        Ok(journal)
    }

    pub(crate) fn clear(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(
                        "PLUGIN_SETUP_JOURNAL_UNSAFE: refusing to remove an unsafe journal path"
                            .to_string(),
                    );
                }
                validate_private_file(&metadata)?;
                fs::remove_file(&self.path)
                    .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_REMOVE_FAILED: {error}"))?;
                sync_directory(&self.root)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("PLUGIN_SETUP_JOURNAL_INSPECTION_FAILED: {error}")),
        }
    }

    fn write(&self, journal: &SetupTransactionJournal) -> Result<(), String> {
        ensure_private_directory(&self.root)?;
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_SERIALIZE_FAILED: {error}"))?;
        atomic_write_private(&self.path, &bytes)?;
        sync_directory(&self.root)
    }
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        "PLUGIN_SETUP_JOURNAL_WRITE_FAILED: target has no parent directory".to_string()
    })?;
    ensure_real_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "PLUGIN_SETUP_RESTORE_UNSAFE: {} must be a regular non-symlink file",
                path.display()
            ));
        }
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "PLUGIN_SETUP_JOURNAL_WRITE_FAILED: invalid filename".to_string())?;
    let temp = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        now_epoch_ms()?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let result = (|| -> Result<(), String> {
        let mut file = options.open(&temp).map_err(|error| {
            format!(
                "PLUGIN_SETUP_JOURNAL_WRITE_FAILED: {}: {error}",
                temp.display()
            )
        })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_SYNC_FAILED: {error}"))?;
        drop(file);
        fs::rename(&temp, path)
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_WRITE_FAILED: {error}"))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "PLUGIN_SETUP_RESTORE_UNSAFE: refusing to remove {}",
                    path.display()
                ));
            }
            fs::remove_file(path)
                .map_err(|error| format!("PLUGIN_SETUP_RESTORE_FAILED: {error}"))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("PLUGIN_SETUP_RESTORE_FAILED: {error}")),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "PLUGIN_SETUP_JOURNAL_UNSAFE: {} must be a real directory",
                        path.display()
                    ));
                }
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o777 != 0o700
                {
                    return Err("PLUGIN_SETUP_JOURNAL_PERMISSIONS_UNSAFE: journal directory must be owned by the effective user with mode 0700".to_string());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(path)
                    .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_CREATE_FAILED: {error}"))?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_PERMISSIONS_FAILED: {error}"))?;
            }
            Err(error) => {
                return Err(format!("PLUGIN_SETUP_JOURNAL_INSPECTION_FAILED: {error}"));
            }
        }
    }
    #[cfg(not(unix))]
    ensure_real_directory(path)?;
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(format!(
            "PLUGIN_SETUP_JOURNAL_UNSAFE: {} must be a real directory",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)
            .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_CREATE_FAILED: {error}")),
        Err(error) => Err(format!("PLUGIN_SETUP_JOURNAL_INSPECTION_FAILED: {error}")),
    }
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(
            "PLUGIN_SETUP_JOURNAL_PERMISSIONS_UNSAFE: journal must be private to this user"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(_metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_SYNC_FAILED: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn now_epoch_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| format!("PLUGIN_SETUP_JOURNAL_CLOCK_INVALID: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "loomex-setup-journal-{label}-{}-{}",
            std::process::id(),
            now_epoch_ms().unwrap()
        ))
    }

    fn snapshot(root: &Path) -> SetupTransactionSnapshot {
        SetupTransactionSnapshot {
            runtime_root: root.join("runtime"),
            active_runtime_version: Some("1.0.0".to_string()),
            previous_runtime_version: Some("0.9.0".to_string()),
            config: FileSnapshot::capture(root.join("config.toml")).unwrap(),
            service_file: FileSnapshot::capture(root.join("loomex.service")).unwrap(),
            service_installed: true,
            service_enabled: true,
            service_active: true,
        }
    }

    fn prepare_test_root(root: &Path) {
        fs::create_dir_all(root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn journal_is_durable_and_restores_exact_file_snapshots() {
        let root = test_root("restore");
        prepare_test_root(&root);
        fs::write(root.join("config.toml"), b"old config").unwrap();
        fs::write(root.join("loomex.service"), b"old service").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("config.toml"), fs::Permissions::from_mode(0o640))
                .unwrap();
            fs::set_permissions(
                root.join("loomex.service"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let store = SetupTransactionStore::new(&root);
        let mut journal = store
            .begin(SetupTransactionOperation::Apply, snapshot(&root))
            .unwrap();
        fs::write(root.join("config.toml"), b"new config").unwrap();
        fs::write(root.join("loomex.service"), b"new service").unwrap();
        store
            .update_phase(&mut journal, SetupTransactionPhase::ServiceStarted)
            .unwrap();

        let recovered = SetupTransactionStore::new(&root).load().unwrap().unwrap();
        recovered.snapshot.config.restore().unwrap();
        recovered.snapshot.service_file.restore().unwrap();
        assert_eq!(
            b"old config",
            fs::read(root.join("config.toml")).unwrap().as_slice()
        );
        assert_eq!(
            b"old service",
            fs::read(root.join("loomex.service")).unwrap().as_slice()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                0o640,
                fs::metadata(root.join("config.toml"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
            assert_eq!(
                0o644,
                fs::metadata(root.join("loomex.service"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
        }
        assert!(recovered.snapshot.service_installed);
        assert!(recovered.snapshot.service_active);
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_files_are_removed_during_compensation() {
        let root = test_root("absent");
        prepare_test_root(&root);
        let store = SetupTransactionStore::new(&root);
        let journal = store
            .begin(SetupTransactionOperation::Rollback, snapshot(&root))
            .unwrap();
        fs::write(root.join("config.toml"), b"created").unwrap();
        fs::write(root.join("loomex.service"), b"created").unwrap();
        journal.snapshot.config.restore().unwrap();
        journal.snapshot.service_file.restore().unwrap();
        assert!(!root.join("config.toml").exists());
        assert!(!root.join("loomex.service").exists());
        store.clear().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compensation_removes_only_recorded_created_empty_parent_directories() {
        let root = test_root("parent-shape");
        prepare_test_root(&root);
        let path = root.join("created-a/created-b/config.toml");
        let snapshot = FileSnapshot::capture(path.clone()).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"created during setup").unwrap();

        snapshot.restore().unwrap();

        assert!(!path.exists());
        assert!(!root.join("created-a").exists());
        assert!(root.exists());

        let preserved = root.join("preserved/child/config.toml");
        let preserved_snapshot = FileSnapshot::capture(preserved.clone()).unwrap();
        fs::create_dir_all(preserved.parent().unwrap()).unwrap();
        fs::write(&preserved, b"created").unwrap();
        fs::write(root.join("preserved/keep.txt"), b"keep").unwrap();
        preserved_snapshot.restore().unwrap();
        assert!(!preserved.exists());
        assert!(root.join("preserved/keep.txt").exists());
        assert!(root.join("preserved").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_rejects_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink");
        prepare_test_root(&root);
        let victim = root.join("victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, root.join(SETUP_TRANSACTION_FILE_NAME)).unwrap();
        let store = SetupTransactionStore::new(&root);
        let error = store.load().unwrap_err();
        assert!(error.starts_with("PLUGIN_SETUP_JOURNAL_UNSAFE"));
        assert_eq!(b"victim", fs::read(victim).unwrap().as_slice());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_path_swap_cannot_change_the_opened_file_being_validated_and_read() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = test_root("path-swap");
        prepare_test_root(&root);
        let store = SetupTransactionStore::new(&root);
        let expected = store
            .begin(SetupTransactionOperation::Apply, snapshot(&root))
            .unwrap();
        let mut opened = store.open_journal().unwrap().unwrap();

        let original = root.join("opened-original.json");
        fs::rename(&store.path, &original).unwrap();
        let replacement = root.join("replacement.json");
        fs::write(&replacement, b"not the opened journal").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&replacement, &store.path).unwrap();

        let loaded = SetupTransactionStore::read_opened_journal(&mut opened).unwrap();
        assert_eq!(expected, loaded);
        assert!(store
            .load()
            .unwrap_err()
            .starts_with("PLUGIN_SETUP_JOURNAL_UNSAFE"));
        assert_eq!(
            b"not the opened journal",
            fs::read(replacement).unwrap().as_slice()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_permissive_preexisting_directory_and_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("permissions-unsafe");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let store = SetupTransactionStore::new(&root);
        let error = store
            .begin(SetupTransactionOperation::Apply, snapshot(&root))
            .unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_JOURNAL_PERMISSIONS_UNSAFE"));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        store
            .begin(SetupTransactionOperation::Apply, snapshot(&root))
            .unwrap();
        fs::set_permissions(&store.path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = store.load().unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_JOURNAL_PERMISSIONS_UNSAFE"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failure_injection_snapshots_cover_config_registration_start_and_health() {
        for (index, phase) in [
            SetupTransactionPhase::Prepared,
            SetupTransactionPhase::ConfigSaved,
            SetupTransactionPhase::ServiceRegistered,
            SetupTransactionPhase::ServiceStarted,
        ]
        .into_iter()
        .enumerate()
        {
            let root = test_root(&format!("failure-{index}"));
            prepare_test_root(&root);
            fs::write(root.join("config.toml"), b"old config").unwrap();
            fs::write(root.join("loomex.service"), b"old service").unwrap();
            let store = SetupTransactionStore::new(&root);
            let mut journal = store
                .begin(SetupTransactionOperation::Apply, snapshot(&root))
                .unwrap();
            fs::write(root.join("config.toml"), b"partial config").unwrap();
            fs::write(root.join("loomex.service"), b"partial service").unwrap();
            store.update_phase(&mut journal, phase).unwrap();

            let interrupted = SetupTransactionStore::new(&root).load().unwrap().unwrap();
            interrupted.snapshot.config.restore().unwrap();
            interrupted.snapshot.service_file.restore().unwrap();
            assert_eq!(
                b"old config",
                fs::read(root.join("config.toml")).unwrap().as_slice()
            );
            assert_eq!(
                b"old service",
                fs::read(root.join("loomex.service")).unwrap().as_slice()
            );
            store.clear().unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }
}
