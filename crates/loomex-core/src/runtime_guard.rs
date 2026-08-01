use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerRuntimeGuardInfo {
    pub surface: String,
    pub pid: u32,
    pub runner_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RunnerRuntimeGuard {
    path: PathBuf,
    runner_id: String,
    surface: String,
    released: bool,
}

impl RunnerRuntimeGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn runner_id(&self) -> &str {
        &self.runner_id
    }

    pub fn surface(&self) -> &str {
        &self.surface
    }

    pub fn release(mut self) -> CoreResult<()> {
        self.released = true;
        release_runner_runtime_guard_owned(&self.path, &self.runner_id, &self.surface)
    }

    pub fn persist(mut self) -> PathBuf {
        self.released = true;
        self.path.clone()
    }
}

impl Drop for RunnerRuntimeGuard {
    fn drop(&mut self) {
        if !self.released {
            let _ = release_runner_runtime_guard_owned(&self.path, &self.runner_id, &self.surface);
            self.released = true;
        }
    }
}

pub fn runner_runtime_guard_path(config_path: &Path, runner_id: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(runner_id.as_bytes());
    let digest = hasher.finalize();
    let fingerprint = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("runtime")
        .join(format!("runner-scope-{fingerprint}.lock"))
}

pub fn acquire_runner_runtime_guard(
    config_path: &Path,
    runner_id: &str,
    surface: &str,
) -> CoreResult<RunnerRuntimeGuard> {
    if runner_id.trim().is_empty() {
        return Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_INVALID",
            "runner id is required",
        ));
    }
    let path = runner_runtime_guard_path(config_path, runner_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| CoreError::new("RUNNER_RUNTIME_GUARD_FAILED", err.to_string()))?;
    }
    match create_guard_file(&path, runner_id, surface) {
        Ok(()) => Ok(RunnerRuntimeGuard {
            path,
            runner_id: runner_id.to_string(),
            surface: surface.to_string(),
            released: false,
        }),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            match read_runner_runtime_guard(&path) {
                Ok(Some(info)) if process_is_alive(info.pid) => Err(CoreError::new(
                    "RUNNER_RUNTIME_GUARD_CONFLICT",
                    format!(
                        "runner core for runner {runner_id} is already held by {} pid {}",
                        info.surface, info.pid
                    ),
                )),
                Ok(_) | Err(_) => {
                    cleanup_stale_runner_runtime_guard(&path)?;
                    create_guard_file(&path, runner_id, surface).map_err(|err| {
                        CoreError::new("RUNNER_RUNTIME_GUARD_FAILED", err.to_string())
                    })?;
                    Ok(RunnerRuntimeGuard {
                        path,
                        runner_id: runner_id.to_string(),
                        surface: surface.to_string(),
                        released: false,
                    })
                }
            }
        }
        Err(err) => Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_FAILED",
            err.to_string(),
        )),
    }
}

pub fn release_runner_runtime_guard_owned(
    path: &Path,
    runner_id: &str,
    surface: &str,
) -> CoreResult<()> {
    let Some(info) = read_runner_runtime_guard(path)? else {
        return Ok(());
    };
    if info.pid != std::process::id() || info.surface != surface || info.runner_id != runner_id {
        return Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_NOT_OWNER",
            format!(
                "runner guard for runner {} is owned by {} pid {}",
                info.runner_id, info.surface, info.pid
            ),
        ));
    }
    remove_guard_file(path)
}

pub fn release_runner_runtime_guard_for_surface(
    path: &Path,
    runner_id: &str,
    surface: &str,
) -> CoreResult<()> {
    let Some(info) = read_runner_runtime_guard(path)? else {
        return Ok(());
    };
    if info.surface != surface || info.runner_id != runner_id {
        return Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_NOT_OWNER",
            format!(
                "runner guard for runner {} is owned by {} pid {}",
                info.runner_id, info.surface, info.pid
            ),
        ));
    }
    if info.pid == std::process::id() || !process_is_alive(info.pid) {
        return remove_guard_file(path);
    }
    Err(CoreError::new(
        "RUNNER_RUNTIME_GUARD_CONFLICT",
        format!(
            "runner guard for runner {} is still owned by {} pid {}",
            info.runner_id, info.surface, info.pid
        ),
    ))
}

pub fn cleanup_stale_runner_runtime_guard(path: &Path) -> CoreResult<()> {
    let Some(info) = read_runner_runtime_guard(path)? else {
        return remove_guard_file(path);
    };
    if process_is_alive(info.pid) {
        return Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_CONFLICT",
            format!(
                "runner guard for runner {} is still owned by {} pid {}",
                info.runner_id, info.surface, info.pid
            ),
        ));
    }
    remove_guard_file(path)
}

fn remove_guard_file(path: &Path) -> CoreResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CoreError::new(
            "RUNNER_RUNTIME_GUARD_FAILED",
            err.to_string(),
        )),
    }
}

pub fn read_runner_runtime_guard(path: &Path) -> CoreResult<Option<RunnerRuntimeGuardInfo>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)
        .map_err(|err| CoreError::new("RUNNER_RUNTIME_GUARD_FAILED", err.to_string()))?;
    let mut surface = None;
    let mut pid = None;
    let mut runner_id = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "surface" => surface = Some(value.trim().to_string()),
            "pid" => {
                pid = value.trim().parse::<u32>().ok();
            }
            "runner_id" => runner_id = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let (Some(surface), Some(pid), Some(runner_id)) = (surface, pid, runner_id) else {
        return Ok(None);
    };
    Ok(Some(RunnerRuntimeGuardInfo {
        surface,
        pid,
        runner_id,
    }))
}

fn create_guard_file(path: &Path, runner_id: &str, surface: &str) -> std::io::Result<()> {
    let payload = format!(
        "surface={surface}\npid={}\nrunner_id={runner_id}\n",
        std::process::id()
    );
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(payload.as_bytes())
}

fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    if pid > i32::MAX as u32 {
        return false;
    }
    process_is_alive_platform(pid)
}

#[cfg(unix)]
fn process_is_alive_platform(pid: u32) -> bool {
    unsafe {
        if libc::kill(pid as libc::pid_t, 0) == 0 {
            return true;
        }
        current_errno() == libc::EPERM
    }
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
unsafe fn current_errno() -> i32 {
    *libc::__error()
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
unsafe fn current_errno() -> i32 {
    *libc::__errno_location()
}

#[cfg(not(unix))]
fn process_is_alive_platform(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "loomex-runtime-guard-{label}-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ))
            .join(".loomex")
            .join("config.toml")
    }

    #[test]
    fn guard_path_is_runner_scoped_and_stable() {
        let config = temp_config_path("stable");

        assert_eq!(
            runner_runtime_guard_path(&config, "runner_123"),
            runner_runtime_guard_path(&config, "runner_123")
        );
        assert_ne!(
            runner_runtime_guard_path(&config, "runner_123"),
            runner_runtime_guard_path(&config, "runner_other")
        );
    }

    #[test]
    fn live_pid_conflict_is_rejected() {
        let config = temp_config_path("live-conflict");
        let first = acquire_runner_runtime_guard(&config, "runner_123", "test").unwrap();

        let err = acquire_runner_runtime_guard(&config, "runner_123", "other").unwrap_err();
        let path = first.path().to_path_buf();
        first.release().unwrap();
        let _ = fs::remove_dir_all(config.parent().unwrap().parent().unwrap());

        assert_eq!("RUNNER_RUNTIME_GUARD_CONFLICT", err.code);
        assert!(!path.exists());
    }

    #[test]
    fn dead_pid_stale_lock_is_cleaned_up() {
        let config = temp_config_path("dead-pid");
        let path = runner_runtime_guard_path(&config, "runner_123");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "surface=old-cli\npid=4294967295\nrunner_id=runner_123\n",
        )
        .unwrap();

        let guard = acquire_runner_runtime_guard(&config, "runner_123", "new-app").unwrap();
        let info = read_runner_runtime_guard(guard.path()).unwrap().unwrap();
        let root = config.parent().unwrap().parent().unwrap().to_path_buf();
        guard.release().unwrap();
        let _ = fs::remove_dir_all(root);

        assert_eq!("new-app", info.surface);
        assert_eq!(std::process::id(), info.pid);
    }

    #[test]
    fn owned_release_refuses_live_guard_for_other_surface() {
        let config = temp_config_path("owned-release-other");
        let guard = acquire_runner_runtime_guard(&config, "runner_123", "loomex-tauri").unwrap();
        let path = guard.path().to_path_buf();

        let err =
            release_runner_runtime_guard_owned(&path, "runner_123", "loomex-cli").unwrap_err();
        let still_present = read_runner_runtime_guard(&path).unwrap().unwrap();
        let root = config.parent().unwrap().parent().unwrap().to_path_buf();
        guard.release().unwrap();
        let _ = fs::remove_dir_all(root);

        assert_eq!("RUNNER_RUNTIME_GUARD_NOT_OWNER", err.code);
        assert_eq!("loomex-tauri", still_present.surface);
        assert_eq!(std::process::id(), still_present.pid);
    }

    #[test]
    fn surface_release_removes_dead_cli_guard_but_not_other_surface() {
        let config = temp_config_path("surface-release-dead-cli");
        let path = runner_runtime_guard_path(&config, "runner_123");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "surface=loomex-cli\npid=4294967295\nrunner_id=runner_123\n",
        )
        .unwrap();

        release_runner_runtime_guard_for_surface(&path, "runner_123", "loomex-cli").unwrap();
        assert!(!path.exists());

        fs::write(
            &path,
            "surface=loomex-tauri\npid=4294967295\nrunner_id=runner_123\n",
        )
        .unwrap();
        let err = release_runner_runtime_guard_for_surface(&path, "runner_123", "loomex-cli")
            .unwrap_err();
        let still_present = read_runner_runtime_guard(&path).unwrap().unwrap();
        let _ = fs::remove_dir_all(config.parent().unwrap().parent().unwrap());

        assert_eq!("RUNNER_RUNTIME_GUARD_NOT_OWNER", err.code);
        assert_eq!("loomex-tauri", still_present.surface);
    }

    #[test]
    fn explicit_stale_cleanup_removes_dead_pid_but_not_live_pid() {
        let config = temp_config_path("explicit-stale-cleanup");
        let path = runner_runtime_guard_path(&config, "runner_123");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "surface=old-cli\npid=4294967295\nrunner_id=runner_123\n",
        )
        .unwrap();

        cleanup_stale_runner_runtime_guard(&path).unwrap();
        assert!(!path.exists());

        let guard = acquire_runner_runtime_guard(&config, "runner_123", "live").unwrap();
        let err = cleanup_stale_runner_runtime_guard(guard.path()).unwrap_err();
        let root = config.parent().unwrap().parent().unwrap().to_path_buf();
        guard.release().unwrap();
        let _ = fs::remove_dir_all(root);

        assert_eq!("RUNNER_RUNTIME_GUARD_CONFLICT", err.code);
    }
}
