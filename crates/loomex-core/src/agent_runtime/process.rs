use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::{io::AsRawHandle, process::CommandExt};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{OpenThread, ResumeThread, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME},
    },
};

/// Unit tests exercise hundreds of process-backed runtime paths in one binary.
/// Serialize those children so unrelated CPU- and I/O-heavy journal tests
/// cannot starve a fake CLI past its bounded probe deadline. Production builds
/// do not contain this gate.
#[cfg(test)]
static TEST_PROCESS_SERIALIZATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Vec<u8>,
    /// Explicit non-secret overrides. Secrets should be inherited through the
    /// allowlist instead of copied into a serializable command description.
    pub env: BTreeMap<String, OsString>,
}

impl CommandSpec {
    pub fn new<I, S>(executable: impl Into<PathBuf>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            executable: executable.into(),
            args: args.into_iter().map(Into::into).collect(),
            cwd: None,
            stdin: Vec::new(),
            env: BTreeMap::new(),
        }
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = stdin;
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub terminate_grace: Duration,
    /// Maximum time to wait for bounded pipe readers after the full process
    /// tree has been terminated. A leaked writer must never hang the runner.
    pub reader_grace: Duration,
    pub poll_interval: Duration,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15 * 60),
            max_stdout_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 256 * 1024,
            terminate_grace: Duration::from_millis(500),
            reader_grace: Duration::from_secs(1),
            poll_interval: Duration::from_millis(20),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: String,
    /// Redacted and bounded diagnostic output. Never include it verbatim in a
    /// backend error context.
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}

pub trait ProcessObserver: Send + Sync {
    /// Receives bounded stdout records while the child is still running.
    /// Implementations must return quickly and must not persist the raw line.
    fn on_stdout_line(&self, line: &str);
}

#[derive(Debug, Clone)]
pub struct ProcessRunner {
    inherited_env: BTreeSet<String>,
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new([
            "HOME",
            "PATH",
            "TMPDIR",
            "TEMP",
            "TMP",
            "LANG",
            "LC_ALL",
            "TERM",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "CODEX_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "CLAUDE_CONFIG_DIR",
            "ANTHROPIC_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_PROJECT",
            "GEMINI_API_KEY",
        ])
    }
}

impl ProcessRunner {
    pub fn new<I, S>(inherited_env: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            inherited_env: inherited_env.into_iter().map(Into::into).collect(),
        }
    }

    pub fn run(
        &self,
        spec: &CommandSpec,
        limits: &ProcessLimits,
        cancellation: &CancellationToken,
    ) -> std::io::Result<ProcessOutput> {
        self.run_observed(spec, limits, cancellation, None)
    }

    pub fn run_observed(
        &self,
        spec: &CommandSpec,
        limits: &ProcessLimits,
        cancellation: &CancellationToken,
        observer: Option<Arc<dyn ProcessObserver>>,
    ) -> std::io::Result<ProcessOutput> {
        #[cfg(test)]
        let _test_process_guard = TEST_PROCESS_SERIALIZATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        validate_command(spec)?;

        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        for key in &self.inherited_env {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for (key, value) in &spec.env {
            if self.inherited_env.contains(key) {
                command.env(key, value);
            }
        }

        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        #[cfg(windows)]
        command.creation_flags(CREATE_SUSPENDED);

        #[cfg(windows)]
        let mut process_tree = ProcessTree::new()?;
        let mut child = command.spawn()?;
        let pid = child.id();
        #[cfg(not(windows))]
        let mut process_tree = ProcessTree::new(pid)?;
        #[cfg(windows)]
        process_tree.assign_and_resume(&mut child, pid)?;
        let streams = (child.stdout.take(), child.stderr.take(), child.stdin.take());
        let (Some(stdout), Some(stderr), Some(stdin)) = streams else {
            let _ = process_tree.terminate(&mut child, limits.terminate_grace);
            return Err(std::io::Error::other(
                "agent process did not expose its configured standard streams",
            ));
        };

        let stdin_bytes = spec.stdin.clone();
        let (stdin_tx, stdin_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdin = stdin;
            if !stdin_bytes.is_empty() {
                let _ = stdin.write_all(&stdin_bytes);
            }
            // Dropping closes stdin, preventing an interactive prompt from
            // waiting indefinitely for additional user input.
            let _ = stdin_tx.send(());
        });
        let max_stdout_bytes = limits.max_stdout_bytes;
        let max_stderr_bytes = limits.max_stderr_bytes;
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = stdout_tx.send(read_bounded_observed(stdout, max_stdout_bytes, observer));
        });
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = stderr_tx.send(read_bounded(stderr, max_stderr_bytes));
        });

        let started = Instant::now();
        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => {
                    let _ = process_tree.terminate(&mut child, limits.terminate_grace);
                    break Err(error);
                }
            }
            if cancellation.is_cancelled() {
                cancelled = true;
                break process_tree.terminate(&mut child, limits.terminate_grace);
            }
            if started.elapsed() >= limits.timeout {
                timed_out = true;
                break process_tree.terminate(&mut child, limits.terminate_grace);
            }
            thread::sleep(limits.poll_interval);
        };

        // A normally exiting CLI may leave a descendant behind with inherited
        // stdout/stderr handles. Terminate the still-contained descendants
        // before waiting for EOF so pipe readers cannot block indefinitely.
        process_tree.terminate_descendants();
        let _ = stdin_rx.recv_timeout(limits.reader_grace);
        let (stdout, stdout_truncated) = stdout_rx
            .recv_timeout(limits.reader_grace)
            .unwrap_or_else(|_| (Vec::new(), true));
        let (stderr, stderr_truncated) = stderr_rx
            .recv_timeout(limits.reader_grace)
            .unwrap_or_else(|_| (Vec::new(), true));
        let status = status?;

        Ok(ProcessOutput {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: redact_diagnostics(&String::from_utf8_lossy(&stderr)),
            stdout_truncated,
            stderr_truncated,
            timed_out,
            cancelled,
        })
    }
}

#[cfg(unix)]
struct ProcessTree {
    process_group: libc::pid_t,
    armed: bool,
}

#[cfg(unix)]
impl ProcessTree {
    fn new(pid: u32) -> std::io::Result<Self> {
        Ok(Self {
            process_group: pid as libc::pid_t,
            armed: true,
        })
    }

    fn terminate(
        &mut self,
        child: &mut std::process::Child,
        grace: Duration,
    ) -> std::io::Result<ExitStatus> {
        unsafe {
            libc::kill(-self.process_group, libc::SIGTERM);
        }
        let started = Instant::now();
        while started.elapsed() < grace {
            if let Some(status) = child.try_wait()? {
                self.terminate_descendants();
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.terminate_descendants();
        child.wait()
    }

    fn terminate_descendants(&mut self) {
        if !self.armed {
            return;
        }
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        // Never retain a reusable numeric PGID after issuing the final tree
        // kill. Drop is only an early-exit guard while ownership is armed.
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(-self.process_group, libc::SIGKILL);
            }
        }
    }
}

#[cfg(windows)]
struct ProcessTree {
    job: HANDLE,
}

#[cfg(windows)]
impl ProcessTree {
    fn new() -> std::io::Result<Self> {
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            unsafe {
                CloseHandle(job);
            }
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { job })
    }

    fn assign_and_resume(&self, child: &mut std::process::Child, pid: u32) -> std::io::Result<()> {
        let assigned =
            unsafe { AssignProcessToJobObject(self.job, child.as_raw_handle() as HANDLE) };
        if assigned == 0 {
            let error = std::io::Error::last_os_error();
            // CREATE_SUSPENDED guarantees the child has not executed or
            // spawned descendants before containment. If assignment fails,
            // terminate it while it is still suspended.
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let thread = match suspended_process_thread(pid) {
            Ok(thread) => thread,
            Err(error) => {
                self.terminate_contained_after_setup_failure(child);
                return Err(error);
            }
        };
        let resume_result = unsafe { ResumeThread(thread) };
        unsafe {
            CloseHandle(thread);
        }
        if resume_result == u32::MAX {
            let error = std::io::Error::last_os_error();
            self.terminate_contained_after_setup_failure(child);
            return Err(error);
        }
        Ok(())
    }

    fn terminate_contained_after_setup_failure(&self, child: &mut std::process::Child) {
        unsafe {
            TerminateJobObject(self.job, 1);
        }
        let _ = child.wait();
    }

    fn terminate(
        &self,
        child: &mut std::process::Child,
        _grace: Duration,
    ) -> std::io::Result<ExitStatus> {
        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        child.wait()
    }

    fn terminate_descendants(&self) {
        unsafe {
            TerminateJobObject(self.job, 1);
        }
    }
}

#[cfg(windows)]
fn suspended_process_thread(pid: u32) -> std::io::Result<HANDLE> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };
        let mut has_entry = unsafe { Thread32First(snapshot, &raw mut entry) } != 0;
        while has_entry {
            if entry.th32OwnerProcessID == pid {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(std::io::Error::last_os_error());
                }
                return Ok(thread);
            }
            has_entry = unsafe { Thread32Next(snapshot, &raw mut entry) } != 0;
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "suspended agent primary thread was not found",
        ))
    })();
    unsafe {
        CloseHandle(snapshot);
    }
    result
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.job);
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ProcessTree {
    pid: u32,
}

#[cfg(not(any(unix, windows)))]
impl ProcessTree {
    fn new(pid: u32) -> std::io::Result<Self> {
        Ok(Self { pid })
    }

    fn terminate(
        &self,
        child: &mut std::process::Child,
        _grace: Duration,
    ) -> std::io::Result<ExitStatus> {
        let _ = self.pid;
        child.kill()?;
        child.wait()
    }

    fn terminate_descendants(&self) {}
}

fn validate_command(spec: &CommandSpec) -> std::io::Result<()> {
    if spec.executable.as_os_str().is_empty() || !spec.executable.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "agent executable must be a canonical absolute path",
        ));
    }
    if spec.args.iter().any(|arg| arg.as_bytes().contains(&0)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "agent argument contains a NUL byte",
        ));
    }
    if let Some(cwd) = &spec.cwd {
        if !cwd.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent workspace must be an absolute path",
            ));
        }
    }
    Ok(())
}

fn read_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let remaining = limit.saturating_sub(kept.len());
        if remaining > 0 {
            kept.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if read > remaining {
            truncated = true;
        }
        // Continue draining after reaching the limit so the child cannot
        // deadlock on a full pipe.
    }
    (kept, truncated)
}

fn read_bounded_observed(
    mut reader: impl Read,
    limit: usize,
    observer: Option<Arc<dyn ProcessObserver>>,
) -> (Vec<u8>, bool) {
    let mut kept = Vec::with_capacity(limit.min(64 * 1024));
    let mut line = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let remaining = limit.saturating_sub(kept.len());
        if remaining > 0 {
            kept.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if read > remaining {
            truncated = true;
        }
        if let Some(observer) = observer.as_ref() {
            for byte in &buffer[..read] {
                if *byte == b'\n' {
                    emit_observed_line(observer.as_ref(), &line);
                    line.clear();
                } else if line.len() < 64 * 1024 {
                    line.push(*byte);
                }
            }
        }
    }
    if let Some(observer) = observer.as_ref() {
        emit_observed_line(observer.as_ref(), &line);
    }
    (kept, truncated)
}

fn emit_observed_line(observer: &dyn ProcessObserver, line: &[u8]) {
    if !line.is_empty() {
        observer.on_stdout_line(&String::from_utf8_lossy(line));
    }
}

pub(crate) fn redact_diagnostics(input: &str) -> String {
    let mut redacted = String::with_capacity(input.len().min(4096));
    for raw_line in input.lines().take(64) {
        let mut line = raw_line.to_string();
        for marker in [
            "authorization:",
            "api_key=",
            "api-key=",
            "apikey=",
            "token=",
            "access_token=",
            "refresh_token=",
            "cookie:",
        ] {
            if let Some(index) = line.to_ascii_lowercase().find(marker) {
                line.truncate(index + marker.len());
                line.push_str("[REDACTED]");
            }
        }
        line = redact_home_paths(&line);
        if !redacted.is_empty() {
            redacted.push('\n');
        }
        redacted.push_str(&line);
        if redacted.len() >= 4096 {
            redacted.truncate(4096);
            break;
        }
    }
    redacted
}

fn redact_home_paths(input: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return input.to_string();
    };
    let home = Path::new(&home).to_string_lossy();
    if home.is_empty() || home == "/" {
        input.to_string()
    } else {
        input.replace(home.as_ref(), "$HOME")
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::ProcessTree;

    #[test]
    fn job_object_with_kill_on_close_can_be_created() {
        let job = ProcessTree::new().expect("Windows runner requires Job Object containment");
        drop(job);
    }
}
