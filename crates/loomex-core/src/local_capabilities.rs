use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::capability::{CapabilityExecutor, CapabilityRequest, CapabilityResult};
use crate::policy::{AuthorizationEnvelope, CapabilityAuthorizationGateway, ExecutionRoot};
use crate::redaction::Redactor;
use crate::security::{
    ChildEnvironmentPolicy, LocalSecurityPolicy, NetworkSecurityPolicy, SandboxProfile,
};
use crate::{CoreError, CoreResult};

const DEFAULT_MAX_READ_BYTES: usize = 262_144;
const DEFAULT_FS_READ_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_FS_READ_TIMEOUT: Duration = Duration::from_secs(30);
const FS_READ_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1_048_576;
const DEFAULT_MAX_GIT_DIFF_BYTES: usize = 262_144;
const DEFAULT_MAX_HTTP_RESPONSE_BYTES: usize = 1_048_576;
const MAX_HTTP_RESPONSE_BYTES: usize = 10_485_760;
const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_HTTP_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_BROWSER_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_DB_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_TEST_TIMEOUT_SECONDS: u64 = 600;
const MAX_EXPANDED_OUTPUT_BYTES: usize = 10_485_760;
const SHELL_POLL_INTERVAL_MS: u64 = 10;

#[derive(Debug, Clone)]
pub struct LocalCapabilityExecutor {
    workspace_root: PathBuf,
    redactor: Redactor,
    secret_env_names: Vec<String>,
    docker_allowed_containers: Vec<String>,
    security: LocalSecurityPolicy,
}

/// A capability request that has crossed the authorization boundary.
///
/// The fields and proof marker are private so callers cannot manufacture a
/// request for `execute_authorized`; they must obtain one from
/// `authorize_request`, which consumes the policy gateway nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCapabilityRequest {
    capability: String,
    input: String,
    _authorization: AuthorizationProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationProof;

impl LocalCapabilityExecutor {
    pub fn new(workspace_root: impl Into<PathBuf>) -> CoreResult<Self> {
        let workspace_root = normalize_root(workspace_root.into())?;
        Ok(Self {
            workspace_root,
            redactor: Redactor::new(Vec::new()),
            secret_env_names: default_secret_env_names(),
            docker_allowed_containers: Vec::new(),
            security: LocalSecurityPolicy::default(),
        })
    }

    pub fn with_redaction(
        workspace_root: impl Into<PathBuf>,
        secrets: Vec<String>,
        secret_env_names: Vec<String>,
    ) -> CoreResult<Self> {
        let workspace_root = normalize_root(workspace_root.into())?;
        Ok(Self {
            workspace_root,
            redactor: Redactor::new(secrets),
            secret_env_names: if secret_env_names.is_empty() {
                default_secret_env_names()
            } else {
                secret_env_names
            },
            docker_allowed_containers: Vec::new(),
            security: LocalSecurityPolicy::default(),
        })
    }

    pub fn with_docker_allowed_containers(mut self, allowed_containers: Vec<String>) -> Self {
        self.docker_allowed_containers = allowed_containers;
        self
    }

    pub fn with_security_policy(mut self, security: LocalSecurityPolicy) -> Self {
        self.security = security;
        self
    }

    pub fn with_network_security_policy(mut self, network: NetworkSecurityPolicy) -> Self {
        self.security.network = network;
        self
    }

    pub fn with_sandbox_profile(mut self, sandbox: SandboxProfile) -> Self {
        self.security.sandbox = sandbox;
        self
    }

    pub fn with_child_environment_policy(
        mut self,
        child_environment: ChildEnvironmentPolicy,
    ) -> Self {
        self.security.child_environment = child_environment;
        self
    }

    pub fn authorize_request(
        gateway: &mut CapabilityAuthorizationGateway,
        envelope: &AuthorizationEnvelope,
        capability: impl Into<String>,
        input: serde_json::Value,
        execution_root: &ExecutionRoot,
        actor: &str,
        lease_version: u64,
        now_epoch_ms: u64,
    ) -> CoreResult<AuthorizedCapabilityRequest> {
        let capability = capability.into();
        if envelope.capability != capability {
            return Err(CoreError::new(
                "AUTHORIZATION_CAPABILITY_MISMATCH",
                format!(
                    "envelope authorizes {}, request requires {capability}",
                    envelope.capability
                ),
            ));
        }
        gateway.authorize(
            envelope,
            &input,
            execution_root,
            actor,
            lease_version,
            now_epoch_ms,
        )?;
        let input = serde_json::to_string(&input)
            .map_err(json_error("CAPABILITY_INPUT_SERIALIZE_FAILED"))?;
        Ok(AuthorizedCapabilityRequest {
            capability,
            input,
            _authorization: AuthorizationProof,
        })
    }

    pub fn execute_authorized(
        &self,
        request: AuthorizedCapabilityRequest,
    ) -> CoreResult<CapabilityResult> {
        self.execute_request(request.capability, request.input)
    }

    pub fn execute_authorized_with_working_directory(
        &self,
        request: AuthorizedCapabilityRequest,
        working_directory: &str,
        cancellation: &ShellCancellationToken,
    ) -> CoreResult<ShellExecOutput> {
        if request.capability != "shell.exec" {
            return Err(CoreError::new(
                "UNSUPPORTED_CAPABILITY",
                "working-directory execution requires shell.exec",
            ));
        }
        let input: ShellExecInput =
            serde_json::from_str(&request.input).map_err(json_error("CAPABILITY_INPUT_INVALID"))?;
        self.shell_exec_with_working_directory(input, working_directory, cancellation)
    }

    pub fn fs_list(&self, input: FsListInput) -> CoreResult<FsListOutput> {
        let base =
            self.resolve_workspace_path(&input.path, input.follow_symlinks.unwrap_or(false))?;
        let mut entries = Vec::new();
        let max_entries = input.max_entries.unwrap_or(1000).max(1);
        self.collect_entries(&base, &mut entries, &input, max_entries)?;
        let truncated = entries.len() > max_entries;
        entries.truncate(max_entries);
        Ok(FsListOutput { entries, truncated })
    }

    pub fn fs_read(&self, input: FsReadInput) -> CoreResult<FsReadOutput> {
        self.fs_read_with_cancel(input, &ShellCancellationToken::default())
    }

    pub fn fs_read_with_cancel(
        &self,
        input: FsReadInput,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<FsReadOutput> {
        let path = self.resolve_workspace_path(&input.path, true)?;
        let metadata = fs::metadata(&path).map_err(fs_error("FS_READ_FAILED"))?;
        if !metadata.is_file() {
            return Err(CoreError::new(
                "FS_READ_NOT_FILE",
                "fs.read requires a file path",
            ));
        }

        let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_READ_BYTES).max(1);
        let offset = input.offset.unwrap_or(0);
        let initial_identity = file_identity(&metadata);
        if metadata.len() > DEFAULT_FS_READ_TOTAL_BYTES {
            return Err(CoreError::new(
                "FS_READ_TOO_LARGE",
                format!(
                    "fs.read file exceeds the {} byte work budget",
                    DEFAULT_FS_READ_TOTAL_BYTES
                ),
            ));
        }

        let mut file = File::open(&path).map_err(fs_error("FS_READ_FAILED"))?;
        let opened_metadata = file.metadata().map_err(fs_error("FS_READ_FAILED"))?;
        if file_identity(&opened_metadata) != initial_identity {
            return Err(CoreError::new(
                "FS_READ_MUTATED",
                "file changed while fs.read was opening it",
            ));
        }

        let started = Instant::now();
        let mut hasher = Sha256::new();
        let mut preview = Vec::with_capacity(max_bytes.min(FS_READ_BUFFER_BYTES));
        let preview_end = offset.saturating_add(max_bytes as u64);
        let mut buffer = [0u8; FS_READ_BUFFER_BYTES];
        let mut total_read = 0u64;
        loop {
            if cancel.is_cancelled() {
                return Err(CoreError::new("FS_READ_CANCELLED", "fs.read was cancelled"));
            }
            if started.elapsed() >= DEFAULT_FS_READ_TIMEOUT {
                return Err(CoreError::new(
                    "FS_READ_TIMEOUT",
                    "fs.read exceeded its time budget",
                ));
            }
            let count = file.read(&mut buffer).map_err(fs_error("FS_READ_FAILED"))?;
            if count == 0 {
                break;
            }
            let chunk_start = total_read;
            total_read = total_read.saturating_add(count as u64);
            if total_read > DEFAULT_FS_READ_TOTAL_BYTES {
                return Err(CoreError::new(
                    "FS_READ_TOO_LARGE",
                    "fs.read exceeded its byte work budget",
                ));
            }
            hasher.update(&buffer[..count]);

            let preview_start = offset.max(chunk_start);
            let preview_stop = preview_end.min(total_read);
            if preview_start < preview_stop {
                let start = (preview_start - chunk_start) as usize;
                let stop = (preview_stop - chunk_start) as usize;
                preview.extend_from_slice(&buffer[start..stop]);
            }
        }

        let final_metadata = fs::metadata(&path).map_err(fs_error("FS_READ_FAILED"))?;
        if file_identity(&final_metadata) != initial_identity || total_read != opened_metadata.len()
        {
            return Err(CoreError::new(
                "FS_READ_MUTATED",
                "file changed while fs.read was reading it",
            ));
        }

        let binary = std::str::from_utf8(&preview).is_err();
        let requested_encoding = input.encoding.unwrap_or_else(|| "utf-8".to_string());
        let encoding = if binary || requested_encoding == "base64" {
            "base64".to_string()
        } else {
            "utf-8".to_string()
        };
        let content = if encoding == "base64" {
            BASE64_STANDARD.encode(&preview)
        } else {
            String::from_utf8(preview).map_err(|_| {
                CoreError::new(
                    "FS_READ_BINARY_REQUIRES_BASE64",
                    "binary file reads must use base64 encoding",
                )
            })?
        };
        Ok(FsReadOutput {
            path: self.relative_path(&path)?,
            encoding,
            content,
            sha256: format!("{:x}", hasher.finalize()),
            size_bytes: total_read as usize,
            truncated: preview_end < total_read,
            binary,
        })
    }

    pub fn fs_write(&self, input: FsWriteInput) -> CoreResult<FsWriteOutput> {
        let path = self.resolve_workspace_path_for_write(&input.path)?;
        if !matches!(input.mode.as_str(), "create" | "overwrite" | "append") {
            return Err(CoreError::new(
                "FS_WRITE_MODE_INVALID",
                "fs.write mode must be create, overwrite, or append",
            ));
        }
        let bytes = decode_content(&input.content, &input.encoding)?;
        if input.create_parent_directories.unwrap_or(false) {
            if let Some(parent) = path.parent() {
                validate_write_parent_chain(parent)?;
                fs::create_dir_all(parent).map_err(fs_error("FS_WRITE_CREATE_PARENT_FAILED"))?;
            }
        }
        let snapshot = write_snapshot(&path, input.mode == "create")?;
        let created = snapshot.target.is_none();
        let before = if snapshot.target.is_some() {
            Some(fs::read(&path).map_err(fs_error("FS_WRITE_READ_BEFORE_FAILED"))?)
        } else {
            None
        };
        if let Some(expected) = &input.expected_sha256 {
            let actual = before
                .as_ref()
                .map(|bytes| sha256_hex(bytes))
                .unwrap_or_default();
            if &actual != expected {
                return Err(CoreError::new(
                    "FS_WRITE_SHA256_MISMATCH",
                    "file content does not match expected sha256",
                ));
            }
        }
        if let Some(parent) = path.parent() {
            self.ensure_inside_root(parent, true)?;
        }
        match input.mode.as_str() {
            "create" if snapshot.target.is_some() => {
                return Err(CoreError::new("FS_WRITE_EXISTS", "file already exists"));
            }
            "create" | "overwrite" => atomic_write_checked(
                &path,
                &bytes,
                snapshot.target.as_ref(),
                &snapshot.parent,
                "FS_WRITE_FAILED",
            )?,
            "append" => {
                let mut appended = before.clone().unwrap_or_default();
                appended.extend_from_slice(&bytes);
                atomic_write_checked(
                    &path,
                    &appended,
                    snapshot.target.as_ref(),
                    &snapshot.parent,
                    "FS_WRITE_FAILED",
                )?;
            }
            _ => unreachable!("fs.write mode was validated above"),
        }
        let after = fs::read(&path).map_err(fs_error("FS_WRITE_VERIFY_FAILED"))?;
        Ok(FsWriteOutput {
            path: self.relative_path(&path)?,
            sha256: sha256_hex(&after),
            size_bytes: after.len(),
            created,
            diff_ref: diff_ref(&self.relative_path(&path)?, before.as_deref(), &after),
        })
    }

    pub fn fs_apply_patch(&self, input: FsApplyPatchInput) -> CoreResult<FsApplyPatchOutput> {
        let mut files_changed = Vec::new();
        let mut conflicts = Vec::new();
        let changes = parse_unified_patch(&input.patch)?;
        if changes.is_empty() {
            return Err(CoreError::new(
                "PATCH_EMPTY",
                "patch did not contain file changes",
            ));
        }
        for change in &changes {
            let path = self.resolve_workspace_path_for_write(&change.path)?;
            let snapshot = write_snapshot(&path, false).map_err(|error| {
                if error.code == "FS_WRITE_PERMISSION_DENIED" {
                    CoreError::new("PATCH_PREPARE_FAILED", "patch target is not writable")
                } else {
                    error
                }
            })?;
            let before = fs::read_to_string(&path).map_err(fs_error("PATCH_READ_FAILED"))?;
            if let Some(expected) = input.base_sha256_by_path.get(&change.path) {
                if sha256_hex(before.as_bytes()) != *expected {
                    conflicts.push(change.path.clone());
                    continue;
                }
            }
            let Some(after) = apply_line_patch(&before, &change.hunks) else {
                conflicts.push(change.path.clone());
                continue;
            };
            files_changed.push(ParsedFileChange {
                path,
                relative_path: change.path.clone(),
                before,
                after,
                target: snapshot.target,
                parent: snapshot.parent,
            });
        }
        if !conflicts.is_empty() {
            return Ok(FsApplyPatchOutput {
                applied: false,
                files_changed: Vec::new(),
                conflicts,
            });
        }
        let output_changes = commit_patch_changes(files_changed)?;
        Ok(FsApplyPatchOutput {
            applied: true,
            files_changed: output_changes,
            conflicts: Vec::new(),
        })
    }

    pub fn shell_exec(&self, input: ShellExecInput) -> CoreResult<ShellExecOutput> {
        self.shell_exec_with_cancel(input, &ShellCancellationToken::default())
    }

    pub fn shell_exec_in_working_directory(
        &self,
        input: ShellExecInput,
        working_directory: &str,
    ) -> CoreResult<ShellExecOutput> {
        self.shell_exec_with_working_directory(
            input,
            working_directory,
            &ShellCancellationToken::default(),
        )
    }

    pub fn shell_exec_with_cancel(
        &self,
        input: ShellExecInput,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<ShellExecOutput> {
        self.shell_exec_with_working_directory(input, ".", cancel)
    }

    pub fn shell_exec_with_working_directory(
        &self,
        input: ShellExecInput,
        working_directory: &str,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<ShellExecOutput> {
        if input.command.is_empty() || input.command.iter().any(|part| part.trim().is_empty()) {
            return Err(CoreError::new(
                "SHELL_COMMAND_EMPTY",
                "shell.exec command must not be empty",
            ));
        }
        let cwd = self.resolve_workspace_path(working_directory, true)?;
        if !cwd.is_dir() {
            return Err(CoreError::new(
                "SHELL_CWD_NOT_DIRECTORY",
                "shell.exec working_directory must be a directory",
            ));
        }
        let timeout = Duration::from_secs(
            input
                .timeout_seconds
                .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
                .max(1),
        );
        let max_output_bytes = input
            .max_output_bytes
            .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
            .max(1);
        let mut command = command_with_workspace_scope(&input, &cwd)?;
        let env = self.filtered_env(input.env);
        let started = Instant::now();
        command
            .current_dir(cwd)
            .env_clear()
            .envs(
                env.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        let mut child = command.spawn().map_err(fs_error("SHELL_SPAWN_FAILED"))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CoreError::new(
                "SHELL_STDOUT_CAPTURE_FAILED",
                "stdout pipe was not captured",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            CoreError::new(
                "SHELL_STDERR_CAPTURE_FAILED",
                "stderr pipe was not captured",
            )
        })?;
        let stdout_reader = read_bounded_pipe(stdout, max_output_bytes);
        let stderr_reader = read_bounded_pipe(stderr, max_output_bytes);
        let mut timed_out = false;
        let mut cancelled = false;
        loop {
            if cancel.is_cancelled() {
                cancelled = true;
                kill_process_tree(&mut child);
                break;
            }
            if started.elapsed() >= timeout {
                timed_out = true;
                kill_process_tree(&mut child);
                break;
            }
            if child
                .try_wait()
                .map_err(fs_error("SHELL_WAIT_FAILED"))?
                .is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(SHELL_POLL_INTERVAL_MS));
        }
        let status = child.wait().map_err(fs_error("SHELL_WAIT_FAILED"))?;
        let stdout = stdout_reader.join().map_err(|_| {
            CoreError::new("SHELL_STDOUT_CAPTURE_FAILED", "stdout reader panicked")
        })??;
        let stderr = stderr_reader.join().map_err(|_| {
            CoreError::new("SHELL_STDERR_CAPTURE_FAILED", "stderr reader panicked")
        })??;
        let exit_code = status
            .code()
            .unwrap_or(if timed_out || cancelled { -1 } else { 1 });
        let stdout_lossy = String::from_utf8_lossy(&stdout.bytes);
        let stderr_lossy = String::from_utf8_lossy(&stderr.bytes);
        let stdout_value = self.redactor.redact(stdout_lossy.as_ref());
        let stderr_value = self.redactor.redact(stderr_lossy.as_ref());
        let stdout_truncated = truncate_to_bytes(&stdout_value, max_output_bytes);
        let stderr_truncated = truncate_to_bytes(&stderr_value, max_output_bytes);
        Ok(ShellExecOutput {
            exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
            stdout_ref: "inline:stdout".to_string(),
            stderr_ref: "inline:stderr".to_string(),
            truncated: stdout.truncated
                || stderr.truncated
                || stdout_truncated.truncated
                || stderr_truncated.truncated,
            artifacts: ShellExecOutputArtifacts {
                stdout: stdout_truncated.value,
                stderr: stderr_truncated.value,
                timed_out,
                cancelled,
                redaction_metadata: RedactionMetadata {
                    filtered_env: filtered_env_names(&self.secret_env_names),
                },
            },
        })
    }

    pub fn git_status(&self, input: GitStatusInput) -> CoreResult<GitStatusOutput> {
        let repo = self.discover_git_repository(None)?;
        self.validate_git_scope(None)?;
        let untracked_mode = if input.include_untracked.unwrap_or(true) {
            "all"
        } else {
            "no"
        };
        let status = self.run_git(
            &repo.path,
            &[
                "status",
                "--porcelain=v1",
                "--branch",
                &format!("--untracked-files={untracked_mode}"),
            ],
        )?;
        let (branch, detached, files) = parse_git_status(&status.stdout);
        Ok(GitStatusOutput {
            branch,
            detached,
            clean: files.is_empty(),
            files,
        })
    }

    pub fn git_diff(&self, input: GitDiffInput) -> CoreResult<GitDiffOutput> {
        let repo = self.discover_git_repository(None)?;
        self.validate_git_scope(input.paths.as_deref())?;
        let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_GIT_DIFF_BYTES).max(1);
        let mut diff_args = vec!["diff".to_string(), "--no-ext-diff".to_string()];
        if let Some(context_lines) = input.context_lines {
            diff_args.push(format!("--unified={}", context_lines.min(20)));
        }
        if input.cached.unwrap_or(false) {
            diff_args.push("--cached".to_string());
        }
        append_git_pathspecs(&mut diff_args, input.paths.as_deref())?;
        let diff_arg_refs = diff_args.iter().map(String::as_str).collect::<Vec<_>>();
        let diff = self.run_git_bounded(&repo.path, &diff_arg_refs, max_bytes)?;

        let mut names_args = vec![
            "diff".to_string(),
            "--name-status".to_string(),
            "--no-ext-diff".to_string(),
        ];
        if input.cached.unwrap_or(false) {
            names_args.push("--cached".to_string());
        }
        append_git_pathspecs(&mut names_args, input.paths.as_deref())?;
        let name_arg_refs = names_args.iter().map(String::as_str).collect::<Vec<_>>();
        let names = self.run_git(&repo.path, &name_arg_refs)?;
        let files_changed = parse_git_name_status(&names.stdout);
        let diff_ref = format!("inline:git-diff:{}", sha256_hex(diff.stdout.as_bytes()));

        Ok(GitDiffOutput {
            diff_ref,
            truncated: diff.truncated,
            files_changed,
            artifacts: GitDiffArtifacts { diff: diff.stdout },
        })
    }

    pub fn git_log(&self, input: GitLogInput) -> CoreResult<GitLogOutput> {
        let repo = self.discover_git_repository(None)?;
        self.validate_git_scope(input.paths.as_deref())?;
        let max_count = input.max_count.unwrap_or(20).clamp(1, 100);
        let mut args = vec![
            "log".to_string(),
            "--pretty=format:%H%x1f%an%x1f%cI%x1f%s".to_string(),
            "-n".to_string(),
            max_count.to_string(),
        ];
        append_git_pathspecs(&mut args, input.paths.as_deref())?;
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self.run_git(&repo.path, &arg_refs)?;
        Ok(GitLogOutput {
            commits: parse_git_log(&output.stdout)?,
        })
    }

    pub fn http_request(&self, input: HttpRequestInput) -> CoreResult<HttpRequestOutput> {
        self.http_request_with_redirects(input, false)
    }

    pub fn browser_playwright(
        &self,
        input: BrowserPlaywrightInput,
    ) -> CoreResult<BrowserPlaywrightOutput> {
        let started = Instant::now();
        let url = Url::parse(&input.url)
            .map_err(|error| CoreError::new("BROWSER_URL_INVALID", error.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(CoreError::new(
                "BROWSER_URL_INVALID",
                "browser.playwright URL must be absolute http or https",
            ));
        }
        validate_http_url(&url)?;
        self.security.network.validate_url(&url)?;
        let timeout_seconds = bounded_seconds(
            input.timeout_seconds,
            DEFAULT_BROWSER_TIMEOUT_SECONDS,
            1,
            300,
            "BROWSER_TIMEOUT_INVALID",
            "browser.playwright timeout_seconds must be between 1 and 300",
        )?;
        let max_output_bytes = expanded_output_limit(input.max_output_bytes)?;
        let browser = input.browser.unwrap_or_else(|| "chromium".to_string());
        validate_browser_name(&browser)?;
        if input.headless == Some(false) {
            return Err(CoreError::new(
                "BROWSER_HEADFUL_UNSUPPORTED",
                "browser.playwright runs in deterministic headless mode",
            ));
        }
        self.validate_browser_network_preflight(&url, timeout_seconds)?;
        let browser_proxy = ControlledBrowserProxy::start(self.security.network.clone())?;
        let screenshot_path = if let Some(path) = &input.screenshot_path {
            let resolved = self.resolve_workspace_path_for_write(path)?;
            if let Some(parent) = resolved.parent() {
                fs::create_dir_all(parent)
                    .map_err(fs_error("BROWSER_SCREENSHOT_PREPARE_FAILED"))?;
            }
            Some((path.clone(), resolved))
        } else {
            None
        };
        let (playwright_launcher, browser_env) = resolve_bundled_browser_runtime(&browser)?;
        let mut command = vec![
            playwright_launcher.to_string_lossy().into_owned(),
            "screenshot".to_string(),
            "--browser".to_string(),
            browser.clone(),
            "--timeout".to_string(),
            (timeout_seconds * 1000).to_string(),
            "--proxy-server".to_string(),
            browser_proxy.address().to_string(),
        ];
        command.push(input.url.clone());
        if let Some((_, absolute_path)) = &screenshot_path {
            command.push(absolute_path.to_string_lossy().to_string());
        } else {
            let temp_path = self.workspace_root.join(".loomex-browser-screenshot.png");
            command.push(temp_path.to_string_lossy().to_string());
        }
        let shell_output = self.shell_exec(ShellExecInput {
            command,
            workspace_scope: ShellWorkspaceScope::Unrestricted,
            env: command_env_with_path_and(browser_env),
            timeout_seconds: Some(timeout_seconds),
            max_output_bytes: Some(max_output_bytes),
        })?;
        if shell_output.exit_code != 0 || shell_output.artifacts.timed_out {
            return Err(CoreError::new(
                if shell_output.artifacts.timed_out {
                    "BROWSER_TIMEOUT"
                } else {
                    "BROWSER_PLAYWRIGHT_FAILED"
                },
                non_empty_message(
                    &shell_output.artifacts.stderr,
                    "browser.playwright command failed",
                ),
            ));
        }
        let screenshot_ref = screenshot_path.as_ref().and_then(|(relative, absolute)| {
            artifact_ref_for_file("browser-screenshot", relative, absolute)
        });
        let trace_ref = if let Some(trace_path) = &input.trace_path {
            let trace = self.resolve_workspace_path_for_write(trace_path)?;
            if let Some(parent) = trace.parent() {
                fs::create_dir_all(parent).map_err(fs_error("BROWSER_TRACE_PREPARE_FAILED"))?;
            }
            let manifest = serde_json::json!({
                "url": input.url,
                "browser": browser,
                "screenshot_ref": screenshot_ref,
                "duration_ms": started.elapsed().as_millis() as u64
            });
            atomic_write(
                &trace,
                serde_json::to_string_pretty(&manifest)
                    .map_err(json_error("BROWSER_TRACE_SERIALIZE_FAILED"))?
                    .as_bytes(),
                "BROWSER_TRACE_WRITE_FAILED",
            )?;
            artifact_ref_for_file("browser-trace", trace_path, &trace)
        } else {
            None
        };

        Ok(BrowserPlaywrightOutput {
            url: input.url,
            browser,
            screenshot_ref,
            trace_ref,
            duration_ms: started.elapsed().as_millis() as u64,
            stdout_ref: shell_output.stdout_ref,
            stderr_ref: shell_output.stderr_ref,
            truncated: shell_output.truncated,
            artifacts: BrowserPlaywrightArtifacts {
                stdout: shell_output.artifacts.stdout,
                stderr: shell_output.artifacts.stderr,
            },
        })
    }
}

struct ControlledBrowserProxy {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl ControlledBrowserProxy {
    fn start(policy: NetworkSecurityPolicy) -> CoreResult<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| CoreError::new("BROWSER_PROXY_START_FAILED", error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| CoreError::new("BROWSER_PROXY_START_FAILED", error.to_string()))?;
        let address = listener
            .local_addr()
            .map_err(|error| CoreError::new("BROWSER_PROXY_START_FAILED", error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let policy = policy.clone();
                        thread::spawn(move || handle_browser_proxy_connection(stream, policy));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { address, stop })
    }

    fn address(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for ControlledBrowserProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle_browser_proxy_connection(mut stream: TcpStream, policy: NetworkSecurityPolicy) {
    let mut request = Vec::with_capacity(8192);
    let mut buffer = [0u8; 4096];
    while request.len() < 64 * 1024 {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(count) => {
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let header_end = match request.windows(4).position(|part| part == b"\r\n\r\n") {
        Some(position) => position + 4,
        None => return,
    };
    let header = String::from_utf8_lossy(&request[..header_end]);
    let mut lines = header.lines();
    let Some(first_line) = lines.next() else {
        return;
    };
    let mut parts = first_line.split_whitespace();
    let Some(method) = parts.next() else { return };
    let Some(target) = parts.next() else { return };
    let (url, connect) = if method.eq_ignore_ascii_case("CONNECT") {
        let authority = target;
        let url = Url::parse(&format!("https://{authority}/"));
        (url, true)
    } else {
        (Url::parse(target), false)
    };
    let Ok(url) = url else {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let Ok(addresses) = policy.validated_socket_addrs(&url) else {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
    };
    let Some(address) = addresses.first() else {
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(*address) else {
        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        return;
    };
    if connect {
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        relay_proxy_streams(stream, upstream);
    } else {
        let request_target = url
            .path_segments()
            .map(|segments| format!("/{}", segments.collect::<Vec<_>>().join("/")))
            .unwrap_or_else(|| "/".to_string());
        let request_target = if let Some(query) = url.query() {
            format!("{request_target}?{query}")
        } else {
            request_target
        };
        let mut forwarded = format!("{method} {request_target} HTTP/1.1\r\n");
        for line in lines {
            if !line.to_ascii_lowercase().starts_with("proxy-connection:") {
                forwarded.push_str(line);
                forwarded.push_str("\r\n");
            }
        }
        forwarded.push_str("\r\n");
        if upstream.write_all(forwarded.as_bytes()).is_err() {
            return;
        }
        let _ = std::io::copy(&mut upstream, &mut stream);
    }
}

fn relay_proxy_streams(mut client: TcpStream, mut upstream: TcpStream) {
    let mut client_reader = match client.try_clone() {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut upstream_writer = match upstream.try_clone() {
        Ok(value) => value,
        Err(_) => return,
    };
    let upload = thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
    });
    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = upload.join();
}

impl LocalCapabilityExecutor {
    pub fn db_query(&self, input: DbQueryInput) -> CoreResult<DbQueryOutput> {
        self.db_query_with_cancel(input, &ShellCancellationToken::default())
    }

    pub fn db_query_with_cancel(
        &self,
        input: DbQueryInput,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<DbQueryOutput> {
        let started = Instant::now();
        if input.read_only == Some(false) {
            return Err(CoreError::new(
                "DB_READ_ONLY_REQUIRED",
                "db.query is read-only-only; use a separate approved mutation capability for writes",
            ));
        }
        validate_read_only_sql(&input.query)?;
        let timeout_seconds = bounded_seconds(
            input.timeout_seconds,
            DEFAULT_DB_TIMEOUT_SECONDS,
            1,
            300,
            "DB_TIMEOUT_INVALID",
            "db.query timeout_seconds must be between 1 and 300",
        )?;
        let max_output_bytes = expanded_output_limit(input.max_output_bytes)?;
        let max_rows = input.max_rows.unwrap_or(100).clamp(1, 10_000);
        let output = match input.driver.as_str() {
            "sqlite" => {
                self.db_query_sqlite(&input, timeout_seconds, max_output_bytes, max_rows, cancel)?
            }
            "postgres" => {
                self.db_query_postgres(&input, timeout_seconds, max_output_bytes, max_rows, cancel)?
            }
            _ => {
                return Err(CoreError::new(
                    "DB_DRIVER_UNSUPPORTED",
                    "db.query driver must be sqlite or postgres",
                ));
            }
        };
        if output
            .artifacts
            .rows_json
            .contains(&input.connection_string)
        {
            return Err(CoreError::new(
                "DB_SECRET_LEAK_DETECTED",
                "db.query output contained the raw connection string",
            ));
        }
        let rows_json = self.redactor.redact(&output.artifacts.rows_json);
        let limited_rows = limit_db_rows_json(&rows_json, max_rows);
        let columns = db_columns_from_json(&rows_json);
        let total_rows = db_row_count_from_json(&rows_json);
        let row_count = total_rows.min(max_rows);
        let rows_truncated = total_rows > max_rows || output.truncated;
        Ok(DbQueryOutput {
            driver: input.driver,
            columns,
            row_count,
            rows_ref: format!("inline:db-rows:{}", sha256_hex(limited_rows.as_bytes())),
            duration_ms: started.elapsed().as_millis() as u64,
            truncated: rows_truncated,
            artifacts: DbQueryArtifacts {
                rows_json: limited_rows,
            },
        })
    }

    pub fn docker_exec(&self, input: DockerExecInput) -> CoreResult<DockerExecOutput> {
        self.docker_exec_with_binary(input, "docker")
    }

    fn docker_exec_with_binary(
        &self,
        input: DockerExecInput,
        docker_binary: &str,
    ) -> CoreResult<DockerExecOutput> {
        if input.command.is_empty() || input.command.iter().any(|part| part.trim().is_empty()) {
            return Err(CoreError::new(
                "DOCKER_COMMAND_EMPTY",
                "docker.exec command must not be empty",
            ));
        }
        if !self
            .docker_allowed_containers
            .iter()
            .any(|container| container == &input.container)
        {
            return Err(CoreError::new(
                "DOCKER_CONTAINER_DENIED",
                "docker.exec container is not in the allowlist",
            ));
        }
        let timeout_seconds = bounded_seconds(
            input.timeout_seconds,
            DEFAULT_TIMEOUT_SECONDS,
            1,
            3600,
            "DOCKER_TIMEOUT_INVALID",
            "docker.exec timeout_seconds must be between 1 and 3600",
        )?;
        let max_output_bytes = expanded_output_limit(input.max_output_bytes)?;
        Command::new(docker_binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| CoreError::new("DOCKER_UNAVAILABLE", "docker command is unavailable"))?;
        let mut command = vec![
            docker_binary.to_string(),
            "exec".to_string(),
            input.container.clone(),
        ];
        command.extend(input.command.clone());
        let started = Instant::now();
        let shell_output = self.shell_exec(ShellExecInput {
            command,
            workspace_scope: ShellWorkspaceScope::Unrestricted,
            env: command_env_with_path(),
            timeout_seconds: Some(timeout_seconds),
            max_output_bytes: Some(max_output_bytes),
        })?;
        Ok(DockerExecOutput {
            container: input.container,
            exit_code: shell_output.exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
            stdout_ref: shell_output.stdout_ref,
            stderr_ref: shell_output.stderr_ref,
            truncated: shell_output.truncated,
            artifacts: ShellExecOutputArtifacts {
                stdout: shell_output.artifacts.stdout,
                stderr: shell_output.artifacts.stderr,
                timed_out: shell_output.artifacts.timed_out,
                cancelled: shell_output.artifacts.cancelled,
                redaction_metadata: shell_output.artifacts.redaction_metadata,
            },
        })
    }

    pub fn test_run(&self, input: TestRunInput) -> CoreResult<TestRunOutput> {
        let command = test_runner_command(&input)?;
        let timeout_seconds = bounded_seconds(
            input.timeout_seconds,
            DEFAULT_TEST_TIMEOUT_SECONDS,
            1,
            3600,
            "TEST_TIMEOUT_INVALID",
            "test.run timeout_seconds must be between 1 and 3600",
        )?;
        let max_output_bytes = expanded_output_limit(input.max_output_bytes)?;
        let started = Instant::now();
        let output = self.shell_exec_with_working_directory(
            ShellExecInput {
                command,
                workspace_scope: ShellWorkspaceScope::Unrestricted,
                env: command_env_with_path_and(input.env.clone()),
                timeout_seconds: Some(timeout_seconds),
                max_output_bytes: Some(max_output_bytes),
            },
            input.working_directory.as_deref().unwrap_or("."),
            &ShellCancellationToken::default(),
        )?;
        let combined = format!("{}\n{}", output.artifacts.stdout, output.artifacts.stderr);
        let report = parse_test_report(&combined, output.exit_code);
        Ok(TestRunOutput {
            runner: input.runner,
            exit_code: output.exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
            passed: report.passed,
            failed: report.failed,
            skipped: report.skipped,
            stdout_ref: output.stdout_ref,
            stderr_ref: output.stderr_ref,
            truncated: output.truncated,
            artifacts: ShellExecOutputArtifacts {
                stdout: output.artifacts.stdout,
                stderr: output.artifacts.stderr,
                timed_out: output.artifacts.timed_out,
                cancelled: output.artifacts.cancelled,
                redaction_metadata: output.artifacts.redaction_metadata,
            },
        })
    }

    pub fn http_request_with_redirects(
        &self,
        input: HttpRequestInput,
        follow_redirects: bool,
    ) -> CoreResult<HttpRequestOutput> {
        let started = Instant::now();
        let method = parse_http_method(&input.method)?;
        let url = Url::parse(&input.url)
            .map_err(|error| CoreError::new("HTTP_URL_INVALID", error.to_string()))?;
        validate_http_url(&url)?;
        let timeout = Duration::from_secs(http_timeout_seconds(input.timeout_seconds)?);
        let max_response_bytes = http_response_limit(input.max_response_bytes)?;
        self.security.network.validate_url(&url)?;
        let validated_addresses = self.security.network.validated_socket_addrs(&url)?;
        let client = Client::builder()
            .timeout(timeout)
            .resolve_to_addrs(
                url.host_str().ok_or_else(|| {
                    CoreError::new("NETWORK_HOST_MISSING", "network host is required")
                })?,
                &validated_addresses,
            )
            .redirect(http_redirect_policy(
                follow_redirects,
                self.security.network.clone(),
            ))
            .build()
            .map_err(|error| CoreError::new("HTTP_CLIENT_CREATE_FAILED", error.to_string()))?;
        let redacted_request_headers =
            redact_request_headers(&input.headers, &self.secret_env_names);
        let mut request = client.request(method, url);
        for (name, value) in &input.headers {
            validate_http_header_name(name)?;
            request = request.header(name.as_str(), value.as_str());
        }
        if let Some(body) = input.body {
            request = request.body(decode_http_body(
                &body,
                input.body_encoding.as_deref().unwrap_or("utf-8"),
            )?);
        }
        let mut response = request.send().map_err(http_send_error)?;
        let status_code = response.status().as_u16();
        let headers = redact_response_headers(response.headers(), &self.secret_env_names);
        let mut bytes = Vec::new();
        let read_limit = max_response_bytes.saturating_add(1) as u64;
        response
            .by_ref()
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(fs_error("HTTP_RESPONSE_READ_FAILED"))?;
        let body_truncated = bytes.len() > max_response_bytes;
        if body_truncated {
            bytes.truncate(max_response_bytes);
        }
        Ok(HttpRequestOutput {
            status_code,
            headers,
            body_ref: format!("inline:http-body:{}", sha256_hex(&bytes)),
            body_truncated,
            duration_ms: started.elapsed().as_millis() as u64,
            artifacts: HttpRequestArtifacts {
                body: bytes,
                request_headers: redacted_request_headers,
            },
        })
    }

    fn db_query_sqlite(
        &self,
        input: &DbQueryInput,
        timeout_seconds: u64,
        max_output_bytes: usize,
        max_rows: usize,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<DbRawOutput> {
        let database_path = sqlite_database_path(&input.connection_string)?;
        let resolved = self.resolve_workspace_path(&database_path, true)?;
        let output = self.shell_exec_with_cancel(
            ShellExecInput {
                command: vec![
                    "sqlite3".to_string(),
                    "-readonly".to_string(),
                    "-bail".to_string(),
                    "-json".to_string(),
                    resolved.to_string_lossy().to_string(),
                    format!(
                        "PRAGMA query_only=ON; BEGIN; {}; COMMIT;",
                        sqlite_limit_query(&input.query, max_rows.saturating_add(1))
                    ),
                ],
                workspace_scope: ShellWorkspaceScope::Unrestricted,
                env: command_env_with_path(),
                timeout_seconds: Some(timeout_seconds),
                max_output_bytes: Some(max_output_bytes),
            },
            cancel,
        )?;
        if output.exit_code != 0 {
            return Err(CoreError::new(
                if output.artifacts.cancelled {
                    "DB_QUERY_CANCELLED"
                } else if output.artifacts.timed_out {
                    "DB_QUERY_TIMEOUT"
                } else {
                    "DB_QUERY_FAILED"
                },
                non_empty_message(&output.artifacts.stderr, "sqlite query failed"),
            ));
        }
        Ok(DbRawOutput {
            truncated: output.truncated,
            artifacts: DbQueryArtifacts {
                rows_json: output.artifacts.stdout,
            },
        })
    }

    fn db_query_postgres(
        &self,
        input: &DbQueryInput,
        timeout_seconds: u64,
        max_output_bytes: usize,
        max_rows: usize,
        cancel: &ShellCancellationToken,
    ) -> CoreResult<DbRawOutput> {
        let role = postgres_read_only_role()?;
        let timeout_ms = timeout_seconds.saturating_mul(1000);
        let output = self.shell_exec_with_cancel(ShellExecInput {
            command: vec![
                "psql".to_string(),
                input.connection_string.clone(),
                "--username".to_string(),
                role,
                "--no-psqlrc".to_string(),
                "--set".to_string(),
                "ON_ERROR_STOP=1".to_string(),
                "--csv".to_string(),
                "--command".to_string(),
                format!(
                    "BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '{}ms'; {}; COMMIT;",
                    timeout_ms,
                    postgres_limit_query(&input.query, max_rows)
                ),
            ],
            workspace_scope: ShellWorkspaceScope::Unrestricted,
            env: command_env_with_path(),
            timeout_seconds: Some(timeout_seconds),
            max_output_bytes: Some(max_output_bytes),
        }, cancel)?;
        if output.exit_code != 0 {
            return Err(CoreError::new(
                if output.artifacts.cancelled {
                    "DB_QUERY_CANCELLED"
                } else if output.artifacts.timed_out {
                    "DB_QUERY_TIMEOUT"
                } else {
                    "DB_QUERY_FAILED"
                },
                non_empty_message(&output.artifacts.stderr, "postgres query failed"),
            ));
        }
        Ok(DbRawOutput {
            truncated: output.truncated,
            artifacts: DbQueryArtifacts {
                rows_json: self.redactor.redact(&output.artifacts.stdout),
            },
        })
    }

    fn collect_entries(
        &self,
        base: &Path,
        entries: &mut Vec<FileEntry>,
        input: &FsListInput,
        max_entries: usize,
    ) -> CoreResult<()> {
        if entries.len() > max_entries {
            return Ok(());
        }
        let read_dir = fs::read_dir(base).map_err(fs_error("FS_LIST_FAILED"))?;
        for entry in read_dir {
            let entry = entry.map_err(fs_error("FS_LIST_FAILED"))?;
            let file_name = entry.file_name().to_string_lossy().to_string();
            if !input.include_hidden.unwrap_or(false) && file_name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let metadata = if input.follow_symlinks.unwrap_or(false) {
                fs::metadata(&path)
            } else {
                fs::symlink_metadata(&path)
            }
            .map_err(fs_error("FS_LIST_FAILED"))?;
            if input.follow_symlinks.unwrap_or(false) {
                self.ensure_inside_root(&path, true)?;
            }
            let entry_type = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else {
                "file"
            }
            .to_string();
            entries.push(FileEntry {
                path: self.relative_path(&path)?,
                entry_type,
                size_bytes: metadata.len() as usize,
                modified_epoch_ms: metadata.modified().ok().and_then(system_time_epoch_ms),
            });
            if metadata.is_dir() && input.recursive.unwrap_or(false) {
                self.collect_entries(&path, entries, input, max_entries)?;
            }
            if entries.len() > max_entries {
                break;
            }
        }
        Ok(())
    }

    fn resolve_workspace_path(
        &self,
        requested_path: &str,
        follow_symlinks: bool,
    ) -> CoreResult<PathBuf> {
        validate_relative_path(requested_path)?;
        self.security
            .sandbox
            .validate_relative_path(requested_path)?;
        let joined = self.workspace_root.join(requested_path);
        self.ensure_inside_root(&joined, follow_symlinks)
    }

    fn resolve_workspace_path_for_write(&self, requested_path: &str) -> CoreResult<PathBuf> {
        validate_relative_path(requested_path)?;
        self.security
            .sandbox
            .validate_relative_path(requested_path)?;
        let joined = self.workspace_root.join(requested_path);
        if let Ok(metadata) = fs::symlink_metadata(&joined) {
            if metadata.file_type().is_symlink() {
                return Err(CoreError::new(
                    "FS_WRITE_SYMLINK_OR_NOT_FILE",
                    "write targets must be regular, non-symlink files",
                ));
            }
        }
        if joined.exists() {
            self.ensure_inside_root(&joined, true)
        } else {
            let parent = joined.parent().ok_or_else(|| {
                CoreError::new("WORKSPACE_PATH_INVALID", "workspace path parent is invalid")
            })?;
            self.ensure_inside_root(parent, true)?;
            Ok(joined)
        }
    }

    fn ensure_inside_root(&self, path: &Path, follow_symlinks: bool) -> CoreResult<PathBuf> {
        let target = if follow_symlinks && path.exists() {
            fs::canonicalize(path).map_err(fs_error("WORKSPACE_PATH_RESOLVE_FAILED"))?
        } else {
            normalize_path_without_symlink(path)?
        };
        if !target.starts_with(&self.workspace_root) {
            return Err(CoreError::new(
                "WORKSPACE_PATH_OUTSIDE_ROOT",
                "workspace path escapes the execution root",
            ));
        }
        Ok(target)
    }

    fn relative_path(&self, path: &Path) -> CoreResult<String> {
        let target = if path.exists() {
            fs::canonicalize(path).map_err(fs_error("WORKSPACE_PATH_RESOLVE_FAILED"))?
        } else {
            normalize_path_without_symlink(path)?
        };
        let relative = target.strip_prefix(&self.workspace_root).map_err(|_| {
            CoreError::new(
                "WORKSPACE_PATH_OUTSIDE_ROOT",
                "workspace path escapes the execution root",
            )
        })?;
        let value = relative.to_string_lossy().replace('\\', "/");
        Ok(if value.is_empty() {
            ".".to_string()
        } else {
            value
        })
    }

    fn filtered_env(&self, env: BTreeMap<String, String>) -> BTreeMap<String, String> {
        // `shell.exec` deliberately uses `env_clear` before spawning a child so
        // arbitrary credentials from the Runner process never leak into a job.
        // Keep the small, non-secret execution baseline that a user-level CLI
        // needs under launchd/systemd though. In particular, a LaunchAgent's
        // PATH does not normally include ~/.local/bin and an unset HOME makes
        // provider CLIs unable to read their own user configuration.
        let mut filtered = default_child_environment();
        filtered.extend(
            self.security
                .child_environment
                .filter_env(env, &self.secret_env_names),
        );
        filtered
    }

    fn validate_git_scope(&self, pathspecs: Option<&[String]>) -> CoreResult<()> {
        match pathspecs {
            Some(paths) if !paths.is_empty() => {
                for path in paths {
                    validate_relative_path(path)?;
                    self.security.sandbox.validate_relative_path(path)?;
                }
                Ok(())
            }
            _ if self.security.sandbox.denied_workspace_prefixes.is_empty() => Ok(()),
            _ => Err(CoreError::new(
                "GIT_SANDBOX_SCOPE_REQUIRED",
                "repo-wide git output is disabled when sandbox denied paths are configured",
            )),
        }
    }

    fn validate_browser_network_preflight(
        &self,
        url: &Url,
        timeout_seconds: u64,
    ) -> CoreResult<()> {
        if self.security.network == NetworkSecurityPolicy::default() {
            return Ok(());
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(http_redirect_policy(true, self.security.network.clone()))
            .build()
            .map_err(|error| CoreError::new("BROWSER_CLIENT_CREATE_FAILED", error.to_string()))?;
        client
            .get(url.clone())
            .send()
            .map_err(http_send_error)
            .map(|_| ())
    }

    fn discover_git_repository(&self, repository_path: Option<&str>) -> CoreResult<GitRepository> {
        let requested = repository_path.unwrap_or(".");
        let start = self.resolve_workspace_path(requested, true)?;
        if !start.exists() {
            return Err(CoreError::new(
                "GIT_REPOSITORY_NOT_FOUND",
                "git repository path does not exist",
            ));
        }
        let output = self
            .run_git_allow_failure(&start, &["rev-parse", "--show-toplevel"])
            .map_err(|_| {
                CoreError::new(
                    "GIT_REPOSITORY_NOT_FOUND",
                    "no git repository found inside workspace path",
                )
            })?
            .map_err(|_| {
                CoreError::new(
                    "GIT_REPOSITORY_NOT_FOUND",
                    "no git repository found inside workspace path",
                )
            })?;
        let repo_path = PathBuf::from(output.stdout.trim());
        let repo_path = self.ensure_inside_root(&repo_path, true)?;
        Ok(GitRepository { path: repo_path })
    }

    fn run_git(&self, repo_path: &Path, args: &[&str]) -> CoreResult<GitCommandOutput> {
        self.run_git_allow_failure(repo_path, args)?
    }

    fn run_git_allow_failure(
        &self,
        repo_path: &Path,
        args: &[&str],
    ) -> CoreResult<CoreResult<GitCommandOutput>> {
        let output = self
            .spawn_git_command(repo_path, args)
            .output()
            .map_err(fs_error("GIT_COMMAND_SPAWN_FAILED"))?;
        Ok(git_output_result(
            output.status.code(),
            output.stdout,
            output.stderr,
        ))
    }

    fn run_git_bounded(
        &self,
        repo_path: &Path,
        args: &[&str],
        max_bytes: usize,
    ) -> CoreResult<GitCommandOutput> {
        let mut child = self
            .spawn_git_command(repo_path, args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(fs_error("GIT_COMMAND_SPAWN_FAILED"))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CoreError::new(
                "GIT_STDOUT_CAPTURE_FAILED",
                "git stdout pipe was not captured",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            CoreError::new(
                "GIT_STDERR_CAPTURE_FAILED",
                "git stderr pipe was not captured",
            )
        })?;
        let stdout_reader = read_bounded_pipe(stdout, max_bytes);
        let stderr_reader = read_bounded_pipe(stderr, max_bytes);
        let status = child.wait().map_err(fs_error("GIT_COMMAND_WAIT_FAILED"))?;
        let stdout = stdout_reader.join().map_err(|_| {
            CoreError::new("GIT_STDOUT_CAPTURE_FAILED", "git stdout reader panicked")
        })??;
        let stderr = stderr_reader.join().map_err(|_| {
            CoreError::new("GIT_STDERR_CAPTURE_FAILED", "git stderr reader panicked")
        })??;
        let mut output = git_output_result(status.code(), stdout.bytes, stderr.bytes)?;
        output.truncated = stdout.truncated || stderr.truncated;
        Ok(output)
    }

    fn spawn_git_command(&self, repo_path: &Path, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(repo_path)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        command
    }
}

impl CapabilityExecutor for LocalCapabilityExecutor {
    fn capability(&self) -> &'static str {
        "local.runner"
    }

    fn supports(&self, capability: &str) -> bool {
        matches!(
            capability,
            "fs.list"
                | "fs.read"
                | "fs.write"
                | "fs.apply_patch"
                | "shell.exec"
                | "git.status"
                | "git.diff"
                | "git.log"
                | "http.request"
                | "browser.playwright"
                | "db.query"
                | "docker.exec"
                | "test.run"
        )
    }

    fn execute(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult> {
        let _ = request;
        Err(CoreError::new(
            "AUTHORIZED_REQUEST_REQUIRED",
            "local capability execution requires an authorized request",
        ))
    }
}

impl LocalCapabilityExecutor {
    fn execute_request(&self, capability: String, input: String) -> CoreResult<CapabilityResult> {
        let request = CapabilityRequest { capability, input };
        let output = match request.capability.as_str() {
            "fs.list" => serde_json::to_string(&self.fs_list(parse_input(&request)?)?),
            "fs.read" => serde_json::to_string(&self.fs_read(parse_input(&request)?)?),
            "fs.write" => serde_json::to_string(&self.fs_write(parse_input(&request)?)?),
            "fs.apply_patch" => {
                serde_json::to_string(&self.fs_apply_patch(parse_input(&request)?)?)
            }
            "shell.exec" => serde_json::to_string(&self.shell_exec(parse_input(&request)?)?),
            "git.status" => serde_json::to_string(&self.git_status(parse_input(&request)?)?),
            "git.diff" => serde_json::to_string(&self.git_diff(parse_input(&request)?)?),
            "git.log" => serde_json::to_string(&self.git_log(parse_input(&request)?)?),
            "http.request" => serde_json::to_string(&self.http_request(parse_input(&request)?)?),
            "browser.playwright" => {
                serde_json::to_string(&self.browser_playwright(parse_input(&request)?)?)
            }
            "db.query" => serde_json::to_string(&self.db_query(parse_input(&request)?)?),
            "docker.exec" => serde_json::to_string(&self.docker_exec(parse_input(&request)?)?),
            "test.run" => serde_json::to_string(&self.test_run(parse_input(&request)?)?),
            _ => {
                return Err(CoreError::new(
                    "UNSUPPORTED_CAPABILITY",
                    format!("unsupported local capability {}", request.capability),
                ));
            }
        }
        .map_err(json_error("CAPABILITY_RESULT_SERIALIZE_FAILED"))?;
        Ok(CapabilityResult {
            capability: request.capability,
            output,
        })
    }

    #[cfg(test)]
    fn execute_unchecked(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult> {
        self.execute_request(request.capability, request.input)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FsListInput {
    pub path: String,
    #[serde(default)]
    pub recursive: Option<bool>,
    #[serde(default)]
    pub include_hidden: Option<bool>,
    #[serde(default)]
    pub follow_symlinks: Option<bool>,
    #[serde(default)]
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsListOutput {
    pub entries: Vec<FileEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size_bytes: usize,
    pub modified_epoch_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FsReadInput {
    pub path: String,
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsReadOutput {
    pub path: String,
    pub encoding: String,
    pub content: String,
    pub sha256: String,
    pub size_bytes: usize,
    pub truncated: bool,
    pub binary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FsWriteInput {
    pub path: String,
    pub content: String,
    pub encoding: String,
    pub mode: String,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub create_parent_directories: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsWriteOutput {
    pub path: String,
    pub sha256: String,
    pub size_bytes: usize,
    pub created: bool,
    pub diff_ref: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FsApplyPatchInput {
    pub patch: String,
    #[serde(default)]
    pub base_sha256_by_path: BTreeMap<String, String>,
    #[serde(default)]
    pub strip: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsApplyPatchOutput {
    pub applied: bool,
    pub files_changed: Vec<FileChange>,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileChange {
    pub path: String,
    pub change_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecInput {
    pub command: Vec<String>,
    #[serde(default)]
    pub workspace_scope: ShellWorkspaceScope,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

/// Process-level workspace restriction requested by a trusted Runner job.
///
/// This is deliberately separate from the command's cwd: a cwd merely sets a
/// starting directory and does not stop a provider CLI from using an absolute
/// path elsewhere on the machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellWorkspaceScope {
    #[default]
    Unrestricted,
    ProviderWriteConfined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellExecOutput {
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_ref: String,
    pub stderr_ref: String,
    pub truncated: bool,
    #[serde(skip)]
    pub artifacts: ShellExecOutputArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellExecOutputArtifacts {
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
    pub redaction_metadata: RedactionMetadata,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedactionMetadata {
    pub filtered_env: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitStatusInput {
    #[serde(default)]
    pub porcelain: Option<bool>,
    #[serde(default)]
    pub include_untracked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitStatusOutput {
    pub branch: String,
    #[serde(skip)]
    pub detached: bool,
    pub clean: bool,
    pub files: Vec<GitStatusFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitStatusFile {
    pub path: String,
    pub status: String,
    #[serde(skip)]
    pub index_status: String,
    #[serde(skip)]
    pub working_tree_status: String,
    #[serde(skip)]
    pub original_path: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitDiffInput {
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub cached: Option<bool>,
    #[serde(default)]
    pub context_lines: Option<usize>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitDiffOutput {
    pub diff_ref: String,
    pub truncated: bool,
    pub files_changed: Vec<FileChange>,
    #[serde(skip)]
    pub artifacts: GitDiffArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitDiffArtifacts {
    pub diff: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLogInput {
    #[serde(default)]
    pub max_count: Option<usize>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitLogOutput {
    pub commits: Vec<GitCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitCommit {
    pub sha: String,
    pub author: String,
    pub committed_at: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestInput {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub body_encoding: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpRequestOutput {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body_ref: String,
    pub body_truncated: bool,
    pub duration_ms: u64,
    #[serde(skip)]
    pub artifacts: HttpRequestArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequestArtifacts {
    pub body: Vec<u8>,
    pub request_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPlaywrightInput {
    pub url: String,
    #[serde(default)]
    pub browser: Option<String>,
    #[serde(default)]
    pub headless: Option<bool>,
    #[serde(default)]
    pub screenshot_path: Option<String>,
    #[serde(default)]
    pub trace_path: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserPlaywrightOutput {
    pub url: String,
    pub browser: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_ref: Option<String>,
    pub duration_ms: u64,
    pub stdout_ref: String,
    pub stderr_ref: String,
    pub truncated: bool,
    #[serde(skip)]
    pub artifacts: BrowserPlaywrightArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserPlaywrightArtifacts {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbQueryInput {
    pub driver: String,
    pub connection_string: String,
    pub query: String,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub max_rows: Option<usize>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DbQueryOutput {
    pub driver: String,
    pub columns: Vec<String>,
    pub row_count: usize,
    pub rows_ref: String,
    pub duration_ms: u64,
    pub truncated: bool,
    #[serde(skip)]
    pub artifacts: DbQueryArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbQueryArtifacts {
    pub rows_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerExecInput {
    pub container: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerExecOutput {
    pub container: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_ref: String,
    pub stderr_ref: String,
    pub truncated: bool,
    #[serde(skip)]
    pub artifacts: ShellExecOutputArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRunInput {
    pub runner: String,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestRunOutput {
    pub runner: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub stdout_ref: String,
    pub stderr_ref: String,
    pub truncated: bool,
    #[serde(skip)]
    pub artifacts: ShellExecOutputArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DbRawOutput {
    truncated: bool,
    artifacts: DbQueryArtifacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedTestReport {
    passed: usize,
    failed: usize,
    skipped: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ShellCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl ShellCancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct ParsedPatchFile {
    path: String,
    hunks: Vec<ParsedHunk>,
}

#[derive(Debug, Clone)]
struct ParsedHunk {
    old_start: usize,
    lines: Vec<PatchLine>,
}

#[derive(Debug, Clone)]
enum PatchLine {
    Context(String),
    Remove(String),
    Add(String),
}

#[derive(Debug, Clone)]
struct ParsedFileChange {
    path: PathBuf,
    relative_path: String,
    before: String,
    after: String,
    target: Option<FileIdentity>,
    parent: FileIdentity,
}

#[derive(Debug)]
struct PreparedPatchChange {
    path: PathBuf,
    temp_path: PathBuf,
    rollback_path: Option<PathBuf>,
    relative_path: String,
    before: Vec<u8>,
    after: Vec<u8>,
    target: Option<FileIdentity>,
    parent: FileIdentity,
}

#[derive(Debug)]
struct WriteSnapshot {
    target: Option<FileIdentity>,
    parent: FileIdentity,
}

#[derive(Debug)]
struct BoundedPipeOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug, Clone)]
struct TruncatedText {
    value: String,
    truncated: bool,
}

#[derive(Debug, Clone)]
struct GitRepository {
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct GitCommandOutput {
    stdout: String,
    truncated: bool,
}

fn parse_input<T: for<'de> Deserialize<'de>>(request: &CapabilityRequest) -> CoreResult<T> {
    serde_json::from_str(&request.input).map_err(json_error("CAPABILITY_INPUT_INVALID"))
}

fn git_output_result(
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> CoreResult<GitCommandOutput> {
    let stdout = String::from_utf8_lossy(&stdout).to_string();
    let stderr = String::from_utf8_lossy(&stderr).to_string();
    if exit_code.unwrap_or(1) != 0 {
        return Err(CoreError::new(
            "GIT_COMMAND_FAILED",
            if stderr.trim().is_empty() {
                "git command failed".to_string()
            } else {
                stderr.trim().to_string()
            },
        ));
    }
    Ok(GitCommandOutput {
        stdout,
        truncated: false,
    })
}

fn append_git_pathspecs(args: &mut Vec<String>, pathspecs: Option<&[String]>) -> CoreResult<()> {
    let Some(pathspecs) = pathspecs else {
        return Ok(());
    };
    if pathspecs.is_empty() {
        return Ok(());
    }
    args.push("--".to_string());
    for pathspec in pathspecs {
        validate_relative_path(pathspec)?;
        args.push(pathspec.clone());
    }
    Ok(())
}

fn parse_git_status(output: &str) -> (String, bool, Vec<GitStatusFile>) {
    let mut branch = "unknown".to_string();
    let mut detached = false;
    let mut files = Vec::new();
    for line in output.lines() {
        if let Some(branch_line) = line.strip_prefix("## ") {
            let branch_name = branch_line.split("...").next().unwrap_or(branch_line);
            detached = branch_name.starts_with("HEAD (no branch)")
                || branch_name.starts_with("HEAD detached");
            branch = if detached {
                "HEAD".to_string()
            } else {
                branch_name.to_string()
            };
            continue;
        }
        if line.len() < 3 {
            continue;
        }
        let index_status = line.chars().next().unwrap_or(' ').to_string();
        let working_tree_status = line.chars().nth(1).unwrap_or(' ').to_string();
        let path_text = &line[3..];
        let (original_path, path) = path_text
            .split_once(" -> ")
            .map(|(original, path)| (Some(original.to_string()), path.to_string()))
            .unwrap_or((None, path_text.to_string()));
        files.push(GitStatusFile {
            path,
            status: git_status_name(&index_status, &working_tree_status),
            index_status,
            working_tree_status,
            original_path,
        });
    }
    (branch, detached, files)
}

fn git_status_name(index_status: &str, working_tree_status: &str) -> String {
    if index_status == "?" && working_tree_status == "?" {
        return "untracked".to_string();
    }
    if index_status == "A" || working_tree_status == "A" {
        return "added".to_string();
    }
    if index_status == "D" || working_tree_status == "D" {
        return "deleted".to_string();
    }
    if index_status == "R" || working_tree_status == "R" {
        return "renamed".to_string();
    }
    if index_status == "C" || working_tree_status == "C" {
        return "copied".to_string();
    }
    if index_status == "U" || working_tree_status == "U" {
        return "conflicted".to_string();
    }
    "modified".to_string()
}

fn parse_git_name_status(output: &str) -> Vec<FileChange> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let status = parts.next()?;
            let path = if status.starts_with('R') || status.starts_with('C') {
                let _old = parts.next()?;
                parts.next()?
            } else {
                parts.next()?
            };
            Some(FileChange {
                path: path.to_string(),
                change_type: git_change_type(status).to_string(),
                before_sha256: None,
                after_sha256: None,
            })
        })
        .collect()
}

fn git_change_type(status: &str) -> &'static str {
    match status.chars().next().unwrap_or('M') {
        'A' => "added",
        'D' => "deleted",
        _ => "modified",
    }
}

fn parse_git_log(output: &str) -> CoreResult<Vec<GitCommit>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split('\x1f').collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(CoreError::new(
                    "GIT_LOG_PARSE_FAILED",
                    "git log output did not match expected format",
                ));
            }
            Ok(GitCommit {
                sha: fields[0].to_string(),
                author: fields[1].to_string(),
                committed_at: fields[2].to_string(),
                subject: fields[3].to_string(),
            })
        })
        .collect()
}

fn parse_http_method(method: &str) -> CoreResult<Method> {
    match method {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        "HEAD" => Ok(Method::HEAD),
        "OPTIONS" => Ok(Method::OPTIONS),
        _ => Err(CoreError::new(
            "HTTP_METHOD_UNSUPPORTED",
            "http.request method is not supported",
        )),
    }
}

fn validate_http_url(url: &Url) -> CoreResult<()> {
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(CoreError::new(
            "HTTP_URL_INVALID",
            "http.request URL must be absolute http or https",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| CoreError::new("HTTP_URL_INVALID", "http.request URL host is required"))?;
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        validate_http_ip(ip)?;
        return Ok(());
    }
    if host.contains('_') {
        return Err(CoreError::new(
            "HTTP_DNS_FAILED",
            "http.request host is not a valid DNS name",
        ));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| CoreError::new("HTTP_DNS_FAILED", error.to_string()))?
        .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(CoreError::new(
            "HTTP_DNS_FAILED",
            "http.request host did not resolve",
        ));
    }
    for address in resolved {
        validate_http_ip(address.ip())?;
    }
    Ok(())
}

fn http_response_limit(value: Option<usize>) -> CoreResult<usize> {
    let value = value.unwrap_or(DEFAULT_MAX_HTTP_RESPONSE_BYTES);
    if value == 0 {
        return Err(CoreError::new(
            "HTTP_RESPONSE_LIMIT_INVALID",
            "http.request max_response_bytes must be at least 1",
        ));
    }
    if value > MAX_HTTP_RESPONSE_BYTES {
        return Err(CoreError::new(
            "HTTP_RESPONSE_LIMIT_INVALID",
            "http.request max_response_bytes exceeds the contract maximum",
        ));
    }
    Ok(value)
}

fn http_timeout_seconds(value: Option<u64>) -> CoreResult<u64> {
    let value = value.unwrap_or(DEFAULT_HTTP_TIMEOUT_SECONDS);
    if value == 0 || value > 300 {
        return Err(CoreError::new(
            "HTTP_TIMEOUT_INVALID",
            "http.request timeout_seconds must be between 1 and 300",
        ));
    }
    Ok(value)
}

fn http_redirect_policy(
    follow_redirects: bool,
    network_policy: NetworkSecurityPolicy,
) -> RedirectPolicy {
    if !follow_redirects {
        return RedirectPolicy::none();
    }
    RedirectPolicy::custom(move |attempt| {
        if attempt.previous().len() > 10 {
            return attempt.error("too many redirects");
        }
        match validate_http_url(attempt.url())
            .and_then(|_| network_policy.validate_url(attempt.url()))
        {
            Ok(()) => attempt.follow(),
            Err(error) => attempt.error(format!(
                "redirect target denied by local network safety rules: {}",
                error.code
            )),
        }
    })
}

fn validate_http_ip(ip: IpAddr) -> CoreResult<()> {
    if is_metadata_ip(ip) || is_unsafe_ip(ip) {
        return Err(CoreError::new(
            "HTTP_ENDPOINT_DENIED",
            "http.request target is denied by local network safety rules",
        ));
    }
    Ok(())
}

fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets()[0] == 169 && ip.octets()[1] == 254,
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            is_ipv6_link_local(ip) || segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

fn is_ipv6_link_local(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_unsafe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

fn validate_http_header_name(name: &str) -> CoreResult<()> {
    if name.trim().is_empty()
        || name.contains('\0')
        || name.contains('\n')
        || name.contains('\r')
        || name.contains(':')
    {
        return Err(CoreError::new(
            "HTTP_HEADER_INVALID",
            "http.request header name is invalid",
        ));
    }
    Ok(())
}

fn decode_http_body(body: &str, encoding: &str) -> CoreResult<Vec<u8>> {
    match encoding {
        "utf-8" => Ok(body.as_bytes().to_vec()),
        "base64" => BASE64_STANDARD.decode(body.as_bytes()).map_err(|_| {
            CoreError::new(
                "HTTP_BODY_BASE64_INVALID",
                "http.request body is not valid base64",
            )
        }),
        _ => Err(CoreError::new(
            "HTTP_BODY_ENCODING_INVALID",
            "http.request body_encoding must be utf-8 or base64",
        )),
    }
}

fn redact_response_headers(
    headers: &reqwest::header::HeaderMap,
    secret_header_names: &[String],
) -> BTreeMap<String, String> {
    let mut redacted = BTreeMap::new();
    for (name, value) in headers {
        let name_text = name.as_str().to_ascii_lowercase();
        let value_text = value.to_str().unwrap_or("<binary>").to_string();
        if is_secret_http_header_name(&name_text, secret_header_names) {
            redacted.insert(name_text, "[REDACTED]".to_string());
        } else {
            redacted.insert(name_text, value_text);
        }
    }
    redacted
}

fn redact_request_headers(
    headers: &BTreeMap<String, String>,
    secret_header_names: &[String],
) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| {
            let normalized = name.to_ascii_lowercase();
            if is_secret_http_header_name(&normalized, secret_header_names) {
                (normalized, "[REDACTED]".to_string())
            } else {
                (normalized, value.clone())
            }
        })
        .collect()
}

fn is_secret_http_header_name(name: &str, secret_header_names: &[String]) -> bool {
    matches!(name, "authorization" | "cookie" | "set-cookie")
        || secret_header_names
            .iter()
            .any(|secret| secret.eq_ignore_ascii_case(name))
}

fn http_send_error(error: reqwest::Error) -> CoreError {
    if error.is_timeout() {
        CoreError::new("HTTP_TIMEOUT", error.to_string())
    } else if error.to_string().contains("redirect target denied") || error.is_redirect() {
        CoreError::new("HTTP_ENDPOINT_DENIED", error.to_string())
    } else if error.is_connect() {
        CoreError::new("HTTP_CONNECT_FAILED", error.to_string())
    } else {
        CoreError::new("HTTP_REQUEST_FAILED", error.to_string())
    }
}

fn commit_patch_changes(changes: Vec<ParsedFileChange>) -> CoreResult<Vec<FileChange>> {
    let mut seen_paths = Vec::new();
    for change in &changes {
        if seen_paths.contains(&change.path) {
            return Err(CoreError::new(
                "PATCH_DUPLICATE_PATH",
                "patch contains duplicate file paths and cannot be committed atomically",
            ));
        }
        seen_paths.push(change.path.clone());
    }

    let mut prepared: Vec<PreparedPatchChange> = Vec::new();
    for change in changes {
        match prepare_atomic_write(
            &change.path,
            change.after.as_bytes(),
            "PATCH_PREPARE_FAILED",
        ) {
            Ok(temp_path) => {
                let before = change.before.into_bytes();
                let rollback_path =
                    prepare_atomic_write(&change.path, &before, "PATCH_PREPARE_FAILED").ok();
                if rollback_path.is_none() {
                    let _ = fs::remove_file(temp_path);
                    for item in &prepared {
                        let _ = fs::remove_file(&item.temp_path);
                        if let Some(path) = &item.rollback_path {
                            let _ = fs::remove_file(path);
                        }
                    }
                    return Err(CoreError::new(
                        "PATCH_PREPARE_FAILED",
                        "could not create patch rollback journal",
                    ));
                }
                prepared.push(PreparedPatchChange {
                    path: change.path,
                    temp_path,
                    rollback_path,
                    relative_path: change.relative_path,
                    before,
                    after: change.after.into_bytes(),
                    target: change.target,
                    parent: change.parent,
                });
            }
            Err(error) => {
                for item in &prepared {
                    let _ = fs::remove_file(&item.temp_path);
                    if let Some(path) = &item.rollback_path {
                        let _ = fs::remove_file(path);
                    }
                }
                return Err(error);
            }
        }
    }

    let mut committed_indices: Vec<usize> = Vec::new();
    for (index, change) in prepared.iter().enumerate() {
        if let Err(error) = validate_snapshot(&change.path, change.target.as_ref(), &change.parent)
        {
            cleanup_patch_temps(&prepared);
            if let Err(rollback) = rollback_patch_changes(&prepared, &committed_indices) {
                return Err(rollback);
            }
            cleanup_patch_journal(&prepared);
            return Err(error);
        }
        if let Err(error) = fs::rename(&change.temp_path, &change.path) {
            cleanup_patch_temps(&prepared);
            if let Err(rollback) = rollback_patch_changes(&prepared, &committed_indices) {
                return Err(rollback);
            }
            cleanup_patch_journal(&prepared);
            return Err(CoreError::new("PATCH_COMMIT_FAILED", error.to_string()));
        }
        fsync_parent(&change.path);
        committed_indices.push(index);
    }

    Ok(prepared
        .into_iter()
        .map(|change| {
            if let Some(path) = change.rollback_path {
                let _ = fs::remove_file(path);
            }
            FileChange {
                path: change.relative_path,
                change_type: "modified".to_string(),
                before_sha256: Some(sha256_hex(&change.before)),
                after_sha256: Some(sha256_hex(&change.after)),
            }
        })
        .collect())
}

fn cleanup_patch_journal(changes: &[PreparedPatchChange]) {
    for item in changes {
        let _ = fs::remove_file(&item.temp_path);
        if let Some(path) = &item.rollback_path {
            let _ = fs::remove_file(path);
        }
    }
}

fn cleanup_patch_temps(changes: &[PreparedPatchChange]) {
    for item in changes {
        let _ = fs::remove_file(&item.temp_path);
    }
}

fn rollback_patch_changes(changes: &[PreparedPatchChange], committed: &[usize]) -> CoreResult<()> {
    for index in committed.iter().rev() {
        let item = &changes[*index];
        let current =
            fs::symlink_metadata(&item.path).map_err(fs_error("PATCH_ROLLBACK_FAILED"))?;
        if current.file_type().is_symlink() || !current.is_file() {
            return Err(CoreError::new(
                "PATCH_ROLLBACK_FAILED",
                "target changed to a symlink or non-file while rolling back",
            ));
        }
        let Some(rollback_path) = &item.rollback_path else {
            return Err(CoreError::new(
                "PATCH_ROLLBACK_FAILED",
                "rollback journal missing",
            ));
        };
        fs::rename(rollback_path, &item.path).map_err(fs_error("PATCH_ROLLBACK_FAILED"))?;
        fsync_parent(&item.path);
    }
    Ok(())
}

fn write_snapshot(path: &Path, allow_missing: bool) -> CoreResult<WriteSnapshot> {
    let parent = snapshot_parent(path)?;
    let target = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CoreError::new(
                    "FS_WRITE_SYMLINK_OR_NOT_FILE",
                    "write targets must be regular, non-symlink files",
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o222 == 0 {
                return Err(CoreError::new(
                    "FS_WRITE_PERMISSION_DENIED",
                    "write target is not writable",
                ));
            }
            Some(file_identity(&metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && allow_missing => None,
        Err(error) => return Err(fs_error("FS_WRITE_TARGET_FAILED")(error)),
    };
    Ok(WriteSnapshot { target, parent })
}

fn snapshot_parent(path: &Path) -> CoreResult<FileIdentity> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::new("FS_WRITE_PARENT_FAILED", "target path parent is invalid"))?;
    let mut current = Some(parent);
    while let Some(directory) = current {
        let metadata =
            fs::symlink_metadata(directory).map_err(fs_error("FS_WRITE_PARENT_FAILED"))?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::new(
                "FS_WRITE_SYMLINK_OR_NOT_FILE",
                "write target parents must not contain symlinks",
            ));
        }
        current = directory.parent();
    }
    let metadata = fs::symlink_metadata(parent).map_err(fs_error("FS_WRITE_PARENT_FAILED"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoreError::new(
            "FS_WRITE_PARENT_CHANGED",
            "write target parent must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o222 == 0 {
        return Err(CoreError::new(
            "FS_WRITE_PERMISSION_DENIED",
            "write target parent is not writable",
        ));
    }
    Ok(file_identity(&metadata))
}

fn validate_write_parent_chain(path: &Path) -> CoreResult<()> {
    let mut current = Some(path);
    while let Some(directory) = current {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CoreError::new(
                    "FS_WRITE_SYMLINK_OR_NOT_FILE",
                    "write target parents must not contain symlinks",
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(CoreError::new(
                    "FS_WRITE_PARENT_CHANGED",
                    "write target parent must be a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(fs_error("FS_WRITE_PARENT_FAILED")(error)),
        }
        current = directory.parent();
    }
    Ok(())
}

fn validate_snapshot(
    path: &Path,
    expected_target: Option<&FileIdentity>,
    expected_parent: &FileIdentity,
) -> CoreResult<()> {
    if &snapshot_parent(path)? != expected_parent {
        return Err(CoreError::new(
            "FS_WRITE_PATH_CHANGED",
            "write target parent changed during commit",
        ));
    }
    let current = fs::symlink_metadata(path).map_err(fs_error("FS_WRITE_PATH_CHANGED"))?;
    if current.file_type().is_symlink() || !current.is_file() {
        return Err(CoreError::new(
            "FS_WRITE_PATH_CHANGED",
            "write target changed to a symlink or non-file",
        ));
    }
    if expected_target != Some(&file_identity(&current)) {
        return Err(CoreError::new(
            "FS_WRITE_CONFLICT",
            "write target changed since it was read",
        ));
    }
    Ok(())
}

fn atomic_write_checked(
    path: &Path,
    bytes: &[u8],
    expected_target: Option<&FileIdentity>,
    expected_parent: &FileIdentity,
    code: &'static str,
) -> CoreResult<()> {
    let temp_path = prepare_atomic_write(path, bytes, code)?;
    let validation = if expected_target.is_some() {
        validate_snapshot(path, expected_target, expected_parent)
    } else if &snapshot_parent(path)? != expected_parent {
        Err(CoreError::new(
            "FS_WRITE_CONFLICT",
            "create target parent changed",
        ))
    } else {
        match fs::symlink_metadata(path) {
            Ok(_) => Err(CoreError::new(
                "FS_WRITE_CONFLICT",
                "create target appeared or changed",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fs_error("FS_WRITE_CONFLICT")(error)),
        }
    };
    if let Err(error) = validation {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(CoreError::new(code, error.to_string()));
    }
    fsync_parent(path);
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], code: &'static str) -> CoreResult<()> {
    let temp_path = prepare_atomic_write(path, bytes, code)?;
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(CoreError::new(code, error.to_string()));
    }
    fsync_parent(path);
    Ok(())
}

fn prepare_atomic_write(path: &Path, bytes: &[u8], code: &'static str) -> CoreResult<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::new(code, "target path parent is invalid"))?;
    let temp_path = unique_temp_path(path);
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(fs_error(code))?;
    file.write_all(bytes).map_err(fs_error(code))?;
    file.flush().map_err(fs_error(code))?;
    file.sync_all().map_err(fs_error(code))?;
    fsync_parent(parent);
    Ok(temp_path)
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(
        ".{name}.loomex-tmp-{}-{unique}",
        std::process::id()
    ))
}

fn fsync_parent(path: &Path) {
    let directory = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };
    if let Ok(file) = File::open(directory) {
        let _ = file.sync_all();
    }
}

fn read_bounded_pipe<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<CoreResult<BoundedPipeOutput>> {
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(max_bytes.min(8192));
        let mut truncated = false;
        let mut buffer = [0u8; 8192];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(fs_error("SHELL_OUTPUT_READ_FAILED"))?;
            if read == 0 {
                break;
            }
            let remaining = max_bytes.saturating_sub(bytes.len());
            if remaining == 0 {
                truncated = true;
                continue;
            }
            let take = read.min(remaining);
            bytes.extend_from_slice(&buffer[..take]);
            if take < read {
                truncated = true;
            }
        }
        Ok(BoundedPipeOutput { bytes, truncated })
    })
}

fn normalize_root(root: PathBuf) -> CoreResult<PathBuf> {
    fs::create_dir_all(&root).map_err(fs_error("WORKSPACE_ROOT_CREATE_FAILED"))?;
    fs::canonicalize(&root).map_err(fs_error("WORKSPACE_ROOT_INVALID"))
}

fn validate_relative_path(path: &str) -> CoreResult<()> {
    crate::service::validate_cross_platform_relative_path(path)?;
    if path.trim().is_empty() || path.contains('\0') || path.contains('\n') || path.contains('\r') {
        return Err(CoreError::new(
            "WORKSPACE_PATH_INVALID",
            "workspace path is invalid",
        ));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(CoreError::new(
            "WORKSPACE_PATH_ABSOLUTE",
            "workspace path must be relative",
        ));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(CoreError::new(
                "WORKSPACE_PATH_OUTSIDE_ROOT",
                "workspace path escapes the execution root",
            ));
        }
    }
    Ok(())
}

fn normalize_path_without_symlink(path: &Path) -> CoreResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn decode_content(content: &str, encoding: &str) -> CoreResult<Vec<u8>> {
    match encoding {
        "utf-8" => Ok(content.as_bytes().to_vec()),
        "base64" => BASE64_STANDARD.decode(content.as_bytes()).map_err(|_| {
            CoreError::new("FS_CONTENT_BASE64_INVALID", "content is not valid base64")
        }),
        _ => Err(CoreError::new(
            "FS_CONTENT_ENCODING_INVALID",
            "encoding must be utf-8 or base64",
        )),
    }
}

fn bounded_seconds(
    value: Option<u64>,
    default: u64,
    min: u64,
    max: u64,
    code: &'static str,
    message: &'static str,
) -> CoreResult<u64> {
    let value = value.unwrap_or(default);
    if value < min || value > max {
        return Err(CoreError::new(code, message));
    }
    Ok(value)
}

fn expanded_output_limit(value: Option<usize>) -> CoreResult<usize> {
    let value = value.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES);
    if value == 0 || value > MAX_EXPANDED_OUTPUT_BYTES {
        return Err(CoreError::new(
            "CAPABILITY_OUTPUT_LIMIT_INVALID",
            "max_output_bytes must be between 1 and 10485760",
        ));
    }
    Ok(value)
}

fn command_with_workspace_scope(input: &ShellExecInput, cwd: &Path) -> CoreResult<Command> {
    match input.workspace_scope {
        ShellWorkspaceScope::Unrestricted => {
            let mut command = Command::new(&input.command[0]);
            command.args(&input.command[1..]);
            Ok(command)
        }
        ShellWorkspaceScope::ProviderWriteConfined => {
            provider_write_confined_command(&input.command, cwd)
        }
    }
}

#[cfg(target_os = "macos")]
fn provider_write_confined_command(command_argv: &[String], cwd: &Path) -> CoreResult<Command> {
    const SANDBOX_EXECUTABLE: &str = "/usr/bin/sandbox-exec";
    if !Path::new(SANDBOX_EXECUTABLE).is_file() {
        return Err(CoreError::new(
            "PROVIDER_WORKSPACE_SANDBOX_UNAVAILABLE",
            "macOS sandbox-exec is unavailable; refusing to run a provider without workspace confinement",
        ));
    }
    let workspace_path = cwd
        .canonicalize()
        .map_err(fs_error("WORKSPACE_PATH_RESOLVE_FAILED"))?;
    let execution_argv = provider_workspace_command_argv(command_argv, &workspace_path)?;
    let workspace = sandbox_profile_path(&workspace_path)?;
    let provider_state_policy = provider_state_write_policy(&execution_argv[0])?;
    // A provider's cwd is only a convenience. The sandbox is the actual
    // boundary inherited by all child processes: reads and network access are
    // available for CLI/runtime compatibility, while writes are allowed only
    // inside the selected Runner workspace plus the provider's narrowly scoped
    // runtime state directory (credentials and conversation metadata). AGY's
    // own scratch directory is explicitly denied: it is a second workspace,
    // not provider state, and allowing it would bypass the selected execution root.
    let profile = format!(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow file-read*)\n(allow process*)\n(allow mach-lookup)\n(allow network-outbound)\n(allow network-inbound)\n(allow file-write* (subpath \"{workspace}\")){provider_state_policy}"
    );
    let mut sandboxed = Command::new(SANDBOX_EXECUTABLE);
    sandboxed
        .arg("-p")
        .arg(profile)
        .arg(&execution_argv[0])
        .args(&execution_argv[1..]);
    Ok(sandboxed)
}

#[cfg(target_os = "macos")]
fn provider_workspace_command_argv(
    command_argv: &[String],
    workspace: &Path,
) -> CoreResult<Vec<String>> {
    let provider = Path::new(&command_argv[0])
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if provider != "agy" || command_argv.iter().any(|argument| argument == "--add-dir") {
        return Ok(command_argv.to_vec());
    }
    let prompt_index = command_argv
        .iter()
        .position(|argument| argument == "-p" || argument == "--prompt")
        .ok_or_else(|| {
            CoreError::new(
                "PROVIDER_WORKSPACE_ARGUMENT_INVALID",
                "AGY provider command is missing its required prompt argument",
            )
        })?;
    if prompt_index + 1 >= command_argv.len() {
        return Err(CoreError::new(
            "PROVIDER_WORKSPACE_ARGUMENT_INVALID",
            "AGY provider command has no prompt value",
        ));
    }
    let workspace = workspace.to_str().ok_or_else(|| {
        CoreError::new(
            "PROVIDER_WORKSPACE_ARGUMENT_INVALID",
            "workspace path is not valid UTF-8 for AGY --add-dir",
        )
    })?;
    let mut argv = command_argv.to_vec();
    argv.splice(
        prompt_index + 2..prompt_index + 2,
        ["--add-dir".to_string(), workspace.to_string()],
    );
    Ok(argv)
}

#[cfg(target_os = "macos")]
fn provider_state_write_policy(command: &str) -> CoreResult<String> {
    let provider = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let (relative_state_path, denied_child) = match provider {
        // AGY's scratch tree is a provider-created scratch workspace. It must
        // never inherit the runtime-state exception, otherwise AGY can report
        // changes outside the execution root while still running sandboxed.
        "agy" => (Some(".gemini/antigravity-cli"), Some("scratch")),
        "claude" => (Some(".claude"), None),
        _ => (None, None),
    };
    let Some(relative_state_path) = relative_state_path else {
        return Ok(String::new());
    };
    let home = std::env::var_os("HOME").ok_or_else(|| {
        CoreError::new(
            "PROVIDER_WORKSPACE_SANDBOX_HOME_UNAVAILABLE",
            "Runner HOME is required to confine provider runtime state",
        )
    })?;
    let state_root = PathBuf::from(home).join(relative_state_path);
    let state_path = sandbox_profile_path(&state_root)?;
    let mut policy = format!("\n(allow file-write* (subpath \"{state_path}\"))");
    if let Some(denied_child) = denied_child {
        let denied_path = sandbox_profile_path(&state_root.join(denied_child))?;
        policy.push_str(&format!("\n(deny file-write* (subpath \"{denied_path}\"))"));
    }
    Ok(policy)
}

#[cfg(target_os = "macos")]
fn sandbox_profile_path(path: &Path) -> CoreResult<String> {
    let value = path.to_str().ok_or_else(|| {
        CoreError::new(
            "PROVIDER_WORKSPACE_SANDBOX_INVALID",
            "workspace path is not valid UTF-8 for the macOS sandbox profile",
        )
    })?;
    if value.contains('\0') {
        return Err(CoreError::new(
            "PROVIDER_WORKSPACE_SANDBOX_INVALID",
            "workspace path contains a NUL byte",
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(not(target_os = "macos"))]
fn provider_write_confined_command(_command_argv: &[String], _cwd: &Path) -> CoreResult<Command> {
    // Do not silently downgrade to an unrestricted process on platforms that
    // do not yet have a native confinement adapter. The Backend converts this
    // into a durable provider failure instead of allowing an escape.
    Err(CoreError::new(
        "PROVIDER_WORKSPACE_SANDBOX_UNAVAILABLE",
        "this Runner platform has no native provider workspace sandbox",
    ))
}

fn default_child_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in [
        "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
    ] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    if let Some(path) = command_search_path(
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("HOME").as_deref(),
    ) {
        env.insert("PATH".to_string(), path);
    }
    env
}

#[derive(Debug, Deserialize)]
struct BrowserRuntimeManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "playwrightVersion")]
    playwright_version: String,
    artifacts: BTreeMap<String, BrowserRuntimeTarget>,
}

#[derive(Debug, Deserialize)]
struct BrowserRuntimeTarget {
    launcher: BrowserRuntimeArtifact,
    browsers: BTreeMap<String, BrowserRuntimeArtifact>,
}

#[derive(Debug, Deserialize)]
struct BrowserRuntimeArtifact {
    path: String,
    sha256: String,
    size: u64,
}

fn resolve_bundled_browser_runtime(
    browser: &str,
) -> CoreResult<(PathBuf, BTreeMap<String, String>)> {
    let plugin_root = std::env::var_os("LOOMEX_PLUGIN_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            CoreError::new(
                "BROWSER_RUNTIME_NOT_CONFIGURED",
                "browser.playwright requires a packaged browser runtime",
            )
        })?;
    let manifest_path = plugin_root.join("packaging/browser-runtime.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|error| {
        CoreError::new(
            "BROWSER_RUNTIME_MANIFEST_MISSING",
            format!("cannot read packaged browser runtime manifest: {error}"),
        )
    })?;
    let manifest: BrowserRuntimeManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            CoreError::new(
                "BROWSER_RUNTIME_MANIFEST_INVALID",
                format!("cannot parse packaged browser runtime manifest: {error}"),
            )
        })?;
    if manifest.schema_version != 1 || manifest.playwright_version.trim().is_empty() {
        return Err(CoreError::new(
            "BROWSER_RUNTIME_MANIFEST_INVALID",
            "packaged browser runtime manifest has an unsupported schema or version",
        ));
    }
    let target = browser_runtime_target_key();
    let target_manifest = manifest.artifacts.get(&target).ok_or_else(|| {
        CoreError::new(
            "BROWSER_RUNTIME_UNSUPPORTED_PLATFORM",
            format!("no packaged browser runtime exists for {target}"),
        )
    })?;
    let browser_manifest = target_manifest.browsers.get(browser).ok_or_else(|| {
        CoreError::new(
            "BROWSER_RUNTIME_BROWSER_UNAVAILABLE",
            format!("no packaged {browser} browser exists for {target}"),
        )
    })?;
    let launcher =
        verify_browser_runtime_artifact(&plugin_root, &target_manifest.launcher, "launcher")?;
    let browser_binary = verify_browser_runtime_artifact(&plugin_root, browser_manifest, browser)?;
    let mut env = BTreeMap::new();
    env.insert(
        "LOOMEX_BROWSER_BINARY".to_string(),
        browser_binary.to_string_lossy().into_owned(),
    );
    env.insert(
        "LOOMEX_PLAYWRIGHT_VERSION".to_string(),
        manifest.playwright_version,
    );
    Ok((launcher, env))
}

fn verify_browser_runtime_artifact(
    plugin_root: &Path,
    artifact: &BrowserRuntimeArtifact,
    label: &str,
) -> CoreResult<PathBuf> {
    if artifact.path.is_empty()
        || !is_sha256_hex(&artifact.sha256)
        || artifact.size == 0
        || Path::new(&artifact.path).is_absolute()
    {
        return Err(CoreError::new(
            "BROWSER_RUNTIME_MANIFEST_INVALID",
            format!("packaged browser {label} artifact metadata is invalid"),
        ));
    }
    let candidate = plugin_root.join(&artifact.path);
    let info = fs::symlink_metadata(&candidate).map_err(|error| {
        CoreError::new(
            "BROWSER_RUNTIME_ARTIFACT_MISSING",
            format!("packaged browser {label} artifact is unavailable: {error}"),
        )
    })?;
    if !info.file_type().is_file() || info.file_type().is_symlink() || info.len() != artifact.size {
        return Err(CoreError::new(
            "BROWSER_RUNTIME_ARTIFACT_INVALID",
            format!("packaged browser {label} artifact is not the expected regular file"),
        ));
    }
    #[cfg(unix)]
    if info.permissions().mode() & 0o111 == 0 {
        return Err(CoreError::new(
            "BROWSER_RUNTIME_ARTIFACT_INVALID",
            format!("packaged browser {label} artifact is not executable"),
        ));
    }
    let actual = sha256_file(&candidate).map_err(|error| {
        CoreError::new(
            "BROWSER_RUNTIME_ARTIFACT_INVALID",
            format!("cannot hash packaged browser {label} artifact: {error}"),
        )
    })?;
    if actual != artifact.sha256 {
        return Err(CoreError::new(
            "BROWSER_RUNTIME_CHECKSUM_MISMATCH",
            format!("checksum mismatch for packaged browser {label} artifact"),
        ));
    }
    Ok(candidate)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

fn browser_runtime_target_key() -> String {
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unsupported"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        "unsupported"
    };
    format!("{platform}-{arch}")
}

fn command_env_with_path() -> BTreeMap<String, String> {
    default_child_environment()
}

fn command_env_with_path_and(mut env: BTreeMap<String, String>) -> BTreeMap<String, String> {
    if !env.contains_key("PATH") {
        if let Some(path) = command_search_path(
            std::env::var_os("PATH").as_deref(),
            std::env::var_os("HOME").as_deref(),
        ) {
            env.insert("PATH".to_string(), path);
        }
    }
    env
}

fn command_search_path(
    inherited_path: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<String> {
    let mut paths = inherited_path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if let Some(home) = home {
        let home = PathBuf::from(home);
        paths.extend([home.join(".local/bin"), home.join(".cargo/bin")]);
    }
    paths.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/sbin"),
    ]);
    let mut unique = Vec::new();
    for path in paths {
        if !unique.iter().any(|candidate| candidate == &path) {
            unique.push(path);
        }
    }
    std::env::join_paths(unique)
        .ok()
        .and_then(|path| path.into_string().ok())
}

fn validate_browser_name(browser: &str) -> CoreResult<()> {
    if matches!(browser, "chromium" | "firefox" | "webkit") {
        Ok(())
    } else {
        Err(CoreError::new(
            "BROWSER_UNSUPPORTED",
            "browser.playwright browser must be chromium, firefox, or webkit",
        ))
    }
}

fn validate_read_only_sql(query: &str) -> CoreResult<()> {
    let normalized = query
        .trim_start_matches('\u{feff}')
        .trim_start()
        .trim_start_matches(|ch: char| ch == '(' || ch.is_whitespace())
        .to_ascii_lowercase();
    let first = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .find(|part| !part.is_empty())
        .unwrap_or("");
    if contains_sql_statement_separator(&normalized)
        || (first == "pragma" && pragma_assigns_value(&normalized))
    {
        return Err(CoreError::new(
            "DB_WRITE_DENIED",
            "db.query accepts one read-only statement and denies PRAGMA assignments",
        ));
    }
    if matches!(
        first,
        "select" | "with" | "show" | "describe" | "explain" | "pragma"
    ) && !contains_sql_mutation_keyword(&normalized)
    {
        Ok(())
    } else {
        Err(CoreError::new(
            "DB_WRITE_DENIED",
            "db.query is read-only by default and denied this statement",
        ))
    }
}

fn contains_sql_statement_separator(query: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for ch in query.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == active_quote {
                quote = None;
            } else if ch == '\\' && active_quote == '\'' {
                escaped = true;
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch == ';' {
            return true;
        }
    }
    false
}

fn pragma_assigns_value(query: &str) -> bool {
    let Some(pragma) = query.strip_prefix("pragma") else {
        return false;
    };
    pragma.contains('=')
}

fn sqlite_limit_query(query: &str, max_rows: usize) -> String {
    // The parser remains defense-in-depth. SQLite's read-only open and
    // query_only pragma are the actual side-effect boundary.
    if query
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("pragma")
    {
        query.to_string()
    } else {
        format!("SELECT * FROM ({query}) LIMIT {max_rows}")
    }
}

fn postgres_limit_query(query: &str, max_rows: usize) -> String {
    format!("SELECT * FROM ({query}) AS loomex_read_only_query LIMIT {max_rows}")
}

fn postgres_read_only_role() -> CoreResult<String> {
    let role = std::env::var("LOOMEX_DB_READ_ONLY_ROLE").map_err(|_| {
        CoreError::new(
            "DB_ROLE_NOT_CONFIGURED",
            "LOOMEX_DB_READ_ONLY_ROLE must name the low-privilege PostgreSQL role",
        )
    })?;
    let valid = role.bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_alphabetic() || byte == b'_'
        } else {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
        }
    });
    if role.is_empty() || !valid {
        return Err(CoreError::new(
            "DB_ROLE_INVALID",
            "LOOMEX_DB_READ_ONLY_ROLE must be a simple PostgreSQL identifier",
        ));
    }
    Ok(role)
}

fn contains_sql_mutation_keyword(query: &str) -> bool {
    let words = query
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|part| !part.is_empty());
    words.into_iter().any(|word| {
        matches!(
            word,
            "insert"
                | "update"
                | "delete"
                | "drop"
                | "alter"
                | "create"
                | "truncate"
                | "replace"
                | "merge"
                | "grant"
                | "revoke"
                | "vacuum"
                | "attach"
                | "detach"
        )
    })
}

fn sqlite_database_path(connection_string: &str) -> CoreResult<String> {
    let path = connection_string
        .strip_prefix("sqlite://")
        .or_else(|| connection_string.strip_prefix("sqlite:"))
        .unwrap_or(connection_string);
    if path == ":memory:" {
        return Err(CoreError::new(
            "DB_CONNECTION_UNSUPPORTED",
            "db.query requires a workspace SQLite file, not :memory:",
        ));
    }
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Err(CoreError::new(
            "DB_CONNECTION_INVALID",
            "sqlite connection string must include a database path",
        ));
    }
    Ok(path.to_string())
}

fn db_columns_from_json(rows_json: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(rows_json)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .and_then(|rows| rows.first().cloned())
        .and_then(|row| row.as_object().cloned())
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn db_row_count_from_json(rows_json: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(rows_json)
        .ok()
        .and_then(|value| value.as_array().map(Vec::len))
        .unwrap_or(0)
}

fn limit_db_rows_json(rows_json: &str, max_rows: usize) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(rows_json) else {
        return rows_json.to_string();
    };
    let Some(rows) = value.as_array_mut() else {
        return rows_json.to_string();
    };
    rows.truncate(max_rows);
    serde_json::to_string(rows).unwrap_or_else(|_| rows_json.to_string())
}

fn test_runner_command(input: &TestRunInput) -> CoreResult<Vec<String>> {
    let mut command = match input.runner.as_str() {
        "npm" => {
            let script = input.script.as_deref().unwrap_or("test");
            vec!["npm".to_string(), "run".to_string(), script.to_string()]
        }
        "pnpm" => {
            let script = input.script.as_deref().unwrap_or("test");
            vec!["pnpm".to_string(), script.to_string()]
        }
        "yarn" => {
            let script = input.script.as_deref().unwrap_or("test");
            vec!["yarn".to_string(), script.to_string()]
        }
        "pytest" => vec![
            "python3".to_string(),
            "-m".to_string(),
            "pytest".to_string(),
        ],
        "custom" => input.command.clone().ok_or_else(|| {
            CoreError::new(
                "TEST_COMMAND_REQUIRED",
                "test.run custom runner requires command",
            )
        })?,
        _ => {
            return Err(CoreError::new(
                "TEST_RUNNER_UNSUPPORTED",
                "test.run runner must be npm, pnpm, yarn, pytest, or custom",
            ));
        }
    };
    command.extend(input.args.clone());
    if command.is_empty() || command.iter().any(|part| part.trim().is_empty()) {
        return Err(CoreError::new(
            "TEST_COMMAND_EMPTY",
            "test.run command must not be empty",
        ));
    }
    Ok(command)
}

fn parse_test_report(output: &str, exit_code: i32) -> ParsedTestReport {
    let passed = count_before_word(output, "passed");
    let failed = count_before_word(output, "failed").max(if exit_code == 0 { 0 } else { 1 });
    let skipped = count_before_word(output, "skipped");
    ParsedTestReport {
        passed,
        failed,
        skipped,
    }
}

fn count_before_word(output: &str, word: &str) -> usize {
    output
        .split([',', '\n', ';'])
        .filter_map(|part| {
            let mut tokens = part.split_whitespace().collect::<Vec<_>>();
            let found = tokens.pop()?;
            if found.trim_matches(|ch: char| !ch.is_ascii_alphabetic()) != word {
                return None;
            }
            tokens.last().and_then(|value| value.parse::<usize>().ok())
        })
        .sum()
}

fn artifact_ref_for_file(kind: &str, relative_path: &str, path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| format!("artifact:{kind}:{relative_path}:{}", sha256_hex(&bytes)))
}

fn non_empty_message(value: &str, fallback: &'static str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_unified_patch(patch: &str) -> CoreResult<Vec<ParsedPatchFile>> {
    let mut files = Vec::new();
    let mut current: Option<ParsedPatchFile> = None;
    let mut current_hunk: Option<ParsedHunk> = None;
    for line in patch.lines() {
        if line.starts_with("--- ") && current.is_some() {
            if let Some(hunk) = current_hunk.take() {
                if let Some(file) = &mut current {
                    file.hunks.push(hunk);
                }
            }
            if let Some(file) = current.take() {
                files.push(file);
            }
        } else if let Some(path) = line.strip_prefix("+++ ") {
            if let Some(hunk) = current_hunk.take() {
                if let Some(file) = &mut current {
                    file.hunks.push(hunk);
                }
            }
            if let Some(file) = current.take() {
                files.push(file);
            }
            current = Some(ParsedPatchFile {
                path: clean_patch_path(path),
                hunks: Vec::new(),
            });
        } else if line.starts_with("@@") {
            if let Some(hunk) = current_hunk.take() {
                if let Some(file) = &mut current {
                    file.hunks.push(hunk);
                }
            }
            current_hunk = Some(ParsedHunk {
                old_start: parse_hunk_old_start(line)?,
                lines: Vec::new(),
            });
        } else if let Some(hunk) = &mut current_hunk {
            if let Some(value) = line.strip_prefix(' ') {
                hunk.lines.push(PatchLine::Context(value.to_string()));
            } else if let Some(value) = line.strip_prefix('-') {
                hunk.lines.push(PatchLine::Remove(value.to_string()));
            } else if let Some(value) = line.strip_prefix('+') {
                hunk.lines.push(PatchLine::Add(value.to_string()));
            }
        }
    }
    if let Some(hunk) = current_hunk.take() {
        if let Some(file) = &mut current {
            file.hunks.push(hunk);
        }
    }
    if let Some(file) = current.take() {
        files.push(file);
    }
    Ok(files)
}

fn clean_patch_path(path: &str) -> String {
    path.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .to_string()
}

fn parse_hunk_old_start(header: &str) -> CoreResult<usize> {
    let old = header
        .split_whitespace()
        .find(|part| part.starts_with('-'))
        .ok_or_else(|| CoreError::new("PATCH_HUNK_INVALID", "patch hunk header is invalid"))?;
    let start = old
        .trim_start_matches('-')
        .split(',')
        .next()
        .unwrap_or("1")
        .parse::<usize>()
        .map_err(|_| CoreError::new("PATCH_HUNK_INVALID", "patch hunk start is invalid"))?;
    Ok(start.max(1))
}

fn apply_line_patch(before: &str, hunks: &[ParsedHunk]) -> Option<String> {
    let original: Vec<String> = before.lines().map(|line| line.to_string()).collect();
    let ended_with_newline = before.ends_with('\n');
    let mut output = Vec::new();
    let mut cursor = 0usize;
    for hunk in hunks {
        let hunk_start = hunk.old_start.saturating_sub(1);
        if hunk_start < cursor || hunk_start > original.len() {
            return None;
        }
        output.extend_from_slice(&original[cursor..hunk_start]);
        cursor = hunk_start;
        for line in &hunk.lines {
            match line {
                PatchLine::Context(expected) => {
                    if original.get(cursor) != Some(expected) {
                        return None;
                    }
                    output.push(expected.clone());
                    cursor += 1;
                }
                PatchLine::Remove(expected) => {
                    if original.get(cursor) != Some(expected) {
                        return None;
                    }
                    cursor += 1;
                }
                PatchLine::Add(value) => output.push(value.clone()),
            }
        }
    }
    output.extend_from_slice(&original[cursor..]);
    let mut result = output.join("\n");
    if ended_with_newline || !result.is_empty() {
        result.push('\n');
    }
    Some(result)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    let (len, modified) = if metadata.is_dir() {
        // Creating the atomic temporary file changes the parent directory's
        // length/mtime. Directory identity must therefore use stable inode
        // data only, otherwise every safe atomic write looks like a race.
        (0, None)
    } else {
        (metadata.len(), metadata.modified().ok())
    };
    #[cfg(not(unix))]
    let (len, modified) = (metadata.len(), metadata.modified().ok());
    FileIdentity {
        len,
        modified,
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

fn diff_ref(path: &str, before: Option<&[u8]>, after: &[u8]) -> String {
    match before {
        None => format!("created:{path}:{}", sha256_hex(after)),
        Some(before) => format!(
            "changed:{path}:{}..{}",
            sha256_hex(before),
            sha256_hex(after)
        ),
    }
}

fn truncate_to_bytes(value: &str, max_bytes: usize) -> TruncatedText {
    if value.len() <= max_bytes {
        return TruncatedText {
            value: value.to_string(),
            truncated: false,
        };
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    TruncatedText {
        value: value[..end].to_string(),
        truncated: true,
    }
}

fn default_secret_env_names() -> Vec<String> {
    vec![
        "TOKEN".to_string(),
        "API_KEY".to_string(),
        "SECRET".to_string(),
        "PASSWORD".to_string(),
        "AUTHORIZATION".to_string(),
    ]
}

fn filtered_env_names(secret_env_names: &[String]) -> Vec<String> {
    let mut names = secret_env_names.to_vec();
    names.sort();
    names.dedup();
    names
}

fn fs_error(code: &'static str) -> impl Fn(std::io::Error) -> CoreError {
    move |error| CoreError::new(code, error.to_string())
}

fn json_error(code: &'static str) -> impl Fn(serde_json::Error) -> CoreError {
    move |error| CoreError::new(code, error.to_string())
}

fn system_time_epoch_ms(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_tree(child: &mut std::process::Child) {
    let process_group_id = child.id() as libc::pid_t;
    unsafe {
        libc::kill(-process_group_id, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn list_and_read_inside_workspace() {
        let root = test_workspace("list_read");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/app.txt"), "hello\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let list = executor
            .fs_list(FsListInput {
                path: "src".to_string(),
                ..Default::default()
            })
            .unwrap();
        let read = executor
            .fs_read(FsReadInput {
                path: "src/app.txt".to_string(),
                ..Default::default()
            })
            .unwrap();

        assert_eq!("src/app.txt", list.entries[0].path);
        assert_eq!("hello\n", read.content);
        assert!(!read.truncated);
        assert!(!read.binary);
    }

    #[test]
    fn read_streams_hash_while_bounding_preview() {
        let root = test_workspace("streamed_read");
        let bytes = (0..32_768)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(root.join("payload.bin"), &bytes).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let read = executor
            .fs_read(FsReadInput {
                path: "payload.bin".to_string(),
                encoding: Some("base64".to_string()),
                max_bytes: Some(17),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(BASE64_STANDARD.encode(&bytes[..17]), read.content);
        assert_eq!(sha256_hex(&bytes), read.sha256);
        assert_eq!(bytes.len(), read.size_bytes);
        assert!(read.truncated);
    }

    #[test]
    fn read_rejects_file_over_total_work_budget_before_open() {
        let root = test_workspace("oversized_read");
        let file = File::create(root.join("large.bin")).unwrap();
        file.set_len(DEFAULT_FS_READ_TOTAL_BYTES + 1).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .fs_read(FsReadInput {
                path: "large.bin".to_string(),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("FS_READ_TOO_LARGE", error.code);
    }

    #[test]
    fn read_honors_cancellation_before_work() {
        let root = test_workspace("cancelled_read");
        fs::write(root.join("payload.txt"), "payload").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();
        let cancel = ShellCancellationToken::default();
        cancel.cancel();

        let error = executor
            .fs_read_with_cancel(
                FsReadInput {
                    path: "payload.txt".to_string(),
                    ..Default::default()
                },
                &cancel,
            )
            .unwrap_err();

        assert_eq!("FS_READ_CANCELLED", error.code);
    }

    #[test]
    fn read_outside_workspace_denied() {
        let root = test_workspace("outside_read");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let err = executor
            .fs_read(FsReadInput {
                path: "../secret.txt".to_string(),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("WORKSPACE_PATH_OUTSIDE_ROOT", err.code);
    }

    #[test]
    fn read_windows_absolute_and_unc_paths_denied_on_any_host() {
        let root = test_workspace("windows_path_read");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let drive_err = executor
            .fs_read(FsReadInput {
                path: "C:\\Users\\dev\\secret.txt".to_string(),
                ..Default::default()
            })
            .unwrap_err();
        let unc_err = executor
            .fs_read(FsReadInput {
                path: "\\\\server\\share\\secret.txt".to_string(),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("WORKSPACE_PATH_ESCAPE", drive_err.code);
        assert_eq!("WORKSPACE_PATH_ESCAPE", unc_err.code);
    }

    #[test]
    fn sandbox_profile_blocks_forbidden_workspace_path() {
        let root = test_workspace("sandbox_forbidden_path");
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::write(root.join("secrets/token.txt"), "secret").unwrap();
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_sandbox_profile(SandboxProfile::new(vec!["secrets".to_string()]).unwrap());

        let error = executor
            .fs_read(FsReadInput {
                path: "secrets/token.txt".to_string(),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("SANDBOX_PATH_DENIED", error.code);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_denied() {
        let root = test_workspace("symlink_escape");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("secret_link")).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let err = executor
            .fs_read(FsReadInput {
                path: "secret_link".to_string(),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("WORKSPACE_PATH_OUTSIDE_ROOT", err.code);
    }

    #[test]
    fn write_allowed_after_approval_boundary() {
        let root = test_workspace("write_allowed");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .fs_write(FsWriteInput {
                path: "docs/output.md".to_string(),
                content: "ok\n".to_string(),
                encoding: "utf-8".to_string(),
                mode: "create".to_string(),
                expected_sha256: None,
                create_parent_directories: Some(true),
            })
            .unwrap();

        assert_eq!("docs/output.md", output.path);
        assert!(output.created);
        assert_eq!(
            "ok\n",
            fs::read_to_string(root.join("docs/output.md")).unwrap()
        );
    }

    #[test]
    fn patch_conflict_returns_structured_result_without_writing() {
        let root = test_workspace("patch_conflict");
        fs::write(root.join("app.txt"), "old\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .fs_apply_patch(FsApplyPatchInput {
                patch: "--- a/app.txt\n+++ b/app.txt\n@@ -1,1 +1,1 @@\n-missing\n+new\n"
                    .to_string(),
                ..Default::default()
            })
            .unwrap();

        assert!(!output.applied);
        assert_eq!(vec!["app.txt".to_string()], output.conflicts);
        assert_eq!("old\n", fs::read_to_string(root.join("app.txt")).unwrap());
    }

    #[test]
    fn patch_expected_digest_conflict_does_not_overwrite() {
        let root = test_workspace("patch_digest_conflict");
        fs::write(root.join("app.txt"), "old\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();
        let output = executor
            .fs_apply_patch(FsApplyPatchInput {
                patch: "--- a/app.txt\n+++ b/app.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
                base_sha256_by_path: [("app.txt".to_string(), sha256_hex(b"stale\n"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .unwrap();

        assert!(!output.applied);
        assert_eq!(vec!["app.txt".to_string()], output.conflicts);
        assert_eq!("old\n", fs::read_to_string(root.join("app.txt")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_symlink_target_without_touching_link() {
        let root = test_workspace("write_symlink_target");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("target.txt"), "outside\n").unwrap();
        std::os::unix::fs::symlink(outside.join("target.txt"), root.join("link.txt")).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .fs_write(FsWriteInput {
                path: "link.txt".to_string(),
                content: "inside\n".to_string(),
                encoding: "utf-8".to_string(),
                mode: "overwrite".to_string(),
                expected_sha256: None,
                create_parent_directories: None,
            })
            .unwrap_err();

        assert_eq!("FS_WRITE_SYMLINK_OR_NOT_FILE", error.code);
        assert_eq!(
            "outside\n",
            fs::read_to_string(outside.join("target.txt")).unwrap()
        );
    }

    #[test]
    fn apply_patch_changes_file() {
        let root = test_workspace("patch_apply");
        fs::write(root.join("app.txt"), "old\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .fs_apply_patch(FsApplyPatchInput {
                patch: "--- a/app.txt\n+++ b/app.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
                ..Default::default()
            })
            .unwrap();

        assert!(output.applied);
        assert_eq!("new\n", fs::read_to_string(root.join("app.txt")).unwrap());
        assert_eq!("app.txt", output.files_changed[0].path);
    }

    #[test]
    fn shell_success_and_non_zero_are_structured() {
        let root = test_workspace("shell_success");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let success = executor
            .shell_exec(ShellExecInput {
                command: vec!["sh".to_string(), "-c".to_string(), "printf ok".to_string()],
                ..Default::default()
            })
            .unwrap();
        let failure = executor
            .shell_exec(ShellExecInput {
                command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                ..Default::default()
            })
            .unwrap();

        assert_eq!(0, success.exit_code);
        assert_eq!("ok", success.artifacts.stdout);
        assert_eq!(7, failure.exit_code);
    }

    #[test]
    fn command_search_path_includes_user_cli_locations() {
        let path = command_search_path(
            Some(std::ffi::OsStr::new("/usr/bin")),
            Some(std::ffi::OsStr::new("/tmp/loomex-home")),
        )
        .unwrap();
        let entries = std::env::split_paths(&std::ffi::OsString::from(path)).collect::<Vec<_>>();

        assert!(entries.contains(&PathBuf::from("/tmp/loomex-home/.local/bin")));
        assert!(entries.contains(&PathBuf::from("/tmp/loomex-home/.cargo/bin")));
        assert!(entries.contains(&PathBuf::from("/usr/bin")));
    }

    #[cfg(unix)]
    #[test]
    fn shell_exec_finds_a_provider_in_user_local_bin() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_workspace("shell_user_local_bin");
        let home = root.join("home");
        let provider_dir = home.join(".local/bin");
        fs::create_dir_all(&provider_dir).unwrap();
        let provider = provider_dir.join("agy");
        fs::write(&provider, "#!/bin/sh\nprintf provider-ok\n").unwrap();
        let mut permissions = fs::metadata(&provider).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&provider, permissions).unwrap();
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), home.to_string_lossy().to_string());
        env.insert(
            "PATH".to_string(),
            command_search_path(
                Some(std::ffi::OsStr::new("/usr/bin")),
                Some(home.as_os_str()),
            )
            .unwrap(),
        );

        let output = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .shell_exec(ShellExecInput {
                command: vec!["agy".to_string()],
                env,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(0, output.exit_code);
        assert_eq!("provider-ok", output.artifacts.stdout);
    }

    #[test]
    fn shell_working_directory_comes_from_context_not_input() {
        let root = test_workspace("shell_working_directory");
        fs::create_dir_all(root.join("subdir")).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .shell_exec_in_working_directory(
                ShellExecInput {
                    command: vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        "basename \"$PWD\"".to_string(),
                    ],
                    ..Default::default()
                },
                "subdir",
            )
            .unwrap();

        assert_eq!("subdir", output.artifacts.stdout.trim());
    }

    #[test]
    fn shell_working_directory_context_stays_inside_workspace() {
        let root = test_workspace("shell_working_directory_escape");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .shell_exec_in_working_directory(
                ShellExecInput {
                    command: vec!["sh".to_string(), "-c".to_string(), "pwd".to_string()],
                    ..Default::default()
                },
                "..",
            )
            .unwrap_err();

        assert_eq!("WORKSPACE_PATH_OUTSIDE_ROOT", error.code);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provider_workspace_scope_allows_writes_inside_and_blocks_outside() {
        let root = test_workspace("provider_workspace_scope");
        let outside = root.parent().unwrap().join(format!(
            "{}-outside.txt",
            root.file_name().unwrap().to_string_lossy()
        ));
        let script = format!(
            "printf inside > inside.txt; printf blocked > {}",
            outside.display()
        );

        let output = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .shell_exec(ShellExecInput {
                command: vec!["sh".to_string(), "-c".to_string(), script],
                workspace_scope: ShellWorkspaceScope::ProviderWriteConfined,
                ..Default::default()
            })
            .unwrap();

        assert_ne!(0, output.exit_code);
        assert_eq!(
            "inside",
            fs::read_to_string(root.join("inside.txt")).unwrap()
        );
        assert!(!outside.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provider_runtime_state_exception_does_not_open_other_workspace_paths() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_workspace("provider_runtime_state_scope");
        for provider in ["agy", "claude"] {
            let executable = root.join(provider);
            fs::write(
                &executable,
                "#!/bin/sh\nprintf inside > inside-$2.txt; printf blocked > $3\n",
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            let outside = root
                .parent()
                .unwrap()
                .join(format!("{provider}-outside.txt"));

            let _output = LocalCapabilityExecutor::new(&root)
                .unwrap()
                .shell_exec(ShellExecInput {
                    command: vec![
                        executable.to_string_lossy().to_string(),
                        "-p".to_string(),
                        provider.to_string(),
                        outside.to_string_lossy().to_string(),
                    ],
                    workspace_scope: ShellWorkspaceScope::ProviderWriteConfined,
                    ..Default::default()
                })
                .unwrap();

            assert!(root.join(format!("inside-{provider}.txt")).exists());
            assert!(!outside.exists());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn agy_runtime_state_policy_explicitly_denies_its_scratch_workspace() {
        let policy = provider_state_write_policy("agy").unwrap();

        assert!(policy.contains("(allow file-write* (subpath \""));
        assert!(policy.contains(".gemini/antigravity-cli\"))"));
        assert!(policy.contains("(deny file-write* (subpath \""));
        assert!(policy.contains(".gemini/antigravity-cli/scratch\"))"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn agy_provider_command_gets_the_selected_workspace_once() {
        let root = test_workspace("agy_provider_workspace_argument");
        let command = vec![
            "agy".to_string(),
            "-p".to_string(),
            "opaque prompt".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
        ];

        let argv = provider_workspace_command_argv(&command, &root).unwrap();
        assert_eq!(
            vec![
                "agy",
                "-p",
                "opaque prompt",
                "--add-dir",
                root.to_string_lossy().as_ref(),
                "--output-format",
                "json",
            ],
            argv
        );
        assert_eq!(argv, provider_workspace_command_argv(&argv, &root).unwrap());
    }

    #[test]
    fn shell_timeout() {
        let root = test_workspace("shell_timeout");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .shell_exec(ShellExecInput {
                command: vec!["sh".to_string(), "-c".to_string(), "sleep 2".to_string()],
                timeout_seconds: Some(1),
                ..Default::default()
            })
            .unwrap();

        assert!(output.artifacts.timed_out);
        assert_eq!(-1, output.exit_code);
    }

    #[test]
    fn shell_cancellation() {
        let root = test_workspace("shell_cancel");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();
        let cancel = ShellCancellationToken::default();
        let cancel_for_thread = cancel.clone();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            cancel_for_thread.cancel();
        });
        let output = executor
            .shell_exec_with_cancel(
                ShellExecInput {
                    command: vec!["sh".to_string(), "-c".to_string(), "sleep 2".to_string()],
                    timeout_seconds: Some(5),
                    ..Default::default()
                },
                &cancel,
            )
            .unwrap();
        tx.send(output.artifacts.cancelled).unwrap();

        assert!(rx.recv().unwrap());
    }

    #[test]
    fn max_output_truncation() {
        let root = test_workspace("shell_truncation");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .shell_exec(ShellExecInput {
                command: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf 123456".to_string(),
                ],
                max_output_bytes: Some(3),
                ..Default::default()
            })
            .unwrap();

        assert_eq!("123", output.artifacts.stdout);
        assert!(output.truncated);
    }

    #[test]
    fn large_shell_output_is_bounded_before_timeout_or_completion() {
        let root = test_workspace("shell_bounded_output");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .shell_exec(ShellExecInput {
                command: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "i=0; while [ $i -lt 20000 ]; do printf 0123456789; i=$((i+1)); done"
                        .to_string(),
                ],
                max_output_bytes: Some(1024),
                timeout_seconds: Some(5),
                ..Default::default()
            })
            .unwrap();

        assert!(output.truncated);
        assert!(output.artifacts.stdout.len() <= 1024);
    }

    #[test]
    fn env_secret_filtering_and_output_redaction() {
        let root = test_workspace("shell_env_filter");
        let executor = LocalCapabilityExecutor::with_redaction(
            &root,
            vec!["visible-secret".to_string()],
            vec!["API_KEY".to_string()],
        )
        .unwrap();
        let mut env = BTreeMap::new();
        env.insert("API_KEY".to_string(), "hidden".to_string());
        env.insert("SAFE".to_string(), "visible-secret".to_string());

        let output = executor
            .shell_exec(ShellExecInput {
                command: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf \"$API_KEY:$SAFE\"".to_string(),
                ],
                env,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(":[REDACTED]", output.artifacts.stdout);
        assert!(output
            .artifacts
            .redaction_metadata
            .filtered_env
            .contains(&"API_KEY".to_string()));
    }

    #[test]
    fn secret_env_can_only_reach_child_when_explicitly_allowed() {
        let root = test_workspace("shell_env_explicit_allow");
        let executor = LocalCapabilityExecutor::with_redaction(
            &root,
            vec!["hidden".to_string()],
            vec!["API_KEY".to_string()],
        )
        .unwrap()
        .with_child_environment_policy(
            ChildEnvironmentPolicy::with_allowed_secret_env_names(vec!["API_KEY".to_string()]),
        );
        let mut env = BTreeMap::new();
        env.insert("API_KEY".to_string(), "hidden".to_string());

        let output = executor
            .shell_exec(ShellExecInput {
                command: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    r#"[ "$API_KEY" = "hidden" ] && printf allowed"#.to_string(),
                ],
                env,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(0, output.exit_code);
        assert_eq!("allowed", output.artifacts.stdout);
    }

    #[test]
    fn capability_executor_accepts_json_input() {
        let root = test_workspace("json_executor");
        fs::write(root.join("app.txt"), "hello").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor
            .execute_unchecked(CapabilityRequest {
                capability: "fs.read".to_string(),
                input: r#"{"path":"app.txt"}"#.to_string(),
            })
            .unwrap();

        assert_eq!("fs.read", result.capability);
        assert!(result.output.contains("\"content\":\"hello\""));
    }

    #[test]
    fn public_executor_rejects_untyped_requests_without_authorization() {
        let root = test_workspace("authorization_boundary");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .execute(CapabilityRequest {
                capability: "fs.list".to_string(),
                input: r#"{"path":"."}"#.to_string(),
            })
            .unwrap_err();

        assert_eq!("AUTHORIZED_REQUEST_REQUIRED", error.code);
    }

    #[test]
    fn serialized_shell_result_matches_contract_shape() {
        let root = test_workspace("shell_schema_shape");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor
            .execute_unchecked(CapabilityRequest {
                capability: "shell.exec".to_string(),
                input: r#"{"command":["sh","-c","printf ok"],"max_output_bytes":16}"#.to_string(),
            })
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            vec![
                "duration_ms".to_string(),
                "exit_code".to_string(),
                "stderr_ref".to_string(),
                "stdout_ref".to_string(),
                "truncated".to_string()
            ],
            keys
        );
        assert!(value.get("stdout").is_none());
        assert!(value.get("stderr").is_none());
        assert!(value.get("timed_out").is_none());
        assert!(value.get("cancelled").is_none());
    }

    #[test]
    fn shell_json_input_accepts_only_contract_fields() {
        let canonical: ShellExecInput = serde_json::from_str(
            r#"{"command":["sh","-c","printf ok"],"env":{"SAFE":"1"},"timeout_seconds":5,"max_output_bytes":16}"#,
        )
        .unwrap();

        assert_eq!(vec!["sh", "-c", "printf ok"], canonical.command);
        assert_eq!(Some(5), canonical.timeout_seconds);
        assert_eq!(Some(16), canonical.max_output_bytes);
    }

    #[test]
    fn shell_json_input_rejects_cwd_inside_input() {
        let root = test_workspace("shell_reject_cwd");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .execute_unchecked(CapabilityRequest {
                capability: "shell.exec".to_string(),
                input: r#"{"command":["sh","-c","printf ok"],"cwd":"subdir"}"#.to_string(),
            })
            .unwrap_err();

        assert_eq!("CAPABILITY_INPUT_INVALID", error.code);
    }

    #[test]
    fn git_status_clean() {
        let root = git_workspace("git_status_clean");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor.git_status(GitStatusInput::default()).unwrap();

        assert!(output.clean);
        assert!(output.files.is_empty());
        assert!(!output.branch.is_empty());
    }

    #[test]
    fn git_status_dirty_and_untracked_files_are_structured() {
        let root = git_workspace("git_status_dirty");
        fs::write(root.join("tracked.txt"), "changed\n").unwrap();
        fs::write(root.join("new.txt"), "new\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor.git_status(GitStatusInput::default()).unwrap();

        assert!(!output.clean);
        assert!(output
            .files
            .iter()
            .any(|file| file.path == "tracked.txt" && file.working_tree_status == "M"));
        assert!(output.files.iter().any(|file| file.path == "new.txt"
            && file.index_status == "?"
            && file.working_tree_status == "?"));
    }

    #[test]
    fn git_diff_returns_bounded_structured_output() {
        let root = git_workspace("git_diff");
        fs::write(root.join("tracked.txt"), "hello\nchanged\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .git_diff(GitDiffInput {
                max_bytes: Some(4096),
                ..Default::default()
            })
            .unwrap();

        assert!(output.artifacts.diff.contains(" hello"));
        assert!(output.artifacts.diff.contains("+changed"));
        assert_eq!("tracked.txt", output.files_changed[0].path);
        assert_eq!("modified", output.files_changed[0].change_type);
        assert!(output.diff_ref.starts_with("inline:git-diff:"));
        assert!(!output.truncated);
    }

    #[test]
    fn git_status_fails_closed_when_sandbox_denied_paths_exist() {
        let root = git_workspace("git_status_sandbox");
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::write(root.join("secrets/token.txt"), "secret\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_sandbox_profile(SandboxProfile::new(vec!["secrets".to_string()]).unwrap());

        let error = executor.git_status(GitStatusInput::default()).unwrap_err();

        assert_eq!("GIT_SANDBOX_SCOPE_REQUIRED", error.code);
    }

    #[test]
    fn git_diff_does_not_leak_sandbox_denied_paths_when_pathscoped() {
        let root = git_workspace("git_diff_sandbox");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::write(root.join("src/app.txt"), "public\n").unwrap();
        fs::write(root.join("secrets/token.txt"), "secret\n").unwrap();
        run_git_test_command(&root, &["add", "src/app.txt", "secrets/token.txt"]);
        run_git_test_command(&root, &["commit", "-m", "add scoped files"]);
        fs::write(root.join("src/app.txt"), "public\nchanged\n").unwrap();
        fs::write(root.join("secrets/token.txt"), "secret\nchanged\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_sandbox_profile(SandboxProfile::new(vec!["secrets".to_string()]).unwrap());

        let output = executor
            .git_diff(GitDiffInput {
                paths: Some(vec!["src".to_string()]),
                max_bytes: Some(4096),
                ..Default::default()
            })
            .unwrap();
        let denied = executor
            .git_diff(GitDiffInput {
                paths: Some(vec!["secrets".to_string()]),
                max_bytes: Some(4096),
                ..Default::default()
            })
            .unwrap_err();

        assert!(output.artifacts.diff.contains("src/app.txt"));
        assert!(!output.artifacts.diff.contains("secrets/token.txt"));
        assert_eq!("SANDBOX_PATH_DENIED", denied.code);
    }

    #[test]
    fn git_log_does_not_leak_sandbox_denied_paths_when_pathscoped() {
        let root = git_workspace("git_log_sandbox");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::write(root.join("secrets/token.txt"), "secret\n").unwrap();
        run_git_test_command(&root, &["add", "secrets/token.txt"]);
        run_git_test_command(&root, &["commit", "-m", "secret leak commit"]);
        fs::write(root.join("src/app.txt"), "public\n").unwrap();
        run_git_test_command(&root, &["add", "src/app.txt"]);
        run_git_test_command(&root, &["commit", "-m", "src change"]);
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_sandbox_profile(SandboxProfile::new(vec!["secrets".to_string()]).unwrap());

        let output = executor
            .git_log(GitLogInput {
                paths: Some(vec!["src".to_string()]),
                max_count: Some(10),
            })
            .unwrap();
        let denied = executor
            .git_log(GitLogInput {
                paths: Some(vec!["secrets".to_string()]),
                max_count: Some(10),
            })
            .unwrap_err();

        assert!(output
            .commits
            .iter()
            .any(|commit| commit.subject == "src change"));
        assert!(!output
            .commits
            .iter()
            .any(|commit| commit.subject.contains("secret")));
        assert_eq!("SANDBOX_PATH_DENIED", denied.code);
    }

    #[test]
    fn git_repository_missing_returns_structured_error() {
        let root = test_workspace("git_missing");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor.git_status(GitStatusInput::default()).unwrap_err();

        assert_eq!("GIT_REPOSITORY_NOT_FOUND", error.code);
    }

    #[test]
    fn git_nested_repository_discovery_prefers_requested_nested_repo() {
        let root = git_workspace("git_nested_outer");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        init_git_repo(&nested);
        let executor = LocalCapabilityExecutor::new(&nested).unwrap();

        let output = executor.git_status(GitStatusInput::default()).unwrap();

        assert!(output.clean);
    }

    #[test]
    fn git_status_reports_detached_head() {
        let root = git_workspace("git_detached_head");
        run_git_test_command(&root, &["checkout", "--detach", "HEAD"]);
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let status = executor.git_status(GitStatusInput::default()).unwrap();

        assert!(status.detached);
        assert_eq!("HEAD", status.branch);
    }

    #[test]
    fn git_log_is_structured() {
        let root = git_workspace("git_log");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let log = executor
            .git_log(GitLogInput {
                max_count: Some(1),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(1, log.commits.len());
        assert_eq!("initial", log.commits[0].subject);
        assert!(!log.commits[0].sha.is_empty());
        assert_eq!("Loomex Runner", log.commits[0].author);
        assert!(log.commits[0].committed_at.contains('T'));
    }

    #[test]
    fn git_unsupported_capabilities_have_no_public_executor() {
        let root = git_workspace("git_unsupported");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        assert!(!executor.supports("git.commit"));
        assert!(!executor.supports("git.push"));
        assert!(!executor.supports("git.branch"));
        assert!(!executor.supports("git.remote"));
        for capability in ["git.commit", "git.push", "git.branch", "git.remote"] {
            assert_eq!(
                "UNSUPPORTED_CAPABILITY",
                executor
                    .execute_unchecked(CapabilityRequest {
                        capability: capability.to_string(),
                        input: "{}".to_string(),
                    })
                    .unwrap_err()
                    .code
            );
        }
    }

    #[test]
    fn git_repository_path_outside_workspace_denied() {
        let root = git_workspace("git_outside_root");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .git_diff(GitDiffInput {
                paths: Some(vec!["../outside".to_string()]),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!("WORKSPACE_PATH_OUTSIDE_ROOT", error.code);
    }

    #[test]
    fn git_status_json_input_accepts_only_contract_fields() {
        let root = git_workspace("git_json_contract");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor
            .execute_unchecked(CapabilityRequest {
                capability: "git.status".to_string(),
                input: r#"{"porcelain":true,"include_untracked":true}"#.to_string(),
            })
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();

        assert_eq!("git.status", result.capability);
        assert_eq!(
            vec![
                "branch".to_string(),
                "clean".to_string(),
                "files".to_string()
            ],
            keys
        );
        assert!(value["clean"].as_bool().unwrap());
    }

    #[test]
    fn git_diff_json_output_matches_contract_shape() {
        let root = git_workspace("git_diff_json_contract");
        fs::write(root.join("tracked.txt"), "hello\nchanged\n").unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor
            .execute_unchecked(CapabilityRequest {
                capability: "git.diff".to_string(),
                input:
                    r#"{"paths":["tracked.txt"],"cached":false,"context_lines":3,"max_bytes":4096}"#
                        .to_string(),
            })
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            vec![
                "diff_ref".to_string(),
                "files_changed".to_string(),
                "truncated".to_string()
            ],
            keys
        );
        assert!(value["diff"].is_null());
        let file_change = value["files_changed"][0].as_object().unwrap();
        let mut file_change_keys = file_change.keys().cloned().collect::<Vec<_>>();
        file_change_keys.sort();
        assert_eq!(
            vec!["change_type".to_string(), "path".to_string()],
            file_change_keys
        );
        assert_eq!("tracked.txt", file_change["path"]);
        assert_eq!("modified", file_change["change_type"]);
        assert!(!file_change.contains_key("before_sha256"));
        assert!(!file_change.contains_key("after_sha256"));
    }

    #[test]
    fn git_log_json_output_matches_contract_shape() {
        let root = git_workspace("git_log_json_contract");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor
            .execute_unchecked(CapabilityRequest {
                capability: "git.log".to_string(),
                input: r#"{"max_count":1,"paths":["tracked.txt"]}"#.to_string(),
            })
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let commit = &value["commits"][0];

        assert!(commit["sha"].as_str().unwrap().len() >= 7);
        assert_eq!("Loomex Runner", commit["author"]);
        assert!(commit["committed_at"].as_str().unwrap().contains('T'));
        assert_eq!("initial", commit["subject"]);
        assert!(commit["hash"].is_null());
        assert!(commit["short_hash"].is_null());
        assert!(commit["author_name"].is_null());
        assert!(commit["authored_at_epoch_seconds"].is_null());
    }

    #[test]
    fn git_json_input_rejects_old_rust_shape_fields() {
        let root = git_workspace("git_json_reject_unknown");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        for (capability, input) in [
            ("git.status", r#"{"repository_path":"."}"#),
            (
                "git.diff",
                r#"{"pathspecs":["tracked.txt"],"staged":false}"#,
            ),
            ("git.log", r#"{"ref_name":"HEAD"}"#),
        ] {
            let error = executor
                .execute_unchecked(CapabilityRequest {
                    capability: capability.to_string(),
                    input: input.to_string(),
                })
                .unwrap_err();
            assert_eq!("CAPABILITY_INPUT_INVALID", error.code);
        }

        let error = executor
            .execute_unchecked(CapabilityRequest {
                capability: "git.status".to_string(),
                input: r#"{"repository_path":".","command":"commit"}"#.to_string(),
            })
            .unwrap_err();

        assert_eq!("CAPABILITY_INPUT_INVALID", error.code);
    }

    #[test]
    fn http_localhost_request_returns_contract_shape_and_body_artifact() {
        let root = test_workspace("http_localhost");
        let executor = local_http_executor(&root);
        let url = spawn_http_server(|_request| {
            http_response(
                "200 OK",
                &[("Content-Type", "application/json")],
                br#"{"ok":true}"#,
            )
        });

        let output = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                ..http_input_defaults()
            })
            .unwrap();
        let serialized = serde_json::to_value(&output).unwrap();
        let mut keys = serialized
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            vec![
                "body_ref".to_string(),
                "body_truncated".to_string(),
                "duration_ms".to_string(),
                "headers".to_string(),
                "status_code".to_string()
            ],
            keys
        );
        assert_eq!(200, output.status_code);
        assert_eq!(br#"{"ok":true}"#, output.artifacts.body.as_slice());
        assert_eq!("application/json", output.headers["content-type"]);
    }

    #[test]
    fn http_private_ip_is_allowed_for_policy_layer_to_decide() {
        validate_http_url(&Url::parse("http://10.0.0.1/health").unwrap()).unwrap();
        validate_http_url(&Url::parse("http://192.168.1.10/health").unwrap()).unwrap();
    }

    #[test]
    fn enterprise_network_policy_blocks_private_network() {
        let root = test_workspace("http_private_network_policy");
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_network_security_policy(NetworkSecurityPolicy {
                allowed_domains: vec!["10.0.0.1".to_string()],
                allow_private_network: false,
                ..NetworkSecurityPolicy::default()
            });

        let error = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url: "http://10.0.0.1/health".to_string(),
                ..http_input_defaults()
            })
            .unwrap_err();

        assert_eq!("NETWORK_PRIVATE_DENIED", error.code);
    }

    #[test]
    fn enterprise_network_policy_allows_allowlisted_domain() {
        let root = test_workspace("http_domain_allowlist");
        let mut network =
            NetworkSecurityPolicy::enterprise_restricted(vec!["localhost".to_string()]);
        network.allow_localhost = true;
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_network_security_policy(network);
        let url = spawn_http_server(|_request| http_response("200 OK", &[], b"ok"))
            .replace("127.0.0.1", "localhost");

        let output = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                ..http_input_defaults()
            })
            .unwrap();

        assert_eq!(200, output.status_code);
    }

    #[test]
    fn http_public_https_url_is_valid_for_rustls_transport() {
        validate_http_url(&Url::parse("https://example.com/").unwrap()).unwrap();
    }

    #[test]
    fn http_invalid_url_and_dns_failure_are_structured() {
        let root = test_workspace("http_invalid_url");
        let executor = local_http_executor(&root);

        let invalid = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url: "not a url".to_string(),
                ..http_input_defaults()
            })
            .unwrap_err();
        let dns = validate_http_url(&Url::parse("http://_loomex_invalid_/").unwrap()).unwrap_err();

        assert_eq!("HTTP_URL_INVALID", invalid.code);
        assert_eq!("HTTP_DNS_FAILED", dns.code);
    }

    #[test]
    fn http_timeout_returns_structured_error() {
        let root = test_workspace("http_timeout");
        let executor = local_http_executor(&root);
        let url = spawn_http_server(|_request| {
            thread::sleep(Duration::from_secs(2));
            http_response("200 OK", &[], b"late")
        });

        let error = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                timeout_seconds: Some(1),
                ..http_input_defaults()
            })
            .unwrap_err();

        assert_eq!("HTTP_TIMEOUT", error.code);
    }

    #[test]
    fn http_timeout_seconds_outside_contract_range_is_rejected() {
        let root = test_workspace("http_timeout_invalid");
        let executor = local_http_executor(&root);

        for timeout_seconds in [0, 301] {
            let error = executor
                .http_request(HttpRequestInput {
                    method: "GET".to_string(),
                    url: "http://127.0.0.1/".to_string(),
                    timeout_seconds: Some(timeout_seconds),
                    ..http_input_defaults()
                })
                .unwrap_err();

            assert_eq!("HTTP_TIMEOUT_INVALID", error.code);
        }
    }

    #[test]
    fn http_timeout_seconds_contract_max_is_accepted() {
        let root = test_workspace("http_timeout_contract_max");
        let executor = local_http_executor(&root);
        let url = spawn_http_server(|_request| http_response("200 OK", &[], b"ok"));

        let output = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                timeout_seconds: Some(300),
                ..http_input_defaults()
            })
            .unwrap();

        assert_eq!(200, output.status_code);
    }

    #[test]
    fn http_redirect_blocked_by_default_and_allowed_by_internal_policy() {
        let root = test_workspace("http_redirect");
        let executor = local_http_executor(&root);
        let blocked_target =
            spawn_http_server(|_request| http_response("200 OK", &[], b"blocked-target"));
        let blocked_redirect = spawn_http_server(move |_request| {
            http_response("302 Found", &[("Location", blocked_target.as_str())], b"")
        });

        let blocked = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url: blocked_redirect,
                ..http_input_defaults()
            })
            .unwrap();
        let followed_target = spawn_http_server(|_request| http_response("200 OK", &[], b"target"));
        let followed_redirect = spawn_http_server(move |_request| {
            http_response("302 Found", &[("Location", followed_target.as_str())], b"")
        });
        let followed = executor
            .http_request_with_redirects(
                HttpRequestInput {
                    method: "GET".to_string(),
                    url: followed_redirect,
                    ..http_input_defaults()
                },
                true,
            )
            .unwrap();

        assert_eq!(302, blocked.status_code);
        assert_eq!(200, followed.status_code);
        assert_eq!(b"target", followed.artifacts.body.as_slice());
    }

    #[test]
    fn http_response_too_large_is_truncated() {
        let root = test_workspace("http_truncate");
        let executor = local_http_executor(&root);
        let url = spawn_http_server(|_request| http_response("200 OK", &[], b"0123456789"));

        let output = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                max_response_bytes: Some(4),
                ..http_input_defaults()
            })
            .unwrap();

        assert!(output.body_truncated);
        assert_eq!(b"0123", output.artifacts.body.as_slice());
    }

    #[test]
    fn http_response_limit_above_contract_max_is_rejected() {
        let root = test_workspace("http_limit_too_large");
        let executor = local_http_executor(&root);
        let url = spawn_http_server(|_request| http_response("200 OK", &[], b"ok"));

        let error = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                max_response_bytes: Some(MAX_HTTP_RESPONSE_BYTES + 1),
                ..http_input_defaults()
            })
            .unwrap_err();

        assert_eq!("HTTP_RESPONSE_LIMIT_INVALID", error.code);
    }

    #[test]
    fn http_headers_are_redacted() {
        let root = test_workspace("http_redaction");
        let executor = LocalCapabilityExecutor::with_redaction(
            &root,
            Vec::new(),
            vec!["x-secret-header".to_string()],
        )
        .unwrap()
        .with_network_security_policy({
            let mut network = NetworkSecurityPolicy::default();
            network.allowed_domains = vec!["127.0.0.1".to_string()];
            network.allow_localhost = true;
            network
        });
        let url = spawn_http_server(|_request| {
            http_response(
                "200 OK",
                &[
                    ("Set-Cookie", "session=hidden"),
                    ("X-Secret-Header", "hidden-response"),
                    ("X-Public", "visible"),
                ],
                b"ok",
            )
        });
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer hidden".to_string());
        headers.insert("Cookie".to_string(), "session=hidden".to_string());
        headers.insert("X-Secret-Header".to_string(), "hidden-request".to_string());
        headers.insert("X-Public".to_string(), "visible".to_string());

        let output = executor
            .http_request(HttpRequestInput {
                method: "GET".to_string(),
                url,
                headers,
                ..http_input_defaults()
            })
            .unwrap();

        assert_eq!("[REDACTED]", output.headers["set-cookie"]);
        assert_eq!("[REDACTED]", output.headers["x-secret-header"]);
        assert_eq!("visible", output.headers["x-public"]);
        assert_eq!(
            "[REDACTED]",
            output.artifacts.request_headers["authorization"]
        );
        assert_eq!("[REDACTED]", output.artifacts.request_headers["cookie"]);
        assert_eq!(
            "[REDACTED]",
            output.artifacts.request_headers["x-secret-header"]
        );
        assert_eq!("visible", output.artifacts.request_headers["x-public"]);
    }

    #[test]
    fn http_metadata_ip_is_denied() {
        let root = test_workspace("http_metadata_denied");
        let executor = local_http_executor(&root);

        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.170.2/credentials",
            "http://[fe80::1]/metadata",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ] {
            let error = executor
                .http_request(HttpRequestInput {
                    method: "GET".to_string(),
                    url: url.to_string(),
                    ..http_input_defaults()
                })
                .unwrap_err();

            assert_eq!("HTTP_ENDPOINT_DENIED", error.code);
        }
    }

    #[test]
    fn http_redirect_to_metadata_is_denied_before_follow() {
        let root = test_workspace("http_redirect_metadata_denied");
        let executor = local_http_executor(&root);
        let redirect = spawn_http_server(|_request| {
            http_response(
                "302 Found",
                &[("Location", "http://169.254.170.2/credentials")],
                b"",
            )
        });

        let error = executor
            .http_request_with_redirects(
                HttpRequestInput {
                    method: "GET".to_string(),
                    url: redirect,
                    ..http_input_defaults()
                },
                true,
            )
            .unwrap_err();

        assert_eq!("HTTP_ENDPOINT_DENIED", error.code);
    }

    #[test]
    fn browser_network_policy_rejects_unallowlisted_target_before_playwright() {
        let root = test_workspace("browser_network_allowlist");
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_network_security_policy(NetworkSecurityPolicy::enterprise_restricted(vec![
                "example.com".to_string(),
            ]));

        let error = executor
            .browser_playwright(BrowserPlaywrightInput {
                url: "https://example.org/".to_string(),
                browser: Some("chromium".to_string()),
                headless: Some(true),
                screenshot_path: None,
                trace_path: None,
                timeout_seconds: Some(1),
                max_output_bytes: Some(1024),
            })
            .unwrap_err();

        assert_eq!("NETWORK_DOMAIN_NOT_ALLOWED", error.code);
    }

    #[test]
    fn browser_network_policy_rejects_private_and_metadata_targets_before_playwright() {
        let root = test_workspace("browser_network_private");
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_network_security_policy(NetworkSecurityPolicy {
                allowed_domains: vec!["10.0.0.1".to_string(), "169.254.169.254".to_string()],
                allow_private_network: false,
                ..NetworkSecurityPolicy::default()
            });

        let private = executor
            .browser_playwright(BrowserPlaywrightInput {
                url: "http://10.0.0.1/".to_string(),
                browser: Some("chromium".to_string()),
                headless: Some(true),
                screenshot_path: None,
                trace_path: None,
                timeout_seconds: Some(1),
                max_output_bytes: Some(1024),
            })
            .unwrap_err();
        let metadata = executor
            .browser_playwright(BrowserPlaywrightInput {
                url: "http://169.254.169.254/latest/meta-data/".to_string(),
                browser: Some("chromium".to_string()),
                headless: Some(true),
                screenshot_path: None,
                trace_path: None,
                timeout_seconds: Some(1),
                max_output_bytes: Some(1024),
            })
            .unwrap_err();

        assert_eq!("NETWORK_PRIVATE_DENIED", private.code);
        assert_eq!("HTTP_ENDPOINT_DENIED", metadata.code);
    }

    #[test]
    fn browser_network_preflight_rejects_redirect_to_denied_target() {
        let root = test_workspace("browser_redirect_denied");
        let mut network =
            NetworkSecurityPolicy::enterprise_restricted(vec!["localhost".to_string()]);
        network.allow_localhost = true;
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_network_security_policy(network);
        let redirect = spawn_http_server(|_request| {
            http_response(
                "302 Found",
                &[("Location", "http://169.254.170.2/credentials")],
                b"",
            )
        })
        .replace("127.0.0.1", "localhost");

        let error = executor
            .browser_playwright(BrowserPlaywrightInput {
                url: redirect,
                browser: Some("chromium".to_string()),
                headless: Some(true),
                screenshot_path: None,
                trace_path: None,
                timeout_seconds: Some(5),
                max_output_bytes: Some(1024),
            })
            .unwrap_err();

        assert_eq!("HTTP_ENDPOINT_DENIED", error.code);
    }

    #[test]
    fn expanded_capabilities_are_publicly_supported() {
        let root = test_workspace("expanded_support");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        for capability in ["browser.playwright", "db.query", "docker.exec", "test.run"] {
            assert!(executor.supports(capability));
        }
    }

    #[test]
    fn playwright_opens_local_ui_and_writes_screenshot_when_available() {
        if !playwright_available() {
            return;
        }
        let root = test_workspace("browser_playwright");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();
        let url = spawn_http_server(|_request| {
            http_response(
                "200 OK",
                &[("Content-Type", "text/html")],
                b"<html><body><h1>Loomex UI</h1></body></html>",
            )
        });

        let result = executor.browser_playwright(BrowserPlaywrightInput {
            url,
            browser: Some("chromium".to_string()),
            headless: Some(true),
            screenshot_path: Some("artifacts/ui.png".to_string()),
            trace_path: Some("artifacts/trace.json".to_string()),
            timeout_seconds: Some(30),
            max_output_bytes: Some(4096),
        });
        let output = match result {
            Ok(output) => output,
            Err(error) => panic!("unexpected browser.playwright failure: {error:?}"),
        };

        assert!(root.join("artifacts/ui.png").exists());
        assert!(root.join("artifacts/trace.json").exists());
        assert!(output
            .screenshot_ref
            .unwrap()
            .starts_with("artifact:browser-screenshot:"));
        assert!(output
            .trace_ref
            .unwrap()
            .starts_with("artifact:browser-trace:"));
    }

    #[test]
    fn db_query_sqlite_read_only_query_returns_structured_rows() {
        let root = test_workspace("db_query_sqlite");
        let db_path = root.join("data.sqlite");
        run_sqlite_test_command(&db_path, "create table items(id integer, name text);");
        run_sqlite_test_command(&db_path, "insert into items values (1, 'one');");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .db_query(DbQueryInput {
                driver: "sqlite".to_string(),
                connection_string: "sqlite://data.sqlite".to_string(),
                query: "select id, name from items".to_string(),
                read_only: None,
                max_rows: Some(10),
                timeout_seconds: Some(5),
                max_output_bytes: Some(4096),
            })
            .unwrap();

        assert_eq!(vec!["id".to_string(), "name".to_string()], output.columns);
        assert_eq!(1, output.row_count);
        assert!(output.rows_ref.starts_with("inline:db-rows:"));
        assert!(output.artifacts.rows_json.contains("\"one\""));
    }

    #[test]
    fn db_query_write_is_denied_by_default_before_connection_use() {
        let root = test_workspace("db_write_denied");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .db_query(DbQueryInput {
                driver: "sqlite".to_string(),
                connection_string: "sqlite://missing.sqlite".to_string(),
                query: "delete from items".to_string(),
                read_only: None,
                max_rows: None,
                timeout_seconds: None,
                max_output_bytes: None,
            })
            .unwrap_err();

        assert_eq!("DB_WRITE_DENIED", error.code);
    }

    #[test]
    fn db_query_read_only_false_cannot_bypass_write_denial() {
        let root = test_workspace("db_read_only_false_denied");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        for query in [
            "insert into items values (1)",
            "update items set id = 2",
            "delete from items",
            "drop table items",
        ] {
            let error = executor
                .db_query(DbQueryInput {
                    driver: "sqlite".to_string(),
                    connection_string: "sqlite://missing.sqlite".to_string(),
                    query: query.to_string(),
                    read_only: Some(false),
                    max_rows: None,
                    timeout_seconds: None,
                    max_output_bytes: None,
                })
                .unwrap_err();

            assert_eq!("DB_READ_ONLY_REQUIRED", error.code);
        }
    }

    #[test]
    fn db_query_sqlite_pragma_assignment_is_denied_before_execution() {
        let root = test_workspace("db_pragma_assignment_denied");
        let db_path = root.join("data.sqlite");
        run_sqlite_test_command(&db_path, "create table items(id integer);");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .db_query(DbQueryInput {
                driver: "sqlite".to_string(),
                connection_string: "sqlite://data.sqlite".to_string(),
                query: "pragma user_version = 7".to_string(),
                read_only: None,
                max_rows: None,
                timeout_seconds: Some(5),
                max_output_bytes: Some(4096),
            })
            .unwrap_err();

        assert_eq!("DB_WRITE_DENIED", error.code);
    }

    #[test]
    fn db_query_sqlite_enforces_row_limit_at_query_boundary() {
        let root = test_workspace("db_row_limit");
        let db_path = root.join("data.sqlite");
        run_sqlite_test_command(
            &db_path,
            "create table items(id integer); insert into items values(1),(2),(3);",
        );
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .db_query(DbQueryInput {
                driver: "sqlite".to_string(),
                connection_string: "sqlite://data.sqlite".to_string(),
                query: "select id from items order by id".to_string(),
                read_only: None,
                max_rows: Some(2),
                timeout_seconds: Some(5),
                max_output_bytes: Some(4096),
            })
            .unwrap();

        assert_eq!(2, output.row_count);
        assert!(output.truncated);
        assert!(!output.artifacts.rows_json.contains("3"));
    }

    #[test]
    fn db_query_artifacts_are_redacted() {
        let root = test_workspace("db_query_redaction");
        let db_path = root.join("data.sqlite");
        run_sqlite_test_command(&db_path, "create table secrets(value text);");
        run_sqlite_test_command(&db_path, "insert into secrets values ('top-secret');");
        let executor =
            LocalCapabilityExecutor::with_redaction(&root, vec!["top-secret".to_string()], vec![])
                .unwrap();

        let output = executor
            .db_query(DbQueryInput {
                driver: "sqlite".to_string(),
                connection_string: "sqlite://data.sqlite".to_string(),
                query: "select value from secrets".to_string(),
                read_only: None,
                max_rows: None,
                timeout_seconds: Some(5),
                max_output_bytes: Some(4096),
            })
            .unwrap();

        assert!(!output.artifacts.rows_json.contains("top-secret"));
        assert!(output.artifacts.rows_json.contains("[REDACTED]"));
    }

    #[test]
    fn docker_unavailable_is_structured() {
        let root = test_workspace("docker_unavailable");
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_docker_allowed_containers(vec!["loomex-api".to_string()]);

        let error = executor
            .docker_exec_with_binary(
                DockerExecInput {
                    container: "loomex-api".to_string(),
                    command: vec!["echo".to_string(), "ok".to_string()],
                    timeout_seconds: Some(5),
                    max_output_bytes: Some(1024),
                },
                "__loomex_missing_docker__",
            )
            .unwrap_err();

        assert_eq!("DOCKER_UNAVAILABLE", error.code);
    }

    #[test]
    fn docker_container_not_allowlisted_is_denied_before_availability_check() {
        let root = test_workspace("docker_denied");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .docker_exec(DockerExecInput {
                container: "postgres".to_string(),
                command: vec!["echo".to_string(), "ok".to_string()],
                timeout_seconds: Some(5),
                max_output_bytes: Some(1024),
            })
            .unwrap_err();

        assert_eq!("DOCKER_CONTAINER_DENIED", error.code);
    }

    #[test]
    fn docker_request_payload_cannot_self_authorize_container() {
        let root = test_workspace("docker_self_authorize");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let error = executor
            .execute_unchecked(CapabilityRequest {
                capability: "docker.exec".to_string(),
                input: r#"{"container":"postgres","command":["echo","ok"],"allowed_containers":["postgres"]}"#.to_string(),
            })
            .unwrap_err();

        assert_eq!("CAPABILITY_INPUT_INVALID", error.code);
    }

    #[test]
    fn docker_timeout_and_output_bounds_are_enforced_before_spawn() {
        let root = test_workspace("docker_bounds");
        let executor = LocalCapabilityExecutor::new(&root)
            .unwrap()
            .with_docker_allowed_containers(vec!["api".to_string()]);

        let timeout = executor
            .docker_exec_with_binary(
                DockerExecInput {
                    container: "api".to_string(),
                    command: vec!["echo".to_string(), "ok".to_string()],
                    timeout_seconds: Some(3601),
                    max_output_bytes: Some(1024),
                },
                "__loomex_missing_docker__",
            )
            .unwrap_err();
        let output = executor
            .docker_exec_with_binary(
                DockerExecInput {
                    container: "api".to_string(),
                    command: vec!["echo".to_string(), "ok".to_string()],
                    timeout_seconds: Some(5),
                    max_output_bytes: Some(MAX_EXPANDED_OUTPUT_BYTES + 1),
                },
                "__loomex_missing_docker__",
            )
            .unwrap_err();

        assert_eq!("DOCKER_TIMEOUT_INVALID", timeout.code);
        assert_eq!("CAPABILITY_OUTPUT_LIMIT_INVALID", output.code);
    }

    #[test]
    fn test_runner_returns_structured_report() {
        let root = test_workspace("test_runner_report");
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let output = executor
            .test_run(TestRunInput {
                runner: "custom".to_string(),
                script: None,
                command: Some(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf '2 passed, 1 skipped\\n'".to_string(),
                ]),
                args: Vec::new(),
                env: BTreeMap::new(),
                working_directory: None,
                timeout_seconds: Some(5),
                max_output_bytes: Some(1024),
            })
            .unwrap();

        assert_eq!(0, output.exit_code);
        assert_eq!(2, output.passed);
        assert_eq!(0, output.failed);
        assert_eq!(1, output.skipped);
        assert!(output.stdout_ref.starts_with("inline:"));
    }

    #[test]
    fn pytest_runner_uses_python3() {
        let command = test_runner_command(&TestRunInput {
            runner: "pytest".to_string(),
            script: None,
            command: None,
            args: vec!["-q".to_string()],
            env: BTreeMap::new(),
            working_directory: None,
            timeout_seconds: None,
            max_output_bytes: None,
        })
        .unwrap();

        assert_eq!(
            vec!["python3", "-m", "pytest", "-q"],
            command.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[cfg(unix)]
    #[test]
    fn patch_prepare_failure_does_not_partially_write_previous_files() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_workspace("patch_prepare_failure");
        fs::write(root.join("first.txt"), "first-old\n").unwrap();
        fs::create_dir_all(root.join("locked")).unwrap();
        fs::write(root.join("locked/second.txt"), "second-old\n").unwrap();
        let mut permissions = fs::metadata(root.join("locked")).unwrap().permissions();
        permissions.set_mode(0o500);
        fs::set_permissions(root.join("locked"), permissions).unwrap();
        let executor = LocalCapabilityExecutor::new(&root).unwrap();

        let result = executor.fs_apply_patch(FsApplyPatchInput {
            patch: concat!(
                "--- a/first.txt\n",
                "+++ b/first.txt\n",
                "@@ -1,1 +1,1 @@\n",
                "-first-old\n",
                "+first-new\n",
                "--- a/locked/second.txt\n",
                "+++ b/locked/second.txt\n",
                "@@ -1,1 +1,1 @@\n",
                "-second-old\n",
                "+second-new\n"
            )
            .to_string(),
            ..Default::default()
        });

        let mut permissions = fs::metadata(root.join("locked")).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(root.join("locked"), permissions).unwrap();
        assert_eq!("PATCH_PREPARE_FAILED", result.unwrap_err().code);
        assert_eq!(
            "first-old\n",
            fs::read_to_string(root.join("first.txt")).unwrap()
        );
        assert_eq!(
            "second-old\n",
            fs::read_to_string(root.join("locked/second.txt")).unwrap()
        );
    }

    fn test_workspace(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "loomex-core-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn git_workspace(name: &str) -> PathBuf {
        let root = test_workspace(name);
        init_git_repo(&root);
        root
    }

    fn init_git_repo(root: &Path) {
        run_git_test_command(root, &["init"]);
        run_git_test_command(root, &["config", "user.email", "runner@example.test"]);
        run_git_test_command(root, &["config", "user.name", "Loomex Runner"]);
        fs::write(root.join("tracked.txt"), "hello\n").unwrap();
        run_git_test_command(root, &["add", "tracked.txt"]);
        run_git_test_command(root, &["commit", "-m", "initial"]);
    }

    fn run_git_test_command(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn http_input_defaults() -> HttpRequestInput {
        HttpRequestInput {
            method: "GET".to_string(),
            url: "http://127.0.0.1/".to_string(),
            headers: BTreeMap::new(),
            body: None,
            body_encoding: None,
            timeout_seconds: Some(5),
            max_response_bytes: Some(1024),
        }
    }

    fn local_http_executor(root: &Path) -> LocalCapabilityExecutor {
        let mut network = NetworkSecurityPolicy::default();
        network.allowed_domains = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        network.allow_localhost = true;
        LocalCapabilityExecutor::new(root)
            .unwrap()
            .with_network_security_policy(network)
    }

    fn spawn_http_server(handler: impl FnOnce(String) -> Vec<u8> + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_http_request(&mut stream);
                let response = handler(request);
                stream.write_all(&response).unwrap();
                stream.flush().unwrap();
            }
        });
        format!("http://{address}/")
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buffer = [0u8; 2048];
        let read = stream.read(&mut buffer).unwrap_or(0);
        String::from_utf8_lossy(&buffer[..read]).to_string()
    }

    fn http_response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .into_bytes();
        for (name, value) in headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(body);
        response
    }

    fn run_sqlite_test_command(path: &Path, sql: &str) {
        let output = Command::new("sqlite3").arg(path).arg(sql).output().unwrap();
        assert!(
            output.status.success(),
            "sqlite command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn playwright_available() -> bool {
        std::env::var_os("LOOMEX_PLUGIN_ROOT")
            .map(|root| {
                PathBuf::from(root)
                    .join("packaging/browser-runtime.json")
                    .is_file()
            })
            .unwrap_or(false)
    }
}
