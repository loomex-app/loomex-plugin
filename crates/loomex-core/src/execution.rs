use crate::binding::{
    validate_session_and_grant_for_local_tool_call, BindingValidationContext, ProjectRunnerBinding,
    RunnerCapabilityGrant, RunnerSession,
};
use crate::capability::{CapabilityExecutor, CapabilityRequest, CapabilityResult};
use crate::policy::{enforce_policy_decision, PolicyEngine, PolicyEvaluationInput};
use crate::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RUNNER_JOB_RECOVERY_JOURNAL_SCHEMA_VERSION: &str = "loomex.runner.jobRecoveryJournal/v1";

/// Whether a job whose process died after it entered `running` may be executed again.
///
/// The default must be [`ManualReconciliation`]. A shell command or filesystem mutation can
/// have committed side effects before the daemon died, even when no result was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobReplaySafety {
    ManualReconciliation,
    Idempotent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverableJobPhase {
    Leased,
    Running,
    SucceededPendingAck,
    FailedPendingAck,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverableRunnerJob {
    pub job_id: String,
    pub runner_id: String,
    pub session_id: String,
    pub kind: String,
    /// Stable server-issued key used for idempotent terminal submission after reconnect.
    pub idempotency_key: String,
    /// A stable digest of the canonical server payload. The payload itself is deliberately not
    /// persisted because it may contain credentials or other sensitive input.
    pub payload_fingerprint: String,
    pub attempt_count: u32,
    /// Monotonic compare-and-swap generation advanced by every lease/reclaim.
    pub lease_version: u64,
    pub leased_until_epoch_ms: u64,
    pub replay_safety: JobReplaySafety,
    pub phase: RecoverableJobPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_payload: Option<Value>,
    pub updated_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRunnerJobStatus {
    Queued,
    Leased,
    Running,
    Succeeded,
    Failed,
    Canceling,
    Canceled,
    Expired,
}

impl RemoteRunnerJobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::Expired
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRunnerJobSnapshot {
    pub job_id: String,
    pub session_id: Option<String>,
    pub status: RemoteRunnerJobStatus,
    pub attempt_count: u32,
    pub lease_version: u64,
    pub leased_until_epoch_ms: Option<u64>,
    pub payload_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JobRecoveryAction {
    /// The server is terminal. The local entry can be removed without replaying anything.
    ForgetTerminal,
    /// The old server lease is still authoritative; wait rather than stealing or duplicating it.
    WaitForLeaseExpiry { leased_until_epoch_ms: u64 },
    /// No active lease can be used. Ask the server to atomically reclaim this exact job.
    RequestServerReclaim,
    /// The job was only leased locally and is now leased to this daemon's current session.
    StartExecution,
    /// A running job was interrupted, but its contract explicitly permits idempotent replay.
    ResumeIdempotentExecution,
    /// Execution finished locally and this exact payload must be submitted without re-execution.
    SubmitSucceeded(Value),
    /// Execution failed locally and this exact error must be submitted without re-execution.
    SubmitFailed(Value),
    /// The daemon cannot prove that replay is safe.
    ManualReconciliation { reason: &'static str },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunnerJobRecoveryDocument {
    schema_version: String,
    jobs: Vec<RecoverableRunnerJob>,
}

/// A small durable write-ahead journal for local runner jobs.
///
/// Callers must persist transitions in this order:
///
/// 1. `record_lease` after the server lease response;
/// 2. acknowledge start to the server, then `mark_running` **immediately before** executing
///    locally;
/// 3. `record_succeeded`/`record_failed` before sending the terminal server request;
/// 4. `acknowledge_terminal` only after the server durably accepts that request.
///
/// This ordering lets a restarted daemon submit a saved result without repeating local side
/// effects. An interrupted `running` job is replayed only when it was explicitly declared
/// idempotent. Server-side lease expiry/reclaim is still required to move ownership to a newly
/// created runner session.
#[derive(Debug, Clone)]
pub struct RunnerJobRecoveryJournal {
    path: PathBuf,
    document: RunnerJobRecoveryDocument,
}

impl RunnerJobRecoveryJournal {
    pub fn open(path: impl Into<PathBuf>) -> CoreResult<Self> {
        let path = path.into();
        let document = if path.exists() {
            let bytes = fs::read(&path).map_err(|error| {
                CoreError::new(
                    "RUNNER_JOB_RECOVERY_READ_FAILED",
                    format!("failed to read {}: {error}", path.display()),
                )
            })?;
            let document: RunnerJobRecoveryDocument =
                serde_json::from_slice(&bytes).map_err(|error| {
                    CoreError::new(
                        "RUNNER_JOB_RECOVERY_CORRUPT",
                        format!("failed to parse {}: {error}", path.display()),
                    )
                })?;
            validate_recovery_document(&document)?;
            document
        } else {
            RunnerJobRecoveryDocument {
                schema_version: RUNNER_JOB_RECOVERY_JOURNAL_SCHEMA_VERSION.to_string(),
                jobs: Vec::new(),
            }
        };
        Ok(Self { path, document })
    }

    pub fn pending_jobs(&self) -> &[RecoverableRunnerJob] {
        &self.document.jobs
    }

    pub fn job(&self, job_id: &str) -> Option<&RecoverableRunnerJob> {
        self.document.jobs.iter().find(|job| job.job_id == job_id)
    }

    pub fn record_lease(&mut self, job: RecoverableRunnerJob) -> CoreResult<()> {
        validate_recoverable_job(&job)?;
        if job.phase != RecoverableJobPhase::Leased || job.terminal_payload.is_some() {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_INVALID_TRANSITION",
                "a newly recorded lease must be in leased phase without a terminal payload",
            ));
        }
        if let Some(existing) = self.job(&job.job_id) {
            if existing == &job {
                return Ok(());
            }
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_CONFLICT",
                "an unacknowledged recovery record already exists for this job",
            ));
        }
        self.document.jobs.push(job);
        self.persist()
    }

    pub fn mark_running(
        &mut self,
        job_id: &str,
        session_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        let job = self.job_mut_for_session(job_id, session_id)?;
        if now_epoch_ms > job.leased_until_epoch_ms {
            return Err(CoreError::new(
                "RUNNER_JOB_LEASE_EXPIRED",
                "runner job lease expired before local execution started",
            ));
        }
        match job.phase {
            RecoverableJobPhase::Leased => job.phase = RecoverableJobPhase::Running,
            RecoverableJobPhase::Running => return Ok(()),
            _ => {
                return Err(CoreError::new(
                    "RUNNER_JOB_RECOVERY_INVALID_TRANSITION",
                    "a terminal outcome cannot transition back to running",
                ))
            }
        }
        job.updated_at_epoch_ms = now_epoch_ms;
        self.persist()
    }

    /// Persist the authoritative expiry returned by a successful fenced lease renewal.
    pub fn renew_lease(
        &mut self,
        job_id: &str,
        session_id: &str,
        new_lease_version: u64,
        leased_until_epoch_ms: u64,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        let job = self.job_mut_for_session(job_id, session_id)?;
        if new_lease_version <= job.lease_version {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_LEASE_VERSION_MISMATCH",
                "runner job renewal must advance the durable lease version",
            ));
        }
        if leased_until_epoch_ms <= now_epoch_ms {
            return Err(CoreError::new(
                "RUNNER_JOB_LEASE_EXPIRED",
                "runner job renewal did not extend the lease into the future",
            ));
        }
        if leased_until_epoch_ms < job.leased_until_epoch_ms {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_LEASE_REGRESSION",
                "runner job renewal cannot shorten the durable lease",
            ));
        }
        job.lease_version = new_lease_version;
        job.leased_until_epoch_ms = leased_until_epoch_ms;
        job.updated_at_epoch_ms = now_epoch_ms;
        self.persist()
    }

    pub fn record_succeeded(
        &mut self,
        job_id: &str,
        session_id: &str,
        result: Value,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        self.record_terminal(
            job_id,
            session_id,
            RecoverableJobPhase::SucceededPendingAck,
            result,
            now_epoch_ms,
        )
    }

    pub fn record_failed(
        &mut self,
        job_id: &str,
        session_id: &str,
        error: Value,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        self.record_terminal(
            job_id,
            session_id,
            RecoverableJobPhase::FailedPendingAck,
            error,
            now_epoch_ms,
        )
    }

    pub fn acknowledge_terminal(&mut self, job_id: &str) -> CoreResult<()> {
        let index = self
            .document
            .jobs
            .iter()
            .position(|job| job.job_id == job_id)
            .ok_or_else(|| {
                CoreError::new(
                    "RUNNER_JOB_RECOVERY_NOT_FOUND",
                    "runner job recovery record was not found",
                )
            })?;
        if !matches!(
            self.document.jobs[index].phase,
            RecoverableJobPhase::SucceededPendingAck | RecoverableJobPhase::FailedPendingAck
        ) {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_INVALID_TRANSITION",
                "runner job cannot be forgotten before a terminal outcome is persisted",
            ));
        }
        self.document.jobs.remove(index);
        self.persist()
    }

    /// Remove any local phase after the authoritative server snapshot is already terminal.
    ///
    /// This covers a crash after the terminal request committed remotely but before the local
    /// journal could be cleaned up. Identity is checked before removal so an unrelated server
    /// record can never discard local recovery state.
    pub fn forget_server_terminal(
        &mut self,
        job_id: &str,
        remote: &RemoteRunnerJobSnapshot,
    ) -> CoreResult<()> {
        let local = self.job(job_id).ok_or_else(|| {
            CoreError::new(
                "RUNNER_JOB_RECOVERY_NOT_FOUND",
                "runner job recovery record was not found",
            )
        })?;
        if !remote.status.is_terminal()
            || remote.job_id != local.job_id
            || remote.payload_fingerprint != local.payload_fingerprint
            || remote.attempt_count < local.attempt_count
            || remote.lease_version < local.lease_version
        {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_SERVER_NOT_TERMINAL",
                "matching authoritative server job is not terminal",
            ));
        }
        let index = self
            .document
            .jobs
            .iter()
            .position(|job| job.job_id == job_id)
            .expect("local recovery record was checked above");
        self.document.jobs.remove(index);
        self.persist()
    }

    /// Plans recovery against an authoritative server snapshot.
    ///
    /// `current_session_id` is the freshly connected daemon session. Returning a start, resume, or
    /// submit action requires the server snapshot to be owned by that exact session. This prevents
    /// a local stale journal from bypassing server lease ownership.
    pub fn recovery_action(
        &self,
        job_id: &str,
        remote: Option<&RemoteRunnerJobSnapshot>,
        current_session_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<JobRecoveryAction> {
        let local = self.job(job_id).ok_or_else(|| {
            CoreError::new(
                "RUNNER_JOB_RECOVERY_NOT_FOUND",
                "runner job recovery record was not found",
            )
        })?;
        let Some(remote) = remote else {
            return Ok(JobRecoveryAction::RequestServerReclaim);
        };
        if remote.job_id != local.job_id
            || remote.payload_fingerprint != local.payload_fingerprint
            || remote.attempt_count < local.attempt_count
            || remote.lease_version < local.lease_version
        {
            return Ok(JobRecoveryAction::ManualReconciliation {
                reason: "server job identity does not match the durable local record",
            });
        }
        if remote.status.is_terminal() {
            return Ok(JobRecoveryAction::ForgetTerminal);
        }
        if remote.status == RemoteRunnerJobStatus::Canceling {
            return Ok(JobRecoveryAction::ManualReconciliation {
                reason: "server cancellation must be reconciled before execution can resume",
            });
        }

        let owned_by_current_session = remote.session_id.as_deref() == Some(current_session_id);
        if !owned_by_current_session {
            if let Some(leased_until_epoch_ms) = remote.leased_until_epoch_ms {
                if now_epoch_ms <= leased_until_epoch_ms
                    && matches!(
                        remote.status,
                        RemoteRunnerJobStatus::Leased | RemoteRunnerJobStatus::Running
                    )
                {
                    return Ok(JobRecoveryAction::WaitForLeaseExpiry {
                        leased_until_epoch_ms,
                    });
                }
            }
            return Ok(JobRecoveryAction::RequestServerReclaim);
        }
        if !matches!(
            remote.status,
            RemoteRunnerJobStatus::Leased | RemoteRunnerJobStatus::Running
        ) {
            return Ok(JobRecoveryAction::ManualReconciliation {
                reason: "current session does not own an active server lease",
            });
        }
        if current_session_id != local.session_id && remote.lease_version <= local.lease_version {
            return Ok(JobRecoveryAction::ManualReconciliation {
                reason: "server changed session ownership without advancing the lease version",
            });
        }

        match local.phase {
            // With the documented ordering, a durable leased phase proves local execution never
            // began. The server start acknowledgement may already have committed, so either
            // active remote phase is safe to continue.
            RecoverableJobPhase::Leased => Ok(JobRecoveryAction::StartExecution),
            RecoverableJobPhase::Running => {
                if remote.status != RemoteRunnerJobStatus::Leased {
                    return Ok(JobRecoveryAction::ManualReconciliation {
                        reason: "an interrupted running job must be reclaimed as a new lease before replay",
                    });
                }
                match local.replay_safety {
                    JobReplaySafety::Idempotent => Ok(JobRecoveryAction::ResumeIdempotentExecution),
                    JobReplaySafety::ManualReconciliation => {
                        Ok(JobRecoveryAction::ManualReconciliation {
                            reason: "interrupted local execution was not declared idempotent",
                        })
                    }
                }
            }
            RecoverableJobPhase::SucceededPendingAck => Ok(JobRecoveryAction::SubmitSucceeded(
                local.terminal_payload.clone().ok_or_else(|| {
                    CoreError::new(
                        "RUNNER_JOB_RECOVERY_CORRUPT",
                        "succeeded recovery record has no terminal payload",
                    )
                })?,
            )),
            RecoverableJobPhase::FailedPendingAck => Ok(JobRecoveryAction::SubmitFailed(
                local.terminal_payload.clone().ok_or_else(|| {
                    CoreError::new(
                        "RUNNER_JOB_RECOVERY_CORRUPT",
                        "failed recovery record has no terminal payload",
                    )
                })?,
            )),
        }
    }

    /// Persist new server ownership after an atomic reclaim response.
    pub fn adopt_reclaimed_lease(
        &mut self,
        job_id: &str,
        remote: &RemoteRunnerJobSnapshot,
        current_session_id: &str,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        let local = self.job(job_id).ok_or_else(|| {
            CoreError::new(
                "RUNNER_JOB_RECOVERY_NOT_FOUND",
                "runner job recovery record was not found",
            )
        })?;
        if remote.job_id != local.job_id
            || remote.payload_fingerprint != local.payload_fingerprint
            || remote.attempt_count < local.attempt_count
            || remote.lease_version <= local.lease_version
            || remote.session_id.as_deref() != Some(current_session_id)
            || remote.status != RemoteRunnerJobStatus::Leased
        {
            return Err(CoreError::new(
                "RUNNER_JOB_RECLAIM_NOT_OWNED",
                "server did not return a matching, advanced lease owned by the current session",
            ));
        }
        let job = self.job_mut_for_id(job_id)?;
        job.session_id = current_session_id.to_string();
        job.attempt_count = remote.attempt_count;
        job.lease_version = remote.lease_version;
        job.leased_until_epoch_ms = remote.leased_until_epoch_ms.ok_or_else(|| {
            CoreError::new(
                "RUNNER_JOB_RECLAIM_INVALID",
                "reclaimed server job did not include a lease expiry",
            )
        })?;
        job.updated_at_epoch_ms = now_epoch_ms;
        self.persist()
    }

    fn record_terminal(
        &mut self,
        job_id: &str,
        session_id: &str,
        phase: RecoverableJobPhase,
        payload: Value,
        now_epoch_ms: u64,
    ) -> CoreResult<()> {
        let job = self.job_mut_for_session(job_id, session_id)?;
        if job.phase != RecoverableJobPhase::Running {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_INVALID_TRANSITION",
                "a terminal outcome can only be recorded for a running job",
            ));
        }
        job.phase = phase;
        job.terminal_payload = Some(payload);
        job.updated_at_epoch_ms = now_epoch_ms;
        self.persist()
    }

    fn job_mut_for_id(&mut self, job_id: &str) -> CoreResult<&mut RecoverableRunnerJob> {
        self.document
            .jobs
            .iter_mut()
            .find(|job| job.job_id == job_id)
            .ok_or_else(|| {
                CoreError::new(
                    "RUNNER_JOB_RECOVERY_NOT_FOUND",
                    "runner job recovery record was not found",
                )
            })
    }

    fn job_mut_for_session(
        &mut self,
        job_id: &str,
        session_id: &str,
    ) -> CoreResult<&mut RecoverableRunnerJob> {
        let job = self.job_mut_for_id(job_id)?;
        if job.session_id != session_id {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_SESSION_MISMATCH",
                "runner job is not owned by this local session",
            ));
        }
        Ok(job)
    }

    fn persist(&self) -> CoreResult<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            CoreError::new(
                "RUNNER_JOB_RECOVERY_WRITE_FAILED",
                format!("failed to create {}: {error}", parent.display()),
            )
        })?;
        let file_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("runner-job-recovery.json");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = parent.join(format!(".{file_name}.{}.{nonce}.tmp", std::process::id()));
        let bytes = serde_json::to_vec_pretty(&self.document).map_err(|error| {
            CoreError::new(
                "RUNNER_JOB_RECOVERY_WRITE_FAILED",
                format!("failed to serialize recovery journal: {error}"),
            )
        })?;
        let write_result = (|| -> std::io::Result<()> {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_WRITE_FAILED",
                format!("failed to write {}: {error}", self.path.display()),
            ));
        }
        Ok(())
    }
}

fn validate_recovery_document(document: &RunnerJobRecoveryDocument) -> CoreResult<()> {
    if document.schema_version != RUNNER_JOB_RECOVERY_JOURNAL_SCHEMA_VERSION {
        return Err(CoreError::new(
            "RUNNER_JOB_RECOVERY_SCHEMA_UNSUPPORTED",
            "runner job recovery journal schema is not supported",
        ));
    }
    for (index, job) in document.jobs.iter().enumerate() {
        validate_recoverable_job(job)?;
        if document.jobs[..index]
            .iter()
            .any(|candidate| candidate.job_id == job.job_id)
        {
            return Err(CoreError::new(
                "RUNNER_JOB_RECOVERY_CORRUPT",
                "runner job recovery journal contains duplicate job ids",
            ));
        }
    }
    Ok(())
}

fn validate_recoverable_job(job: &RecoverableRunnerJob) -> CoreResult<()> {
    if job.job_id.trim().is_empty()
        || job.runner_id.trim().is_empty()
        || job.session_id.trim().is_empty()
        || job.kind.trim().is_empty()
        || job.idempotency_key.trim().is_empty()
        || job.payload_fingerprint.trim().is_empty()
        || job.attempt_count == 0
        || job.lease_version == 0
        || job.leased_until_epoch_ms == 0
    {
        return Err(CoreError::new(
            "RUNNER_JOB_RECOVERY_CORRUPT",
            "runner job recovery record is incomplete",
        ));
    }
    let terminal = matches!(
        job.phase,
        RecoverableJobPhase::SucceededPendingAck | RecoverableJobPhase::FailedPendingAck
    );
    if terminal != job.terminal_payload.is_some() {
        return Err(CoreError::new(
            "RUNNER_JOB_RECOVERY_CORRUPT",
            "runner job recovery terminal phase and payload do not match",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub struct ExecutionRegistry {
    executors: Vec<Box<dyn CapabilityExecutor>>,
}

impl ExecutionRegistry {
    pub fn new(executors: Vec<Box<dyn CapabilityExecutor>>) -> Self {
        Self { executors }
    }

    pub fn execute(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult> {
        let executor = self
            .executors
            .iter()
            .find(|candidate| candidate.supports(&request.capability))
            .ok_or_else(|| {
                CoreError::new("CAPABILITY_NOT_REGISTERED", request.capability.clone())
            })?;
        executor.execute(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_binding(
        &self,
        request: CapabilityRequest,
        binding: Option<&ProjectRunnerBinding>,
        session: Option<&RunnerSession>,
        grant: Option<&RunnerCapabilityGrant>,
        context: &BindingValidationContext,
        requested_path: &str,
        resolved_path: Option<&str>,
    ) -> CoreResult<CapabilityResult> {
        validate_session_and_grant_for_local_tool_call(
            binding,
            session,
            grant,
            context,
            &request.capability,
            requested_path,
            resolved_path,
        )?;
        self.execute(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_policy(
        &self,
        request: CapabilityRequest,
        binding: Option<&ProjectRunnerBinding>,
        session: Option<&RunnerSession>,
        grant: Option<&RunnerCapabilityGrant>,
        context: &BindingValidationContext,
        policy_engine: &PolicyEngine,
        policy_input: &PolicyEvaluationInput,
        requested_path: &str,
        resolved_path: Option<&str>,
    ) -> CoreResult<CapabilityResult> {
        validate_policy_input_matches_request(&request, policy_input, requested_path)?;
        validate_session_and_grant_for_local_tool_call(
            binding,
            session,
            grant,
            context,
            &request.capability,
            requested_path,
            resolved_path,
        )?;
        let binding = binding.ok_or_else(|| {
            CoreError::new(
                "PROJECT_BINDING_REQUIRED",
                "local tool call requires an active project runner binding",
            )
        })?;
        let evaluation = policy_engine.dry_run(policy_input, binding)?;
        enforce_policy_decision(&evaluation)?;
        self.execute(request)
    }
}

fn validate_policy_input_matches_request(
    request: &CapabilityRequest,
    policy_input: &PolicyEvaluationInput,
    requested_path: &str,
) -> CoreResult<()> {
    if policy_input.capability != request.capability {
        return Err(CoreError::new(
            "POLICY_CAPABILITY_MISMATCH",
            "policy input capability must match execution request capability",
        ));
    }
    let Some(policy_path) = &policy_input.requested_path else {
        return Err(CoreError::new(
            "POLICY_PATH_MISMATCH",
            "policy input path is required for path-bound execution",
        ));
    };
    if policy_path != requested_path {
        return Err(CoreError::new(
            "POLICY_PATH_MISMATCH",
            "policy input path must match execution request path",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{
        BindingRegistry, CreateBindingInput, RunnerCapabilityGrant, RunnerSession,
        RunnerSessionStatus,
    };
    use crate::policy::{
        PolicyDecision, PolicyEngine, PolicyEvaluationInput, PolicyLayer, PolicyRule, PolicySource,
    };
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct EchoExecutor;

    impl CapabilityExecutor for EchoExecutor {
        fn capability(&self) -> &'static str {
            "mock.echo"
        }

        fn execute(&self, request: CapabilityRequest) -> CoreResult<CapabilityResult> {
            Ok(CapabilityResult {
                capability: request.capability,
                output: request.input,
            })
        }
    }

    fn registry_with_binding() -> (BindingRegistry, ProjectRunnerBinding) {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(CreateBindingInput {
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_device_id: "device_123".to_string(),
                local_workspace_root: "/Users/example/app".to_string(),
                local_root_fingerprint: None,
                created_by: "user_123".to_string(),
                now_epoch_ms: 1_000,
                allow_same_path_different_project: false,
                project_archived: false,
                runner_disabled: false,
            })
            .unwrap();
        (registry, binding)
    }

    fn context() -> BindingValidationContext {
        BindingValidationContext {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            project_permission_active: true,
        }
    }

    fn session(binding: &ProjectRunnerBinding) -> RunnerSession {
        RunnerSession {
            id: "session_123".to_string(),
            organization_id: binding.organization_id.clone(),
            project_id: binding.project_id.clone(),
            runner_device_id: binding.runner_device_id.clone(),
            project_runner_binding_id: binding.id.clone(),
            status: RunnerSessionStatus::Connected,
            last_seen_at_epoch_ms: Some(1_000),
            lease_expires_at_epoch_ms: 31_000,
            connected_at_epoch_ms: 1_000,
            disconnected_at_epoch_ms: None,
            replaced_by_session_id: None,
            disconnect_reason: None,
        }
    }

    fn grant(binding: &ProjectRunnerBinding, capability: &str) -> RunnerCapabilityGrant {
        RunnerCapabilityGrant {
            project_runner_binding_id: binding.id.clone(),
            capability: capability.to_string(),
            granted_by: "policy_123".to_string(),
            created_at_epoch_ms: 1_000,
            revoked_at_epoch_ms: None,
        }
    }

    fn policy_input(capability: &str, requested_path: &str) -> PolicyEvaluationInput {
        let mut input = PolicyEvaluationInput::capability(capability);
        input.requested_path = Some(requested_path.to_string());
        input
    }

    fn recovery_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "loomex-execution-recovery-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn recoverable_job(replay_safety: JobReplaySafety) -> RecoverableRunnerJob {
        RecoverableRunnerJob {
            job_id: "job_123".to_string(),
            runner_id: "runner_123".to_string(),
            session_id: "session_old".to_string(),
            kind: "shell.exec".to_string(),
            idempotency_key: "job_123:terminal".to_string(),
            payload_fingerprint: "sha256:abc".to_string(),
            attempt_count: 1,
            lease_version: 1,
            leased_until_epoch_ms: 2_000,
            replay_safety,
            phase: RecoverableJobPhase::Leased,
            terminal_payload: None,
            updated_at_epoch_ms: 1_000,
        }
    }

    fn remote_job(
        session_id: Option<&str>,
        status: RemoteRunnerJobStatus,
        attempt_count: u32,
        leased_until_epoch_ms: Option<u64>,
    ) -> RemoteRunnerJobSnapshot {
        RemoteRunnerJobSnapshot {
            job_id: "job_123".to_string(),
            session_id: session_id.map(str::to_string),
            status,
            attempt_count,
            lease_version: u64::from(attempt_count),
            leased_until_epoch_ms,
            payload_fingerprint: "sha256:abc".to_string(),
        }
    }

    #[test]
    fn recovery_journal_durably_restores_a_running_job_after_process_restart() {
        let path = recovery_path("running");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::ManualReconciliation))
            .unwrap();
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();

        let reopened = RunnerJobRecoveryJournal::open(&path).unwrap();
        let restored = reopened.job("job_123").unwrap();
        assert_eq!(RecoverableJobPhase::Running, restored.phase);
        assert_eq!("session_old", restored.session_id);
        assert_eq!(1, restored.attempt_count);
        assert_eq!(None, restored.terminal_payload);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn lease_renewal_persists_the_advanced_fencing_version() {
        let path = recovery_path("renew-version");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::Idempotent))
            .unwrap();

        journal
            .renew_lease("job_123", "session_old", 2, 4_000, 1_500)
            .unwrap();
        let renewed = journal.job("job_123").unwrap();
        assert_eq!(2, renewed.lease_version);
        assert_eq!(4_000, renewed.leased_until_epoch_ms);

        let err = journal
            .renew_lease("job_123", "session_old", 2, 5_000, 2_000)
            .unwrap_err();
        assert_eq!("RUNNER_JOB_RECOVERY_LEASE_VERSION_MISMATCH", err.code);

        let reopened = RunnerJobRecoveryJournal::open(&path).unwrap();
        assert_eq!(2, reopened.job("job_123").unwrap().lease_version);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn completed_outcome_is_replayed_to_a_reclaimed_session_without_reexecution() {
        let path = recovery_path("outcome");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::ManualReconciliation))
            .unwrap();
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();
        journal
            .record_succeeded(
                "job_123",
                "session_old",
                json!({"exitCode": 0, "stdout": "ok\n"}),
                1_200,
            )
            .unwrap();

        // A daemon crash occurs here. The server atomically reclaims the expired job for a new
        // session and returns the next attempt in its lease response.
        let mut reopened = RunnerJobRecoveryJournal::open(&path).unwrap();
        let reclaimed = remote_job(
            Some("session_new"),
            RemoteRunnerJobStatus::Leased,
            2,
            Some(5_000),
        );
        let action = reopened
            .recovery_action("job_123", Some(&reclaimed), "session_new", 3_000)
            .unwrap();
        assert_eq!(
            JobRecoveryAction::SubmitSucceeded(json!({"exitCode": 0, "stdout": "ok\n"})),
            action
        );

        reopened
            .adopt_reclaimed_lease("job_123", &reclaimed, "session_new", 3_000)
            .unwrap();
        let adopted = RunnerJobRecoveryJournal::open(&path).unwrap();
        assert_eq!("session_new", adopted.job("job_123").unwrap().session_id);
        assert_eq!(2, adopted.job("job_123").unwrap().attempt_count);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interrupted_non_idempotent_running_job_requires_manual_reconciliation() {
        let path = recovery_path("non-idempotent");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::ManualReconciliation))
            .unwrap();
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();
        let reclaimed = remote_job(
            Some("session_new"),
            RemoteRunnerJobStatus::Leased,
            2,
            Some(5_000),
        );

        assert_eq!(
            JobRecoveryAction::ManualReconciliation {
                reason: "interrupted local execution was not declared idempotent"
            },
            journal
                .recovery_action("job_123", Some(&reclaimed), "session_new", 3_000)
                .unwrap()
        );
        journal
            .adopt_reclaimed_lease("job_123", &reclaimed, "session_new", 3_000)
            .unwrap();
        assert_eq!("session_new", journal.job("job_123").unwrap().session_id);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interrupted_idempotent_running_job_can_resume_only_after_server_reclaim() {
        let path = recovery_path("idempotent");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::Idempotent))
            .unwrap();
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();

        let old_lease = remote_job(
            Some("session_old"),
            RemoteRunnerJobStatus::Running,
            1,
            Some(2_000),
        );
        assert_eq!(
            JobRecoveryAction::WaitForLeaseExpiry {
                leased_until_epoch_ms: 2_000
            },
            journal
                .recovery_action("job_123", Some(&old_lease), "session_new", 1_500)
                .unwrap()
        );
        assert_eq!(
            JobRecoveryAction::RequestServerReclaim,
            journal
                .recovery_action("job_123", Some(&old_lease), "session_new", 2_001)
                .unwrap()
        );

        let reclaimed = remote_job(
            Some("session_new"),
            RemoteRunnerJobStatus::Leased,
            2,
            Some(5_000),
        );
        assert_eq!(
            JobRecoveryAction::ResumeIdempotentExecution,
            journal
                .recovery_action("job_123", Some(&reclaimed), "session_new", 3_000)
                .unwrap()
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminal_record_is_removed_only_after_server_ack() {
        let path = recovery_path("ack");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::ManualReconciliation))
            .unwrap();
        assert_eq!(
            "RUNNER_JOB_RECOVERY_INVALID_TRANSITION",
            journal.acknowledge_terminal("job_123").unwrap_err().code
        );
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();
        journal
            .record_failed(
                "job_123",
                "session_old",
                json!({"code": "COMMAND_FAILED"}),
                1_200,
            )
            .unwrap();
        assert!(RunnerJobRecoveryJournal::open(&path)
            .unwrap()
            .job("job_123")
            .is_some());

        journal.acknowledge_terminal("job_123").unwrap();
        assert!(RunnerJobRecoveryJournal::open(&path)
            .unwrap()
            .pending_jobs()
            .is_empty());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn server_terminal_state_cleans_up_a_pre_ack_crash_record() {
        let path = recovery_path("server-terminal");
        let mut journal = RunnerJobRecoveryJournal::open(&path).unwrap();
        journal
            .record_lease(recoverable_job(JobReplaySafety::ManualReconciliation))
            .unwrap();
        journal
            .mark_running("job_123", "session_old", 1_100)
            .unwrap();
        let terminal = remote_job(
            Some("session_old"),
            RemoteRunnerJobStatus::Succeeded,
            1,
            None,
        );

        assert_eq!(
            JobRecoveryAction::ForgetTerminal,
            journal
                .recovery_action("job_123", Some(&terminal), "session_new", 3_000)
                .unwrap()
        );
        journal
            .forget_server_terminal("job_123", &terminal)
            .unwrap();
        assert!(RunnerJobRecoveryJournal::open(&path)
            .unwrap()
            .pending_jobs()
            .is_empty());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupt_recovery_journal_fails_closed() {
        let path = recovery_path("corrupt");
        fs::write(&path, b"{not-json").unwrap();

        assert_eq!(
            "RUNNER_JOB_RECOVERY_CORRUPT",
            RunnerJobRecoveryJournal::open(&path).unwrap_err().code
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn execute_with_binding_runs_inside_active_binding() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);

        let result = registry
            .execute_with_binding(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant(&binding, "mock.echo")),
                &context(),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap();

        assert_eq!("ok", result.output);
    }

    #[test]
    fn execute_with_binding_blocks_missing_binding_before_local_tool_call() {
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);

        let err = registry
            .execute_with_binding(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                None,
                None,
                None,
                &context(),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap_err();

        assert_eq!("PROJECT_BINDING_REQUIRED", err.code);
    }

    #[test]
    fn execute_with_binding_blocks_revoked_grant_before_executor() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);
        let mut grant = grant(&binding, "mock.echo");
        grant.revoked_at_epoch_ms = Some(2_000);

        let err = registry
            .execute_with_binding(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant),
                &context(),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap_err();

        assert_eq!("RUNNER_CAPABILITY_GRANT_REVOKED", err.code);
    }

    #[test]
    fn execute_with_policy_requires_allow_decision_before_executor() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);
        let engine = PolicyEngine::new(vec![PolicyLayer {
            source: PolicySource::Project,
            default_decision: None,
            rules: vec![PolicyRule::for_capability(
                "mock.echo",
                PolicyDecision::Allow,
            )],
        }]);

        let result = registry
            .execute_with_policy(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant(&binding, "mock.echo")),
                &context(),
                &engine,
                &policy_input("mock.echo", "/Users/example/app/file.txt"),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap();

        assert_eq!("ok", result.output);
    }

    #[test]
    fn execute_with_policy_blocks_ask_decision_before_executor() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);
        let engine = PolicyEngine::default();

        let err = registry
            .execute_with_policy(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant(&binding, "mock.echo")),
                &context(),
                &engine,
                &policy_input("mock.echo", "/Users/example/app/file.txt"),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap_err();

        assert_eq!("POLICY_APPROVAL_REQUIRED", err.code);
    }

    #[test]
    fn execute_with_policy_rejects_mismatched_policy_capability_before_executor() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);
        let engine = PolicyEngine::new(vec![PolicyLayer {
            source: PolicySource::Project,
            default_decision: None,
            rules: vec![PolicyRule::for_capability(
                "git.status",
                PolicyDecision::Allow,
            )],
        }]);

        let err = registry
            .execute_with_policy(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant(&binding, "mock.echo")),
                &context(),
                &engine,
                &policy_input("git.status", "/Users/example/app/file.txt"),
                "/Users/example/app/file.txt",
                None,
            )
            .unwrap_err();

        assert_eq!("POLICY_CAPABILITY_MISMATCH", err.code);
    }

    #[test]
    fn execute_with_policy_rejects_missing_policy_path_before_executor() {
        let (_, binding) = registry_with_binding();
        let registry = ExecutionRegistry::new(vec![Box::new(EchoExecutor)]);
        let mut sensitive_rule = PolicyRule::for_capability("mock.echo", PolicyDecision::Deny);
        sensitive_rule.sensitive_path_pattern = Some(".env".to_string());
        let engine = PolicyEngine::new(vec![PolicyLayer {
            source: PolicySource::Project,
            default_decision: Some(PolicyDecision::Allow),
            rules: vec![sensitive_rule],
        }]);

        let err = registry
            .execute_with_policy(
                CapabilityRequest {
                    capability: "mock.echo".to_string(),
                    input: "ok".to_string(),
                },
                Some(&binding),
                Some(&session(&binding)),
                Some(&grant(&binding, "mock.echo")),
                &context(),
                &engine,
                &PolicyEvaluationInput::capability("mock.echo"),
                "/Users/example/app/.env",
                None,
            )
            .unwrap_err();

        assert_eq!("POLICY_PATH_MISMATCH", err.code);
    }
}
