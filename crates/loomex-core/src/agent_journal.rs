//! Durable, data-minimizing journal for local AI agent execution.
//!
//! The journal is deliberately separate from the process adapters. An integrator must:
//!
//! 1. call [`AgentExecutionJournal::claim_before_spawn`] and receive `Claimed` before spawning;
//! 2. durably record every state transition using the next progress sequence;
//! 3. call [`AgentExecutionJournal::checkpoint_initialized_session`] as soon as the provider
//!    exposes its session identity, before consuming more provider events;
//! 4. validate a continuation with [`AgentExecutionJournal::validate_resume`] before resume;
//! 5. turn a timeout or process loss after spawn into `indeterminate` with
//!    [`AgentExecutionJournal::mark_process_lost`].
//!
//! Prompt content, executable paths, credentials, environment values, raw provider stderr, and
//! arbitrary provider payloads are not represented by the persisted schema. Exact protocol output
//! exists only in a bounded pending-delivery slot until Backend acknowledgement. Protocol error
//! envelopes are canonicalized before persistence, including removal of caller-provided messages
//! and safe details. This file is an atomically replaced, explicitly bounded write-ahead document;
//! every mutating method fsyncs the replacement and its parent directory before returning.
//! Acknowledged immutable terminal entries are compacted into private, hash-addressed tombstones;
//! capacity exhaustion otherwise fails closed and never evicts idempotency fences.

use crate::{CoreError, CoreResult};
use loomex_protocol::agent_runtime_v2::{
    validate_agent_attempt_delivery_idempotency_key, validate_agent_attempt_task_idempotency_key,
    AgentAttemptRetryV2, AgentAttemptState, AgentErrorCode, AgentErrorContext,
    AgentExecutionBindingV2, AgentExecutionState, AgentExecutionV2, AgentProcessDeliveryV2,
    AgentProvider, AgentRemediationAction, AgentRetryDisposition, AgentRuntimeErrorEnvelopeV2,
    AgentSessionCheckpointV2, AgentSessionContinuationV2, AgentSessionState, ExecutorKind,
    AGENT_ERROR_SCHEMA_V2, AGENT_EXECUTION_SCHEMA_V2, MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION,
};
use loomex_protocol::{validate_agent_terminal_execution, AGENT_TERMINAL_EXECUTION_MAX_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION: &str = "loomex.agent-execution-journal/v1";
pub const AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION: &str = "loomex.agent-execution-tombstone/v1";

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PROGRESS_EVENTS: usize = 512;
const MAX_AGENT_TOMBSTONE_BYTES: u64 = 64 * 1024;
pub const MAX_AGENT_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_AGENT_JOURNAL_REQUESTS: usize = 1_024;
pub const MAX_AGENT_JOURNAL_ATTEMPTS_PER_REQUEST: usize = MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION;
pub const MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST: usize =
    MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION;
pub const MAX_AGENT_JOURNAL_PENDING_DELIVERIES: usize = 256;
/// Pending deliveries store the exact serialized `AgentExecutionV2`, so this bound must stay
/// aligned with the authoritative protocol limit instead of introducing a smaller journal-only
/// failure boundary.
pub const MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES: usize = AGENT_TERMINAL_EXECUTION_MAX_BYTES;

#[derive(Debug, Clone, PartialEq)]
pub struct AgentExecutionClaim {
    pub request_id: String,
    pub idempotency_key: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub retry_kind: loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2,
    pub from_attempt_id: Option<String>,
    pub delivery: loomex_protocol::agent_runtime_v2::AgentProcessDeliveryV2,
    pub task_idempotency_key: String,
    pub delivery_idempotency_key: String,
    /// Digest of the canonical v2 task with `continuation` removed. This immutable digest fences
    /// prompt/model/requirements/binding intent across all attempts for one request/key.
    pub task_intent_digest: String,
    /// Backend-authoritative digest of the complete canonical v2 request for this exact attempt.
    /// The canonical request itself must never be persisted.
    pub payload_digest: String,
    pub binding: AgentExecutionBindingV2,
    /// Durable ownership of every pending delivery for this logical execution.
    /// This fences the same request/idempotency pair from being claimed through
    /// both the direct HumanRequest and leased runner-job transports.
    pub delivery_route: AgentDeliveryRoute,
    pub execution: AgentExecutionV2,
    pub claimed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentExecutionClaimOutcome {
    /// The durable claim was created and fsynced. It is now safe for the caller to spawn.
    Claimed(AgentExecutionReplay),
    /// The same operation is already journaled. The caller must not spawn another process.
    Replay(AgentExecutionReplay),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentExecutionReplay {
    pub request_id: String,
    pub execution_id: String,
    pub state: AgentExecutionState,
    pub last_progress_sequence: u64,
    pub cancel_requested: bool,
    pub has_session_checkpoint: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentJournalProgressKind {
    Claimed,
    Probing,
    Starting,
    Running,
    Blocked,
    RepairingOutput,
    SessionCheckpointed,
    CancelRequested,
    Completed,
    Failed,
    Cancelled,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentJournalProgress {
    pub sequence: u64,
    pub kind: AgentJournalProgressKind,
    pub recorded_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProcessLoss {
    Timeout,
    Crash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentResumeExpectation {
    pub binding: AgentExecutionBindingV2,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    pub model_key: Option<String>,
    pub provider_model_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSessionCheckpointOutcome {
    Checkpointed,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelRequestOutcome {
    Requested,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPendingDeliveryKind {
    Checkpoint,
    Execution,
    /// Exact blocked execution retained until the owning runner job is durably deferred.
    Deferred,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "channel", rename_all = "snake_case")]
pub enum AgentDeliveryRoute {
    #[default]
    DirectHuman,
    RunnerJob {
        job_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        predecessor_job_id: Option<String>,
    },
}

/// Exact protocol payload awaiting authoritative Backend acknowledgement.
///
/// Unlike the data-minimized execution projection, this private `0600` journal field may
/// temporarily contain terminal output. It is removed immediately after an exact sequence ack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPendingDelivery {
    pub sequence: u64,
    pub kind: AgentPendingDeliveryKind,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionJournalEntry {
    pub request_id: String,
    pub idempotency_key: String,
    /// Immutable continuation-stripped task intent digest for this request/key.
    pub payload_digest: String,
    #[serde(default)]
    pub attempt_claims: Vec<PersistedAgentAttemptClaim>,
    pub binding: AgentExecutionBindingV2,
    #[serde(default)]
    pub delivery_route: AgentDeliveryRoute,
    pub execution_id: String,
    pub state: AgentExecutionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_attempt_id: Option<String>,
    #[serde(default)]
    pub attempts: Vec<PersistedAgentAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentRuntimeErrorEnvelopeV2>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    pub updated_at: String,
    pub claimed_at_epoch_ms: u64,
    pub last_progress_sequence: u64,
    #[serde(default)]
    pub progress: Vec<AgentJournalProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_checkpoint: Option<AgentSessionCheckpointV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation: Option<PersistedCancellation>,
    /// Fresh user-control operation key reserved before the Backend cancellation request.
    ///
    /// This is intentionally distinct from the runner cancellation acknowledgement key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_control_idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_delivery: Option<AgentPendingDelivery>,
    /// Present only after the exact terminal delivery was acknowledged. On the next durable
    /// compaction step this bulky entry is replaced by an immutable archive tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_delivery_acknowledged_sequence: Option<u64>,
}

/// Minimal immutable replay/conflict fence retained after terminal acknowledgement.
///
/// Prompt/output/provider diagnostics, local paths, credentials and session payloads are
/// deliberately excluded. Tombstones are stored as private hash-addressed records outside the
/// bounded active journal so normal long-running use cannot exhaust the active-entry cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionTombstone {
    pub schema_version: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub task_intent_digest: String,
    pub attempt_claims: Vec<PersistedAgentAttemptClaim>,
    pub binding: AgentExecutionBindingV2,
    pub delivery_route: AgentDeliveryRoute,
    pub execution_id: String,
    pub terminal_state: AgentExecutionState,
    pub terminal_sequence: u64,
    pub terminal_delivery_acknowledged_sequence: u64,
    pub has_session_checkpoint: bool,
    /// Retained only to replay/conflict-fence an acknowledged cancellation request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_idempotency_key: Option<String>,
    /// Retained so a lost user-control response can be replayed after terminal compaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_control_idempotency_key: Option<String>,
    /// Tombstones are created only when no protocol transition can resume the execution.
    pub resumable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedAgentAttemptClaim {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub retry_kind: loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_attempt_id: Option<String>,
    pub delivery: loomex_protocol::agent_runtime_v2::AgentProcessDeliveryV2,
    pub task_idempotency_key: String,
    pub delivery_idempotency_key: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedAgentAttempt {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub task_idempotency_key: String,
    pub delivery_idempotency_key: String,
    pub payload_digest: String,
    pub state: AgentAttemptState,
    pub started_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_sequence: Option<u64>,
    pub selection_index: u32,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_model_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_provider_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_model_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_provider_model_id: Option<String>,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Per-attempt immutable checkpoint history. `session_checkpoint` on the entry remains the
    /// current resumable checkpoint, while this field preserves predecessor proof across retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<AgentSessionCheckpointV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<AgentAttemptRetryV2>,
    pub delivery: AgentProcessDeliveryV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentRuntimeErrorEnvelopeV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedCancellation {
    pub idempotency_key: String,
    pub requested_at_epoch_ms: u64,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_directive: Option<PersistedRunnerCancellationDirective>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedRunnerCancellationDirective {
    pub cancellation_id: String,
    pub job_id: String,
    pub process_attempt_id: String,
    pub lease_version: u64,
    pub binding_generation: u64,
    pub requested_at: String,
    #[serde(default)]
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentExecutionJournalDocument {
    schema_version: String,
    entries: Vec<AgentExecutionJournalEntry>,
}

#[derive(Debug, Clone)]
pub struct AgentExecutionJournal {
    path: PathBuf,
    document: AgentExecutionJournalDocument,
}

impl AgentExecutionJournal {
    pub fn open(path: impl Into<PathBuf>) -> CoreResult<Self> {
        let path = path.into();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                None
            }
            Err(error) => {
                return Err(journal_error(
                    "AGENT_JOURNAL_READ_FAILED",
                    &format!("failed to inspect durable agent journal: {error}"),
                ))
            }
        };
        let document = if let Some(metadata) = metadata {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(journal_error(
                    "AGENT_JOURNAL_INSECURE",
                    "durable agent journal must be a regular non-symlink file",
                ));
            }
            validate_owned_regular_file(&metadata)?;
            if metadata.len() > MAX_AGENT_JOURNAL_BYTES {
                return Err(journal_capacity_error(
                    "durable agent journal exceeds its maximum file size",
                ));
            }
            ensure_private_permissions(&path)?;
            let bytes = fs::read(&path).map_err(|error| {
                journal_error(
                    "AGENT_JOURNAL_READ_FAILED",
                    &format!("failed to read durable agent journal: {error}"),
                )
            })?;
            let document: AgentExecutionJournalDocument =
                serde_json::from_slice(&bytes).map_err(|_| {
                    journal_error(
                        "AGENT_JOURNAL_CORRUPT",
                        "durable agent journal is not valid JSON",
                    )
                })?;
            validate_document(&document)?;
            document
        } else {
            AgentExecutionJournalDocument {
                schema_version: AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION.to_string(),
                entries: Vec::new(),
            }
        };
        let mut journal = Self { path, document };
        journal.validate_tombstone_storage()?;
        journal.compact_acknowledged_terminal_entries()?;
        Ok(journal)
    }

    pub fn entries(&self) -> &[AgentExecutionJournalEntry] {
        &self.document.entries
    }

    pub fn entry(&self, request_id: &str) -> Option<&AgentExecutionJournalEntry> {
        self.document
            .entries
            .iter()
            .find(|entry| entry.request_id == request_id)
    }

    pub fn tombstone(&self, request_id: &str) -> CoreResult<Option<AgentExecutionTombstone>> {
        self.read_tombstone_index(TombstoneIndexKind::Request, request_id)
    }

    pub fn pending_delivery(&self, request_id: &str) -> CoreResult<Option<&AgentPendingDelivery>> {
        if let Some(entry) = self.entry(request_id) {
            return Ok(entry.pending_delivery.as_ref());
        }
        if self.tombstone(request_id)?.is_some() {
            return Ok(None);
        }
        Err(journal_error(
            "AGENT_JOURNAL_NOT_FOUND",
            "agent execution journal entry was not found",
        ))
    }

    /// Removes an exact pending payload only after the Backend acknowledges its sequence.
    pub fn acknowledge_delivery(&mut self, request_id: &str, sequence: u64) -> CoreResult<()> {
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        let pending = entry.pending_delivery.as_ref().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_DELIVERY_NOT_FOUND",
                "agent execution has no pending protocol delivery",
            )
        })?;
        if pending.sequence != sequence {
            return Err(journal_error(
                "AGENT_JOURNAL_DELIVERY_SEQUENCE_MISMATCH",
                "delivery acknowledgement does not match the exact pending sequence",
            ));
        }
        let terminal = is_immutable_terminal_entry(entry);
        let previous = self.document.clone();
        self.document.entries[index].pending_delivery = None;
        if terminal {
            self.document.entries[index].terminal_delivery_acknowledged_sequence = Some(sequence);
        }
        self.persist_or_recover(previous)?;
        if terminal {
            self.compact_terminal_entry(index)?;
        }
        Ok(())
    }

    /// Creates the durable idempotency claim that must happen before process spawn.
    pub fn claim_before_spawn(
        &mut self,
        claim: AgentExecutionClaim,
    ) -> CoreResult<AgentExecutionClaimOutcome> {
        validate_claim(&claim)?;
        let normalized_intent_digest = normalize_payload_digest(&claim.task_intent_digest)?;
        let normalized_payload_digest = normalize_payload_digest(&claim.payload_digest)?;

        if let Some(index) = self.document.entries.iter().position(|entry| {
            entry.request_id == claim.request_id || entry.idempotency_key == claim.idempotency_key
        }) {
            let existing = &self.document.entries[index];
            let route_handoff = matches!(
                (&existing.delivery_route, &claim.delivery_route),
                (
                    AgentDeliveryRoute::RunnerJob {
                        job_id: predecessor_job_id,
                        ..
                    },
                    AgentDeliveryRoute::RunnerJob {
                        job_id: successor_job_id,
                        predecessor_job_id: Some(claimed_predecessor_job_id),
                    }
                ) if successor_job_id != predecessor_job_id
                    && claimed_predecessor_job_id == predecessor_job_id
            ) && matches!(
                existing.state,
                AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
            ) && existing.pending_delivery.is_none();
            if existing.request_id == claim.request_id
                && existing.idempotency_key == claim.idempotency_key
                && existing.binding == claim.binding
                && existing.execution_id == claim.execution.execution_id
            {
                if existing.payload_digest != normalized_intent_digest {
                    return Err(journal_error(
                        "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                        "request intent changed for an existing request or idempotency key",
                    ));
                }
                if let Some(attempt_claim) = existing
                    .attempt_claims
                    .iter()
                    .find(|attempt| attempt.task_idempotency_key == claim.task_idempotency_key)
                {
                    if attempt_claim.attempt_id == claim.attempt_id
                        && attempt_claim.attempt_number == claim.attempt_number
                        && attempt_claim.retry_kind == claim.retry_kind
                        && attempt_claim.from_attempt_id == claim.from_attempt_id
                        && attempt_claim.delivery == claim.delivery
                        && attempt_claim.task_idempotency_key == claim.task_idempotency_key
                        && attempt_claim.delivery_idempotency_key == claim.delivery_idempotency_key
                        && attempt_claim.payload_digest == normalized_payload_digest
                    {
                        return Ok(AgentExecutionClaimOutcome::Replay(existing.replay()));
                    }
                    return Err(journal_error(
                        "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                        "attempt id is already claimed with a different authoritative payload digest",
                    ));
                }
                let previous_attempt_id = existing
                    .attempt_claims
                    .last()
                    .map(|attempt| attempt.attempt_id.as_str());
                let retry_state_is_valid = match claim.retry_kind {
                    loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial => false,
                    loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::FreshAfterRemediation => {
                        existing.state == AgentExecutionState::Blocked
                            && existing.session_checkpoint.is_none()
                    }
                    loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::ResumeFromCheckpoint => {
                        matches!(
                            existing.state,
                            AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
                        ) && existing.session_checkpoint.is_some()
                    }
                };
                let delivery_handoff_is_valid = route_handoff
                    || matches!(
                        (&existing.delivery_route, &claim.delivery_route),
                        (
                            AgentDeliveryRoute::DirectHuman,
                            AgentDeliveryRoute::DirectHuman
                        )
                    );
                if existing.pending_delivery.is_some()
                    || !retry_state_is_valid
                    || !delivery_handoff_is_valid
                    || claim.from_attempt_id.as_deref() != previous_attempt_id
                {
                    return Err(journal_error(
                        "AGENT_JOURNAL_RETRY_NOT_ALLOWED",
                        "fresh process attempt requires an exact durable predecessor, retry mode, and delivery handoff",
                    ));
                }
                if existing.attempt_claims.len() >= MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST {
                    return Err(journal_capacity_error(
                        "agent execution reached its maximum durable attempt claims",
                    ));
                }
                let expected_attempt_number = u32::try_from(existing.attempt_claims.len() + 1)
                    .map_err(|_| {
                        journal_error(
                            "AGENT_JOURNAL_ATTEMPT_EXHAUSTED",
                            "agent process attempt number is exhausted",
                        )
                    })?;
                if claim.attempt_number != expected_attempt_number
                    || existing.attempt_claims.iter().any(|attempt| {
                        attempt.task_idempotency_key == claim.task_idempotency_key
                            || attempt.delivery_idempotency_key == claim.delivery_idempotency_key
                            || attempt.payload_digest == normalized_payload_digest
                    })
                {
                    return Err(journal_error(
                        "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                        "process attempt identity is not unique and contiguous",
                    ));
                }
                let previous = self.document.clone();
                let entry = &mut self.document.entries[index];
                entry.delivery_route = claim.delivery_route;
                entry.attempt_claims.push(PersistedAgentAttemptClaim {
                    attempt_id: claim.attempt_id,
                    attempt_number: claim.attempt_number,
                    retry_kind: claim.retry_kind,
                    from_attempt_id: claim.from_attempt_id,
                    delivery: claim.delivery,
                    task_idempotency_key: claim.task_idempotency_key,
                    delivery_idempotency_key: claim.delivery_idempotency_key,
                    payload_digest: normalized_payload_digest,
                });
                self.persist_or_recover(previous)?;
                return Ok(AgentExecutionClaimOutcome::Claimed(
                    self.document.entries[index].replay(),
                ));
            }
            return Err(journal_error(
                "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                "request or idempotency key is already claimed with different immutable input",
            ));
        }

        if let Some(tombstone) =
            self.find_tombstone_conflict(&claim.request_id, &claim.idempotency_key)?
        {
            let exact_logical_identity = tombstone.request_id == claim.request_id
                && tombstone.idempotency_key == claim.idempotency_key
                && tombstone.execution_id == claim.execution.execution_id
                && tombstone.binding == claim.binding
                && tombstone.task_intent_digest == normalized_intent_digest;
            let exact_process = tombstone.attempt_claims.iter().any(|attempt| {
                attempt.attempt_id == claim.attempt_id
                    && attempt.attempt_number == claim.attempt_number
                    && attempt.retry_kind == claim.retry_kind
                    && attempt.from_attempt_id == claim.from_attempt_id
                    && attempt.delivery == claim.delivery
                    && attempt.task_idempotency_key == claim.task_idempotency_key
                    && attempt.delivery_idempotency_key == claim.delivery_idempotency_key
                    && attempt.payload_digest == normalized_payload_digest
            });
            if exact_logical_identity && exact_process {
                return Ok(AgentExecutionClaimOutcome::Replay(tombstone.replay()));
            }
            return Err(journal_error(
                "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                "request or process identity conflicts with an archived execution",
            ));
        }

        if self.document.entries.len() >= MAX_AGENT_JOURNAL_REQUESTS {
            return Err(journal_capacity_error(
                "durable agent journal reached its maximum request entries",
            ));
        }
        if claim.attempt_number != 1 {
            return Err(journal_error(
                "AGENT_JOURNAL_CLAIM_INVALID",
                "the first process attempt number must be one",
            ));
        }
        if matches!(
            &claim.delivery_route,
            AgentDeliveryRoute::RunnerJob {
                predecessor_job_id: Some(_),
                ..
            }
        ) {
            return Err(journal_error(
                "AGENT_JOURNAL_CLAIM_INVALID",
                "the first runner job process attempt cannot name a predecessor job",
            ));
        }
        let mut entry = persisted_entry_from_execution(
            &claim.execution,
            claim.idempotency_key,
            normalized_intent_digest,
            claim.claimed_at_epoch_ms,
        )?;
        entry.delivery_route = claim.delivery_route;
        entry.attempt_claims.push(PersistedAgentAttemptClaim {
            attempt_id: claim.attempt_id,
            attempt_number: claim.attempt_number,
            retry_kind: claim.retry_kind,
            from_attempt_id: claim.from_attempt_id,
            delivery: claim.delivery,
            task_idempotency_key: claim.task_idempotency_key,
            delivery_idempotency_key: claim.delivery_idempotency_key,
            payload_digest: normalized_payload_digest,
        });
        entry.last_progress_sequence = 1;
        entry.progress.push(AgentJournalProgress {
            sequence: 1,
            kind: AgentJournalProgressKind::Claimed,
            recorded_at_epoch_ms: claim.claimed_at_epoch_ms,
        });
        entry.pending_delivery = Some(AgentPendingDelivery {
            sequence: 1,
            kind: AgentPendingDeliveryKind::Execution,
            payload: serde_json::to_value(&claim.execution).map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "queued execution could not be serialized for durable delivery",
                )
            })?,
        });
        validate_new_pending_delivery_capacity(
            &self.document,
            entry.pending_delivery.as_ref().ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                    "queued execution delivery was not attached to its durable claim",
                )
            })?,
        )?;
        let previous = self.document.clone();
        self.document.entries.push(entry);
        self.persist_or_recover(previous)?;
        let created = self
            .document
            .entries
            .iter()
            .find(|entry| entry.request_id == claim.request_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_COMMIT_INCONSISTENT",
                    "durable claim committed without its execution entry",
                )
            })?;
        Ok(AgentExecutionClaimOutcome::Claimed(created.replay()))
    }

    /// Persists a protocol execution transition while retaining only pathless metadata.
    ///
    /// Any session checkpoint present in `execution` must have been persisted separately first;
    /// this prevents a terminal state from being the first durable appearance of a session.
    pub fn record_execution(
        &mut self,
        request_id: &str,
        sequence: u64,
        execution: &AgentExecutionV2,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<()> {
        self.record_execution_internal(request_id, sequence, execution, recorded_at_epoch_ms, None)
    }

    /// Atomically persists an externally visible execution phase and its exact protocol payload.
    pub fn record_execution_with_delivery(
        &mut self,
        request_id: &str,
        sequence: u64,
        execution: &AgentExecutionV2,
        delivery_payload: Value,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<()> {
        if execution.state == AgentExecutionState::Queued {
            return Err(journal_error(
                "AGENT_JOURNAL_DELIVERY_INVALID",
                "queued delivery is created atomically with its durable claim",
            ));
        }
        validate_agent_terminal_execution(execution).map_err(|_| {
            journal_error(
                "AGENT_TERMINAL_EXECUTION_TOO_LARGE",
                "terminal agent execution exceeds the bounded durable-delivery limit",
            )
        })?;
        validate_execution_delivery(execution, &delivery_payload)?;
        self.record_execution_internal(
            request_id,
            sequence,
            execution,
            recorded_at_epoch_ms,
            Some(AgentPendingDelivery {
                sequence,
                kind: match execution.state {
                    AgentExecutionState::Blocked => AgentPendingDeliveryKind::Deferred,
                    state if state.is_terminal() => AgentPendingDeliveryKind::Terminal,
                    _ => AgentPendingDeliveryKind::Execution,
                },
                payload: delivery_payload,
            }),
        )
    }

    fn record_execution_internal(
        &mut self,
        request_id: &str,
        sequence: u64,
        execution: &AgentExecutionV2,
        recorded_at_epoch_ms: u64,
        pending_delivery: Option<AgentPendingDelivery>,
    ) -> CoreResult<()> {
        execution.validate().map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_EXECUTION_INVALID",
                "agent execution v2 envelope failed validation",
            )
        })?;
        let index = self.entry_index(request_id)?;
        let current = &self.document.entries[index];
        validate_next_sequence(current, sequence)?;
        if execution.sequence != sequence {
            return Err(journal_error(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "execution envelope sequence does not match its journal transition",
            ));
        }
        validate_execution_identity(current, execution)?;
        validate_attempt_history(current, execution)?;
        validate_transition(current.state, execution.state)?;
        ensure_no_pending_delivery(current)?;
        if let Some(delivery) = pending_delivery.as_ref() {
            validate_new_pending_delivery_capacity(&self.document, delivery)?;
        }

        if execution
            .attempts
            .iter()
            .filter_map(|attempt| attempt.session.as_ref())
            .any(|checkpoint| {
                current
                    .attempts
                    .iter()
                    .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
                    .and_then(|attempt| attempt.session.as_ref())
                    .or_else(|| {
                        current
                            .session_checkpoint
                            .as_ref()
                            .filter(|current| current.attempt_id == checkpoint.attempt_id)
                    })
                    != Some(checkpoint)
            })
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CHECKPOINT_REQUIRED",
                "session checkpoint must be durably recorded before the execution transition",
            ));
        }

        let preserved_checkpoint = current.session_checkpoint.clone();
        let preserved_cancellation = current.cancellation.clone();
        let preserved_cancellation_control_idempotency_key =
            current.cancellation_control_idempotency_key.clone();
        let preserved_attempt_claims = current.attempt_claims.clone();
        let idempotency_key = current.idempotency_key.clone();
        let payload_digest = current.payload_digest.clone();
        let claimed_at_epoch_ms = current.claimed_at_epoch_ms;
        let mut progress = current.progress.clone();
        let kind = progress_kind_for_execution(execution)?;
        progress.push(AgentJournalProgress {
            sequence,
            kind,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut progress);

        let mut replacement = persisted_entry_from_execution(
            execution,
            idempotency_key,
            payload_digest,
            claimed_at_epoch_ms,
        )?;
        replacement.last_progress_sequence = sequence;
        replacement.progress = progress;
        replacement.session_checkpoint = preserved_checkpoint;
        replacement.cancellation = preserved_cancellation;
        replacement.cancellation_control_idempotency_key =
            preserved_cancellation_control_idempotency_key;
        replacement.attempt_claims = preserved_attempt_claims;
        replacement.delivery_route = current.delivery_route.clone();
        replacement.pending_delivery = pending_delivery;
        let previous = self.document.clone();
        self.document.entries[index] = replacement;
        self.persist_or_recover(previous)
    }

    /// Persists the first provider session identity immediately after initialization.
    pub fn checkpoint_initialized_session(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        self.checkpoint_initialized_session_internal(
            request_id,
            sequence,
            checkpoint,
            recorded_at_epoch_ms,
            None,
        )
    }

    /// Atomically persists the initialized session and exact checkpoint protocol payload.
    pub fn checkpoint_initialized_session_with_delivery(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        delivery_payload: Value,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        validate_checkpoint_delivery(&checkpoint, &delivery_payload)?;
        self.checkpoint_initialized_session_internal(
            request_id,
            sequence,
            checkpoint,
            recorded_at_epoch_ms,
            Some(AgentPendingDelivery {
                sequence,
                kind: AgentPendingDeliveryKind::Checkpoint,
                payload: delivery_payload,
            }),
        )
    }

    fn checkpoint_initialized_session_internal(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        recorded_at_epoch_ms: u64,
        pending_delivery: Option<AgentPendingDelivery>,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        checkpoint.validate().map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_CHECKPOINT_INVALID",
                "agent session checkpoint v2 failed validation",
            )
        })?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];

        if let Some(existing) = &entry.session_checkpoint {
            if existing == &checkpoint {
                validate_replayed_delivery(entry, pending_delivery.as_ref())?;
                return Ok(AgentSessionCheckpointOutcome::Replay);
            }
            return Err(journal_error(
                "AGENT_JOURNAL_CHECKPOINT_CONFLICT",
                "a different provider session is already checkpointed",
            ));
        }
        ensure_no_pending_delivery(entry)?;
        if let Some(delivery) = pending_delivery.as_ref() {
            validate_new_pending_delivery_capacity(&self.document, delivery)?;
        }
        validate_next_sequence(entry, sequence)?;
        if checkpoint.sequence != sequence {
            return Err(journal_error(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "checkpoint sequence does not match its journal transition",
            ));
        }
        let mut prospective = entry.clone();
        let prospective_attempt = prospective
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
                    "session checkpoint attempt is not durable",
                )
            })?;
        prospective_attempt.executor = checkpoint.executor;
        prospective_attempt.provider = checkpoint.provider;
        prospective_attempt.resolved_model_key = checkpoint.model_key.clone();
        prospective_attempt.resolved_provider_model_id = checkpoint.provider_model_id.clone();
        validate_checkpoint_identity(&prospective, &checkpoint, true)?;

        let previous = self.document.clone();
        let entry = &mut self.document.entries[index];
        let attempt = entry
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
                    "session checkpoint attempt is not durable",
                )
            })?;
        attempt.executor = checkpoint.executor;
        attempt.provider = checkpoint.provider;
        attempt.resolved_model_key = checkpoint.model_key.clone();
        attempt.resolved_provider_model_id = checkpoint.provider_model_id.clone();
        attempt.session = Some(checkpoint.clone());
        entry.session_checkpoint = Some(checkpoint);
        entry.pending_delivery = pending_delivery;
        entry.last_progress_sequence = sequence;
        entry.progress.push(AgentJournalProgress {
            sequence,
            kind: AgentJournalProgressKind::SessionCheckpointed,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut entry.progress);
        self.persist_or_recover(previous)?;
        Ok(AgentSessionCheckpointOutcome::Checkpointed)
    }

    /// Requires continuation, binding, executor, provider, and exact model identity to match the
    /// durable checkpoint. No implicit session replacement or model fallback is permitted.
    pub fn validate_resume(
        &self,
        request_id: &str,
        continuation: &AgentSessionContinuationV2,
        expected: &AgentResumeExpectation,
    ) -> CoreResult<()> {
        validate_binding(&expected.binding)?;
        validate_optional_model_identity(&expected.model_key, &expected.provider_model_id)?;
        if expected.executor.provider() != expected.provider {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_MISMATCH",
                "resume executor and provider do not match",
            ));
        }
        let entry = self.entry(request_id).ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found",
            )
        })?;
        let checkpoint = entry.session_checkpoint.as_ref().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_SESSION_NOT_FOUND",
                "no durable provider session checkpoint exists",
            )
        })?;
        if !executor_supports_continuation(checkpoint.executor) {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_UNSUPPORTED",
                "the durable agent executor does not support session continuation",
            ));
        }
        let durable_continuation = AgentSessionContinuationV2::from(checkpoint);
        if continuation != &durable_continuation
            || expected.binding != entry.binding
            || expected.binding != checkpoint.binding
            || expected.executor != checkpoint.executor
            || expected.provider != checkpoint.provider
            || expected.model_key != checkpoint.model_key
            || expected.provider_model_id != checkpoint.provider_model_id
        {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_MISMATCH",
                "resume requires the exact durable session, binding, executor, provider, and model",
            ));
        }
        Ok(())
    }

    /// Reopens an indeterminate execution for one exact, checkpoint-bound resume attempt.
    ///
    /// This is intentionally narrower than [`Self::record_execution`]: terminal executions
    /// normally never transition. The only exception is an `indeterminate` execution whose
    /// durable provider session is resumed with a newly appended attempt. Callers must invoke
    /// [`Self::validate_resume`] first using the request continuation.
    pub fn reopen_indeterminate_for_resume(
        &mut self,
        request_id: &str,
        sequence: u64,
        execution: &AgentExecutionV2,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<()> {
        execution.validate().map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_EXECUTION_INVALID",
                "resumed agent execution v2 envelope failed validation",
            )
        })?;
        let index = self.entry_index(request_id)?;
        let current = &self.document.entries[index];
        validate_next_sequence(current, sequence)?;
        if execution.sequence != sequence {
            return Err(journal_error(
                "AGENT_JOURNAL_SEQUENCE_MISMATCH",
                "resumed execution sequence does not match its journal transition",
            ));
        }
        validate_execution_identity(current, execution)?;
        validate_attempt_history(current, execution)?;
        ensure_no_pending_delivery(current)?;
        if !matches!(
            current.state,
            AgentExecutionState::Blocked | AgentExecutionState::Indeterminate
        ) || current.session_checkpoint.is_none()
            || current.cancellation.is_some()
        {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_NOT_ALLOWED",
                "only an uncancelled blocked or indeterminate execution with a durable session can resume",
            ));
        }
        if execution.state != AgentExecutionState::Running
            || execution.output.is_some()
            || execution.error.is_some()
            || execution.finished_at.is_some()
            || execution.created_at != current.created_at
            || execution.started_at != current.started_at
            || execution.attempts.len() != current.attempts.len() + 1
        {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_INVALID",
                "resume must append exactly one active starting attempt to the durable execution",
            ));
        }

        let checkpoint = current.session_checkpoint.as_ref().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_SESSION_NOT_FOUND",
                "resume requires a durable provider session checkpoint",
            )
        })?;
        if !executor_supports_continuation(checkpoint.executor) {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_UNSUPPORTED",
                "the durable agent executor does not support session continuation",
            ));
        }
        let resumed_attempt = execution.attempts.last().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_RESUME_INVALID",
                "resume did not append an active attempt",
            )
        })?;
        let expected_attempt_number = current
            .attempts
            .iter()
            .map(|attempt| attempt.attempt_number)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_ATTEMPT_EXHAUSTED",
                    "agent attempt number is exhausted",
                )
            })?;
        if execution.active_attempt_id.as_deref() != Some(resumed_attempt.attempt_id.as_str())
            || resumed_attempt.attempt_number != expected_attempt_number
            || resumed_attempt.state != AgentAttemptState::Starting
            || resumed_attempt.executor != checkpoint.executor
            || resumed_attempt.provider != checkpoint.provider
            || resumed_attempt.requested_model_key != checkpoint.model_key
            || resumed_attempt.requested_provider_model_id != checkpoint.provider_model_id
            || resumed_attempt.resolved_model_key != checkpoint.model_key
            || resumed_attempt.resolved_provider_model_id != checkpoint.provider_model_id
            || resumed_attempt.finished_at.is_some()
            || resumed_attempt.session.is_some()
            || resumed_attempt.error.is_some()
        {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_MISMATCH",
                "resume attempt must use the exact durable executor, provider, and model",
            ));
        }

        let preserved_checkpoint = current.session_checkpoint.clone();
        let preserved_cancellation = current.cancellation.clone();
        let preserved_cancellation_control_idempotency_key =
            current.cancellation_control_idempotency_key.clone();
        let preserved_attempt_claims = current.attempt_claims.clone();
        let idempotency_key = current.idempotency_key.clone();
        let payload_digest = current.payload_digest.clone();
        let claimed_at_epoch_ms = current.claimed_at_epoch_ms;
        let mut progress = current.progress.clone();
        let mut replacement = persisted_entry_from_execution(
            execution,
            idempotency_key,
            payload_digest,
            claimed_at_epoch_ms,
        )?;
        if replacement.attempts[..current.attempts.len()] != current.attempts {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_HISTORY_MISMATCH",
                "resume cannot rewrite durable attempt history",
            ));
        }
        progress.push(AgentJournalProgress {
            sequence,
            kind: AgentJournalProgressKind::Starting,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut progress);
        replacement.last_progress_sequence = sequence;
        replacement.progress = progress;
        replacement.session_checkpoint = preserved_checkpoint;
        replacement.delivery_route = current.delivery_route.clone();
        replacement.cancellation = preserved_cancellation;
        replacement.cancellation_control_idempotency_key =
            preserved_cancellation_control_idempotency_key;
        replacement.attempt_claims = preserved_attempt_claims;
        replacement.pending_delivery = Some(AgentPendingDelivery {
            sequence,
            kind: AgentPendingDeliveryKind::Execution,
            payload: serde_json::to_value(execution).map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "resumed running execution could not be serialized for durable delivery",
                )
            })?,
        });
        let previous = self.document.clone();
        self.document.entries[index] = replacement;
        self.persist_or_recover(previous)
    }

    /// Advances the durable checkpoint to the new attempt after an exact resume.
    ///
    /// The provider session identity is immutable. Only the checkpoint/attempt identity,
    /// monotonic sequence, timestamp, and session state may advance.
    pub fn checkpoint_resumed_session(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        self.checkpoint_resumed_session_internal(
            request_id,
            sequence,
            checkpoint,
            recorded_at_epoch_ms,
            None,
        )
    }

    /// Atomically advances a resumed session and records its exact checkpoint delivery payload.
    pub fn checkpoint_resumed_session_with_delivery(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        delivery_payload: Value,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        validate_checkpoint_delivery(&checkpoint, &delivery_payload)?;
        self.checkpoint_resumed_session_internal(
            request_id,
            sequence,
            checkpoint,
            recorded_at_epoch_ms,
            Some(AgentPendingDelivery {
                sequence,
                kind: AgentPendingDeliveryKind::Checkpoint,
                payload: delivery_payload,
            }),
        )
    }

    fn checkpoint_resumed_session_internal(
        &mut self,
        request_id: &str,
        sequence: u64,
        checkpoint: AgentSessionCheckpointV2,
        recorded_at_epoch_ms: u64,
        pending_delivery: Option<AgentPendingDelivery>,
    ) -> CoreResult<AgentSessionCheckpointOutcome> {
        checkpoint.validate().map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_CHECKPOINT_INVALID",
                "resumed agent session checkpoint v2 failed validation",
            )
        })?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        let existing = entry.session_checkpoint.as_ref().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_SESSION_NOT_FOUND",
                "no durable provider session checkpoint exists",
            )
        })?;
        if existing == &checkpoint {
            validate_replayed_delivery(entry, pending_delivery.as_ref())?;
            return Ok(AgentSessionCheckpointOutcome::Replay);
        }
        ensure_no_pending_delivery(entry)?;
        if let Some(delivery) = pending_delivery.as_ref() {
            validate_new_pending_delivery_capacity(&self.document, delivery)?;
        }
        validate_next_sequence(entry, sequence)?;
        validate_checkpoint_identity(entry, &checkpoint, true)?;
        if existing.provider_session_id != checkpoint.provider_session_id
            || existing.session_id != checkpoint.session_id
            || existing.binding != checkpoint.binding
            || existing.execution_id != checkpoint.execution_id
            || existing.executor != checkpoint.executor
            || existing.provider != checkpoint.provider
            || existing.model_key != checkpoint.model_key
            || existing.provider_model_id != checkpoint.provider_model_id
            || checkpoint.sequence <= existing.sequence
        {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_MISMATCH",
                "resumed checkpoint must preserve the exact durable provider session and model",
            ));
        }

        let previous = self.document.clone();
        let entry = &mut self.document.entries[index];
        let attempt = entry
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
                    "resumed session checkpoint attempt is not durable",
                )
            })?;
        attempt.session = Some(checkpoint.clone());
        entry.session_checkpoint = Some(checkpoint);
        entry.pending_delivery = pending_delivery;
        entry.last_progress_sequence = sequence;
        entry.progress.push(AgentJournalProgress {
            sequence,
            kind: AgentJournalProgressKind::SessionCheckpointed,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut entry.progress);
        self.persist_or_recover(previous)?;
        Ok(AgentSessionCheckpointOutcome::Checkpointed)
    }

    pub fn request_cancel(
        &mut self,
        request_id: &str,
        _sequence: u64,
        cancellation_idempotency_key: &str,
        requested_at_epoch_ms: u64,
    ) -> CoreResult<CancelRequestOutcome> {
        validate_safe_identity("cancellation idempotency key", cancellation_idempotency_key)?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        if let Some(existing) = &entry.cancellation {
            if existing.idempotency_key == cancellation_idempotency_key {
                return Ok(CancelRequestOutcome::Replay);
            }
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_CONFLICT",
                "a different cancellation request is already durable",
            ));
        }
        if entry.state.is_terminal() {
            return Err(journal_error(
                "AGENT_JOURNAL_ALREADY_TERMINAL",
                "terminal agent execution cannot be cancelled",
            ));
        }
        let previous = self.document.clone();
        let entry = &mut self.document.entries[index];
        entry.cancellation = Some(PersistedCancellation {
            idempotency_key: cancellation_idempotency_key.to_string(),
            requested_at_epoch_ms,
            sequence: entry.last_progress_sequence,
            runner_directive: None,
        });
        self.persist_or_recover(previous)?;
        Ok(CancelRequestOutcome::Requested)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_runner_cancel(
        &mut self,
        request_id: &str,
        cancellation_idempotency_key: &str,
        cancellation_id: &str,
        job_id: &str,
        process_attempt_id: &str,
        lease_version: u64,
        binding_generation: u64,
        requested_at: &str,
        requested_at_epoch_ms: u64,
    ) -> CoreResult<CancelRequestOutcome> {
        validate_safe_identity("cancellation idempotency key", cancellation_idempotency_key)?;
        validate_safe_identity("backend cancellation id", cancellation_id)?;
        validate_safe_identity("runner job id", job_id)?;
        validate_safe_identity("process attempt id", process_attempt_id)?;
        validate_safe_timestamp(requested_at)?;
        if lease_version == 0 || binding_generation == 0 || requested_at_epoch_ms == 0 {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_INVALID",
                "runner cancellation generations and timestamp must be positive",
            ));
        }
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        let route_and_binding_match = entry.binding.workspace_binding_generation
            == binding_generation
            && matches!(
                &entry.delivery_route,
                AgentDeliveryRoute::RunnerJob {
                    job_id: owned_job_id,
                    ..
                } if owned_job_id == job_id
            )
            && entry
                .attempt_claims
                .iter()
                .any(|claim| claim.attempt_id == process_attempt_id);
        if !route_and_binding_match {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_MISMATCH",
                "runner cancellation does not match the durable job, binding, and process",
            ));
        }
        let directive = PersistedRunnerCancellationDirective {
            cancellation_id: cancellation_id.to_string(),
            job_id: job_id.to_string(),
            process_attempt_id: process_attempt_id.to_string(),
            lease_version,
            binding_generation,
            requested_at: requested_at.to_string(),
            acknowledged: false,
        };
        if let Some(existing) = &entry.cancellation {
            let same_cancellation = existing.idempotency_key == cancellation_idempotency_key
                && existing.runner_directive.as_ref().is_some_and(|existing| {
                    existing.cancellation_id == directive.cancellation_id
                        && existing.job_id == directive.job_id
                        && existing.process_attempt_id == directive.process_attempt_id
                        && existing.binding_generation == directive.binding_generation
                        && existing.requested_at == directive.requested_at
                });
            if same_cancellation {
                let existing_lease = existing
                    .runner_directive
                    .as_ref()
                    .expect("same runner cancellation requires directive")
                    .lease_version;
                if lease_version == existing_lease {
                    return Ok(CancelRequestOutcome::Replay);
                }
                if lease_version > existing_lease {
                    let previous = self.document.clone();
                    let existing = self.document.entries[index]
                        .cancellation
                        .as_mut()
                        .and_then(|cancellation| cancellation.runner_directive.as_mut())
                        .expect("same runner cancellation requires directive");
                    existing.lease_version = lease_version;
                    existing.acknowledged = false;
                    self.persist_or_recover(previous)?;
                    return Ok(CancelRequestOutcome::Requested);
                }
            }
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_CONFLICT",
                "a different cancellation request is already durable",
            ));
        }
        let unacknowledged_local_terminal = entry.terminal_delivery_acknowledged_sequence.is_none()
            && entry.pending_delivery.as_ref().is_some_and(|delivery| {
                ((entry.state.is_terminal() && delivery.kind == AgentPendingDeliveryKind::Terminal)
                    || (entry.state == AgentExecutionState::Blocked
                        && delivery.kind == AgentPendingDeliveryKind::Deferred))
                    && delivery.sequence == entry.last_progress_sequence
            });
        if entry.active_attempt_id.as_deref() != Some(process_attempt_id)
            && !unacknowledged_local_terminal
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_MISMATCH",
                "a new runner cancellation must target the active process",
            ));
        }
        if (entry.state.is_terminal() || entry.state == AgentExecutionState::Blocked)
            && !unacknowledged_local_terminal
        {
            return Err(journal_error(
                "AGENT_JOURNAL_ALREADY_TERMINAL",
                "terminal agent execution cannot be cancelled",
            ));
        }
        let previous = self.document.clone();
        self.document.entries[index].cancellation = Some(PersistedCancellation {
            idempotency_key: cancellation_idempotency_key.to_string(),
            requested_at_epoch_ms,
            sequence: entry.last_progress_sequence,
            runner_directive: Some(directive),
        });
        self.persist_or_recover(previous)?;
        Ok(CancelRequestOutcome::Requested)
    }

    /// Durably reserves the fresh user-control operation key before contacting Backend.
    ///
    /// This does not signal or mutate the local worker. Backend remains the sole authority that
    /// transitions a runner-owned job to `canceling`.
    pub fn reserve_cancellation_control(
        &mut self,
        request_id: &str,
        operation_idempotency_key: &str,
    ) -> CoreResult<()> {
        validate_agent_control_idempotency_key(operation_idempotency_key)?;
        let index = self.entry_index(request_id)?;
        if let Some(existing) = self.document.entries[index]
            .cancellation_control_idempotency_key
            .as_deref()
        {
            return if existing == operation_idempotency_key {
                Ok(())
            } else {
                Err(journal_error(
                    "IDEMPOTENCY_KEY_CONFLICT",
                    "a different cancellation operation key is already reserved",
                ))
            };
        }
        let previous = self.document.clone();
        self.document.entries[index].cancellation_control_idempotency_key =
            Some(operation_idempotency_key.to_string());
        self.persist_or_recover(previous)
    }

    /// Archives a Backend-authoritative cancellation of an already deferred execution.
    ///
    /// Backend owns the RunnerJob state and has already made the logical cancellation terminal,
    /// so this transition must not synthesize another `AgentExecutionV2` or redeliver a terminal
    /// payload to the deferred predecessor job. The immutable process-attempt history remains
    /// Blocked; only the compact replay fence records the authoritative control terminal.
    pub fn archive_authoritative_blocked_cancellation(
        &mut self,
        request_id: &str,
        operation_idempotency_key: &str,
        authoritative_sequence: u64,
        finished_at: &str,
    ) -> CoreResult<()> {
        validate_agent_control_idempotency_key(operation_idempotency_key)?;
        validate_safe_timestamp(finished_at)?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        if !matches!(entry.delivery_route, AgentDeliveryRoute::RunnerJob { .. })
            || entry.state != AgentExecutionState::Blocked
            || entry.pending_delivery.is_some()
            || entry.terminal_delivery_acknowledged_sequence.is_some()
            || entry.cancellation_control_idempotency_key.as_deref()
                != Some(operation_idempotency_key)
            || entry
                .last_progress_sequence
                .checked_add(1)
                .is_none_or(|next| next != authoritative_sequence)
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCELLATION_CONTROL_MISMATCH",
                "authoritative deferred cancellation does not match the durable blocked execution",
            ));
        }
        let tombstone = AgentExecutionTombstone {
            schema_version: AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION.to_string(),
            request_id: entry.request_id.clone(),
            idempotency_key: entry.idempotency_key.clone(),
            task_intent_digest: entry.payload_digest.clone(),
            attempt_claims: entry.attempt_claims.clone(),
            binding: entry.binding.clone(),
            delivery_route: entry.delivery_route.clone(),
            execution_id: entry.execution_id.clone(),
            terminal_state: AgentExecutionState::Cancelled,
            terminal_sequence: authoritative_sequence,
            terminal_delivery_acknowledged_sequence: authoritative_sequence,
            has_session_checkpoint: entry.session_checkpoint.is_some(),
            cancellation_idempotency_key: entry
                .cancellation
                .as_ref()
                .map(|cancellation| cancellation.idempotency_key.clone()),
            cancellation_control_idempotency_key: Some(operation_idempotency_key.to_string()),
            resumable: false,
            finished_at: Some(finished_at.to_string()),
        };
        validate_tombstone(&tombstone)?;
        self.write_tombstone(&tombstone)?;

        let previous = self.document.clone();
        self.document.entries.remove(index);
        self.persist_or_recover(previous)
    }

    pub fn acknowledge_runner_cancel(
        &mut self,
        request_id: &str,
        cancellation_id: &str,
    ) -> CoreResult<()> {
        validate_safe_identity("backend cancellation id", cancellation_id)?;
        let index = self.entry_index(request_id)?;
        let cancellation = self.document.entries[index]
            .cancellation
            .as_ref()
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_CANCEL_NOT_REQUESTED",
                    "runner cancellation acknowledgement has no durable directive",
                )
            })?;
        let directive = cancellation.runner_directive.as_ref().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_MISMATCH",
                "local cancellation cannot accept a runner acknowledgement",
            )
        })?;
        if directive.cancellation_id != cancellation_id {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_MISMATCH",
                "runner cancellation acknowledgement id does not match",
            ));
        }
        if directive.acknowledged {
            return Ok(());
        }
        let previous = self.document.clone();
        self.document.entries[index]
            .cancellation
            .as_mut()
            .and_then(|cancellation| cancellation.runner_directive.as_mut())
            .expect("runner cancellation directive was checked above")
            .acknowledged = true;
        self.persist_or_recover(previous)
    }

    /// Replaces only an unacknowledged local terminal with `indeterminate` after Backend proves
    /// its cancellation linearized first. An acknowledged terminal is immutable and cannot be
    /// rewritten.
    pub fn reconcile_runner_cancellation_race(
        &mut self,
        request_id: &str,
        cancellation_id: &str,
        finished_at: impl Into<String>,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<Option<AgentExecutionV2>> {
        let finished_at = finished_at.into();
        validate_safe_timestamp(&finished_at)?;
        validate_safe_identity("backend cancellation id", cancellation_id)?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        let exact_directive = entry
            .cancellation
            .as_ref()
            .and_then(|cancellation| cancellation.runner_directive.as_ref())
            .is_some_and(|directive| directive.cancellation_id == cancellation_id);
        if !exact_directive {
            return Err(journal_error(
                "AGENT_JOURNAL_CANCEL_DIRECTIVE_MISMATCH",
                "cancellation-race reconciliation requires the exact durable directive",
            ));
        }
        if matches!(
            entry.state,
            AgentExecutionState::Cancelled | AgentExecutionState::Indeterminate
        ) {
            return Ok(Some(execution_from_journal_entry(entry)));
        }
        if !entry.state.is_terminal() && entry.state != AgentExecutionState::Blocked {
            return Ok(None);
        }
        if entry.terminal_delivery_acknowledged_sequence.is_some()
            || !entry.pending_delivery.as_ref().is_some_and(|delivery| {
                ((entry.state.is_terminal() && delivery.kind == AgentPendingDeliveryKind::Terminal)
                    || (entry.state == AgentExecutionState::Blocked
                        && delivery.kind == AgentPendingDeliveryKind::Deferred))
                    && delivery.sequence == entry.last_progress_sequence
            })
        {
            return Err(journal_error(
                "AGENT_JOURNAL_ALREADY_TERMINAL",
                "an acknowledged terminal cannot lose an authoritative cancellation race",
            ));
        }
        let superseded_state = match entry.state {
            AgentExecutionState::Completed => "completed",
            AgentExecutionState::Failed => "failed",
            AgentExecutionState::Blocked => "blocked",
            _ => "terminal",
        };
        let sequence = entry.last_progress_sequence.checked_add(1).ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_SEQUENCE_EXHAUSTED",
                "agent progress sequence is exhausted",
            )
        })?;
        let attempt_index = entry
            .attempts
            .iter()
            .enumerate()
            .max_by_key(|(_, attempt)| attempt.attempt_number)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_PROCESS_NOT_STARTED",
                    "cancellation race has no durable process attempt",
                )
            })?;
        let mut error = indeterminate_error(entry, AgentProcessLoss::Crash);
        error.context.safe_details.insert(
            "cancellationRace".to_string(),
            "backend_canceling_won".to_string(),
        );
        error.context.safe_details.insert(
            "supersededLocalTerminalState".to_string(),
            superseded_state.to_string(),
        );

        let previous = self.document.clone();
        let entry = &mut self.document.entries[index];
        let attempt = &mut entry.attempts[attempt_index];
        attempt.state = AgentAttemptState::Indeterminate;
        attempt.finished_sequence = Some(sequence);
        attempt.finished_at = Some(finished_at.clone());
        attempt.error = Some(error.clone());
        if let Some(checkpoint) = &mut attempt.session {
            checkpoint.state = AgentSessionState::Lost;
        }
        if let Some(checkpoint) = &mut entry.session_checkpoint {
            checkpoint.state = AgentSessionState::Lost;
        }
        entry.state = AgentExecutionState::Indeterminate;
        entry.active_attempt_id = None;
        entry.error = Some(error);
        entry.finished_at = Some(finished_at.clone());
        entry.updated_at = finished_at;
        entry.last_progress_sequence = sequence;
        entry.progress.push(AgentJournalProgress {
            sequence,
            kind: AgentJournalProgressKind::Indeterminate,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut entry.progress);
        let execution = execution_from_journal_entry(entry);
        validate_agent_terminal_execution(&execution).map_err(|_| {
            journal_error(
                "AGENT_TERMINAL_EXECUTION_TOO_LARGE",
                "cancellation-race execution exceeds the bounded durable-delivery limit",
            )
        })?;
        entry.pending_delivery = Some(AgentPendingDelivery {
            sequence,
            kind: AgentPendingDeliveryKind::Terminal,
            payload: serde_json::to_value(&execution).map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "cancellation-race execution could not be serialized",
                )
            })?,
        });
        self.persist_or_recover(previous)?;
        Ok(Some(execution))
    }

    /// Marks timeout/crash after spawn as indeterminate. It never makes the execution retryable.
    pub fn mark_process_lost(
        &mut self,
        request_id: &str,
        sequence: u64,
        loss: AgentProcessLoss,
        finished_at: impl Into<String>,
        recorded_at_epoch_ms: u64,
    ) -> CoreResult<AgentRuntimeErrorEnvelopeV2> {
        let finished_at = finished_at.into();
        validate_safe_timestamp(&finished_at)?;
        let index = self.entry_index(request_id)?;
        let entry = &self.document.entries[index];
        let supersedes_unacknowledged_terminal = (entry.state.is_terminal()
            || entry.state == AgentExecutionState::Blocked)
            && entry.terminal_delivery_acknowledged_sequence.is_none()
            && entry.pending_delivery.as_ref().is_some_and(|delivery| {
                ((entry.state.is_terminal() && delivery.kind == AgentPendingDeliveryKind::Terminal)
                    || (entry.state == AgentExecutionState::Blocked
                        && delivery.kind == AgentPendingDeliveryKind::Deferred))
                    && delivery.sequence == entry.last_progress_sequence
            });
        if (entry.state.is_terminal() || entry.state == AgentExecutionState::Blocked)
            && !supersedes_unacknowledged_terminal
        {
            return Err(journal_error(
                "AGENT_JOURNAL_ALREADY_TERMINAL",
                "terminal agent execution cannot become indeterminate",
            ));
        }
        if !supersedes_unacknowledged_terminal {
            ensure_no_pending_delivery(entry)?;
        }
        validate_next_sequence(entry, sequence)?;
        let attempt_index = entry
            .attempts
            .iter()
            .enumerate()
            .max_by_key(|(_, attempt)| attempt.attempt_number)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_PROCESS_NOT_STARTED",
                    "process loss cannot be recorded before an attempt starts",
                )
            })?;
        let error = indeterminate_error(entry, loss);

        let previous = self.document.clone();
        let entry = &mut self.document.entries[index];
        let attempt = &mut entry.attempts[attempt_index];
        attempt.state = AgentAttemptState::Indeterminate;
        attempt.finished_sequence = Some(sequence);
        attempt.finished_at = Some(finished_at.clone());
        attempt.error = Some(error.clone());
        if let Some(checkpoint) = &mut entry.session_checkpoint {
            checkpoint.state = AgentSessionState::Lost;
        }
        if let Some(checkpoint) = &mut attempt.session {
            checkpoint.state = AgentSessionState::Lost;
        }
        entry.state = AgentExecutionState::Indeterminate;
        entry.active_attempt_id = None;
        entry.error = Some(error.clone());
        entry.finished_at = Some(finished_at.clone());
        entry.updated_at = finished_at;
        entry.last_progress_sequence = sequence;
        entry.progress.push(AgentJournalProgress {
            sequence,
            kind: AgentJournalProgressKind::Indeterminate,
            recorded_at_epoch_ms,
        });
        trim_progress(&mut entry.progress);
        let delivery = execution_from_journal_entry(entry);
        validate_agent_terminal_execution(&delivery).map_err(|_| {
            journal_error(
                "AGENT_TERMINAL_EXECUTION_TOO_LARGE",
                "indeterminate execution exceeds the bounded durable-delivery limit",
            )
        })?;
        entry.pending_delivery = Some(AgentPendingDelivery {
            sequence,
            kind: AgentPendingDeliveryKind::Terminal,
            payload: serde_json::to_value(delivery).map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_DELIVERY_INVALID",
                    "indeterminate execution could not be serialized for durable delivery",
                )
            })?,
        });
        self.persist_or_recover(previous)?;
        Ok(error)
    }

    pub fn remove_after_authoritative_ack(&mut self, request_id: &str) -> CoreResult<()> {
        let index = self.entry_index(request_id)?;
        if self.document.entries[index].pending_delivery.is_some() {
            return Err(journal_error(
                "AGENT_JOURNAL_DELIVERY_PENDING",
                "agent execution cannot be removed before pending delivery is acknowledged",
            ));
        }
        if !self.document.entries[index].state.is_terminal() {
            return Err(journal_error(
                "AGENT_JOURNAL_NOT_TERMINAL",
                "agent execution cannot be removed before a terminal state is acknowledged",
            ));
        }
        if !is_immutable_terminal_entry(&self.document.entries[index]) {
            return Err(journal_error(
                "AGENT_JOURNAL_RESUME_REQUIRED",
                "resumable indeterminate execution must retain its active journal entry",
            ));
        }
        if self.document.entries[index]
            .terminal_delivery_acknowledged_sequence
            .is_none()
        {
            let previous = self.document.clone();
            let sequence = self.document.entries[index].last_progress_sequence;
            self.document.entries[index].terminal_delivery_acknowledged_sequence = Some(sequence);
            self.persist_or_recover(previous)?;
        }
        self.compact_terminal_entry(index)
    }

    fn compact_acknowledged_terminal_entries(&mut self) -> CoreResult<()> {
        while let Some(index) = self.document.entries.iter().position(|entry| {
            is_immutable_terminal_entry(entry)
                && entry.pending_delivery.is_none()
                && entry.terminal_delivery_acknowledged_sequence.is_some()
        }) {
            self.compact_terminal_entry(index)?;
        }
        Ok(())
    }

    fn compact_terminal_entry(&mut self, index: usize) -> CoreResult<()> {
        let entry = self.document.entries.get(index).ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_NOT_FOUND",
                "agent execution journal entry was not found for compaction",
            )
        })?;
        let acknowledged_sequence =
            entry
                .terminal_delivery_acknowledged_sequence
                .ok_or_else(|| {
                    journal_error(
                        "AGENT_JOURNAL_ACK_REQUIRED",
                        "terminal execution cannot be compacted before delivery acknowledgement",
                    )
                })?;
        if !is_immutable_terminal_entry(entry) {
            return Err(journal_error(
                "AGENT_JOURNAL_NOT_IMMUTABLE",
                "only immutable acknowledged terminal executions may be compacted",
            ));
        }
        if entry.pending_delivery.is_some() {
            return Err(journal_error(
                "AGENT_JOURNAL_DELIVERY_PENDING",
                "pending delivery must be acknowledged before compaction",
            ));
        }
        let tombstone = AgentExecutionTombstone {
            schema_version: AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION.to_string(),
            request_id: entry.request_id.clone(),
            idempotency_key: entry.idempotency_key.clone(),
            task_intent_digest: entry.payload_digest.clone(),
            attempt_claims: entry.attempt_claims.clone(),
            binding: entry.binding.clone(),
            delivery_route: entry.delivery_route.clone(),
            execution_id: entry.execution_id.clone(),
            terminal_state: entry.state,
            terminal_sequence: entry.last_progress_sequence,
            terminal_delivery_acknowledged_sequence: acknowledged_sequence,
            has_session_checkpoint: entry.session_checkpoint.is_some(),
            cancellation_idempotency_key: entry
                .cancellation
                .as_ref()
                .map(|cancellation| cancellation.idempotency_key.clone()),
            cancellation_control_idempotency_key: entry
                .cancellation_control_idempotency_key
                .clone(),
            resumable: false,
            finished_at: entry.finished_at.clone(),
        };
        validate_tombstone(&tombstone)?;
        self.write_tombstone(&tombstone)?;

        let previous = self.document.clone();
        self.document.entries.remove(index);
        self.persist_or_recover(previous)
    }

    fn write_tombstone(&self, tombstone: &AgentExecutionTombstone) -> CoreResult<()> {
        let record_hash = tombstone_record_hash(tombstone);
        let record_path = self.tombstone_hashed_path("records", &record_hash, "json");
        let bytes = serde_json::to_vec(tombstone).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_TOMBSTONE_INVALID",
                "agent execution tombstone could not be serialized",
            )
        })?;
        if bytes.len() as u64 > MAX_AGENT_TOMBSTONE_BYTES {
            return Err(journal_capacity_error(
                "agent execution tombstone exceeds its maximum record size",
            ));
        }
        self.write_private_archive_file(&record_path, &bytes, Some(tombstone))?;
        self.write_tombstone_index(
            TombstoneIndexKind::Request,
            &tombstone.request_id,
            &record_hash,
        )?;
        self.write_tombstone_index(
            TombstoneIndexKind::Idempotency,
            &tombstone.idempotency_key,
            &record_hash,
        )?;
        sync_directory(&self.tombstone_root()).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to sync agent tombstone archive: {error}"),
            )
        })
    }

    fn write_tombstone_index(
        &self,
        kind: TombstoneIndexKind,
        identity: &str,
        record_hash: &str,
    ) -> CoreResult<()> {
        let index_hash = sha256_hex(identity.as_bytes());
        let path = self.tombstone_hashed_path(kind.directory(), &index_hash, "idx");
        self.write_private_archive_file(&path, record_hash.as_bytes(), None)
    }

    fn write_private_archive_file(
        &self,
        path: &Path,
        bytes: &[u8],
        expected_tombstone: Option<&AgentExecutionTombstone>,
    ) -> CoreResult<()> {
        let parent = path.parent().ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                "agent tombstone archive path has no parent",
            )
        })?;
        self.ensure_tombstone_parent(parent)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_private_archive_file(path, &metadata, bytes.len() as u64)?;
                let existing = fs::read(path).map_err(|error| {
                    journal_error(
                        "AGENT_JOURNAL_READ_FAILED",
                        &format!("failed to read existing agent tombstone record: {error}"),
                    )
                })?;
                if existing == bytes {
                    return Ok(());
                }
                if let Some(expected) = expected_tombstone {
                    if serde_json::from_slice::<AgentExecutionTombstone>(&existing)
                        .ok()
                        .as_ref()
                        == Some(expected)
                    {
                        return Ok(());
                    }
                }
                return Err(journal_error(
                    "AGENT_JOURNAL_TOMBSTONE_CONFLICT",
                    "hash-addressed agent tombstone storage contains a conflicting record",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(journal_error(
                    "AGENT_JOURNAL_WRITE_FAILED",
                    &format!("failed to inspect agent tombstone destination: {error}"),
                ))
            }
        }

        let temp_path = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    journal_error(
                        "AGENT_JOURNAL_CLOCK_INVALID",
                        "system clock is before the Unix epoch",
                    )
                })?
                .as_nanos()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to create private agent tombstone: {error}"),
            )
        })?;
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temp_path);
            return Err(journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to persist private agent tombstone: {error}"),
            ));
        }
        validate_replace_destination(path)?;
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to atomically install agent tombstone: {error}"),
            ));
        }
        ensure_private_permissions(path)?;
        sync_directory(parent).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to sync agent tombstone segment: {error}"),
            )
        })
    }

    fn read_tombstone_index(
        &self,
        kind: TombstoneIndexKind,
        identity: &str,
    ) -> CoreResult<Option<AgentExecutionTombstone>> {
        let index_hash = sha256_hex(identity.as_bytes());
        let path = self.tombstone_hashed_path(kind.directory(), &index_hash, "idx");
        if let Some(parent) = path.parent() {
            self.validate_tombstone_parent(parent)?;
        }
        let Some(record_hash) = read_private_archive_index(&path)? else {
            return Ok(None);
        };
        let record_path = self.tombstone_hashed_path("records", &record_hash, "json");
        if let Some(parent) = record_path.parent() {
            self.validate_tombstone_parent(parent)?;
        }
        let tombstone = read_private_tombstone(&record_path)?;
        let matches = match kind {
            TombstoneIndexKind::Request => tombstone.request_id == identity,
            TombstoneIndexKind::Idempotency => tombstone.idempotency_key == identity,
        };
        if !matches || tombstone_record_hash(&tombstone) != record_hash {
            return Err(journal_error(
                "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
                "agent tombstone index does not match its immutable record",
            ));
        }
        Ok(Some(tombstone))
    }

    fn find_tombstone_conflict(
        &self,
        request_id: &str,
        idempotency_key: &str,
    ) -> CoreResult<Option<AgentExecutionTombstone>> {
        let by_request = self.read_tombstone_index(TombstoneIndexKind::Request, request_id)?;
        let by_idempotency =
            self.read_tombstone_index(TombstoneIndexKind::Idempotency, idempotency_key)?;
        match (by_request, by_idempotency) {
            (None, None) => Ok(None),
            (Some(left), Some(right)) if left == right => Ok(Some(left)),
            (Some(tombstone), None) | (None, Some(tombstone)) => Ok(Some(tombstone)),
            (Some(_), Some(_)) => Err(journal_error(
                "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
                "request and idempotency key refer to different archived executions",
            )),
        }
    }

    fn tombstone_root(&self) -> PathBuf {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("agent-journal");
        let suffix = &sha256_hex(name.as_bytes())[..16];
        parent.join(format!(".loomex-agent-tombstones-{suffix}"))
    }

    fn tombstone_hashed_path(&self, namespace: &str, hash: &str, extension: &str) -> PathBuf {
        let (segment, name) = hash.split_at(2);
        self.tombstone_root()
            .join(namespace)
            .join(segment)
            .join(format!("{name}.{extension}"))
    }

    fn ensure_tombstone_parent(&self, target: &Path) -> CoreResult<()> {
        let root = self.tombstone_root();
        let journal_parent = root.parent().unwrap_or_else(|| Path::new("."));
        validate_journal_parent(journal_parent)?;
        ensure_owned_private_directory(&root)?;
        let relative = target.strip_prefix(&root).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_INSECURE",
                "agent tombstone path escaped its private archive root",
            )
        })?;
        let mut current = root;
        for component in relative.components() {
            current.push(component.as_os_str());
            ensure_owned_private_directory(&current)?;
        }
        Ok(())
    }

    fn validate_tombstone_parent(&self, target: &Path) -> CoreResult<()> {
        let root = self.tombstone_root();
        let root_metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(())
            }
            Err(error) => {
                return Err(journal_error(
                    "AGENT_JOURNAL_READ_FAILED",
                    &format!("failed to inspect agent tombstone archive root: {error}"),
                ))
            }
        };
        let relative = target.strip_prefix(&root).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_INSECURE",
                "agent tombstone path escaped its private archive root",
            )
        })?;
        let mut current = root;
        validate_private_archive_directory(&current, &root_metadata)?;
        for component in relative.components() {
            current.push(component.as_os_str());
            let metadata = match fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(journal_error(
                        "AGENT_JOURNAL_READ_FAILED",
                        &format!("failed to inspect agent tombstone archive component: {error}"),
                    ))
                }
            };
            validate_private_archive_directory(&current, &metadata)?;
        }
        Ok(())
    }

    fn validate_tombstone_storage(&self) -> CoreResult<()> {
        let root = self.tombstone_root();
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(())
            }
            Err(error) => {
                return Err(journal_error(
                    "AGENT_JOURNAL_READ_FAILED",
                    &format!("failed to inspect agent tombstone archive: {error}"),
                ))
            }
        };
        validate_private_archive_directory(&root, &metadata)
    }

    fn entry_index(&self, request_id: &str) -> CoreResult<usize> {
        self.document
            .entries
            .iter()
            .position(|entry| entry.request_id == request_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_NOT_FOUND",
                    "agent execution journal entry was not found",
                )
            })
    }

    fn persist(&self) -> CoreResult<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to create durable journal directory: {error}"),
            )
        })?;
        validate_journal_parent(parent)?;
        validate_replace_destination(&self.path)?;
        let file_name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("agent-execution-journal.json");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = parent.join(format!(".{file_name}.{}.{nonce}.tmp", std::process::id()));
        let bytes = serde_json::to_vec(&self.document).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                "failed to serialize durable agent journal",
            )
        })?;
        if bytes.len() as u64 > MAX_AGENT_JOURNAL_BYTES {
            return Err(journal_capacity_error(
                "durable agent journal would exceed its maximum file size",
            ));
        }
        let result = (|| -> std::io::Result<()> {
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
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to persist durable agent journal: {error}"),
            ));
        }
        ensure_private_permissions(&self.path)
    }

    /// Restores the authoritative on-disk document after any failed commit.
    ///
    /// A failure can happen before rename (the old document remains authoritative) or after
    /// rename while syncing the directory (the new document may already be authoritative).
    /// Reloading first handles both cases. If the path itself is unavailable, the exact
    /// pre-mutation snapshot is restored in memory. The original typed persistence error is
    /// returned either way, so callers never continue to spawn/ack on an uncertain commit.
    fn persist_or_recover(&mut self, previous: AgentExecutionJournalDocument) -> CoreResult<()> {
        match self.persist() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.document = match read_existing_document(&self.path) {
                    Ok(durable) => durable,
                    Err(_) => previous,
                };
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TombstoneIndexKind {
    Request,
    Idempotency,
}

impl TombstoneIndexKind {
    const fn directory(self) -> &'static str {
        match self {
            Self::Request => "request-index",
            Self::Idempotency => "idempotency-index",
        }
    }
}

impl AgentExecutionJournalEntry {
    fn replay(&self) -> AgentExecutionReplay {
        AgentExecutionReplay {
            request_id: self.request_id.clone(),
            execution_id: self.execution_id.clone(),
            state: self.state,
            last_progress_sequence: self.last_progress_sequence,
            cancel_requested: self.cancellation.is_some(),
            has_session_checkpoint: self.session_checkpoint.is_some(),
        }
    }

    /// Returns the data-minimized durable execution receipt for transport/service replay.
    pub fn replay_metadata(&self) -> AgentExecutionReplay {
        self.replay()
    }

    /// Returns the canonical redacted protocol snapshot represented by this durable entry.
    pub fn execution_snapshot(&self) -> AgentExecutionV2 {
        execution_from_journal_entry(self)
    }
}

impl AgentExecutionTombstone {
    fn replay(&self) -> AgentExecutionReplay {
        AgentExecutionReplay {
            request_id: self.request_id.clone(),
            execution_id: self.execution_id.clone(),
            state: self.terminal_state,
            last_progress_sequence: self.terminal_sequence,
            cancel_requested: self.cancellation_idempotency_key.is_some(),
            has_session_checkpoint: self.has_session_checkpoint,
        }
    }

    pub fn replay_metadata(&self) -> AgentExecutionReplay {
        self.replay()
    }
}

pub fn sha256_payload_digest(canonical_payload: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(canonical_payload))
}

/// Matches Backend `sha256(canonical-json-v1)` for the complete authoritative AgentTaskRequestV2:
/// recursively sorted keys, compact separators, preserved Unicode, and UTF-8 without a BOM.
pub fn canonical_agent_task_payload_digest(value: &Value) -> CoreResult<String> {
    if value.get("schemaVersion").and_then(Value::as_str) != Some("loomex.plugin-agent-task/v2") {
        return Err(CoreError::new(
            "AGENT_TASK_SCHEMA_INVALID",
            "agent task digest requires loomex.plugin-agent-task/v2",
        ));
    }
    let mut canonical = String::new();
    write_backend_canonical_json(value, &mut canonical)?;
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

/// RFC 8785/JCS-compatible digest used by AgentProcessDispatchV2.
pub fn canonical_json_payload_digest(value: &Value) -> CoreResult<String> {
    let canonical =
        loomex_protocol::agent_runtime_v2::canonicalize_agent_payload(value).map_err(|_| {
            CoreError::new(
                "AGENT_PROCESS_DISPATCH_CANONICALIZATION_FAILED",
                "agent process dispatch is not valid RFC 8785 JSON",
            )
        })?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

/// Compares two already validated digest strings without data-dependent early return.
pub fn constant_time_digest_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn write_backend_canonical_json(value: &Value, output: &mut String) -> CoreResult<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&python_compatible_number(value)),
        Value::String(value) => write_canonical_json_string(value, output)?,
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_backend_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json_string(key, output)?;
                output.push(':');
                let nested = values.get(key).ok_or_else(|| {
                    journal_error(
                        "AGENT_JOURNAL_CANONICALIZATION_FAILED",
                        "canonical JSON object changed while it was being serialized",
                    )
                })?;
                write_backend_canonical_json(nested, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn python_compatible_number(value: &serde_json::Number) -> String {
    let rendered = value.to_string();
    let Some((mantissa, exponent)) = rendered
        .split_once('e')
        .or_else(|| rendered.split_once('E'))
    else {
        return rendered;
    };
    let (sign, digits) = exponent
        .strip_prefix('-')
        .map(|digits| ("-", digits))
        .or_else(|| exponent.strip_prefix('+').map(|digits| ("+", digits)))
        .unwrap_or(("+", exponent));
    let digits = if digits.len() == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    format!("{mantissa}e{sign}{digits}")
}

fn write_canonical_json_string(value: &str, output: &mut String) -> CoreResult<()> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        CoreError::new(
            "AGENT_TASK_SERIALIZATION_FAILED",
            "agent task string could not be canonicalized",
        )
    })?;
    output.push_str(&encoded);
    Ok(())
}

fn validate_claim(claim: &AgentExecutionClaim) -> CoreResult<()> {
    validate_safe_identity("request id", &claim.request_id)?;
    validate_safe_identity("idempotency key", &claim.idempotency_key)?;
    validate_safe_identity("attempt id", &claim.attempt_id)?;
    if claim.attempt_number == 0 {
        return Err(journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "process attempt number must be positive",
        ));
    }
    validate_agent_attempt_task_idempotency_key(&claim.task_idempotency_key).map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "process task idempotency key is invalid",
        )
    })?;
    validate_agent_attempt_delivery_idempotency_key(&claim.delivery_idempotency_key).map_err(
        |_| {
            journal_error(
                "AGENT_JOURNAL_CLAIM_INVALID",
                "process delivery idempotency key is invalid",
            )
        },
    )?;
    if !claim.delivery.is_valid_for_binding(&claim.binding)
        || claim.delivery != process_delivery_for_route(&claim.delivery_route, &claim.binding)
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "process delivery ownership does not match the durable delivery route and binding",
        ));
    }
    let retry_identity_is_valid = match claim.retry_kind {
        loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial => {
            claim.attempt_number == 1 && claim.from_attempt_id.is_none()
        }
        loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::FreshAfterRemediation
        | loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::ResumeFromCheckpoint => {
            claim.attempt_number > 1
                && claim
                    .from_attempt_id
                    .as_ref()
                    .is_some_and(|attempt_id| !attempt_id.trim().is_empty())
        }
    };
    if !retry_identity_is_valid {
        return Err(journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "process retry identity is inconsistent with its attempt number and predecessor",
        ));
    }
    if let AgentDeliveryRoute::RunnerJob {
        job_id,
        predecessor_job_id,
    } = &claim.delivery_route
    {
        validate_safe_identity("runner job id", job_id)?;
        if let Some(predecessor_job_id) = predecessor_job_id {
            validate_safe_identity("predecessor runner job id", predecessor_job_id)?;
        }
    }
    validate_binding(&claim.binding)?;
    if claim.claimed_at_epoch_ms == 0 {
        return Err(journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "claim timestamp must be positive",
        ));
    }
    claim.execution.validate().map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_EXECUTION_INVALID",
            "initial agent execution v2 envelope failed validation",
        )
    })?;
    if claim.execution.request_id != claim.request_id
        || claim.execution.idempotency_key != claim.idempotency_key
        || claim.execution.binding != claim.binding
        || claim.execution.sequence != 1
        || claim.execution.state != AgentExecutionState::Queued
        || !claim.execution.attempts.is_empty()
        || claim.execution.output.is_some()
        || claim.execution.error.is_some()
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CLAIM_INVALID",
            "claim must contain the matching queued execution before any attempt starts",
        ));
    }
    Ok(())
}

fn persisted_entry_from_execution(
    execution: &AgentExecutionV2,
    idempotency_key: String,
    payload_digest: String,
    claimed_at_epoch_ms: u64,
) -> CoreResult<AgentExecutionJournalEntry> {
    validate_agent_attempt_capacity(execution.attempts.len())?;
    validate_safe_identity("request id", &execution.request_id)?;
    validate_safe_identity("execution id", &execution.execution_id)?;
    validate_safe_identity("idempotency key", &idempotency_key)?;
    validate_binding(&execution.binding)?;
    validate_safe_timestamp(&execution.created_at)?;
    validate_safe_timestamp(&execution.updated_at)?;
    if let Some(timestamp) = &execution.started_at {
        validate_safe_timestamp(timestamp)?;
    }
    if let Some(timestamp) = &execution.finished_at {
        validate_safe_timestamp(timestamp)?;
    }
    let attempts = execution
        .attempts
        .iter()
        .map(|attempt| {
            validate_safe_identity("attempt id", &attempt.attempt_id)?;
            validate_safe_timestamp(&attempt.started_at)?;
            if let Some(timestamp) = &attempt.finished_at {
                validate_safe_timestamp(timestamp)?;
            }
            for value in [
                attempt.requested_model_key.as_deref(),
                attempt.requested_provider_model_id.as_deref(),
                attempt.resolved_model_key.as_deref(),
                attempt.resolved_provider_model_id.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_safe_identity("model identity", value)?;
            }
            Ok(PersistedAgentAttempt {
                attempt_id: attempt.attempt_id.clone(),
                attempt_number: attempt.attempt_number,
                task_idempotency_key: attempt.task_idempotency_key.clone(),
                delivery_idempotency_key: attempt.delivery_idempotency_key.clone(),
                payload_digest: attempt.payload_digest.clone(),
                state: attempt.state,
                started_sequence: attempt.started_sequence,
                finished_sequence: attempt.finished_sequence,
                selection_index: attempt.selection_index,
                executor: attempt.executor,
                provider: attempt.provider,
                requested_model_key: attempt.requested_model_key.clone(),
                requested_provider_model_id: attempt.requested_provider_model_id.clone(),
                resolved_model_key: attempt.resolved_model_key.clone(),
                resolved_provider_model_id: attempt.resolved_provider_model_id.clone(),
                started_at: attempt.started_at.clone(),
                finished_at: attempt.finished_at.clone(),
                session: attempt.session.clone(),
                retry: attempt.retry.clone(),
                delivery: attempt.delivery.clone(),
                error: attempt.error.as_ref().map(canonicalize_error).transpose()?,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(AgentExecutionJournalEntry {
        request_id: execution.request_id.clone(),
        idempotency_key,
        payload_digest,
        attempt_claims: Vec::new(),
        binding: execution.binding.clone(),
        delivery_route: AgentDeliveryRoute::DirectHuman,
        execution_id: execution.execution_id.clone(),
        state: execution.state,
        active_attempt_id: execution.active_attempt_id.clone(),
        attempts,
        error: execution
            .error
            .as_ref()
            .map(canonicalize_error)
            .transpose()?,
        created_at: execution.created_at.clone(),
        started_at: execution.started_at.clone(),
        finished_at: execution.finished_at.clone(),
        updated_at: execution.updated_at.clone(),
        claimed_at_epoch_ms,
        last_progress_sequence: 0,
        progress: Vec::new(),
        session_checkpoint: None,
        cancellation: None,
        cancellation_control_idempotency_key: None,
        pending_delivery: None,
        terminal_delivery_acknowledged_sequence: None,
    })
}

fn execution_from_journal_entry(entry: &AgentExecutionJournalEntry) -> AgentExecutionV2 {
    AgentExecutionV2 {
        schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
        execution_id: entry.execution_id.clone(),
        request_id: entry.request_id.clone(),
        idempotency_key: entry.idempotency_key.clone(),
        sequence: entry.last_progress_sequence,
        binding: entry.binding.clone(),
        state: entry.state,
        active_attempt_id: entry.active_attempt_id.clone(),
        attempts: entry
            .attempts
            .iter()
            .map(
                |attempt| loomex_protocol::agent_runtime_v2::AgentAttemptV2 {
                    attempt_id: attempt.attempt_id.clone(),
                    attempt_number: attempt.attempt_number,
                    task_idempotency_key: attempt.task_idempotency_key.clone(),
                    delivery_idempotency_key: attempt.delivery_idempotency_key.clone(),
                    payload_digest: attempt.payload_digest.clone(),
                    state: attempt.state,
                    started_sequence: attempt.started_sequence,
                    finished_sequence: attempt.finished_sequence,
                    selection_index: attempt.selection_index,
                    executor: attempt.executor,
                    provider: attempt.provider,
                    requested_model_key: attempt.requested_model_key.clone(),
                    requested_provider_model_id: attempt.requested_provider_model_id.clone(),
                    resolved_model_key: attempt.resolved_model_key.clone(),
                    resolved_provider_model_id: attempt.resolved_provider_model_id.clone(),
                    started_at: attempt.started_at.clone(),
                    finished_at: attempt.finished_at.clone(),
                    session: attempt.session.clone().or_else(|| {
                        entry
                            .session_checkpoint
                            .as_ref()
                            .filter(|checkpoint| checkpoint.attempt_id == attempt.attempt_id)
                            .cloned()
                    }),
                    retry: attempt.retry.clone(),
                    delivery: attempt.delivery.clone(),
                    error: attempt.error.clone(),
                },
            )
            .collect(),
        output: None,
        error: entry.error.clone(),
        created_at: entry.created_at.clone(),
        started_at: entry.started_at.clone(),
        finished_at: entry.finished_at.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

fn canonicalize_error(
    error: &AgentRuntimeErrorEnvelopeV2,
) -> CoreResult<AgentRuntimeErrorEnvelopeV2> {
    error.validate().map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_ERROR_INVALID",
            "agent error v2 envelope failed validation",
        )
    })?;
    let mut context = error.context.clone();
    context.safe_details = BTreeMap::new();
    for value in [
        context.requested_model_key.as_deref(),
        context.requested_provider_model_id.as_deref(),
        context.resolved_model_key.as_deref(),
        context.resolved_provider_model_id.as_deref(),
        context.execution_id.as_deref(),
        context.attempt_id.as_deref(),
        context.session_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_safe_identity("error context identity", value)?;
    }
    Ok(AgentRuntimeErrorEnvelopeV2 {
        schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
        code: error.code,
        category: error.code.category(),
        message: canonical_error_message(error.code).to_string(),
        retry: error.retry,
        retry_after_seconds: error.retry_after_seconds,
        remediation: error.remediation.clone(),
        context,
    })
}

fn canonical_error_message(code: AgentErrorCode) -> &'static str {
    match code {
        AgentErrorCode::InvalidRequest => "The agent request is invalid.",
        AgentErrorCode::ProtocolMismatch => "The agent protocol version is not supported.",
        AgentErrorCode::ProviderNotInstalled => "The selected agent executor is not installed.",
        AgentErrorCode::ProviderNotAuthenticated => {
            "The selected agent executor is not authenticated."
        }
        AgentErrorCode::ProviderNotEligible => {
            "The current provider account is not eligible for this agent execution."
        }
        AgentErrorCode::AgentRuntimeV2Disabled => "Agent runtime v2 is disabled for this dispatch.",
        AgentErrorCode::RuntimeUnavailable => "The selected agent runtime is unavailable.",
        AgentErrorCode::ModelUnknown => "The selected model is unknown.",
        AgentErrorCode::ModelNotAvailable => "The selected model is not available.",
        AgentErrorCode::UnsupportedCapability => {
            "The selected agent executor does not support a required capability."
        }
        AgentErrorCode::RateLimited => "The selected agent provider is rate limited.",
        AgentErrorCode::NetworkError => "The agent provider could not be reached.",
        AgentErrorCode::Timeout => "The agent operation timed out before execution was confirmed.",
        AgentErrorCode::Cancelled => "The agent execution was cancelled.",
        AgentErrorCode::OutputInvalid => "The agent output did not match the required format.",
        AgentErrorCode::SessionNotFound => "The recorded agent session was not found.",
        AgentErrorCode::SessionMismatch => {
            "The recorded agent session does not match this request."
        }
        AgentErrorCode::ExecutionFailed => "The agent execution failed.",
        AgentErrorCode::ExecutionIndeterminate => {
            "The agent process ended after execution may have started; reconciliation is required."
        }
        AgentErrorCode::InternalError => "The agent runtime encountered an internal error.",
    }
}

fn indeterminate_error(
    entry: &AgentExecutionJournalEntry,
    _loss: AgentProcessLoss,
) -> AgentRuntimeErrorEnvelopeV2 {
    let attempt = entry
        .attempts
        .iter()
        .max_by_key(|attempt| attempt.attempt_number);
    let can_resume = entry.session_checkpoint.is_some()
        && attempt.is_some_and(|attempt| executor_supports_continuation(attempt.executor));
    let (retry, remediation) = if can_resume {
        (
            loomex_protocol::agent_runtime_v2::AgentRetryDisposition::ResumeRequired,
            vec![loomex_protocol::agent_runtime_v2::AgentRemediationAction::ResumeSession],
        )
    } else {
        (
            loomex_protocol::agent_runtime_v2::AgentRetryDisposition::Never,
            vec![loomex_protocol::agent_runtime_v2::AgentRemediationAction::ContactSupport],
        )
    };
    AgentRuntimeErrorEnvelopeV2 {
        schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
        code: AgentErrorCode::ExecutionIndeterminate,
        category: AgentErrorCode::ExecutionIndeterminate.category(),
        message: canonical_error_message(AgentErrorCode::ExecutionIndeterminate).to_string(),
        retry,
        retry_after_seconds: None,
        remediation,
        context: loomex_protocol::agent_runtime_v2::AgentErrorContext {
            executor: attempt.map(|attempt| attempt.executor),
            provider: attempt.map(|attempt| attempt.provider),
            requested_model_key: attempt.and_then(|attempt| attempt.requested_model_key.clone()),
            requested_provider_model_id: attempt
                .and_then(|attempt| attempt.requested_provider_model_id.clone()),
            resolved_model_key: attempt.and_then(|attempt| attempt.resolved_model_key.clone()),
            resolved_provider_model_id: attempt
                .and_then(|attempt| attempt.resolved_provider_model_id.clone()),
            execution_id: Some(entry.execution_id.clone()),
            attempt_id: attempt.map(|attempt| attempt.attempt_id.clone()),
            session_id: entry
                .session_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.session_id.clone()),
            safe_details: BTreeMap::new(),
        },
    }
}

fn executor_supports_continuation(executor: ExecutorKind) -> bool {
    matches!(executor, ExecutorKind::CodexCli | ExecutorKind::ClaudeCli)
}

fn is_immutable_terminal_entry(entry: &AgentExecutionJournalEntry) -> bool {
    match entry.state {
        AgentExecutionState::Completed
        | AgentExecutionState::Failed
        | AgentExecutionState::Cancelled => true,
        AgentExecutionState::Indeterminate => !entry
            .session_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| executor_supports_continuation(checkpoint.executor)),
        AgentExecutionState::Queued
        | AgentExecutionState::Probing
        | AgentExecutionState::Blocked
        | AgentExecutionState::Running => false,
    }
}

fn validate_execution_identity(
    entry: &AgentExecutionJournalEntry,
    execution: &AgentExecutionV2,
) -> CoreResult<()> {
    if execution.request_id != entry.request_id
        || execution.execution_id != entry.execution_id
        || execution.idempotency_key != entry.idempotency_key
        || execution.binding != entry.binding
    {
        return Err(journal_error(
            "AGENT_JOURNAL_EXECUTION_MISMATCH",
            "agent execution identity or binding changed",
        ));
    }
    Ok(())
}

fn validate_execution_delivery(execution: &AgentExecutionV2, payload: &Value) -> CoreResult<()> {
    let delivered: AgentExecutionV2 = serde_json::from_value(payload.clone()).map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_DELIVERY_INVALID",
            "terminal delivery is not an agent execution v2 payload",
        )
    })?;
    delivered.validate().map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_DELIVERY_INVALID",
            "terminal delivery agent execution failed validation",
        )
    })?;
    if &delivered != execution {
        return Err(journal_error(
            "AGENT_JOURNAL_DELIVERY_MISMATCH",
            "terminal delivery must exactly match the committed agent execution",
        ));
    }
    Ok(())
}

fn validate_checkpoint_delivery(
    checkpoint: &AgentSessionCheckpointV2,
    payload: &Value,
) -> CoreResult<()> {
    let delivered: AgentSessionCheckpointV2 =
        serde_json::from_value(payload.clone()).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_DELIVERY_INVALID",
                "checkpoint delivery is not an agent session checkpoint v2 payload",
            )
        })?;
    delivered.validate().map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_DELIVERY_INVALID",
            "checkpoint delivery failed protocol validation",
        )
    })?;
    if &delivered != checkpoint {
        return Err(journal_error(
            "AGENT_JOURNAL_DELIVERY_MISMATCH",
            "checkpoint delivery must exactly match the committed session checkpoint",
        ));
    }
    Ok(())
}

fn ensure_no_pending_delivery(entry: &AgentExecutionJournalEntry) -> CoreResult<()> {
    if entry.pending_delivery.is_some() {
        return Err(journal_error(
            "AGENT_JOURNAL_DELIVERY_PENDING",
            "pending protocol delivery must be acknowledged before another durable transition",
        ));
    }
    Ok(())
}

fn validate_replayed_delivery(
    entry: &AgentExecutionJournalEntry,
    requested: Option<&AgentPendingDelivery>,
) -> CoreResult<()> {
    match (entry.pending_delivery.as_ref(), requested) {
        (None, None) => Ok(()),
        (Some(existing), Some(requested)) if existing == requested => Ok(()),
        _ => Err(journal_error(
            "AGENT_JOURNAL_DELIVERY_CONFLICT",
            "replayed checkpoint delivery does not match durable pending delivery",
        )),
    }
}

fn validate_checkpoint_identity(
    entry: &AgentExecutionJournalEntry,
    checkpoint: &AgentSessionCheckpointV2,
    require_active_attempt: bool,
) -> CoreResult<()> {
    validate_safe_identity("checkpoint id", &checkpoint.checkpoint_id)?;
    validate_safe_identity("session id", &checkpoint.session_id)?;
    validate_safe_identity("provider session id", &checkpoint.provider_session_id)?;
    validate_safe_identity("execution id", &checkpoint.execution_id)?;
    validate_safe_identity("attempt id", &checkpoint.attempt_id)?;
    validate_optional_model_identity(&checkpoint.model_key, &checkpoint.provider_model_id)?;
    validate_safe_timestamp(&checkpoint.recorded_at)?;
    if checkpoint.execution_id != entry.execution_id || checkpoint.binding != entry.binding {
        return Err(journal_error(
            "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
            "session checkpoint execution or binding does not match the durable claim",
        ));
    }
    let attempt = entry
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == checkpoint.attempt_id)
        .ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
                "session checkpoint attempt is not active in the durable execution",
            )
        })?;
    if (require_active_attempt
        && entry.active_attempt_id.as_deref() != Some(attempt.attempt_id.as_str()))
        || attempt.executor != checkpoint.executor
        || attempt.provider != checkpoint.provider
        || attempt.resolved_model_key != checkpoint.model_key
        || attempt.resolved_provider_model_id != checkpoint.provider_model_id
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CHECKPOINT_MISMATCH",
            "session checkpoint executor, provider, or exact model does not match the attempt",
        ));
    }
    Ok(())
}

fn validate_transition(current: AgentExecutionState, next: AgentExecutionState) -> CoreResult<()> {
    if current.is_terminal() {
        return Err(journal_error(
            "AGENT_JOURNAL_ALREADY_TERMINAL",
            "terminal agent execution cannot transition",
        ));
    }
    let allowed = match current {
        AgentExecutionState::Queued => matches!(
            next,
            AgentExecutionState::Probing
                | AgentExecutionState::Running
                | AgentExecutionState::Blocked
                | AgentExecutionState::Failed
                | AgentExecutionState::Cancelled
        ),
        AgentExecutionState::Probing => matches!(
            next,
            AgentExecutionState::Running
                | AgentExecutionState::Blocked
                | AgentExecutionState::Failed
                | AgentExecutionState::Cancelled
        ),
        AgentExecutionState::Blocked => matches!(
            next,
            AgentExecutionState::Probing
                | AgentExecutionState::Running
                | AgentExecutionState::Failed
                | AgentExecutionState::Cancelled
        ),
        AgentExecutionState::Running => matches!(
            next,
            AgentExecutionState::Running
                | AgentExecutionState::Blocked
                | AgentExecutionState::Completed
                | AgentExecutionState::Failed
                | AgentExecutionState::Cancelled
                | AgentExecutionState::Indeterminate
        ),
        AgentExecutionState::Completed
        | AgentExecutionState::Failed
        | AgentExecutionState::Cancelled
        | AgentExecutionState::Indeterminate => false,
    };
    if !allowed {
        return Err(journal_error(
            "AGENT_JOURNAL_INVALID_TRANSITION",
            "agent execution state transition is not permitted",
        ));
    }
    Ok(())
}

fn progress_kind_for_execution(
    execution: &AgentExecutionV2,
) -> CoreResult<AgentJournalProgressKind> {
    Ok(match execution.state {
        AgentExecutionState::Queued => {
            return Err(journal_error(
                "AGENT_JOURNAL_INVALID_TRANSITION",
                "execution cannot transition back to queued",
            ))
        }
        AgentExecutionState::Probing => AgentJournalProgressKind::Probing,
        AgentExecutionState::Blocked => AgentJournalProgressKind::Blocked,
        AgentExecutionState::Completed => AgentJournalProgressKind::Completed,
        AgentExecutionState::Failed => AgentJournalProgressKind::Failed,
        AgentExecutionState::Cancelled => AgentJournalProgressKind::Cancelled,
        AgentExecutionState::Indeterminate => AgentJournalProgressKind::Indeterminate,
        AgentExecutionState::Running => {
            let attempt = execution
                .active_attempt_id
                .as_ref()
                .and_then(|id| {
                    execution
                        .attempts
                        .iter()
                        .find(|attempt| &attempt.attempt_id == id)
                })
                .ok_or_else(|| {
                    journal_error(
                        "AGENT_JOURNAL_EXECUTION_INVALID",
                        "running execution has no active attempt",
                    )
                })?;
            match attempt.state {
                AgentAttemptState::Starting => AgentJournalProgressKind::Starting,
                AgentAttemptState::RepairingOutput => AgentJournalProgressKind::RepairingOutput,
                AgentAttemptState::Running => AgentJournalProgressKind::Running,
                _ => {
                    return Err(journal_error(
                        "AGENT_JOURNAL_EXECUTION_INVALID",
                        "running execution has an incompatible attempt state",
                    ))
                }
            }
        }
    })
}

fn validate_next_sequence(entry: &AgentExecutionJournalEntry, sequence: u64) -> CoreResult<()> {
    let expected = entry.last_progress_sequence.checked_add(1).ok_or_else(|| {
        journal_error(
            "AGENT_JOURNAL_SEQUENCE_EXHAUSTED",
            "agent progress sequence is exhausted",
        )
    })?;
    if sequence != expected {
        return Err(journal_error(
            "AGENT_JOURNAL_SEQUENCE_MISMATCH",
            "agent progress sequence must be exactly monotonic",
        ));
    }
    Ok(())
}

fn validate_document(document: &AgentExecutionJournalDocument) -> CoreResult<()> {
    if document.schema_version != AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION {
        return Err(journal_error(
            "AGENT_JOURNAL_SCHEMA_UNSUPPORTED",
            "durable agent journal schema version is unsupported",
        ));
    }
    if document.entries.len() > MAX_AGENT_JOURNAL_REQUESTS {
        return Err(journal_capacity_error(
            "durable agent journal exceeds its maximum request entries",
        ));
    }
    let pending_count = document
        .entries
        .iter()
        .filter(|entry| entry.pending_delivery.is_some())
        .count();
    if pending_count > MAX_AGENT_JOURNAL_PENDING_DELIVERIES {
        return Err(journal_capacity_error(
            "durable agent journal exceeds its maximum pending deliveries",
        ));
    }
    for (index, entry) in document.entries.iter().enumerate() {
        validate_entry(entry)?;
        if document.entries[..index].iter().any(|candidate| {
            candidate.request_id == entry.request_id
                || candidate.idempotency_key == entry.idempotency_key
                || candidate.execution_id == entry.execution_id
        }) {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable agent journal contains duplicate immutable identities",
            ));
        }
    }
    Ok(())
}

fn read_existing_document(path: &Path) -> CoreResult<AgentExecutionJournalDocument> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_READ_FAILED",
            &format!("failed to inspect durable agent journal during recovery: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(journal_error(
            "AGENT_JOURNAL_INSECURE",
            "durable agent journal must be a regular non-symlink file",
        ));
    }
    validate_owned_regular_file(&metadata)?;
    if metadata.len() > MAX_AGENT_JOURNAL_BYTES {
        return Err(journal_capacity_error(
            "durable agent journal exceeds its maximum file size",
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_READ_FAILED",
            &format!("failed to read durable agent journal during recovery: {error}"),
        )
    })?;
    let document: AgentExecutionJournalDocument = serde_json::from_slice(&bytes).map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "durable agent journal is not valid JSON during recovery",
        )
    })?;
    validate_document(&document)?;
    Ok(document)
}

fn validate_entry(entry: &AgentExecutionJournalEntry) -> CoreResult<()> {
    validate_safe_identity("request id", &entry.request_id)?;
    validate_safe_identity("idempotency key", &entry.idempotency_key)?;
    normalize_payload_digest(&entry.payload_digest)?;
    if entry.attempt_claims.len() > MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST {
        return Err(journal_capacity_error(
            "agent execution exceeds its maximum durable attempt claims",
        ));
    }
    validate_agent_attempt_capacity(entry.attempts.len())?;
    let mut attempt_claim_ids = std::collections::BTreeSet::new();
    let mut attempt_numbers = std::collections::BTreeSet::new();
    let mut task_idempotency_keys = std::collections::BTreeSet::new();
    let mut delivery_idempotency_keys = std::collections::BTreeSet::new();
    let mut payload_digests = std::collections::BTreeSet::new();
    for attempt_claim in &entry.attempt_claims {
        validate_safe_identity("attempt id", &attempt_claim.attempt_id)?;
        normalize_payload_digest(&attempt_claim.payload_digest)?;
        validate_agent_attempt_task_idempotency_key(&attempt_claim.task_idempotency_key)
            .map_err(|_| journal_error("AGENT_JOURNAL_CORRUPT", "invalid process task key"))?;
        validate_agent_attempt_delivery_idempotency_key(&attempt_claim.delivery_idempotency_key)
            .map_err(|_| journal_error("AGENT_JOURNAL_CORRUPT", "invalid process delivery key"))?;
        if attempt_claim.attempt_number == 0
            || !attempt_claim_ids.insert(attempt_claim.attempt_id.as_str())
            || !attempt_numbers.insert(attempt_claim.attempt_number)
            || !task_idempotency_keys.insert(attempt_claim.task_idempotency_key.as_str())
            || !delivery_idempotency_keys.insert(attempt_claim.delivery_idempotency_key.as_str())
            || !payload_digests.insert(attempt_claim.payload_digest.as_str())
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable journal contains invalid or duplicate process attempt claims",
            ));
        }
    }
    if attempt_numbers
        .iter()
        .copied()
        .ne(1..=u32::try_from(attempt_numbers.len()).unwrap_or(u32::MAX))
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "durable process attempt numbers are not contiguous",
        ));
    }
    validate_attempt_claim_chain(&entry.attempt_claims, &entry.binding, &entry.delivery_route)?;
    validate_binding(&entry.binding)?;
    if let AgentDeliveryRoute::RunnerJob {
        job_id,
        predecessor_job_id,
    } = &entry.delivery_route
    {
        validate_safe_identity("runner job id", job_id)?;
        if let Some(predecessor_job_id) = predecessor_job_id {
            validate_safe_identity("predecessor runner job id", predecessor_job_id)?;
        }
    }
    validate_safe_identity("execution id", &entry.execution_id)?;
    validate_safe_timestamp(&entry.created_at)?;
    validate_safe_timestamp(&entry.updated_at)?;
    if entry.claimed_at_epoch_ms == 0
        || entry.last_progress_sequence == 0
        || entry.progress.is_empty()
        || entry.progress.len() > MAX_PROGRESS_EVENTS
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "durable agent journal entry has invalid progress metadata",
        ));
    }
    let mut previous = 0;
    for event in &entry.progress {
        if event.sequence <= previous || event.recorded_at_epoch_ms == 0 {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable agent journal progress sequence is not monotonic",
            ));
        }
        previous = event.sequence;
    }
    if previous != entry.last_progress_sequence {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "durable agent journal last sequence does not match progress",
        ));
    }
    if entry
        .terminal_delivery_acknowledged_sequence
        .is_some_and(|sequence| {
            sequence != entry.last_progress_sequence
                || !is_immutable_terminal_entry(entry)
                || entry.pending_delivery.is_some()
        })
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "terminal delivery acknowledgement metadata is inconsistent",
        ));
    }
    if let Some(pending) = &entry.pending_delivery {
        let bytes = serde_json::to_vec(&pending.payload).map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "pending protocol delivery could not be serialized",
            )
        })?;
        if bytes.len() > MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES {
            return Err(journal_capacity_error(
                "pending protocol delivery exceeds its maximum size",
            ));
        }
        validate_pending_delivery(entry, pending)?;
    }
    if let Some(checkpoint) = &entry.session_checkpoint {
        checkpoint.validate().map_err(|_| {
            journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable session checkpoint is invalid",
            )
        })?;
        validate_checkpoint_identity(entry, checkpoint, false)?;
    }
    if let Some(error) = &entry.error {
        let canonical = canonicalize_error(error)?;
        if &canonical != error {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable error contains non-canonical diagnostic data",
            ));
        }
    }
    if let Some(cancellation) = &entry.cancellation {
        validate_safe_identity(
            "cancellation idempotency key",
            &cancellation.idempotency_key,
        )?;
        if cancellation.requested_at_epoch_ms == 0
            || cancellation.sequence == 0
            || cancellation.sequence > entry.last_progress_sequence
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable cancellation sequence or timestamp is invalid",
            ));
        }
        if let Some(directive) = &cancellation.runner_directive {
            validate_safe_identity("backend cancellation id", &directive.cancellation_id)?;
            validate_safe_identity("runner job id", &directive.job_id)?;
            validate_safe_identity("process attempt id", &directive.process_attempt_id)?;
            validate_safe_timestamp(&directive.requested_at)?;
            if directive.lease_version == 0
                || directive.binding_generation == 0
                || directive.binding_generation != entry.binding.workspace_binding_generation
                || !matches!(
                    &entry.delivery_route,
                    AgentDeliveryRoute::RunnerJob {
                        job_id: owned_job_id,
                        ..
                    } if owned_job_id == &directive.job_id
                )
                || !entry
                    .attempt_claims
                    .iter()
                    .any(|claim| claim.attempt_id == directive.process_attempt_id)
            {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable runner cancellation identity is invalid",
                ));
            }
        }
    }
    for attempt in &entry.attempts {
        validate_safe_identity("attempt id", &attempt.attempt_id)?;
        validate_safe_timestamp(&attempt.started_at)?;
        if validate_agent_attempt_task_idempotency_key(&attempt.task_idempotency_key).is_err()
            || validate_agent_attempt_delivery_idempotency_key(&attempt.delivery_idempotency_key)
                .is_err()
            || normalize_payload_digest(&attempt.payload_digest).is_err()
            || attempt.attempt_number == 0
            || attempt.started_sequence == 0
            || attempt.started_sequence > entry.last_progress_sequence
            || attempt.finished_sequence.is_some_and(|sequence| {
                sequence <= attempt.started_sequence || sequence > entry.last_progress_sequence
            })
            || attempt.state.is_terminal() != attempt.finished_sequence.is_some()
            || !attempt.delivery.is_valid_for_binding(&entry.binding)
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable process attempt lifecycle or delivery metadata is invalid",
            ));
        }
        if !entry.attempt_claims.iter().any(|claim| {
            claim.attempt_id == attempt.attempt_id
                && claim.attempt_number == attempt.attempt_number
                && claim.task_idempotency_key == attempt.task_idempotency_key
                && claim.delivery_idempotency_key == attempt.delivery_idempotency_key
                && claim.payload_digest == attempt.payload_digest
        }) {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable process attempt has no matching dispatch claim",
            ));
        }
        validate_optional_model_identity(
            &attempt.requested_model_key,
            &attempt.requested_provider_model_id,
        )?;
        validate_optional_model_identity(
            &attempt.resolved_model_key,
            &attempt.resolved_provider_model_id,
        )?;
        if let Some(session) = &attempt.session {
            session.validate().map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable per-attempt session checkpoint is invalid",
                )
            })?;
            if session.execution_id != entry.execution_id
                || session.attempt_id != attempt.attempt_id
                || session.binding != entry.binding
                || session.executor != attempt.executor
                || session.provider != attempt.provider
                || session.model_key != attempt.resolved_model_key
                || session.provider_model_id != attempt.resolved_provider_model_id
            {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable per-attempt session checkpoint does not match its attempt",
                ));
            }
        }
        if let Some(error) = &attempt.error {
            let canonical = canonicalize_error(error)?;
            if &canonical != error {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable attempt error contains non-canonical diagnostic data",
                ));
            }
        }
    }
    let mut ordered_attempts: Vec<&PersistedAgentAttempt> = entry.attempts.iter().collect();
    ordered_attempts.sort_by_key(|attempt| attempt.attempt_number);
    for (index, attempt) in ordered_attempts.iter().enumerate() {
        if attempt.attempt_number as usize != index + 1 {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable process attempt numbers are not contiguous",
            ));
        }
        match (index, &attempt.retry) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable process attempt retry metadata is incomplete",
                ))
            }
            (_, Some(retry)) if ordered_attempts[index - 1].attempt_id == retry.from_attempt_id => {
            }
            _ => {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "durable process attempt retry predecessor is invalid",
                ))
            }
        }
    }
    Ok(())
}

fn validate_agent_attempt_capacity(attempt_count: usize) -> CoreResult<()> {
    if attempt_count > MAX_AGENT_JOURNAL_ATTEMPTS_PER_REQUEST {
        return Err(journal_capacity_error(
            "agent execution exceeds its maximum durable attempts",
        ));
    }
    Ok(())
}

fn validate_pending_delivery(
    entry: &AgentExecutionJournalEntry,
    pending: &AgentPendingDelivery,
) -> CoreResult<()> {
    if pending.sequence == 0 {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "pending delivery sequence must be positive",
        ));
    }
    let event = entry
        .progress
        .iter()
        .find(|event| event.sequence == pending.sequence)
        .ok_or_else(|| {
            journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "pending delivery has no matching durable progress event",
            )
        })?;
    match pending.kind {
        AgentPendingDeliveryKind::Checkpoint => {
            if event.kind != AgentJournalProgressKind::SessionCheckpointed {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "checkpoint delivery sequence does not identify a checkpoint event",
                ));
            }
            let checkpoint: AgentSessionCheckpointV2 =
                serde_json::from_value(pending.payload.clone()).map_err(|_| {
                    journal_error(
                        "AGENT_JOURNAL_CORRUPT",
                        "pending checkpoint delivery is not a checkpoint v2 payload",
                    )
                })?;
            checkpoint.validate().map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "pending checkpoint delivery failed protocol validation",
                )
            })?;
            if entry.session_checkpoint.as_ref() != Some(&checkpoint) {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "pending checkpoint delivery does not match durable session state",
                ));
            }
        }
        AgentPendingDeliveryKind::Execution
        | AgentPendingDeliveryKind::Deferred
        | AgentPendingDeliveryKind::Terminal => {
            let kind_matches_state = match pending.kind {
                AgentPendingDeliveryKind::Execution => {
                    !entry.state.is_terminal() && entry.state != AgentExecutionState::Blocked
                }
                AgentPendingDeliveryKind::Deferred => entry.state == AgentExecutionState::Blocked,
                AgentPendingDeliveryKind::Terminal => entry.state.is_terminal(),
                AgentPendingDeliveryKind::Checkpoint => unreachable!(),
            };
            if !kind_matches_state {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "execution delivery kind does not match durable execution state",
                ));
            }
            let expected_kind = match entry.state {
                AgentExecutionState::Queued => AgentJournalProgressKind::Claimed,
                AgentExecutionState::Probing => AgentJournalProgressKind::Probing,
                AgentExecutionState::Running => event.kind,
                AgentExecutionState::Blocked => AgentJournalProgressKind::Blocked,
                AgentExecutionState::Completed => AgentJournalProgressKind::Completed,
                AgentExecutionState::Failed => AgentJournalProgressKind::Failed,
                AgentExecutionState::Cancelled => AgentJournalProgressKind::Cancelled,
                AgentExecutionState::Indeterminate => AgentJournalProgressKind::Indeterminate,
            };
            if event.kind != expected_kind {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "terminal delivery sequence does not identify its terminal event",
                ));
            }
            let execution: AgentExecutionV2 = serde_json::from_value(pending.payload.clone())
                .map_err(|_| {
                    journal_error(
                        "AGENT_JOURNAL_CORRUPT",
                        "pending execution delivery is not an agent execution v2 payload",
                    )
                })?;
            execution.validate().map_err(|_| {
                journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "pending execution delivery failed protocol validation",
                )
            })?;
            if execution.request_id != entry.request_id
                || execution.execution_id != entry.execution_id
                || execution.idempotency_key != entry.idempotency_key
                || execution.binding != entry.binding
                || execution.state != entry.state
            {
                return Err(journal_error(
                    "AGENT_JOURNAL_CORRUPT",
                    "pending execution delivery identity does not match durable execution",
                ));
            }
        }
    }
    Ok(())
}

fn validate_attempt_history(
    entry: &AgentExecutionJournalEntry,
    execution: &AgentExecutionV2,
) -> CoreResult<()> {
    if execution.attempts.len() < entry.attempts.len()
        || execution.attempts.len() > entry.attempts.len() + 1
    {
        return Err(journal_error(
            "AGENT_JOURNAL_ATTEMPT_HISTORY_REWRITTEN",
            "agent process attempt history is not append-only",
        ));
    }
    for previous in &entry.attempts {
        let next = execution
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == previous.attempt_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_ATTEMPT_HISTORY_REWRITTEN",
                    "a durable process attempt disappeared from execution history",
                )
            })?;
        let immutable_changed = previous.attempt_number != next.attempt_number
            || previous.task_idempotency_key != next.task_idempotency_key
            || previous.delivery_idempotency_key != next.delivery_idempotency_key
            || previous.payload_digest != next.payload_digest
            || previous.started_sequence != next.started_sequence
            || previous.selection_index != next.selection_index
            || previous.executor != next.executor
            || previous.provider != next.provider
            || previous.requested_model_key != next.requested_model_key
            || previous.requested_provider_model_id != next.requested_provider_model_id
            || previous.resolved_model_key != next.resolved_model_key
            || previous.resolved_provider_model_id != next.resolved_provider_model_id
            || previous.started_at != next.started_at
            || previous.retry != next.retry
            || previous.delivery != next.delivery;
        let terminal_changed = previous.state.is_terminal()
            && (previous.state != next.state
                || previous.finished_sequence != next.finished_sequence
                || previous.finished_at != next.finished_at
                || previous.session != next.session
                || previous.error != next.error);
        if immutable_changed || terminal_changed {
            return Err(journal_error(
                "AGENT_JOURNAL_ATTEMPT_HISTORY_REWRITTEN",
                "durable process attempt identity, retry, delivery, or terminal history changed",
            ));
        }
    }
    if let Some(new_attempt) = execution.attempts.iter().find(|attempt| {
        !entry
            .attempts
            .iter()
            .any(|previous| previous.attempt_id == attempt.attempt_id)
    }) {
        let claim = entry
            .attempt_claims
            .iter()
            .find(|claim| claim.attempt_id == new_attempt.attempt_id)
            .ok_or_else(|| {
                journal_error(
                    "AGENT_JOURNAL_ATTEMPT_NOT_CLAIMED",
                    "process attempt must be durably claimed before it appears in execution history",
                )
            })?;
        let retry_matches = match (&new_attempt.retry, claim.retry_kind) {
            (None, loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial) => {
                claim.from_attempt_id.is_none()
            }
            (Some(retry), retry_kind) => {
                retry.retry_kind == retry_kind
                    && Some(retry.from_attempt_id.as_str()) == claim.from_attempt_id.as_deref()
            }
            _ => false,
        };
        if claim.attempt_number != new_attempt.attempt_number
            || claim.task_idempotency_key != new_attempt.task_idempotency_key
            || claim.delivery_idempotency_key != new_attempt.delivery_idempotency_key
            || claim.payload_digest != new_attempt.payload_digest
            || claim.delivery != new_attempt.delivery
            || !retry_matches
            || new_attempt.delivery
                != process_delivery_for_route(&entry.delivery_route, &entry.binding)
        {
            return Err(journal_error(
                "AGENT_JOURNAL_ATTEMPT_CLAIM_MISMATCH",
                "process attempt does not match its durable dispatch identity and delivery owner",
            ));
        }
    }
    Ok(())
}

fn process_delivery_for_route(
    route: &AgentDeliveryRoute,
    binding: &AgentExecutionBindingV2,
) -> AgentProcessDeliveryV2 {
    match route {
        AgentDeliveryRoute::DirectHuman => AgentProcessDeliveryV2 {
            route: loomex_protocol::agent_runtime_v2::AgentDeliveryRouteV2::DirectControl,
            runner_job_id: None,
            lease_target_runner_id: None,
        },
        AgentDeliveryRoute::RunnerJob { job_id, .. } => AgentProcessDeliveryV2 {
            route: loomex_protocol::agent_runtime_v2::AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(job_id.clone()),
            lease_target_runner_id: Some(binding.runner_id.clone()),
        },
    }
}

fn validate_binding(binding: &AgentExecutionBindingV2) -> CoreResult<()> {
    if !binding.is_valid() {
        return Err(journal_error(
            "AGENT_JOURNAL_BINDING_INVALID",
            "agent execution binding is invalid",
        ));
    }
    validate_safe_identity("workspace binding id", &binding.workspace_binding_id)?;
    validate_safe_identity("runner id", &binding.runner_id)
}

fn validate_safe_identity(label: &str, value: &str) -> CoreResult<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        });
    if !valid {
        return Err(journal_error(
            "AGENT_JOURNAL_UNSAFE_METADATA",
            &format!("{label} is not an allowlisted non-secret identifier"),
        ));
    }
    Ok(())
}

fn validate_agent_control_idempotency_key(value: &str) -> CoreResult<()> {
    loomex_protocol::agent_runtime_v2::validate_idempotency_key(value).map_err(|_| {
        journal_error(
            "IDEMPOTENCY_KEY_INVALID",
            "agent control idempotency key must use the protocol-safe grammar and not exceed 160 bytes",
        )
    })
}

fn validate_optional_model_identity(
    model_key: &Option<String>,
    provider_model_id: &Option<String>,
) -> CoreResult<()> {
    match (model_key.as_deref(), provider_model_id.as_deref()) {
        (None, None) => Ok(()),
        (Some(model_key), Some(provider_model_id)) => {
            validate_safe_identity("model key", model_key)?;
            validate_safe_identity("provider model id", provider_model_id)
        }
        _ => Err(journal_error(
            "AGENT_JOURNAL_MODEL_IDENTITY_INVALID",
            "model key and provider model id must both be present or both be absent",
        )),
    }
}

fn validate_safe_timestamp(value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'T' | b'Z' | b'+' | b'_')
        })
    {
        return Err(journal_error(
            "AGENT_JOURNAL_UNSAFE_METADATA",
            "timestamp is not an allowlisted RFC 3339 scalar",
        ));
    }
    Ok(())
}

fn normalize_payload_digest(value: &str) -> CoreResult<String> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(journal_error(
            "AGENT_JOURNAL_DIGEST_INVALID",
            "payload digest must be a SHA-256 hexadecimal digest",
        ));
    }
    Ok(format!("sha256:{}", digest.to_ascii_lowercase()))
}

fn trim_progress(progress: &mut Vec<AgentJournalProgress>) {
    if progress.len() > MAX_PROGRESS_EVENTS {
        let excess = progress.len() - MAX_PROGRESS_EVENTS;
        progress.drain(..excess);
    }
}

fn ensure_private_permissions(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_READ_FAILED",
                &format!("failed to inspect durable agent journal: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(journal_error(
                "AGENT_JOURNAL_INSECURE",
                "durable agent journal must be a regular non-symlink file",
            ));
        }
        validate_owned_regular_file(&metadata)?;
        if metadata.mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
                journal_error(
                    "AGENT_JOURNAL_PERMISSION_FAILED",
                    &format!("failed to restrict durable agent journal permissions: {error}"),
                )
            })?;
        }
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

pub fn agent_journal_capacity_error_envelope() -> AgentRuntimeErrorEnvelopeV2 {
    AgentRuntimeErrorEnvelopeV2 {
        schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
        code: AgentErrorCode::InternalError,
        category: AgentErrorCode::InternalError.category(),
        message: "The local agent execution journal reached its safe capacity limit.".to_string(),
        retry: AgentRetryDisposition::UserActionRequired,
        retry_after_seconds: None,
        remediation: vec![AgentRemediationAction::ContactSupport],
        context: AgentErrorContext::default(),
    }
}

fn journal_capacity_error(message: &'static str) -> CoreError {
    CoreError::new("AGENT_JOURNAL_CAPACITY_EXCEEDED", message)
}

fn validate_new_pending_delivery_capacity(
    document: &AgentExecutionJournalDocument,
    delivery: &AgentPendingDelivery,
) -> CoreResult<()> {
    let pending_count = document
        .entries
        .iter()
        .filter(|entry| entry.pending_delivery.is_some())
        .count();
    if pending_count >= MAX_AGENT_JOURNAL_PENDING_DELIVERIES {
        return Err(journal_capacity_error(
            "durable agent journal reached its maximum pending deliveries",
        ));
    }
    let bytes = serde_json::to_vec(&delivery.payload).map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_DELIVERY_INVALID",
            "pending protocol delivery could not be serialized",
        )
    })?;
    if bytes.len() > MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES {
        return Err(journal_capacity_error(
            "pending protocol delivery exceeds its maximum size",
        ));
    }
    Ok(())
}

fn validate_owned_regular_file(metadata: &fs::Metadata) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and does not dereference memory.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(journal_error(
                "AGENT_JOURNAL_INSECURE",
                "durable agent journal must be owned by the current user",
            ));
        }
    }
    Ok(())
}

fn validate_journal_parent(parent: &Path) -> CoreResult<()> {
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_WRITE_FAILED",
            &format!("failed to inspect durable journal directory: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(journal_error(
            "AGENT_JOURNAL_INSECURE",
            "durable agent journal parent must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and does not dereference memory.
        let owned = metadata.uid() == unsafe { libc::geteuid() };
        let sticky_shared = metadata.mode() & 0o1000 != 0;
        if !owned && !sticky_shared {
            return Err(journal_error(
                "AGENT_JOURNAL_INSECURE",
                "durable agent journal parent is not controlled by the current user",
            ));
        }
    }
    Ok(())
}

fn validate_replace_destination(path: &Path) -> CoreResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(journal_error(
                    "AGENT_JOURNAL_INSECURE",
                    "durable agent journal destination must be a regular non-symlink file",
                ));
            }
            validate_owned_regular_file(&metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(journal_error(
            "AGENT_JOURNAL_WRITE_FAILED",
            &format!("failed to inspect durable journal destination: {error}"),
        )),
    }
}

fn ensure_owned_private_directory(path: &Path) -> CoreResult<()> {
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(journal_error(
                    "AGENT_JOURNAL_INSECURE",
                    "agent tombstone archive component must be a non-symlink directory",
                ));
            }
            validate_owned_archive_directory(path, &metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| {
                journal_error(
                    "AGENT_JOURNAL_WRITE_FAILED",
                    &format!("failed to create private agent tombstone directory: {error}"),
                )
            })?;
            created = true;
        }
        Err(error) => {
            return Err(journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to inspect private agent tombstone directory: {error}"),
            ))
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_PERMISSION_FAILED",
                &format!("failed to restrict agent tombstone directory permissions: {error}"),
            )
        })?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_WRITE_FAILED",
            &format!("failed to inspect private agent tombstone directory: {error}"),
        )
    })?;
    validate_private_archive_directory(path, &metadata)?;
    if created {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        sync_directory(parent).map_err(|error| {
            journal_error(
                "AGENT_JOURNAL_WRITE_FAILED",
                &format!("failed to sync agent tombstone parent directory: {error}"),
            )
        })?;
    }
    Ok(())
}

fn validate_private_archive_directory(path: &Path, metadata: &fs::Metadata) -> CoreResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(journal_error(
            "AGENT_JOURNAL_INSECURE",
            "agent tombstone archive component must be a non-symlink directory",
        ));
    }
    validate_owned_archive_directory(path, metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(journal_error(
                "AGENT_JOURNAL_INSECURE",
                "agent tombstone archive directory permissions are not private",
            ));
        }
    }
    Ok(())
}

fn validate_owned_archive_directory(path: &Path, metadata: &fs::Metadata) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and does not dereference memory.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(journal_error(
                "AGENT_JOURNAL_INSECURE",
                &format!(
                    "agent tombstone archive directory is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_private_archive_file(
    path: &Path,
    metadata: &fs::Metadata,
    expected_max_bytes: u64,
) -> CoreResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(journal_error(
            "AGENT_JOURNAL_INSECURE",
            "agent tombstone archive record must be a regular non-symlink file",
        ));
    }
    validate_owned_regular_file(metadata)?;
    if metadata.len() > expected_max_bytes {
        return Err(journal_capacity_error(
            "agent tombstone archive record exceeds its maximum size",
        ));
    }
    ensure_private_permissions(path)
}

fn read_private_archive_index(path: &Path) -> CoreResult<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None)
        }
        Err(error) => {
            return Err(journal_error(
                "AGENT_JOURNAL_READ_FAILED",
                &format!("failed to inspect agent tombstone index: {error}"),
            ))
        }
    };
    validate_private_archive_file(path, &metadata, 64)?;
    if metadata.len() != 64 {
        return Err(journal_error(
            "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
            "agent tombstone index has an invalid record hash",
        ));
    }
    let value = fs::read_to_string(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_READ_FAILED",
            &format!("failed to read agent tombstone index: {error}"),
        )
    })?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(journal_error(
            "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
            "agent tombstone index has an invalid record hash",
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn read_private_tombstone(path: &Path) -> CoreResult<AgentExecutionTombstone> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_READ_FAILED",
            &format!("failed to inspect agent tombstone record: {error}"),
        )
    })?;
    validate_private_archive_file(path, &metadata, MAX_AGENT_TOMBSTONE_BYTES)?;
    let bytes = fs::read(path).map_err(|error| {
        journal_error(
            "AGENT_JOURNAL_READ_FAILED",
            &format!("failed to read agent tombstone record: {error}"),
        )
    })?;
    let tombstone: AgentExecutionTombstone = serde_json::from_slice(&bytes).map_err(|_| {
        journal_error(
            "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
            "agent tombstone record is not valid JSON",
        )
    })?;
    validate_tombstone(&tombstone)?;
    Ok(tombstone)
}

fn validate_tombstone(tombstone: &AgentExecutionTombstone) -> CoreResult<()> {
    if tombstone.schema_version != AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION
        || !matches!(
            tombstone.terminal_state,
            AgentExecutionState::Completed
                | AgentExecutionState::Failed
                | AgentExecutionState::Cancelled
                | AgentExecutionState::Indeterminate
        )
        || tombstone.terminal_sequence == 0
        || tombstone.terminal_delivery_acknowledged_sequence != tombstone.terminal_sequence
        || tombstone.resumable
        || tombstone.attempt_claims.is_empty()
        || tombstone.attempt_claims.len() > MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST
    {
        return Err(journal_error(
            "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
            "agent execution tombstone has invalid terminal metadata",
        ));
    }
    validate_safe_identity("request id", &tombstone.request_id)?;
    validate_safe_identity("idempotency key", &tombstone.idempotency_key)?;
    validate_safe_identity("execution id", &tombstone.execution_id)?;
    if let Some(cancellation_idempotency_key) = &tombstone.cancellation_idempotency_key {
        validate_safe_identity("cancellation idempotency key", cancellation_idempotency_key)?;
    }
    if let Some(operation_idempotency_key) = &tombstone.cancellation_control_idempotency_key {
        validate_agent_control_idempotency_key(operation_idempotency_key)?;
    }
    normalize_payload_digest(&tombstone.task_intent_digest)?;
    validate_binding(&tombstone.binding)?;
    if let AgentDeliveryRoute::RunnerJob {
        job_id,
        predecessor_job_id,
    } = &tombstone.delivery_route
    {
        validate_safe_identity("runner job id", job_id)?;
        if let Some(predecessor_job_id) = predecessor_job_id {
            validate_safe_identity("predecessor runner job id", predecessor_job_id)?;
        }
    }
    if let Some(finished_at) = &tombstone.finished_at {
        validate_safe_timestamp(finished_at)?;
    }
    let mut attempt_ids = std::collections::BTreeSet::new();
    let mut task_keys = std::collections::BTreeSet::new();
    let mut delivery_keys = std::collections::BTreeSet::new();
    for claim in &tombstone.attempt_claims {
        validate_safe_identity("attempt id", &claim.attempt_id)?;
        if claim.attempt_number == 0
            || claim.attempt_number as usize > MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST
            || validate_agent_attempt_task_idempotency_key(&claim.task_idempotency_key).is_err()
            || validate_agent_attempt_delivery_idempotency_key(&claim.delivery_idempotency_key)
                .is_err()
        {
            return Err(journal_error(
                "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
                "agent tombstone contains invalid process identity metadata",
            ));
        }
        normalize_payload_digest(&claim.payload_digest)?;
        if !attempt_ids.insert(claim.attempt_id.as_str())
            || !task_keys.insert(claim.task_idempotency_key.as_str())
            || !delivery_keys.insert(claim.delivery_idempotency_key.as_str())
        {
            return Err(journal_error(
                "AGENT_JOURNAL_TOMBSTONE_CORRUPT",
                "agent tombstone contains duplicate process identity metadata",
            ));
        }
    }
    validate_attempt_claim_chain(
        &tombstone.attempt_claims,
        &tombstone.binding,
        &tombstone.delivery_route,
    )?;
    Ok(())
}

fn validate_attempt_claim_chain(
    claims: &[PersistedAgentAttemptClaim],
    binding: &AgentExecutionBindingV2,
    current_route: &AgentDeliveryRoute,
) -> CoreResult<()> {
    let mut ordered: Vec<&PersistedAgentAttemptClaim> = claims.iter().collect();
    ordered.sort_by_key(|claim| claim.attempt_number);
    for (index, claim) in ordered.iter().enumerate() {
        if claim.attempt_number as usize != index + 1
            || !claim.delivery.is_valid_for_binding(binding)
        {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable process claim has invalid attempt numbering or delivery ownership",
            ));
        }
        let retry_valid = if index == 0 {
            claim.retry_kind == loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial
                && claim.from_attempt_id.is_none()
        } else {
            claim.retry_kind != loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial
                && claim.from_attempt_id.as_deref() == Some(ordered[index - 1].attempt_id.as_str())
        };
        if !retry_valid {
            return Err(journal_error(
                "AGENT_JOURNAL_CORRUPT",
                "durable process claim retry predecessor chain is invalid",
            ));
        }
    }
    if ordered
        .last()
        .is_some_and(|claim| claim.delivery != process_delivery_for_route(current_route, binding))
    {
        return Err(journal_error(
            "AGENT_JOURNAL_CORRUPT",
            "current durable delivery route does not match the latest digest-bound process claim",
        ));
    }
    Ok(())
}

fn tombstone_record_hash(tombstone: &AgentExecutionTombstone) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tombstone.request_id.as_bytes());
    hasher.update([0]);
    hasher.update(tombstone.idempotency_key.as_bytes());
    hasher.update([0]);
    hasher.update(tombstone.execution_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn journal_error(code: &'static str, message: &str) -> CoreError {
    CoreError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loomex_protocol::agent_runtime_v2::{
        AgentAttemptV2, AgentDeliveryRouteV2, AgentErrorCategory, AgentErrorContext, AgentOutput,
        AgentOutputFormat, AgentRemediationAction, AgentRetryDisposition,
        AGENT_EXECUTION_SCHEMA_V2, AGENT_SESSION_SCHEMA_V2,
    };
    use loomex_protocol::{validate_agent_terminal_output, AGENT_TERMINAL_OUTPUT_MAX_BYTES};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn journal_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "loomex-agent-journal-{label}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn cleanup_journal_artifacts(journal: &AgentExecutionJournal) {
        if journal.path.exists() {
            fs::remove_file(&journal.path).unwrap();
        }
        let tombstone_root = journal.tombstone_root();
        if tombstone_root.exists() {
            fs::remove_dir_all(tombstone_root).unwrap();
        }
    }

    fn tombstone_for_claim(
        process_claim: &AgentExecutionClaim,
        terminal_state: AgentExecutionState,
    ) -> AgentExecutionTombstone {
        AgentExecutionTombstone {
            schema_version: AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION.to_string(),
            request_id: process_claim.request_id.clone(),
            idempotency_key: process_claim.idempotency_key.clone(),
            task_intent_digest: normalize_payload_digest(&process_claim.task_intent_digest)
                .unwrap(),
            attempt_claims: vec![PersistedAgentAttemptClaim {
                attempt_id: process_claim.attempt_id.clone(),
                attempt_number: process_claim.attempt_number,
                retry_kind: process_claim.retry_kind,
                from_attempt_id: process_claim.from_attempt_id.clone(),
                delivery: process_claim.delivery.clone(),
                task_idempotency_key: process_claim.task_idempotency_key.clone(),
                delivery_idempotency_key: process_claim.delivery_idempotency_key.clone(),
                payload_digest: normalize_payload_digest(&process_claim.payload_digest).unwrap(),
            }],
            binding: process_claim.binding.clone(),
            delivery_route: process_claim.delivery_route.clone(),
            execution_id: process_claim.execution.execution_id.clone(),
            terminal_state,
            terminal_sequence: 3,
            terminal_delivery_acknowledged_sequence: 3,
            has_session_checkpoint: false,
            cancellation_idempotency_key: None,
            cancellation_control_idempotency_key: None,
            resumable: false,
            finished_at: Some("2026-07-26T10:00:03Z".to_string()),
        }
    }

    fn seed_tombstone_without_fsync(
        journal: &AgentExecutionJournal,
        tombstone: &AgentExecutionTombstone,
    ) {
        validate_tombstone(tombstone).unwrap();
        let record_hash = tombstone_record_hash(tombstone);
        let record_path = journal.tombstone_hashed_path("records", &record_hash, "json");
        let request_index = journal.tombstone_hashed_path(
            TombstoneIndexKind::Request.directory(),
            &sha256_hex(tombstone.request_id.as_bytes()),
            "idx",
        );
        let idempotency_index = journal.tombstone_hashed_path(
            TombstoneIndexKind::Idempotency.directory(),
            &sha256_hex(tombstone.idempotency_key.as_bytes()),
            "idx",
        );
        for path in [&record_path, &request_index, &idempotency_index] {
            journal
                .ensure_tombstone_parent(path.parent().unwrap())
                .unwrap();
        }
        fs::write(&record_path, serde_json::to_vec(tombstone).unwrap()).unwrap();
        fs::write(&request_index, record_hash.as_bytes()).unwrap();
        fs::write(&idempotency_index, record_hash.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&record_path, &request_index, &idempotency_index] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }

    fn binding() -> AgentExecutionBindingV2 {
        AgentExecutionBindingV2 {
            workspace_binding_id: "binding_123".to_string(),
            workspace_binding_generation: 7,
            runner_id: "runner_123".to_string(),
        }
    }

    fn queued_execution(request_id: &str) -> AgentExecutionV2 {
        AgentExecutionV2 {
            schema_version: AGENT_EXECUTION_SCHEMA_V2.to_string(),
            execution_id: format!("execution_{request_id}"),
            request_id: request_id.to_string(),
            idempotency_key: "idem_1".to_string(),
            sequence: 1,
            binding: binding(),
            state: AgentExecutionState::Queued,
            active_attempt_id: None,
            attempts: vec![],
            output: None,
            error: None,
            created_at: "2026-07-26T10:00:00Z".to_string(),
            started_at: None,
            finished_at: None,
            updated_at: "2026-07-26T10:00:00Z".to_string(),
        }
    }

    fn starting_execution(request_id: &str) -> AgentExecutionV2 {
        let mut execution = queued_execution(request_id);
        execution.state = AgentExecutionState::Running;
        execution.sequence = 2;
        execution.active_attempt_id = Some("attempt_1".to_string());
        execution.attempts = vec![AgentAttemptV2 {
            attempt_id: "attempt_1".to_string(),
            attempt_number: 1,
            task_idempotency_key: format!(
                "loomex-agent-attempt-v2:{}",
                &sha256_payload_digest(b"attempt_1")[7..]
            ),
            delivery_idempotency_key: format!(
                "loomex-agent-delivery-v2:{}",
                &sha256_payload_digest(b"delivery_1")[7..]
            ),
            payload_digest: sha256_payload_digest(b"canonical request"),
            state: AgentAttemptState::Starting,
            started_sequence: 2,
            finished_sequence: None,
            selection_index: 1,
            executor: ExecutorKind::CodexCli,
            provider: AgentProvider::OpenAi,
            requested_model_key: Some("openai/gpt-5.2".to_string()),
            requested_provider_model_id: Some("gpt-5.2".to_string()),
            resolved_model_key: Some("openai/gpt-5.2".to_string()),
            resolved_provider_model_id: Some("gpt-5.2".to_string()),
            started_at: "2026-07-26T10:00:01Z".to_string(),
            finished_at: None,
            session: None,
            retry: None,
            delivery: AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
            error: None,
        }];
        execution.started_at = Some("2026-07-26T10:00:01Z".to_string());
        execution.updated_at = "2026-07-26T10:00:01Z".to_string();
        execution
    }

    fn checkpoint(request_id: &str) -> AgentSessionCheckpointV2 {
        AgentSessionCheckpointV2 {
            schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: "checkpoint_1".to_string(),
            sequence: 3,
            session_id: "session_1".to_string(),
            provider_session_id: "provider-session_1".to_string(),
            binding: binding(),
            execution_id: format!("execution_{request_id}"),
            attempt_id: "attempt_1".to_string(),
            selection_index: 1,
            executor: ExecutorKind::CodexCli,
            provider: AgentProvider::OpenAi,
            model_key: Some("openai/gpt-5.2".to_string()),
            provider_model_id: Some("gpt-5.2".to_string()),
            state: AgentSessionState::Created,
            recorded_at: "2026-07-26T10:00:02Z".to_string(),
        }
    }

    fn claim(request_id: &str, idempotency_key: &str, payload: &[u8]) -> AgentExecutionClaim {
        let mut execution = queued_execution(request_id);
        execution.idempotency_key = idempotency_key.to_string();
        AgentExecutionClaim {
            request_id: request_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            attempt_id: "attempt_1".to_string(),
            attempt_number: 1,
            retry_kind: loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial,
            from_attempt_id: None,
            delivery: AgentProcessDeliveryV2 {
                route: AgentDeliveryRouteV2::DirectControl,
                runner_job_id: None,
                lease_target_runner_id: None,
            },
            task_idempotency_key: format!(
                "loomex-agent-attempt-v2:{}",
                &sha256_payload_digest(b"attempt_1")[7..]
            ),
            delivery_idempotency_key: format!(
                "loomex-agent-delivery-v2:{}",
                &sha256_payload_digest(b"delivery_1")[7..]
            ),
            task_intent_digest: sha256_payload_digest(payload),
            payload_digest: sha256_payload_digest(payload),
            binding: binding(),
            delivery_route: AgentDeliveryRoute::DirectHuman,
            execution,
            claimed_at_epoch_ms: 1_000,
        }
    }

    fn claim_and_start(path: &Path, request_id: &str) -> AgentExecutionJournal {
        let mut journal = AgentExecutionJournal::open(path).unwrap();
        journal
            .claim_before_spawn(claim(request_id, "idem_1", b"canonical request"))
            .unwrap();
        journal.acknowledge_delivery(request_id, 1).unwrap();
        journal
            .record_execution(request_id, 2, &starting_execution(request_id), 1_100)
            .unwrap();
        journal
    }

    #[test]
    fn delivery_route_is_atomically_fenced_with_the_execution_claim() {
        let path = journal_path("delivery-route-fence");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let direct = claim("request_route", "idem_route", b"canonical request");
        journal.claim_before_spawn(direct).unwrap();

        let mut runner = claim("request_route", "idem_route", b"canonical request");
        runner.delivery_route = AgentDeliveryRoute::RunnerJob {
            job_id: "job_route".to_string(),
            predecessor_job_id: None,
        };
        runner.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some("job_route".to_string()),
            lease_target_runner_id: Some(runner.binding.runner_id.clone()),
        };
        let error = journal.claim_before_spawn(runner).unwrap_err();
        assert_eq!(error.code, "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT");
        assert_eq!(
            journal.entry("request_route").unwrap().delivery_route,
            AgentDeliveryRoute::DirectHuman
        );

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        assert_eq!(
            reopened.entry("request_route").unwrap().delivery_route,
            AgentDeliveryRoute::DirectHuman
        );
        let mut runner_after_restart = claim("request_route", "idem_route", b"canonical request");
        runner_after_restart.delivery_route = AgentDeliveryRoute::RunnerJob {
            job_id: "job_route".to_string(),
            predecessor_job_id: None,
        };
        runner_after_restart.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some("job_route".to_string()),
            lease_target_runner_id: Some(runner_after_restart.binding.runner_id.clone()),
        };
        assert_eq!(
            reopened
                .claim_before_spawn(runner_after_restart)
                .unwrap_err()
                .code,
            "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runner_job_successor_requires_exact_predecessor_fresh_job_and_contiguous_attempt() {
        let path = journal_path("runner-job-successor-fence");
        let initial = runner_job_claim(
            "request_route",
            "idem_route",
            b"stable intent",
            "job_1",
            None,
        );
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal.claim_before_spawn(initial.clone()).unwrap();
        journal.acknowledge_delivery("request_route", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_route"), &initial);
        journal
            .record_execution("request_route", 2, &starting, 1_100)
            .unwrap();
        let blocked = blocked_execution_for_claim("request_route", &initial);
        journal
            .record_execution("request_route", 3, &blocked, 1_200)
            .unwrap();

        let mut wrong_predecessor = successor_claim(&initial, "job_2", "job_wrong");
        wrong_predecessor.task_intent_digest = initial.task_intent_digest.clone();
        assert_eq!(
            "AGENT_JOURNAL_RETRY_NOT_ALLOWED",
            journal
                .claim_before_spawn(wrong_predecessor)
                .unwrap_err()
                .code
        );
        let mut same_job = successor_claim(&initial, "job_1", "job_1");
        same_job.task_intent_digest = initial.task_intent_digest.clone();
        assert_eq!(
            "AGENT_JOURNAL_RETRY_NOT_ALLOWED",
            journal.claim_before_spawn(same_job).unwrap_err().code
        );
        let mut non_contiguous = successor_claim(&initial, "job_2", "job_1");
        non_contiguous.task_intent_digest = initial.task_intent_digest.clone();
        non_contiguous.attempt_number = 3;
        assert_eq!(
            "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
            journal.claim_before_spawn(non_contiguous).unwrap_err().code
        );

        let mut exact = successor_claim(&initial, "job_2", "job_1");
        exact.task_intent_digest = initial.task_intent_digest.clone();
        assert!(matches!(
            journal.claim_before_spawn(exact.clone()).unwrap(),
            AgentExecutionClaimOutcome::Claimed(_)
        ));
        assert!(matches!(
            journal.claim_before_spawn(exact).unwrap(),
            AgentExecutionClaimOutcome::Replay(_)
        ));
        assert_eq!(
            2,
            journal.entry("request_route").unwrap().attempt_claims.len()
        );
        assert_eq!(
            AgentDeliveryRoute::RunnerJob {
                job_id: "job_2".to_string(),
                predecessor_job_id: Some("job_1".to_string())
            },
            journal.entry("request_route").unwrap().delivery_route
        );
        cleanup_journal_artifacts(&journal);
    }

    #[test]
    fn runner_job_successor_handoff_survives_restart_and_requires_no_pending_delivery() {
        let path = journal_path("runner-job-successor-restart");
        let initial = runner_job_claim(
            "request_route",
            "idem_route",
            b"stable intent",
            "job_1",
            None,
        );
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal.claim_before_spawn(initial.clone()).unwrap();
        journal.acknowledge_delivery("request_route", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_route"), &initial);
        journal
            .record_execution("request_route", 2, &starting, 1_100)
            .unwrap();
        let blocked = blocked_execution_for_claim("request_route", &initial);
        journal
            .record_execution_with_delivery(
                "request_route",
                3,
                &blocked,
                serde_json::to_value(&blocked).unwrap(),
                1_200,
            )
            .unwrap();

        let mut exact = successor_claim(&initial, "job_2", "job_1");
        exact.task_intent_digest = initial.task_intent_digest.clone();
        assert_eq!(
            "AGENT_JOURNAL_RETRY_NOT_ALLOWED",
            journal.claim_before_spawn(exact.clone()).unwrap_err().code
        );
        journal.acknowledge_delivery("request_route", 3).unwrap();
        drop(journal);

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        assert!(matches!(
            reopened.claim_before_spawn(exact.clone()).unwrap(),
            AgentExecutionClaimOutcome::Claimed(_)
        ));
        drop(reopened);

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        assert!(matches!(
            reopened.claim_before_spawn(exact).unwrap(),
            AgentExecutionClaimOutcome::Replay(_)
        ));
        assert_eq!(
            2,
            reopened
                .entry("request_route")
                .unwrap()
                .attempt_claims
                .len()
        );
        cleanup_journal_artifacts(&reopened);
    }

    fn terminal_execution(
        request_id: &str,
        state: AgentExecutionState,
        session: Option<AgentSessionCheckpointV2>,
        output: Option<AgentOutput>,
        error: Option<AgentRuntimeErrorEnvelopeV2>,
    ) -> AgentExecutionV2 {
        let mut execution = starting_execution(request_id);
        execution.sequence = if session.is_some() { 4 } else { 3 };
        let attempt_state = match state {
            AgentExecutionState::Completed => AgentAttemptState::Completed,
            AgentExecutionState::Failed => AgentAttemptState::Failed,
            AgentExecutionState::Cancelled => AgentAttemptState::Cancelled,
            AgentExecutionState::Indeterminate => AgentAttemptState::Indeterminate,
            _ => panic!("test helper only creates terminal executions"),
        };
        execution.state = state;
        execution.active_attempt_id = None;
        execution.output = output;
        execution.error = error.clone();
        execution.finished_at = Some("2026-07-26T10:00:03Z".to_string());
        execution.updated_at = "2026-07-26T10:00:03Z".to_string();
        execution.attempts[0].state = attempt_state;
        execution.attempts[0].finished_sequence = Some(execution.sequence);
        execution.attempts[0].finished_at = execution.finished_at.clone();
        execution.attempts[0].session = session;
        execution.attempts[0].error = error;
        execution
    }

    fn execution_for_claim(
        mut execution: AgentExecutionV2,
        claim: &AgentExecutionClaim,
    ) -> AgentExecutionV2 {
        execution.idempotency_key = claim.idempotency_key.clone();
        for attempt in &mut execution.attempts {
            attempt.task_idempotency_key = claim.task_idempotency_key.clone();
            attempt.delivery_idempotency_key = claim.delivery_idempotency_key.clone();
            attempt.payload_digest = claim.payload_digest.clone();
            attempt.delivery = match &claim.delivery_route {
                AgentDeliveryRoute::DirectHuman => AgentProcessDeliveryV2 {
                    route: AgentDeliveryRouteV2::DirectControl,
                    runner_job_id: None,
                    lease_target_runner_id: None,
                },
                AgentDeliveryRoute::RunnerJob { job_id, .. } => AgentProcessDeliveryV2 {
                    route: AgentDeliveryRouteV2::RunnerJob,
                    runner_job_id: Some(job_id.clone()),
                    lease_target_runner_id: Some(claim.binding.runner_id.clone()),
                },
            };
        }
        execution
    }

    fn runner_job_claim(
        request_id: &str,
        idempotency_key: &str,
        payload: &[u8],
        job_id: &str,
        predecessor_job_id: Option<&str>,
    ) -> AgentExecutionClaim {
        let mut process_claim = claim(request_id, idempotency_key, payload);
        process_claim.delivery_route = AgentDeliveryRoute::RunnerJob {
            job_id: job_id.to_string(),
            predecessor_job_id: predecessor_job_id.map(str::to_string),
        };
        process_claim.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(job_id.to_string()),
            lease_target_runner_id: Some(process_claim.binding.runner_id.clone()),
        };
        process_claim
    }

    fn successor_claim(
        initial: &AgentExecutionClaim,
        job_id: &str,
        predecessor_job_id: &str,
    ) -> AgentExecutionClaim {
        let mut successor = initial.clone();
        successor.attempt_id = "attempt_2".to_string();
        successor.attempt_number = 2;
        successor.retry_kind =
            loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::FreshAfterRemediation;
        successor.from_attempt_id = Some(initial.attempt_id.clone());
        successor.task_idempotency_key = format!(
            "loomex-agent-attempt-v2:{}",
            &sha256_payload_digest(b"attempt_2")[7..]
        );
        successor.delivery_idempotency_key = format!(
            "loomex-agent-delivery-v2:{}",
            &sha256_payload_digest(b"delivery_2")[7..]
        );
        successor.payload_digest = sha256_payload_digest(b"successor payload");
        successor.delivery_route = AgentDeliveryRoute::RunnerJob {
            job_id: job_id.to_string(),
            predecessor_job_id: Some(predecessor_job_id.to_string()),
        };
        successor.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::RunnerJob,
            runner_job_id: Some(job_id.to_string()),
            lease_target_runner_id: Some(successor.binding.runner_id.clone()),
        };
        successor
    }

    fn blocked_execution_for_claim(
        request_id: &str,
        process_claim: &AgentExecutionClaim,
    ) -> AgentExecutionV2 {
        let mut execution = execution_for_claim(starting_execution(request_id), process_claim);
        let error = agent_journal_capacity_error_envelope();
        execution.sequence = 3;
        execution.state = AgentExecutionState::Blocked;
        execution.active_attempt_id = None;
        execution.error = Some(error.clone());
        execution.updated_at = "2026-07-26T10:00:03Z".to_string();
        execution.attempts[0].state = AgentAttemptState::Blocked;
        execution.attempts[0].finished_sequence = Some(3);
        execution.attempts[0].finished_at = Some("2026-07-26T10:00:03Z".to_string());
        execution.attempts[0].error = Some(error);
        execution
    }

    #[test]
    fn claim_is_durable_before_spawn_and_exact_replay_never_claims_twice() {
        let path = journal_path("claim-replay");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let first = journal
            .claim_before_spawn(claim("request_1", "idem_1", b"same"))
            .unwrap();
        assert!(matches!(first, AgentExecutionClaimOutcome::Claimed(_)));

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        let replay = reopened
            .claim_before_spawn(claim("request_1", "idem_1", b"same"))
            .unwrap();
        let AgentExecutionClaimOutcome::Replay(replay) = replay else {
            panic!("same claim must replay rather than authorize another spawn");
        };
        assert_eq!(1, replay.last_progress_sequence);
        assert_eq!(AgentExecutionState::Queued, replay.state);
        assert_eq!(1, reopened.entries().len());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                0o600,
                fs::metadata(&path).unwrap().permissions().mode() & 0o777
            );
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn request_or_idempotency_reuse_with_a_different_digest_conflicts() {
        let path = journal_path("claim-conflict");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal
            .claim_before_spawn(claim("request_1", "idem_1", b"first"))
            .unwrap();

        let different_digest = journal
            .claim_before_spawn(claim("request_1", "idem_1", b"second"))
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_IDEMPOTENCY_CONFLICT", different_digest.code);

        let same_key_different_request = journal
            .claim_before_spawn(claim("request_2", "idem_1", b"first"))
            .unwrap_err();
        assert_eq!(
            "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
            same_key_different_request.code
        );

        let mut different_binding = claim("request_1", "idem_1", b"first");
        different_binding.binding.workspace_binding_generation += 1;
        different_binding.execution.binding = different_binding.binding.clone();
        let binding_conflict = journal.claim_before_spawn(different_binding).unwrap_err();
        assert_eq!("AGENT_JOURNAL_IDEMPOTENCY_CONFLICT", binding_conflict.code);
        assert_eq!(1, journal.entries().len());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn new_attempt_with_changed_prompt_or_model_intent_conflicts() {
        let path = journal_path("intent-conflict");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal
            .claim_before_spawn(claim("request_1", "idem_1", b"original task intent"))
            .unwrap();

        let changed_intent = claim("request_1", "idem_1", b"changed prompt or model");
        let error = journal.claim_before_spawn(changed_intent).unwrap_err();
        assert_eq!("AGENT_JOURNAL_IDEMPOTENCY_CONFLICT", error.code);
        assert_eq!(1, journal.entry("request_1").unwrap().attempt_claims.len());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fresh_after_remediation_claims_a_new_process_without_changing_logical_intent() {
        let path = journal_path("continuation-only-attempt");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let original_intent = sha256_payload_digest(b"stable task intent");
        let mut initial = claim("request_1", "idem_1", b"full payload attempt 1");
        initial.task_intent_digest = original_intent.clone();
        journal.claim_before_spawn(initial.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &initial);
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let blocked = blocked_execution_for_claim("request_1", &initial);
        journal
            .record_execution("request_1", 3, &blocked, 1_200)
            .unwrap();

        let mut continuation = claim("request_1", "idem_1", b"full payload with continuation");
        continuation.attempt_id = "attempt_2".to_string();
        continuation.attempt_number = 2;
        continuation.retry_kind =
            loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::FreshAfterRemediation;
        continuation.from_attempt_id = Some("attempt_1".to_string());
        continuation.task_idempotency_key = format!(
            "loomex-agent-attempt-v2:{}",
            &sha256_payload_digest(b"attempt_2")[7..]
        );
        continuation.delivery_idempotency_key = format!(
            "loomex-agent-delivery-v2:{}",
            &sha256_payload_digest(b"delivery_2")[7..]
        );
        continuation.task_intent_digest = original_intent.clone();
        let full_resume_digest = continuation.payload_digest.clone();
        let outcome = journal.claim_before_spawn(continuation.clone()).unwrap();
        assert!(matches!(outcome, AgentExecutionClaimOutcome::Claimed(_)));
        assert!(matches!(
            journal.claim_before_spawn(continuation).unwrap(),
            AgentExecutionClaimOutcome::Replay(_)
        ));

        let entry = journal.entry("request_1").unwrap();
        assert_eq!(original_intent, entry.payload_digest);
        assert_eq!(2, entry.attempt_claims.len());
        assert_eq!("attempt_2", entry.attempt_claims[1].attempt_id);
        assert_eq!(full_resume_digest, entry.attempt_claims[1].payload_digest);

        let reopened = AgentExecutionJournal::open(&path).unwrap();
        assert_eq!(2, reopened.entry("request_1").unwrap().attempt_claims.len());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn progress_sequence_is_strictly_monotonic() {
        let path = journal_path("sequence");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal
            .claim_before_spawn(claim("request_1", "idem_1", b"canonical"))
            .unwrap();
        let error = journal
            .record_execution("request_1", 3, &starting_execution("request_1"), 1_100)
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_SEQUENCE_MISMATCH", error.code);
        assert_eq!(
            1,
            journal.entry("request_1").unwrap().last_progress_sequence
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn session_checkpoint_must_be_durable_before_terminal_execution() {
        let path = journal_path("checkpoint-order");
        let mut journal = claim_and_start(&path, "request_1");
        let checkpoint = checkpoint("request_1");
        let mut terminal = terminal_execution(
            "request_1",
            AgentExecutionState::Completed,
            Some(checkpoint.clone()),
            Some(AgentOutput {
                format: AgentOutputFormat::Text,
                content: "done".to_string(),
                structured: None,
            }),
            None,
        );
        terminal.sequence = 3;
        terminal.attempts[0].finished_sequence = Some(3);

        let error = journal
            .record_execution("request_1", 3, &terminal, 1_300)
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_EXECUTION_INVALID", error.code);
        assert_eq!(
            2,
            journal.entry("request_1").unwrap().last_progress_sequence
        );

        assert_eq!(
            AgentSessionCheckpointOutcome::Checkpointed,
            journal
                .checkpoint_initialized_session("request_1", 3, checkpoint, 1_200)
                .unwrap()
        );
        terminal.sequence = 4;
        terminal.attempts[0].finished_sequence = Some(4);
        journal
            .record_execution("request_1", 4, &terminal, 1_300)
            .unwrap();
        assert_eq!(
            AgentExecutionState::Completed,
            AgentExecutionJournal::open(&path)
                .unwrap()
                .entry("request_1")
                .unwrap()
                .state
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn resume_rejects_any_binding_generation_or_model_mismatch() {
        let path = journal_path("resume-binding");
        let mut journal = claim_and_start(&path, "request_1");
        let checkpoint = checkpoint("request_1");
        journal
            .checkpoint_initialized_session("request_1", 3, checkpoint.clone(), 1_200)
            .unwrap();
        let continuation = AgentSessionContinuationV2::from(&checkpoint);
        let exact = AgentResumeExpectation {
            binding: binding(),
            executor: ExecutorKind::CodexCli,
            provider: AgentProvider::OpenAi,
            model_key: Some("openai/gpt-5.2".to_string()),
            provider_model_id: Some("gpt-5.2".to_string()),
        };
        journal
            .validate_resume("request_1", &continuation, &exact)
            .unwrap();

        let mut wrong_binding = exact.clone();
        wrong_binding.binding.workspace_binding_generation += 1;
        assert_eq!(
            "AGENT_JOURNAL_RESUME_MISMATCH",
            journal
                .validate_resume("request_1", &continuation, &wrong_binding)
                .unwrap_err()
                .code
        );

        let mut wrong_model = exact;
        wrong_model.provider_model_id = Some("gpt-5.3".to_string());
        assert_eq!(
            "AGENT_JOURNAL_RESUME_MISMATCH",
            journal
                .validate_resume("request_1", &continuation, &wrong_model)
                .unwrap_err()
                .code
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unresolved_auto_checkpoint_round_trips_without_inventing_a_model() {
        let path = journal_path("auto-unresolved");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let auto_claim = claim("request_1", "idem_1", b"auto request");
        journal.claim_before_spawn(auto_claim.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let mut starting = execution_for_claim(starting_execution("request_1"), &auto_claim);
        starting.attempts[0].requested_model_key = None;
        starting.attempts[0].requested_provider_model_id = None;
        starting.attempts[0].resolved_model_key = None;
        starting.attempts[0].resolved_provider_model_id = None;
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let mut unresolved = checkpoint("request_1");
        unresolved.model_key = None;
        unresolved.provider_model_id = None;
        journal
            .checkpoint_initialized_session("request_1", 3, unresolved.clone(), 1_200)
            .unwrap();

        let continuation = AgentSessionContinuationV2::from(&unresolved);
        let expected = AgentResumeExpectation {
            binding: binding(),
            executor: ExecutorKind::CodexCli,
            provider: AgentProvider::OpenAi,
            model_key: None,
            provider_model_id: None,
        };
        journal
            .validate_resume("request_1", &continuation, &expected)
            .unwrap();

        let reopened = AgentExecutionJournal::open(&path).unwrap();
        reopened
            .validate_resume("request_1", &continuation, &expected)
            .unwrap();
        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("\"modelKey\""));
        assert!(!bytes.contains("\"providerModelId\""));
        assert!(!bytes.contains("\"auto\""));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancel_request_is_durable_and_idempotent() {
        let path = journal_path("cancel");
        let mut journal = claim_and_start(&path, "request_1");
        assert_eq!(
            CancelRequestOutcome::Requested,
            journal
                .request_cancel("request_1", 3, "cancel_1", 1_200)
                .unwrap()
        );
        assert_eq!(
            CancelRequestOutcome::Replay,
            journal
                .request_cancel("request_1", 99, "cancel_1", 9_999)
                .unwrap()
        );
        let reopened = AgentExecutionJournal::open(&path).unwrap();
        let entry = reopened.entry("request_1").unwrap();
        assert_eq!(2, entry.last_progress_sequence);
        assert_eq!(
            Some("cancel_1"),
            entry
                .cancellation
                .as_ref()
                .map(|cancellation| cancellation.idempotency_key.as_str())
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn crash_recovery_preserves_checkpoint_and_indeterminate_semantics() {
        let path = journal_path("crash-recovery");
        let mut journal = claim_and_start(&path, "request_1");
        journal
            .checkpoint_initialized_session("request_1", 3, checkpoint("request_1"), 1_200)
            .unwrap();
        let error = journal
            .mark_process_lost(
                "request_1",
                4,
                AgentProcessLoss::Crash,
                "2026-07-26T10:00:03Z",
                1_300,
            )
            .unwrap();
        assert_eq!(AgentErrorCode::ExecutionIndeterminate, error.code);
        assert_eq!(AgentRetryDisposition::ResumeRequired, error.retry);

        let reopened = AgentExecutionJournal::open(&path).unwrap();
        let entry = reopened.entry("request_1").unwrap();
        assert_eq!(AgentExecutionState::Indeterminate, entry.state);
        assert_eq!(
            Some(AgentSessionState::Lost),
            entry
                .session_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.state)
        );
        assert_eq!(AgentAttemptState::Indeterminate, entry.attempts[0].state);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn timeout_after_spawn_is_indeterminate_not_implicitly_retryable() {
        let path = journal_path("timeout");
        let mut journal = claim_and_start(&path, "request_1");
        let error = journal
            .mark_process_lost(
                "request_1",
                3,
                AgentProcessLoss::Timeout,
                "2026-07-26T10:00:03Z",
                1_300,
            )
            .unwrap();
        assert_eq!(AgentErrorCode::ExecutionIndeterminate, error.code);
        assert_eq!(AgentRetryDisposition::Never, error.retry);
        assert_ne!(AgentRetryDisposition::Retryable, error.retry);
        assert!(!error
            .remediation
            .contains(&AgentRemediationAction::ResumeSession));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn acknowledged_blocked_delivery_cannot_be_rewritten_as_process_loss() {
        let path = journal_path("blocked-delivery-ack-immutable");
        let initial = claim("request_1", "idem_1", b"blocked task");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal.claim_before_spawn(initial.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &initial);
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let blocked = blocked_execution_for_claim("request_1", &initial);
        journal
            .record_execution_with_delivery(
                "request_1",
                3,
                &blocked,
                serde_json::to_value(&blocked).unwrap(),
                1_200,
            )
            .unwrap();
        journal.acknowledge_delivery("request_1", 3).unwrap();

        let error = journal
            .mark_process_lost(
                "request_1",
                4,
                AgentProcessLoss::Crash,
                "2026-07-26T10:00:04Z",
                1_300,
            )
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_ALREADY_TERMINAL", error.code);
        assert_eq!(
            AgentExecutionState::Blocked,
            journal.entry("request_1").unwrap().state
        );
        assert!(journal
            .entry("request_1")
            .unwrap()
            .pending_delivery
            .is_none());
        cleanup_journal_artifacts(&journal);
    }

    #[test]
    fn authoritative_blocked_cancellation_archives_without_terminal_redelivery() {
        let path = journal_path("blocked-control-cancellation-archive");
        let initial = runner_job_claim(
            "request_1",
            "idem_1",
            b"blocked cancellation",
            "job_1",
            None,
        );
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        journal.claim_before_spawn(initial.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &initial);
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let blocked = blocked_execution_for_claim("request_1", &initial);
        journal
            .record_execution_with_delivery(
                "request_1",
                3,
                &blocked,
                serde_json::to_value(&blocked).unwrap(),
                1_200,
            )
            .unwrap();
        journal.acknowledge_delivery("request_1", 3).unwrap();
        journal
            .reserve_cancellation_control("request_1", "blocked-cancel-operation")
            .unwrap();

        journal
            .archive_authoritative_blocked_cancellation(
                "request_1",
                "blocked-cancel-operation",
                4,
                "2026-07-27T01:00:00Z",
            )
            .unwrap();

        assert!(journal.entry("request_1").is_none());
        assert!(journal.pending_delivery("request_1").unwrap().is_none());
        let tombstone = journal.tombstone("request_1").unwrap().unwrap();
        assert_eq!(tombstone.terminal_state, AgentExecutionState::Cancelled);
        assert_eq!(tombstone.terminal_sequence, 4);
        assert_eq!(tombstone.terminal_delivery_acknowledged_sequence, 4);
        assert_eq!(
            tombstone.cancellation_control_idempotency_key.as_deref(),
            Some("blocked-cancel-operation")
        );
        assert_eq!(tombstone.attempt_claims.len(), 1);
        assert_eq!(tombstone.attempt_claims[0].attempt_id, initial.attempt_id);

        drop(journal);
        let reopened = AgentExecutionJournal::open(&path).unwrap();
        assert!(reopened.entries().is_empty());
        assert_eq!(
            reopened
                .tombstone("request_1")
                .unwrap()
                .unwrap()
                .terminal_sequence,
            4
        );
        cleanup_journal_artifacts(&reopened);
    }

    #[test]
    fn agy_indeterminate_never_claims_unsupported_session_resume() {
        let path = journal_path("agy-no-resume");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let agy_claim = claim("request_1", "idem_1", b"agy request");
        journal.claim_before_spawn(agy_claim.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let mut starting = execution_for_claim(starting_execution("request_1"), &agy_claim);
        starting.attempts[0].executor = ExecutorKind::AgyCli;
        starting.attempts[0].provider = AgentProvider::Google;
        starting.attempts[0].requested_model_key = Some("google/gemini-2.5-pro".to_string());
        starting.attempts[0].requested_provider_model_id = Some("gemini-2.5-pro".to_string());
        starting.attempts[0].resolved_model_key = Some("google/gemini-2.5-pro".to_string());
        starting.attempts[0].resolved_provider_model_id = Some("gemini-2.5-pro".to_string());
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let mut agy_checkpoint = checkpoint("request_1");
        agy_checkpoint.executor = ExecutorKind::AgyCli;
        agy_checkpoint.provider = AgentProvider::Google;
        agy_checkpoint.model_key = Some("google/gemini-2.5-pro".to_string());
        agy_checkpoint.provider_model_id = Some("gemini-2.5-pro".to_string());
        journal
            .checkpoint_initialized_session("request_1", 3, agy_checkpoint.clone(), 1_200)
            .unwrap();
        let continuation = AgentSessionContinuationV2::from(&agy_checkpoint);
        let resume_error = journal
            .validate_resume(
                "request_1",
                &continuation,
                &AgentResumeExpectation {
                    binding: binding(),
                    executor: ExecutorKind::AgyCli,
                    provider: AgentProvider::Google,
                    model_key: Some("google/gemini-2.5-pro".to_string()),
                    provider_model_id: Some("gemini-2.5-pro".to_string()),
                },
            )
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_RESUME_UNSUPPORTED", resume_error.code);

        let error = journal
            .mark_process_lost(
                "request_1",
                4,
                AgentProcessLoss::Crash,
                "2026-07-26T10:00:03Z",
                1_300,
            )
            .unwrap();
        assert_eq!(AgentErrorCode::ExecutionIndeterminate, error.code);
        assert_eq!(AgentRetryDisposition::Never, error.retry);
        assert!(!error
            .remediation
            .contains(&AgentRemediationAction::ResumeSession));
        assert!(error
            .remediation
            .contains(&AgentRemediationAction::ContactSupport));
        journal.acknowledge_delivery("request_1", 4).unwrap();
        assert!(journal.entry("request_1").is_none());
        assert_eq!(
            Some(AgentExecutionState::Indeterminate),
            journal
                .tombstone("request_1")
                .unwrap()
                .map(|tombstone| tombstone.terminal_state)
        );
        cleanup_journal_artifacts(&journal);
    }

    #[test]
    fn failed_initial_persist_rolls_back_the_in_memory_claim() {
        let parent_blocker = journal_path("claim-persist-blocker");
        fs::write(&parent_blocker, b"not-a-directory").unwrap();
        let path = parent_blocker.join("agent-journal.json");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();

        let error = journal
            .claim_before_spawn(claim("request_1", "idem_1", b"canonical"))
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_WRITE_FAILED", error.code);
        assert!(journal.entries().is_empty());
        assert!(journal.entry("request_1").is_none());

        fs::remove_file(parent_blocker).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symlink_and_non_regular_journal_paths() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let path = journal_path("insecure-open");
        let target = path.with_extension("target");
        fs::write(
            &target,
            format!(
                "{{\"schemaVersion\":\"{}\",\"entries\":[]}}",
                AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION
            ),
        )
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let original = fs::read(&target).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            "AGENT_JOURNAL_INSECURE",
            AgentExecutionJournal::open(&path).unwrap_err().code
        );
        assert_eq!(original, fs::read(&target).unwrap());
        assert_eq!(
            0o644,
            fs::metadata(&target).unwrap().permissions().mode() & 0o777
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            "AGENT_JOURNAL_INSECURE",
            AgentExecutionJournal::open(&path).unwrap_err().code
        );
        fs::remove_dir(&path).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persist_rejects_a_symlink_parent_without_writing_through_it() {
        use std::os::unix::fs::symlink;

        let root = journal_path("symlink-parent");
        let actual_parent = root.join("actual");
        let linked_parent = root.join("linked");
        fs::create_dir_all(&actual_parent).unwrap();
        symlink(&actual_parent, &linked_parent).unwrap();
        let path = linked_parent.join("agent-journal.json");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();

        let error = journal
            .claim_before_spawn(claim("request_1", "idem_1", b"canonical"))
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_INSECURE", error.code);
        assert!(journal.entries().is_empty());
        assert!(!actual_parent.join("agent-journal.json").exists());

        fs::remove_file(linked_parent).unwrap();
        fs::remove_dir(actual_parent).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn failed_transition_persist_restores_the_last_durable_state_without_data_loss() {
        let root = journal_path("transition-persist-root");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("agent-journal.json");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let process_claim = claim("request_1", "idem_1", b"canonical");
        journal.claim_before_spawn(process_claim.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();

        let moved_root = root.with_extension("durable");
        fs::rename(&root, &moved_root).unwrap();
        fs::write(&root, b"not-a-directory").unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &process_claim);
        let error = journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_WRITE_FAILED", error.code);
        let entry = journal.entry("request_1").unwrap();
        assert_eq!(AgentExecutionState::Queued, entry.state);
        assert_eq!(1, entry.last_progress_sequence);
        assert!(entry.attempts.is_empty());

        fs::remove_file(&root).unwrap();
        fs::rename(&moved_root, &root).unwrap();
        let reopened = AgentExecutionJournal::open(&path).unwrap();
        assert_eq!(
            AgentExecutionState::Queued,
            reopened.entry("request_1").unwrap().state
        );
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn runtime_v2_disabled_error_is_canonicalized_without_raw_diagnostics() {
        let raw_diagnostic = "raw runtime toggle diagnostic";
        let mut safe_details = BTreeMap::new();
        safe_details.insert("source".to_string(), "local_control".to_string());
        let canonical = canonicalize_error(&AgentRuntimeErrorEnvelopeV2 {
            schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
            code: AgentErrorCode::AgentRuntimeV2Disabled,
            category: AgentErrorCategory::Availability,
            message: raw_diagnostic.to_string(),
            retry: AgentRetryDisposition::Never,
            retry_after_seconds: None,
            remediation: vec![],
            context: AgentErrorContext {
                safe_details,
                ..AgentErrorContext::default()
            },
        })
        .unwrap();

        assert_eq!(
            "Agent runtime v2 is disabled for this dispatch.",
            canonical.message
        );
        assert!(!canonical.message.contains(raw_diagnostic));
        assert!(canonical.context.safe_details.is_empty());
    }

    #[test]
    fn persisted_error_and_output_remove_tokens_paths_stderr_and_provider_content() {
        let path = journal_path("redaction");
        let mut journal = claim_and_start(&path, "request_1");
        let secret = "sk-secret-token-value";
        let private_path = "/Users/private/.config/provider";
        let mut safe_details = BTreeMap::new();
        safe_details.insert("stderr".to_string(), format!("{secret} at {private_path}"));
        let error = AgentRuntimeErrorEnvelopeV2 {
            schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
            code: AgentErrorCode::ProviderNotEligible,
            category: AgentErrorCategory::Authorization,
            message: format!("raw provider eligibility response: {secret} at {private_path}"),
            retry: AgentRetryDisposition::Never,
            retry_after_seconds: None,
            remediation: vec![AgentRemediationAction::ContactSupport],
            context: AgentErrorContext {
                executor: Some(ExecutorKind::CodexCli),
                provider: Some(AgentProvider::OpenAi),
                requested_model_key: Some("openai/gpt-5.2".to_string()),
                requested_provider_model_id: Some("gpt-5.2".to_string()),
                resolved_model_key: Some("openai/gpt-5.2".to_string()),
                resolved_provider_model_id: Some("gpt-5.2".to_string()),
                execution_id: Some("execution_request_1".to_string()),
                attempt_id: Some("attempt_1".to_string()),
                session_id: None,
                safe_details,
            },
        };
        let failed = terminal_execution(
            "request_1",
            AgentExecutionState::Failed,
            None,
            None,
            Some(error),
        );
        journal
            .record_execution("request_1", 3, &failed, 1_300)
            .unwrap();

        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains(secret));
        assert!(!bytes.contains(private_path));
        assert!(!bytes.contains("raw provider eligibility response"));
        assert!(!bytes.contains("\"stderr\""));
        assert!(bytes
            .contains("The current provider account is not eligible for this agent execution."));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn completed_output_is_not_written_to_the_recovery_journal() {
        let path = journal_path("output-minimization");
        let mut journal = claim_and_start(&path, "request_1");
        let checkpoint = checkpoint("request_1");
        journal
            .checkpoint_initialized_session("request_1", 3, checkpoint.clone(), 1_200)
            .unwrap();
        let terminal = terminal_execution(
            "request_1",
            AgentExecutionState::Completed,
            Some(checkpoint),
            Some(AgentOutput {
                format: AgentOutputFormat::Json,
                content: String::new(),
                structured: Some(json!({
                    "token": "sk-output-secret",
                    "path": "/Users/private/repository"
                })),
            }),
            None,
        );
        journal
            .record_execution("request_1", 4, &terminal, 1_300)
            .unwrap();

        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("sk-output-secret"));
        assert!(!bytes.contains("/Users/private/repository"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pending_checkpoint_and_terminal_delivery_survive_crash_exactly_until_ack() {
        let path = journal_path("pending-delivery");
        let mut journal = claim_and_start(&path, "request_1");
        let checkpoint = checkpoint("request_1");
        let checkpoint_payload = serde_json::to_value(&checkpoint).unwrap();
        journal
            .checkpoint_initialized_session_with_delivery(
                "request_1",
                3,
                checkpoint.clone(),
                checkpoint_payload.clone(),
                1_200,
            )
            .unwrap();

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        let pending_checkpoint = reopened.pending_delivery("request_1").unwrap().unwrap();
        assert_eq!(3, pending_checkpoint.sequence);
        assert_eq!(
            AgentPendingDeliveryKind::Checkpoint,
            pending_checkpoint.kind
        );
        assert_eq!(checkpoint_payload, pending_checkpoint.payload);
        let wrong_ack = reopened.acknowledge_delivery("request_1", 2).unwrap_err();
        assert_eq!("AGENT_JOURNAL_DELIVERY_SEQUENCE_MISMATCH", wrong_ack.code);
        assert!(reopened.pending_delivery("request_1").unwrap().is_some());
        reopened.acknowledge_delivery("request_1", 3).unwrap();

        let output_secret = "terminal-output-survives-until-ack";
        let terminal = terminal_execution(
            "request_1",
            AgentExecutionState::Completed,
            Some(checkpoint),
            Some(AgentOutput {
                format: AgentOutputFormat::Json,
                content: String::new(),
                structured: Some(json!({"result": output_secret})),
            }),
            None,
        );
        let terminal_payload = serde_json::to_value(&terminal).unwrap();
        reopened
            .record_execution_with_delivery(
                "request_1",
                4,
                &terminal,
                terminal_payload.clone(),
                1_300,
            )
            .unwrap();

        let mut recovered = AgentExecutionJournal::open(&path).unwrap();
        let pending_terminal = recovered.pending_delivery("request_1").unwrap().unwrap();
        assert_eq!(4, pending_terminal.sequence);
        assert_eq!(AgentPendingDeliveryKind::Terminal, pending_terminal.kind);
        assert_eq!(terminal_payload, pending_terminal.payload);
        assert!(fs::read_to_string(&path).unwrap().contains(output_secret));
        assert_eq!(
            "AGENT_JOURNAL_DELIVERY_PENDING",
            recovered
                .remove_after_authoritative_ack("request_1")
                .unwrap_err()
                .code
        );

        recovered.acknowledge_delivery("request_1", 4).unwrap();
        let acknowledged = AgentExecutionJournal::open(&path).unwrap();
        assert!(acknowledged
            .pending_delivery("request_1")
            .unwrap()
            .is_none());
        assert!(!fs::read_to_string(&path).unwrap().contains(output_secret));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_capacity_limits_are_inclusive_and_fail_closed_without_eviction() {
        let path = journal_path("capacity-boundaries");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let capacity_claim = claim("request_0", "idem_0", b"canonical");
        journal.claim_before_spawn(capacity_claim.clone()).unwrap();
        let base_entry = journal.entry("request_0").unwrap().clone();

        let mut request_document = AgentExecutionJournalDocument {
            schema_version: AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION.to_string(),
            entries: (0..MAX_AGENT_JOURNAL_REQUESTS)
                .map(|index| {
                    let mut entry = base_entry.clone();
                    entry.request_id = format!("request_{index}");
                    entry.idempotency_key = format!("idem_{index}");
                    entry.execution_id = format!("execution_request_{index}");
                    entry.pending_delivery = None;
                    entry
                })
                .collect(),
        };
        validate_document(&request_document).unwrap();
        request_document
            .entries
            .push(request_document.entries[0].clone());
        assert_eq!(
            "AGENT_JOURNAL_CAPACITY_EXCEEDED",
            validate_document(&request_document).unwrap_err().code
        );
        assert_eq!(
            MAX_AGENT_JOURNAL_REQUESTS + 1,
            request_document.entries.len()
        );

        let mut claim_entry = base_entry.clone();
        claim_entry.pending_delivery = None;
        claim_entry.attempt_claims = (0..MAX_AGENT_JOURNAL_ATTEMPT_CLAIMS_PER_REQUEST)
            .map(|index| PersistedAgentAttemptClaim {
                attempt_id: format!("attempt_{index}"),
                attempt_number: u32::try_from(index + 1).unwrap(),
                retry_kind: if index == 0 {
                    loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::Initial
                } else {
                    loomex_protocol::agent_runtime_v2::AgentProcessRetryKindV2::FreshAfterRemediation
                },
                from_attempt_id: (index > 0).then(|| format!("attempt_{}", index - 1)),
                delivery: AgentProcessDeliveryV2 {
                    route: AgentDeliveryRouteV2::DirectControl,
                    runner_job_id: None,
                    lease_target_runner_id: None,
                },
                task_idempotency_key: format!(
                    "loomex-agent-attempt-v2:{}",
                    &sha256_payload_digest(format!("task_{index}").as_bytes())[7..]
                ),
                delivery_idempotency_key: format!(
                    "loomex-agent-delivery-v2:{}",
                    &sha256_payload_digest(format!("delivery_{index}").as_bytes())[7..]
                ),
                payload_digest: sha256_payload_digest(format!("payload_{index}").as_bytes()),
            })
            .collect();
        validate_entry(&claim_entry).unwrap();
        claim_entry
            .attempt_claims
            .push(claim_entry.attempt_claims[0].clone());
        assert_eq!(
            "AGENT_JOURNAL_CAPACITY_EXCEEDED",
            validate_entry(&claim_entry).unwrap_err().code
        );

        validate_agent_attempt_capacity(MAX_AGENT_JOURNAL_ATTEMPTS_PER_REQUEST).unwrap();
        assert_eq!(
            "AGENT_JOURNAL_CAPACITY_EXCEEDED",
            validate_agent_attempt_capacity(MAX_AGENT_JOURNAL_ATTEMPTS_PER_REQUEST + 1)
                .unwrap_err()
                .code
        );

        let pending = base_entry.pending_delivery.clone().unwrap();
        let pending_document = AgentExecutionJournalDocument {
            schema_version: AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION.to_string(),
            entries: (0..MAX_AGENT_JOURNAL_PENDING_DELIVERIES)
                .map(|index| {
                    let mut entry = base_entry.clone();
                    entry.request_id = format!("pending_request_{index}");
                    entry.idempotency_key = format!("pending_idem_{index}");
                    entry.execution_id = format!("pending_execution_{index}");
                    entry
                })
                .collect(),
        };
        assert_eq!(
            "AGENT_JOURNAL_CAPACITY_EXCEEDED",
            validate_new_pending_delivery_capacity(&pending_document, &pending)
                .unwrap_err()
                .code
        );
        let below_pending_limit = AgentExecutionJournalDocument {
            entries: pending_document.entries[..MAX_AGENT_JOURNAL_PENDING_DELIVERIES - 1].to_vec(),
            ..pending_document
        };
        validate_new_pending_delivery_capacity(&below_pending_limit, &pending).unwrap();

        let exact_payload = AgentPendingDelivery {
            sequence: 1,
            kind: AgentPendingDeliveryKind::Execution,
            payload: Value::String(
                "x".repeat(MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES.saturating_sub(2)),
            ),
        };
        assert_eq!(
            MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES,
            serde_json::to_vec(&exact_payload.payload).unwrap().len()
        );
        validate_new_pending_delivery_capacity(
            &AgentExecutionJournalDocument {
                schema_version: AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION.to_string(),
                entries: Vec::new(),
            },
            &exact_payload,
        )
        .unwrap();
        let oversized_payload = AgentPendingDelivery {
            payload: Value::String(
                "x".repeat(MAX_AGENT_JOURNAL_PENDING_DELIVERY_BYTES.saturating_sub(1)),
            ),
            ..exact_payload
        };
        assert_eq!(
            "AGENT_JOURNAL_CAPACITY_EXCEEDED",
            validate_new_pending_delivery_capacity(
                &AgentExecutionJournalDocument {
                    schema_version: AGENT_EXECUTION_JOURNAL_SCHEMA_VERSION.to_string(),
                    entries: Vec::new(),
                },
                &oversized_payload,
            )
            .unwrap_err()
            .code
        );

        let envelope = agent_journal_capacity_error_envelope();
        envelope.validate().unwrap();
        assert_eq!(AgentErrorCode::InternalError, envelope.code);
        assert_eq!(AgentRetryDisposition::UserActionRequired, envelope.retry);
        assert_eq!(
            vec![AgentRemediationAction::ContactSupport],
            envelope.remediation
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_journal_is_rejected_before_deserialization() {
        let path = journal_path("oversized-file");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_AGENT_JOURNAL_BYTES + 1).unwrap();
        drop(file);

        let error = AgentExecutionJournal::open(&path).unwrap_err();
        assert_eq!("AGENT_JOURNAL_CAPACITY_EXCEEDED", error.code);
        assert_eq!(
            MAX_AGENT_JOURNAL_BYTES + 1,
            fs::metadata(&path).unwrap().len()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn maximum_valid_terminal_output_is_durably_deliverable() {
        let path = journal_path("near-limit-terminal");
        let mut journal = claim_and_start(&path, "request_1");
        let checkpoint = checkpoint("request_1");
        journal
            .checkpoint_initialized_session("request_1", 3, checkpoint.clone(), 1_200)
            .unwrap();

        let empty_output = AgentOutput {
            format: AgentOutputFormat::Text,
            content: String::new(),
            structured: None,
        };
        let empty_size = serde_json::to_vec(&empty_output).unwrap().len();
        let output = AgentOutput {
            content: "x".repeat(AGENT_TERMINAL_OUTPUT_MAX_BYTES - empty_size),
            ..empty_output
        };
        assert_eq!(
            AGENT_TERMINAL_OUTPUT_MAX_BYTES,
            validate_agent_terminal_output(&output).unwrap()
        );
        let terminal = terminal_execution(
            "request_1",
            AgentExecutionState::Completed,
            Some(checkpoint),
            Some(output),
            None,
        );
        let payload = serde_json::to_value(&terminal).unwrap();
        journal
            .record_execution_with_delivery("request_1", 4, &terminal, payload, 1_300)
            .unwrap();

        let reopened = AgentExecutionJournal::open(&path).unwrap();
        assert!(reopened.pending_delivery("request_1").unwrap().is_some());
        assert!(fs::metadata(&path).unwrap().len() <= MAX_AGENT_JOURNAL_BYTES);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn acknowledged_terminal_compaction_survives_restart_and_preserves_fences() {
        let path = journal_path("tombstone-recovery");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let original_claim = claim("request_1", "idem_1", b"canonical request");
        journal.claim_before_spawn(original_claim.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &original_claim);
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let terminal = execution_for_claim(
            terminal_execution(
                "request_1",
                AgentExecutionState::Completed,
                None,
                Some(AgentOutput {
                    format: AgentOutputFormat::Text,
                    content: "done".to_string(),
                    structured: None,
                }),
                None,
            ),
            &original_claim,
        );
        let terminal_payload = serde_json::to_value(&terminal).unwrap();
        journal
            .record_execution_with_delivery("request_1", 3, &terminal, terminal_payload, 1_200)
            .unwrap();

        let before_ack = AgentExecutionJournal::open(&path).unwrap();
        assert!(before_ack.entry("request_1").is_some());
        assert!(before_ack.tombstone("request_1").unwrap().is_none());
        drop(before_ack);

        journal.acknowledge_delivery("request_1", 3).unwrap();
        assert!(journal.entry("request_1").is_none());
        let tombstone = journal.tombstone("request_1").unwrap().unwrap();
        assert_eq!(AgentExecutionState::Completed, tombstone.terminal_state);
        assert_eq!(3, tombstone.terminal_sequence);
        assert_eq!(3, tombstone.terminal_delivery_acknowledged_sequence);

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        assert!(reopened.entry("request_1").is_none());
        assert!(reopened.pending_delivery("request_1").unwrap().is_none());
        assert!(matches!(
            reopened.claim_before_spawn(original_claim.clone()).unwrap(),
            AgentExecutionClaimOutcome::Replay(_)
        ));
        let conflict = reopened
            .claim_before_spawn(claim("request_1", "idem_1", b"changed payload"))
            .unwrap_err();
        assert_eq!("AGENT_JOURNAL_IDEMPOTENCY_CONFLICT", conflict.code);

        cleanup_journal_artifacts(&reopened);
    }

    #[test]
    fn crash_during_compaction_recovers_from_active_entry_plus_tombstone() {
        let path = journal_path("tombstone-mid-compaction");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let original_claim = claim("request_1", "idem_1", b"canonical request");
        journal.claim_before_spawn(original_claim.clone()).unwrap();
        journal.acknowledge_delivery("request_1", 1).unwrap();
        let starting = execution_for_claim(starting_execution("request_1"), &original_claim);
        journal
            .record_execution("request_1", 2, &starting, 1_100)
            .unwrap();
        let terminal = execution_for_claim(
            terminal_execution(
                "request_1",
                AgentExecutionState::Completed,
                None,
                Some(AgentOutput {
                    format: AgentOutputFormat::Text,
                    content: "done".to_string(),
                    structured: None,
                }),
                None,
            ),
            &original_claim,
        );
        journal
            .record_execution_with_delivery(
                "request_1",
                3,
                &terminal,
                serde_json::to_value(&terminal).unwrap(),
                1_200,
            )
            .unwrap();

        let entry = journal.entry("request_1").unwrap().clone();
        let tombstone = AgentExecutionTombstone {
            schema_version: AGENT_EXECUTION_TOMBSTONE_SCHEMA_VERSION.to_string(),
            request_id: entry.request_id.clone(),
            idempotency_key: entry.idempotency_key.clone(),
            task_intent_digest: entry.payload_digest.clone(),
            attempt_claims: entry.attempt_claims.clone(),
            binding: entry.binding.clone(),
            delivery_route: entry.delivery_route.clone(),
            execution_id: entry.execution_id.clone(),
            terminal_state: entry.state,
            terminal_sequence: entry.last_progress_sequence,
            terminal_delivery_acknowledged_sequence: entry.last_progress_sequence,
            has_session_checkpoint: entry.session_checkpoint.is_some(),
            cancellation_idempotency_key: None,
            cancellation_control_idempotency_key: None,
            resumable: false,
            finished_at: entry.finished_at.clone(),
        };
        journal.write_tombstone(&tombstone).unwrap();
        journal.document.entries[0].pending_delivery = None;
        journal.document.entries[0].terminal_delivery_acknowledged_sequence = Some(3);
        journal.persist().unwrap();
        drop(journal);

        let recovered = AgentExecutionJournal::open(&path).unwrap();
        assert!(recovered.entry("request_1").is_none());
        assert_eq!(Some(tombstone), recovered.tombstone("request_1").unwrap());
        cleanup_journal_artifacts(&recovered);
    }

    #[test]
    fn more_than_active_capacity_sequential_completions_remain_usable() {
        let path = journal_path("tombstone-longevity");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let total = MAX_AGENT_JOURNAL_REQUESTS + 1;
        for index in 0..total {
            let request_id = format!("request_{index}");
            let idempotency_key = format!("idem_{index}");
            let payload = format!("payload_{index}");
            let process_claim = claim(&request_id, &idempotency_key, payload.as_bytes());
            seed_tombstone_without_fsync(
                &journal,
                &tombstone_for_claim(&process_claim, AgentExecutionState::Completed),
            );
        }

        let first_claim = claim("request_0", "idem_0", b"payload_0");
        assert!(matches!(
            journal.claim_before_spawn(first_claim).unwrap(),
            AgentExecutionClaimOutcome::Replay(_)
        ));
        assert_eq!(
            "AGENT_JOURNAL_IDEMPOTENCY_CONFLICT",
            journal
                .claim_before_spawn(claim("request_0", "idem_0", b"changed"))
                .unwrap_err()
                .code
        );
        assert!(journal
            .tombstone(&format!("request_{}", total - 1))
            .unwrap()
            .is_some());
        let fresh = claim(
            &format!("request_{total}"),
            &format!("idem_{total}"),
            b"fresh payload",
        );
        assert!(matches!(
            journal.claim_before_spawn(fresh).unwrap(),
            AgentExecutionClaimOutcome::Claimed(_)
        ));

        cleanup_journal_artifacts(&journal);
    }

    #[test]
    fn more_than_active_capacity_nonresumable_indeterminate_tasks_compact() {
        let path = journal_path("tombstone-agy-indeterminate-longevity");
        let mut journal = AgentExecutionJournal::open(&path).unwrap();
        let total = MAX_AGENT_JOURNAL_REQUESTS + 1;
        for index in 0..total {
            let request_id = format!("agy_request_{index}");
            let idempotency_key = format!("agy_idem_{index}");
            let payload = format!("agy_payload_{index}");
            let process_claim = claim(&request_id, &idempotency_key, payload.as_bytes());
            seed_tombstone_without_fsync(
                &journal,
                &tombstone_for_claim(&process_claim, AgentExecutionState::Indeterminate),
            );
        }
        assert_eq!(
            AgentExecutionState::Indeterminate,
            journal
                .tombstone("agy_request_0")
                .unwrap()
                .unwrap()
                .terminal_state
        );
        let fresh = claim(
            &format!("agy_request_{total}"),
            &format!("agy_idem_{total}"),
            b"fresh agy payload",
        );
        assert!(matches!(
            journal.claim_before_spawn(fresh).unwrap(),
            AgentExecutionClaimOutcome::Claimed(_)
        ));
        cleanup_journal_artifacts(&journal);
    }

    #[test]
    fn acknowledged_resumable_indeterminate_execution_stays_active() {
        let path = journal_path("resumable-indeterminate-retained");
        let mut journal = claim_and_start(&path, "request_1");
        journal
            .checkpoint_initialized_session("request_1", 3, checkpoint("request_1"), 1_200)
            .unwrap();
        journal
            .mark_process_lost(
                "request_1",
                4,
                AgentProcessLoss::Crash,
                "2026-07-26T10:00:03Z",
                1_300,
            )
            .unwrap();
        journal.acknowledge_delivery("request_1", 4).unwrap();

        let mut reopened = AgentExecutionJournal::open(&path).unwrap();
        assert_eq!(
            Some(AgentExecutionState::Indeterminate),
            reopened.entry("request_1").map(|entry| entry.state)
        );
        assert!(reopened.tombstone("request_1").unwrap().is_none());
        assert_eq!(
            "AGENT_JOURNAL_RESUME_REQUIRED",
            reopened
                .remove_after_authoritative_ack("request_1")
                .unwrap_err()
                .code
        );
        cleanup_journal_artifacts(&reopened);
    }

    #[test]
    fn canonical_agent_task_digest_matches_backend_golden_contract() {
        let ascii: Value = serde_json::from_str(include_str!(
            "../../loomex-protocol/fixtures/agent_task_v2.json"
        ))
        .unwrap();
        assert_eq!(
            canonical_agent_task_payload_digest(&ascii).unwrap(),
            "d170c133312020eae964273b01f0cb0688c3f37816aca5276830d7792d217a2d"
        );

        let value = json!({
            "schemaVersion": "loomex.plugin-agent-task/v2",
            "prompt": "سلام 😀",
            "outputSchema": {
                "minimum": 1e-6,
                "title": "é"
            }
        });

        assert_eq!(
            canonical_agent_task_payload_digest(&value).unwrap(),
            "53819e42a31d40f0985f92f1147668b688e5d6930d981e59e20e2dc7a6c706da"
        );
    }
}
