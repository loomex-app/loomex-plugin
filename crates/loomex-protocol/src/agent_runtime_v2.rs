//! Transport-neutral contracts for selecting and executing a local AI agent.
//!
//! The types in this module describe data only. They deliberately do not
//! prescribe process spawning, executable discovery, filesystem access, MCP,
//! Tauri, authentication storage, or any other runtime implementation detail.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const AGENT_TASK_SCHEMA_V2: &str = "loomex.plugin-agent-task/v2";
pub const AGENT_PROCESS_DISPATCH_SCHEMA_V2: &str = "loomex.agent-process-dispatch.v2";
pub const AGENT_CAPABILITY_SCHEMA_V2: &str = "loomex.agent-capabilities.v2";
pub const AGENT_EXECUTION_SCHEMA_V2: &str = "loomex.agent-execution.v2";
pub const AGENT_ERROR_SCHEMA_V2: &str = "loomex.agent-error.v2";
pub const AGENT_SESSION_SCHEMA_V2: &str = "loomex.agent-session.v2";
/// Runner capability advertised when the local runtime can accept the v2
/// agent task contract.
pub const AGENT_RUNTIME_CAPABILITY_V2: &str = "agent.runtime.v2";
pub const MAX_MODEL_KEY_LENGTH: usize = 192;
pub const MAX_PROVIDER_MODEL_ID_LENGTH: usize = 192;
pub const MAX_PROVIDER_SESSION_ID_LENGTH: usize = 256;
pub const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 160;
pub const MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION: usize = 8;
pub const AGENT_ATTEMPT_TASK_IDEMPOTENCY_PREFIX_V2: &str = "loomex-agent-attempt-v2:";
pub const AGENT_ATTEMPT_DELIVERY_IDEMPOTENCY_PREFIX_V2: &str = "loomex-agent-delivery-v2:";
pub const AGENT_PAYLOAD_DIGEST_PREFIX_V1: &str = "sha256:";
pub const AGENT_STRUCTURED_OUTPUT_SHAPE_CONTRACT_V1: &str =
    "loomex.agent-structured-output-shape/v1";
pub const AGENT_RUNTIME_V2_DISABLED_REASON_CODE: &str = "agent_runtime_v2_disabled";
pub const AGENT_RUNTIME_V2_DISABLED_MESSAGE: &str = "Local agent runtime v2 execution is disabled.";
pub const AGENT_MALFORMED_DISPATCH_REASON_CODE: &str = "malformed_dispatch";
pub const AGENT_MALFORMED_DISPATCH_MESSAGE: &str = "The process dispatch payload was malformed.";

pub fn default_agent_structured_output_schema() -> Value {
    serde_json::json!({"type": "object"})
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStructuredOutputSchemaValidationError {
    SchemaMustBeObject,
    RootTypeMustBeObject,
}

/// The Backend workflow reducer consumes a JSON object. Requiring an explicit
/// root `type: object` prevents permissive `{}` schemas and scalar/array output
/// from crossing the runtime boundary only to fail during reduction.
pub fn validate_agent_structured_output_schema(
    schema: &Value,
) -> Result<(), AgentStructuredOutputSchemaValidationError> {
    let object = schema
        .as_object()
        .ok_or(AgentStructuredOutputSchemaValidationError::SchemaMustBeObject)?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(AgentStructuredOutputSchemaValidationError::RootTypeMustBeObject);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliIdentifierValidationError {
    Empty,
    TooLong { max: usize },
    UnsafeFirstCharacter,
    UnsafeCharacter { index: usize },
    TraversalLikeSegment,
}

/// Validates a provider-facing identifier before it can be used in CLI argv.
///
/// Grammar: `[A-Za-z0-9][A-Za-z0-9._:/@+-]*`, bounded by `max`. Empty, `.`,
/// and `..` slash-delimited segments are rejected in addition to the character
/// grammar. This validates one argv value; consumers must still pass the value
/// as a distinct argument and must not interpolate it into a shell string.
pub fn validate_cli_identifier(
    value: &str,
    max: usize,
) -> Result<(), CliIdentifierValidationError> {
    if value.is_empty() {
        return Err(CliIdentifierValidationError::Empty);
    }
    if value.len() > max {
        return Err(CliIdentifierValidationError::TooLong { max });
    }
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(CliIdentifierValidationError::UnsafeFirstCharacter);
    }
    for (index, byte) in value.bytes().enumerate().skip(1) {
        if !(byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-'))
        {
            return Err(CliIdentifierValidationError::UnsafeCharacter { index });
        }
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(CliIdentifierValidationError::TraversalLikeSegment);
    }

    Ok(())
}

/// Validates the stable task idempotency domain shared with the Backend.
///
/// Wire grammar: `[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,159}`. The byte-oriented
/// ASCII grammar excludes whitespace, control characters, NUL, and leading
/// flag-like punctuation while preserving common workflow domain separators.
pub fn validate_idempotency_key(value: &str) -> Result<(), CliIdentifierValidationError> {
    validate_cli_identifier(value, MAX_IDEMPOTENCY_KEY_LENGTH)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentDigestIdentifierValidationError {
    WrongPrefix,
    InvalidSha256Hex,
}

fn validate_prefixed_sha256(
    value: &str,
    prefix: &str,
) -> Result<(), AgentDigestIdentifierValidationError> {
    let digest = value
        .strip_prefix(prefix)
        .ok_or(AgentDigestIdentifierValidationError::WrongPrefix)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AgentDigestIdentifierValidationError::InvalidSha256Hex);
    }
    Ok(())
}

pub fn validate_agent_attempt_task_idempotency_key(
    value: &str,
) -> Result<(), AgentDigestIdentifierValidationError> {
    validate_prefixed_sha256(value, AGENT_ATTEMPT_TASK_IDEMPOTENCY_PREFIX_V2)
}

pub fn validate_agent_attempt_delivery_idempotency_key(
    value: &str,
) -> Result<(), AgentDigestIdentifierValidationError> {
    validate_prefixed_sha256(value, AGENT_ATTEMPT_DELIVERY_IDEMPOTENCY_PREFIX_V2)
}

pub fn validate_agent_payload_digest(
    value: &str,
) -> Result<(), AgentDigestIdentifierValidationError> {
    validate_prefixed_sha256(value, AGENT_PAYLOAD_DIGEST_PREFIX_V1)
}

pub fn canonicalize_agent_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json_canonicalizer::to_vec(value)
}

fn agent_attempt_hash_preimage(domain: &str, execution_id: &str, attempt_number: u32) -> Vec<u8> {
    let attempt_number = attempt_number.to_string();
    let mut preimage =
        Vec::with_capacity(domain.len() + execution_id.len() + attempt_number.len() + 2);
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(execution_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(attempt_number.as_bytes());
    preimage
}

/// Exact SHA-256 preimage for `taskIdempotencyKey`.
pub fn agent_attempt_task_idempotency_preimage(execution_id: &str, attempt_number: u32) -> Vec<u8> {
    agent_attempt_hash_preimage("loomex.agent-attempt/v2", execution_id, attempt_number)
}

/// Exact SHA-256 preimage for `deliveryIdempotencyKey`.
pub fn agent_attempt_delivery_idempotency_preimage(
    execution_id: &str,
    attempt_number: u32,
) -> Vec<u8> {
    agent_attempt_hash_preimage("loomex.agent-delivery/v2", execution_id, attempt_number)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProvider {
    OpenAi,
    Anthropic,
    Google,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    CodexCli,
    ClaudeCli,
    /// The supported Gemini-compatible command is `agy`; the protocol never
    /// advertises or selects a `gemini_cli` executor.
    AgyCli,
}

impl ExecutorKind {
    pub const fn provider(self) -> AgentProvider {
        match self {
            Self::CodexCli => AgentProvider::OpenAi,
            Self::ClaudeCli => AgentProvider::Anthropic,
            Self::AgyCli => AgentProvider::Google,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelTarget {
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    /// Stable Loomex catalog key used by workflows and persisted attempts.
    pub model_key: String,
    /// Exact provider-facing identifier passed to the selected executor. It
    /// must never be silently replaced by a default or similarly named model.
    pub provider_model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModelSelectionMode {
    Exact {
        target: ModelTarget,
    },
    /// Delegates primary model choice to a ready executor. Both executor and
    /// provider remain explicit; only the provider-facing model ID is chosen
    /// automatically.
    Auto {
        executor: ExecutorKind,
        provider: AgentProvider,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum ModelFallbackPolicy {
    None,
    /// Fallback is permitted only to these exact targets and in this order.
    Ordered {
        targets: Vec<ModelTarget>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelSelection {
    pub primary: ModelSelectionMode,
    pub fallback: ModelFallbackPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCandidatePinV2 {
    /// Zero selects the primary slot; one and above select the corresponding
    /// one-based position in the immutable ordered fallback list.
    pub selection_index: u32,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_model_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCandidatePinValidationError {
    UnpairedModelIdentity,
    UnsafeModelIdentity,
    CandidateNotAllowed,
    PinnedCandidateChanged,
    ResolvedModelCleared,
}

impl AgentCandidatePinV2 {
    pub fn resolved_model(&self) -> Option<(&str, &str)> {
        self.model_key
            .as_deref()
            .zip(self.provider_model_id.as_deref())
    }

    pub fn validate_identity(&self) -> Result<(), AgentCandidatePinValidationError> {
        if self.executor.provider() != self.provider {
            return Err(AgentCandidatePinValidationError::CandidateNotAllowed);
        }
        match (&self.model_key, &self.provider_model_id) {
            (None, None) => Ok(()),
            (Some(model_key), Some(provider_model_id))
                if validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_ok()
                    && validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_ok() =>
            {
                Ok(())
            }
            (Some(_), Some(_)) => Err(AgentCandidatePinValidationError::UnsafeModelIdentity),
            _ => Err(AgentCandidatePinValidationError::UnpairedModelIdentity),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelSelectionValidationError {
    EmptyExactModelKey,
    EmptyExactProviderModelId,
    UnsafeExactModelKey(CliIdentifierValidationError),
    UnsafeExactProviderModelId(CliIdentifierValidationError),
    PrimaryExecutorProviderMismatch,
    EmptyFallbackList,
    EmptyFallbackModelKey {
        index: usize,
    },
    EmptyFallbackProviderModelId {
        index: usize,
    },
    UnsafeFallbackModelKey {
        index: usize,
        source: CliIdentifierValidationError,
    },
    UnsafeFallbackProviderModelId {
        index: usize,
        source: CliIdentifierValidationError,
    },
    FallbackExecutorProviderMismatch {
        index: usize,
    },
    DuplicateFallbackTarget {
        index: usize,
    },
}

impl ModelSelection {
    /// Validates invariants that serde alone cannot express. Consumers must
    /// call this before starting an execution.
    pub fn validate(&self) -> Result<(), ModelSelectionValidationError> {
        if let ModelSelectionMode::Exact { target } = &self.primary {
            if target.model_key.trim().is_empty() {
                return Err(ModelSelectionValidationError::EmptyExactModelKey);
            }
            if target.provider_model_id.trim().is_empty() {
                return Err(ModelSelectionValidationError::EmptyExactProviderModelId);
            }
            validate_cli_identifier(&target.model_key, MAX_MODEL_KEY_LENGTH)
                .map_err(ModelSelectionValidationError::UnsafeExactModelKey)?;
            validate_cli_identifier(&target.provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                .map_err(ModelSelectionValidationError::UnsafeExactProviderModelId)?;
            if target.executor.provider() != target.provider {
                return Err(ModelSelectionValidationError::PrimaryExecutorProviderMismatch);
            }
        } else if let ModelSelectionMode::Auto { executor, provider } = &self.primary {
            if executor.provider() != *provider {
                return Err(ModelSelectionValidationError::PrimaryExecutorProviderMismatch);
            }
        }

        if let ModelFallbackPolicy::Ordered { targets } = &self.fallback {
            if targets.is_empty() {
                return Err(ModelSelectionValidationError::EmptyFallbackList);
            }

            let mut seen = BTreeSet::new();
            for (index, target) in targets.iter().enumerate() {
                if target.model_key.trim().is_empty() {
                    return Err(ModelSelectionValidationError::EmptyFallbackModelKey { index });
                }
                if target.provider_model_id.trim().is_empty() {
                    return Err(
                        ModelSelectionValidationError::EmptyFallbackProviderModelId { index },
                    );
                }
                validate_cli_identifier(&target.model_key, MAX_MODEL_KEY_LENGTH).map_err(
                    |source| ModelSelectionValidationError::UnsafeFallbackModelKey {
                        index,
                        source,
                    },
                )?;
                validate_cli_identifier(&target.provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                    .map_err(|source| {
                        ModelSelectionValidationError::UnsafeFallbackProviderModelId {
                            index,
                            source,
                        }
                    })?;
                if target.executor.provider() != target.provider {
                    return Err(
                        ModelSelectionValidationError::FallbackExecutorProviderMismatch { index },
                    );
                }
                if !seen.insert((
                    target.executor,
                    target.provider,
                    target.model_key.as_str(),
                    target.provider_model_id.as_str(),
                )) {
                    return Err(ModelSelectionValidationError::DuplicateFallbackTarget { index });
                }
            }
        }

        Ok(())
    }

    /// Returns whether a concrete pin selects exactly one immutable task
    /// candidate. An auto primary may be unresolved (`None/None`) or carry its
    /// once-resolved model; exact and fallback slots require their exact pair.
    pub fn allows_candidate_pin(&self, pin: &AgentCandidatePinV2) -> bool {
        if pin.validate_identity().is_err() {
            return false;
        }
        if pin.selection_index == 0 {
            return match &self.primary {
                ModelSelectionMode::Exact { target } => {
                    pin.executor == target.executor
                        && pin.provider == target.provider
                        && pin.resolved_model()
                            == Some((target.model_key.as_str(), target.provider_model_id.as_str()))
                }
                ModelSelectionMode::Auto { executor, provider } => {
                    pin.executor == *executor && pin.provider == *provider
                }
            };
        }

        let fallback_index = pin.selection_index as usize - 1;
        let ModelFallbackPolicy::Ordered { targets } = &self.fallback else {
            return false;
        };
        targets.get(fallback_index).is_some_and(|target| {
            pin.executor == target.executor
                && pin.provider == target.provider
                && pin.resolved_model()
                    == Some((target.model_key.as_str(), target.provider_model_id.as_str()))
        })
    }

    /// Validates deterministic pin evolution. A task may acquire one allowed
    /// pin, then replay only that pin. The sole refinement permitted is an
    /// unresolved auto-primary model becoming resolved exactly once.
    pub fn validate_candidate_pin_transition(
        &self,
        previous: Option<&AgentCandidatePinV2>,
        next: &AgentCandidatePinV2,
    ) -> Result<(), AgentCandidatePinValidationError> {
        if !self.allows_candidate_pin(next) {
            return Err(AgentCandidatePinValidationError::CandidateNotAllowed);
        }
        let Some(previous) = previous else {
            return Ok(());
        };
        if !self.allows_candidate_pin(previous) {
            return Err(AgentCandidatePinValidationError::CandidateNotAllowed);
        }
        if previous.selection_index != next.selection_index
            || previous.executor != next.executor
            || previous.provider != next.provider
        {
            return Err(AgentCandidatePinValidationError::PinnedCandidateChanged);
        }
        match (previous.resolved_model(), next.resolved_model()) {
            (None, None) => Ok(()),
            (None, Some(_))
                if previous.selection_index == 0
                    && matches!(&self.primary, ModelSelectionMode::Auto { .. }) =>
            {
                Ok(())
            }
            (Some(previous), Some(next)) if previous == next => Ok(()),
            (Some(_), None) => Err(AgentCandidatePinValidationError::ResolvedModelCleared),
            _ => Err(AgentCandidatePinValidationError::PinnedCandidateChanged),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionRequirements {
    pub structured_output: bool,
    pub session_resume: bool,
    pub cancellation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionBindingV2 {
    /// Stable backend binding identifier, not a local filesystem path.
    pub workspace_binding_id: String,
    /// Monotonic binding generation. Rebinding a workspace must increment it,
    /// making previously issued tasks invalid for replay.
    pub workspace_binding_generation: u64,
    /// Exact runner assigned to this task.
    pub runner_id: String,
}

impl AgentExecutionBindingV2 {
    pub fn is_valid(&self) -> bool {
        !self.workspace_binding_id.trim().is_empty()
            && self.workspace_binding_generation > 0
            && !self.runner_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTaskRequestV2 {
    pub schema_version: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub binding: AgentExecutionBindingV2,
    pub selection: ModelSelection,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    pub requirements: AgentExecutionRequirements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<AgentSessionContinuationV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTaskValidationError {
    WrongSchemaVersion,
    EmptyRequestId,
    EmptyIdempotencyKey,
    UnsafeIdempotencyKey(CliIdentifierValidationError),
    EmptyBinding,
    InvalidBindingGeneration,
    EmptyPrompt,
    MissingStructuredOutputSchema,
    InvalidStructuredOutputSchema(AgentStructuredOutputSchemaValidationError),
    InvalidSelection(ModelSelectionValidationError),
    InvalidContinuation,
}

impl AgentTaskRequestV2 {
    /// A runtime must compare the issued target with its current binding before
    /// any execution or replay. A mismatch is an invalid request.
    pub fn is_for_binding(&self, current: &AgentExecutionBindingV2) -> bool {
        &self.binding == current
    }

    pub fn validate(&self) -> Result<(), AgentTaskValidationError> {
        if self.schema_version != AGENT_TASK_SCHEMA_V2 {
            return Err(AgentTaskValidationError::WrongSchemaVersion);
        }
        if self.request_id.trim().is_empty() {
            return Err(AgentTaskValidationError::EmptyRequestId);
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(AgentTaskValidationError::EmptyIdempotencyKey);
        }
        validate_idempotency_key(&self.idempotency_key)
            .map_err(AgentTaskValidationError::UnsafeIdempotencyKey)?;
        if self.binding.workspace_binding_id.trim().is_empty()
            || self.binding.runner_id.trim().is_empty()
        {
            return Err(AgentTaskValidationError::EmptyBinding);
        }
        if self.binding.workspace_binding_generation == 0 {
            return Err(AgentTaskValidationError::InvalidBindingGeneration);
        }
        if self.prompt.trim().is_empty() {
            return Err(AgentTaskValidationError::EmptyPrompt);
        }
        match &self.output_schema {
            Some(schema) => validate_agent_structured_output_schema(schema)
                .map_err(AgentTaskValidationError::InvalidStructuredOutputSchema)?,
            None if self.requirements.structured_output => {
                return Err(AgentTaskValidationError::MissingStructuredOutputSchema);
            }
            None => {}
        }

        self.selection
            .validate()
            .map_err(AgentTaskValidationError::InvalidSelection)?;

        if self
            .continuation
            .as_ref()
            .is_some_and(|continuation| !continuation.matches_request(self))
        {
            return Err(AgentTaskValidationError::InvalidContinuation);
        }

        Ok(())
    }
}

/// One immutable process-dispatch envelope. The logical task idempotency key
/// remains inside `task`; the task/delivery keys identify only this process
/// attempt. `payload_digest` is computed over RFC 8785/JCS canonical JSON of
/// this envelope with the `payloadDigest` member omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProcessRetryKindV2 {
    Initial,
    FreshAfterRemediation,
    ResumeFromCheckpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDeliveryRouteV2 {
    RunnerJob,
    DirectControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcessDeliveryV2 {
    pub route: AgentDeliveryRouteV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_target_runner_id: Option<String>,
}

impl AgentProcessDeliveryV2 {
    pub fn is_valid_for_task(&self, task: &AgentTaskRequestV2) -> bool {
        self.is_valid_for_binding(&task.binding)
    }

    pub fn is_valid_for_binding(&self, binding: &AgentExecutionBindingV2) -> bool {
        match self.route {
            AgentDeliveryRouteV2::RunnerJob => {
                self.runner_job_id
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty())
                    && self
                        .lease_target_runner_id
                        .as_ref()
                        .is_some_and(|runner_id| {
                            !runner_id.trim().is_empty() && runner_id == &binding.runner_id
                        })
            }
            AgentDeliveryRouteV2::DirectControl => {
                self.runner_job_id.is_none() && self.lease_target_runner_id.is_none()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcessDispatchV2 {
    pub schema_version: String,
    /// Unique logical agent-node execution ID. This must not be the shared
    /// parent workflow execution ID.
    pub execution_id: String,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub retry_kind: AgentProcessRetryKindV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_attempt_id: Option<String>,
    pub delivery: AgentProcessDeliveryV2,
    pub task_idempotency_key: String,
    pub delivery_idempotency_key: String,
    pub payload_digest: String,
    pub task: AgentTaskRequestV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentProcessDispatchValidationError {
    WrongSchemaVersion,
    EmptyIdentity,
    InvalidAttemptNumber,
    InvalidTaskIdempotencyKey,
    InvalidDeliveryIdempotencyKey,
    InvalidPayloadDigest,
    PayloadDigestMismatch,
    InvalidDeliveryRoute,
    DeliveryRouteOwnershipMismatch,
    InvalidTask,
    InvalidRetrySource,
}

impl AgentProcessDispatchV2 {
    /// JSON value that consumers canonicalize with RFC 8785/JCS before
    /// computing `payloadDigest`. The digest member itself is excluded.
    pub fn payload_digest_input(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(object) = &mut value {
            object.remove("payloadDigest");
        }
        Ok(value)
    }

    pub fn canonical_payload_digest_input(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonicalize_agent_payload(&self.payload_digest_input()?)
    }

    pub fn computed_payload_digest(&self) -> Result<String, serde_json::Error> {
        let digest = Sha256::digest(self.canonical_payload_digest_input()?);
        Ok(format!("{AGENT_PAYLOAD_DIGEST_PREFIX_V1}{digest:x}"))
    }

    pub fn validate(&self) -> Result<(), AgentProcessDispatchValidationError> {
        if self.schema_version != AGENT_PROCESS_DISPATCH_SCHEMA_V2 {
            return Err(AgentProcessDispatchValidationError::WrongSchemaVersion);
        }
        if self.execution_id.trim().is_empty() || self.attempt_id.trim().is_empty() {
            return Err(AgentProcessDispatchValidationError::EmptyIdentity);
        }
        if self.attempt_number == 0 {
            return Err(AgentProcessDispatchValidationError::InvalidAttemptNumber);
        }
        validate_agent_attempt_task_idempotency_key(&self.task_idempotency_key)
            .map_err(|_| AgentProcessDispatchValidationError::InvalidTaskIdempotencyKey)?;
        validate_agent_attempt_delivery_idempotency_key(&self.delivery_idempotency_key)
            .map_err(|_| AgentProcessDispatchValidationError::InvalidDeliveryIdempotencyKey)?;
        validate_agent_payload_digest(&self.payload_digest)
            .map_err(|_| AgentProcessDispatchValidationError::InvalidPayloadDigest)?;
        self.task
            .validate()
            .map_err(|_| AgentProcessDispatchValidationError::InvalidTask)?;
        if !self.delivery.is_valid_for_task(&self.task) {
            return Err(AgentProcessDispatchValidationError::InvalidDeliveryRoute);
        }
        if self
            .computed_payload_digest()
            .map_err(|_| AgentProcessDispatchValidationError::InvalidPayloadDigest)?
            != self.payload_digest
        {
            return Err(AgentProcessDispatchValidationError::PayloadDigestMismatch);
        }
        let retry_source_is_valid = match self.retry_kind {
            AgentProcessRetryKindV2::Initial => {
                self.attempt_number == 1
                    && self.from_attempt_id.is_none()
                    && self.task.continuation.is_none()
            }
            AgentProcessRetryKindV2::FreshAfterRemediation => {
                self.attempt_number > 1
                    && self
                        .from_attempt_id
                        .as_ref()
                        .is_some_and(|attempt_id| !attempt_id.trim().is_empty())
                    && self.task.continuation.is_none()
            }
            AgentProcessRetryKindV2::ResumeFromCheckpoint => {
                self.attempt_number > 1
                    && self
                        .from_attempt_id
                        .as_ref()
                        .is_some_and(|attempt_id| !attempt_id.trim().is_empty())
                    && self.task.continuation.is_some()
            }
        };
        if !retry_source_is_valid {
            return Err(AgentProcessDispatchValidationError::InvalidRetrySource);
        }
        Ok(())
    }

    pub fn validate_for_runner_job(
        &self,
        runner_job_id: &str,
        lease_target_runner_id: &str,
    ) -> Result<(), AgentProcessDispatchValidationError> {
        self.validate()?;
        if self.delivery.route != AgentDeliveryRouteV2::RunnerJob
            || self.delivery.runner_job_id.as_deref() != Some(runner_job_id)
            || self.delivery.lease_target_runner_id.as_deref() != Some(lease_target_runner_id)
        {
            return Err(AgentProcessDispatchValidationError::DeliveryRouteOwnershipMismatch);
        }
        Ok(())
    }

    pub fn validate_for_direct_control(&self) -> Result<(), AgentProcessDispatchValidationError> {
        self.validate()?;
        if self.delivery.route != AgentDeliveryRouteV2::DirectControl {
            return Err(AgentProcessDispatchValidationError::DeliveryRouteOwnershipMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReadiness {
    Ready,
    NotInstalled,
    NotAuthenticated,
    Unavailable,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    Installed,
    NotInstalled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    Authenticated,
    NotAuthenticated,
    NotRequired,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelDiscoveryKind {
    RuntimeProbe,
    StaticCatalog,
    ProviderDefaultOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAvailability {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentModelCapability {
    pub provider: AgentProvider,
    pub model_key: String,
    pub provider_model_id: String,
    pub availability: ModelAvailability,
    pub is_default: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_reasoning_efforts: Vec<ReasoningEffort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeFeatures {
    pub structured_output: bool,
    pub session_resume: bool,
    pub cancellation: bool,
    pub reasoning_effort: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutorCapability {
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    pub readiness: RuntimeReadiness,
    pub installation: InstallationState,
    pub authentication: AuthenticationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_version: Option<String>,
    pub model_discovery: ModelDiscoveryKind,
    #[serde(default)]
    pub models: Vec<AgentModelCapability>,
    pub features: AgentRuntimeFeatures,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<AgentRuntimeErrorEnvelopeV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeCapabilitySnapshotV2 {
    pub schema_version: String,
    pub runner_id: String,
    /// RFC 3339 timestamp supplied by the runtime.
    pub observed_at: String,
    /// Positive freshness window after which callers must probe again.
    pub ttl_seconds: u64,
    pub executors: Vec<AgentExecutorCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySnapshotValidationError {
    WrongSchemaVersion,
    EmptyRunnerId,
    EmptyObservedAt,
    ZeroTtl,
    DuplicateExecutor {
        executor: ExecutorKind,
    },
    ExecutorProviderMismatch {
        executor: ExecutorKind,
    },
    EmptyModelIdentity {
        executor: ExecutorKind,
        index: usize,
    },
    UnsafeModelIdentity {
        executor: ExecutorKind,
        index: usize,
    },
    ModelProviderMismatch {
        executor: ExecutorKind,
        index: usize,
    },
    DuplicateModel {
        executor: ExecutorKind,
        index: usize,
    },
    InvalidLastError {
        executor: ExecutorKind,
    },
}

impl AgentRuntimeCapabilitySnapshotV2 {
    pub fn validate(&self) -> Result<(), CapabilitySnapshotValidationError> {
        if self.schema_version != AGENT_CAPABILITY_SCHEMA_V2 {
            return Err(CapabilitySnapshotValidationError::WrongSchemaVersion);
        }
        if self.runner_id.trim().is_empty() {
            return Err(CapabilitySnapshotValidationError::EmptyRunnerId);
        }
        if self.observed_at.trim().is_empty() {
            return Err(CapabilitySnapshotValidationError::EmptyObservedAt);
        }
        if self.ttl_seconds == 0 {
            return Err(CapabilitySnapshotValidationError::ZeroTtl);
        }

        let mut executors = BTreeSet::new();
        for capability in &self.executors {
            if !executors.insert(capability.executor) {
                return Err(CapabilitySnapshotValidationError::DuplicateExecutor {
                    executor: capability.executor,
                });
            }
            if capability.executor.provider() != capability.provider {
                return Err(
                    CapabilitySnapshotValidationError::ExecutorProviderMismatch {
                        executor: capability.executor,
                    },
                );
            }

            let mut models = BTreeSet::new();
            for (index, model) in capability.models.iter().enumerate() {
                if model.model_key.trim().is_empty() || model.provider_model_id.trim().is_empty() {
                    return Err(CapabilitySnapshotValidationError::EmptyModelIdentity {
                        executor: capability.executor,
                        index,
                    });
                }
                if validate_cli_identifier(&model.model_key, MAX_MODEL_KEY_LENGTH).is_err()
                    || validate_cli_identifier(
                        &model.provider_model_id,
                        MAX_PROVIDER_MODEL_ID_LENGTH,
                    )
                    .is_err()
                {
                    return Err(CapabilitySnapshotValidationError::UnsafeModelIdentity {
                        executor: capability.executor,
                        index,
                    });
                }
                if model.provider != capability.provider {
                    return Err(CapabilitySnapshotValidationError::ModelProviderMismatch {
                        executor: capability.executor,
                        index,
                    });
                }
                if !models.insert((model.model_key.as_str(), model.provider_model_id.as_str())) {
                    return Err(CapabilitySnapshotValidationError::DuplicateModel {
                        executor: capability.executor,
                        index,
                    });
                }
            }

            if capability
                .last_error
                .as_ref()
                .is_some_and(|error| error.validate().is_err())
            {
                return Err(CapabilitySnapshotValidationError::InvalidLastError {
                    executor: capability.executor,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    InvalidRequest,
    ProtocolMismatch,
    ProviderNotInstalled,
    ProviderNotAuthenticated,
    /// The executable is installed and authenticated, but the current
    /// account, organization, plan, or region is not eligible for access.
    ProviderNotEligible,
    /// A valid v2 dispatch reached the bound runner while its local v2
    /// execution kill switch was disabled. No provider process was spawned.
    AgentRuntimeV2Disabled,
    RuntimeUnavailable,
    ModelUnknown,
    ModelNotAvailable,
    UnsupportedCapability,
    RateLimited,
    NetworkError,
    Timeout,
    Cancelled,
    OutputInvalid,
    SessionNotFound,
    SessionMismatch,
    ExecutionFailed,
    ExecutionIndeterminate,
    InternalError,
}

impl AgentErrorCode {
    pub const fn category(self) -> AgentErrorCategory {
        match self {
            Self::InvalidRequest | Self::ModelUnknown | Self::UnsupportedCapability => {
                AgentErrorCategory::Validation
            }
            Self::ProtocolMismatch => AgentErrorCategory::Protocol,
            Self::ProviderNotInstalled
            | Self::AgentRuntimeV2Disabled
            | Self::RuntimeUnavailable
            | Self::ModelNotAvailable => AgentErrorCategory::Availability,
            Self::ProviderNotAuthenticated => AgentErrorCategory::Authentication,
            Self::ProviderNotEligible => AgentErrorCategory::Authorization,
            Self::RateLimited => AgentErrorCategory::Capacity,
            Self::NetworkError | Self::Timeout => AgentErrorCategory::Transport,
            Self::Cancelled | Self::ExecutionFailed | Self::ExecutionIndeterminate => {
                AgentErrorCategory::Execution
            }
            Self::OutputInvalid => AgentErrorCategory::Output,
            Self::SessionNotFound | Self::SessionMismatch => AgentErrorCategory::Continuity,
            Self::InternalError => AgentErrorCategory::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCategory {
    Validation,
    Protocol,
    Availability,
    Authentication,
    Authorization,
    Capacity,
    Transport,
    Execution,
    Output,
    Continuity,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRetryDisposition {
    Never,
    Retryable,
    UserActionRequired,
    ResumeRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRemediationAction {
    InstallExecutor,
    /// Install a newer supported version of an already discovered executor.
    UpgradeExecutor,
    /// Re-run executable discovery when an executor was installed or moved
    /// after setup and the daemon's persisted absolute location is stale.
    RefreshExecutorDiscovery,
    Authenticate,
    VerifyProviderAccess,
    SelectDifferentModel,
    Retry,
    ResumeSession,
    ReconfigureWorkflow,
    ContactSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<ExecutorKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_model_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_provider_model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_model_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_provider_model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Redacted, user-safe scalar diagnostics. Runtime stderr, credentials,
    /// executable paths, environment values, and raw provider payloads must
    /// never be placed here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub safe_details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeErrorEnvelopeV2 {
    pub schema_version: String,
    pub code: AgentErrorCode,
    pub category: AgentErrorCategory,
    /// Stable, redacted explanation safe for persistence and display.
    pub message: String,
    pub retry: AgentRetryDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediation: Vec<AgentRemediationAction>,
    #[serde(default)]
    pub context: AgentErrorContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentErrorValidationError {
    WrongSchemaVersion,
    CategoryMismatch,
    EmptyMessage,
    RetryDelayWithoutRetryableDisposition,
    UserActionWithoutRemediation,
    UnpairedResolvedModelIdentity,
    UnsafeResolvedModelIdentity,
    VersionGateRemediationMismatch,
}

impl AgentRuntimeErrorEnvelopeV2 {
    pub fn validate(&self) -> Result<(), AgentErrorValidationError> {
        if self.schema_version != AGENT_ERROR_SCHEMA_V2 {
            return Err(AgentErrorValidationError::WrongSchemaVersion);
        }
        if self.category != self.code.category() {
            return Err(AgentErrorValidationError::CategoryMismatch);
        }
        if self.message.trim().is_empty() {
            return Err(AgentErrorValidationError::EmptyMessage);
        }
        if self.retry_after_seconds.is_some() && self.retry != AgentRetryDisposition::Retryable {
            return Err(AgentErrorValidationError::RetryDelayWithoutRetryableDisposition);
        }
        if self.retry == AgentRetryDisposition::UserActionRequired && self.remediation.is_empty() {
            return Err(AgentErrorValidationError::UserActionWithoutRemediation);
        }
        match (
            &self.context.resolved_model_key,
            &self.context.resolved_provider_model_id,
        ) {
            (None, None) => {}
            (Some(model_key), Some(provider_model_id))
                if validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_ok()
                    && validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_ok() => {}
            (Some(_), Some(_)) => {
                return Err(AgentErrorValidationError::UnsafeResolvedModelIdentity);
            }
            _ => return Err(AgentErrorValidationError::UnpairedResolvedModelIdentity),
        }
        if self
            .context
            .safe_details
            .get("reasonCode")
            .map(String::as_str)
            == Some("executor_version_unverified")
            && (self.code != AgentErrorCode::UnsupportedCapability
                || self.retry != AgentRetryDisposition::UserActionRequired
                || self.remediation
                    != [
                        AgentRemediationAction::UpgradeExecutor,
                        AgentRemediationAction::RefreshExecutorDiscovery,
                    ])
        {
            return Err(AgentErrorValidationError::VersionGateRemediationMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentExecutionState {
    Queued,
    Probing,
    Blocked,
    Running,
    Completed,
    Failed,
    Cancelled,
    Indeterminate,
}

impl AgentExecutionState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Indeterminate
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAttemptState {
    Queued,
    Probing,
    Starting,
    DispatchRejected,
    DispatchCancelled,
    Blocked,
    Running,
    RepairingOutput,
    Completed,
    Failed,
    Cancelled,
    Indeterminate,
}

impl AgentAttemptState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::DispatchRejected
                | Self::DispatchCancelled
                | Self::Blocked
                | Self::Completed
                | Self::Failed
                | Self::Cancelled
                | Self::Indeterminate
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionState {
    Created,
    Active,
    Suspended,
    Completed,
    Failed,
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionCheckpointV2 {
    pub schema_version: String,
    pub checkpoint_id: String,
    pub sequence: u64,
    pub session_id: String,
    /// Allowlisted, non-secret provider session identifier. Authentication
    /// tokens, resume tokens, and arbitrary opaque provider payloads are not
    /// part of this persistence contract.
    pub provider_session_id: String,
    pub binding: AgentExecutionBindingV2,
    pub execution_id: String,
    pub attempt_id: String,
    #[serde(default)]
    pub selection_index: u32,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    /// Both model fields are absent only while an `auto` selection is
    /// unresolved. Exact selections and resolved auto sessions carry both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_model_id: Option<String>,
    pub state: AgentSessionState,
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSessionValidationError {
    WrongSchemaVersion,
    EmptyIdentity,
    InvalidSequence,
    InvalidBinding,
    ExecutorProviderMismatch,
    EmptyModelId,
    UnpairedModelIdentity,
    UnsafeCliIdentifier,
    CandidateNotAllowed,
    EmptyTimestamp,
}

impl AgentSessionCheckpointV2 {
    pub fn candidate_pin(&self) -> AgentCandidatePinV2 {
        AgentCandidatePinV2 {
            selection_index: self.selection_index,
            executor: self.executor,
            provider: self.provider,
            model_key: self.model_key.clone(),
            provider_model_id: self.provider_model_id.clone(),
        }
    }

    pub fn validate_for_request(
        &self,
        request: &AgentTaskRequestV2,
    ) -> Result<(), AgentSessionValidationError> {
        self.validate()?;
        if !request
            .selection
            .allows_candidate_pin(&self.candidate_pin())
        {
            return Err(AgentSessionValidationError::CandidateNotAllowed);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AgentSessionValidationError> {
        if self.schema_version != AGENT_SESSION_SCHEMA_V2 {
            return Err(AgentSessionValidationError::WrongSchemaVersion);
        }
        if self.checkpoint_id.trim().is_empty()
            || self.session_id.trim().is_empty()
            || self.provider_session_id.trim().is_empty()
            || self.execution_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
        {
            return Err(AgentSessionValidationError::EmptyIdentity);
        }
        if self.sequence == 0 {
            return Err(AgentSessionValidationError::InvalidSequence);
        }
        if self.executor.provider() != self.provider {
            return Err(AgentSessionValidationError::ExecutorProviderMismatch);
        }
        if !self.binding.is_valid() {
            return Err(AgentSessionValidationError::InvalidBinding);
        }
        if validate_cli_identifier(&self.provider_session_id, MAX_PROVIDER_SESSION_ID_LENGTH)
            .is_err()
        {
            return Err(AgentSessionValidationError::UnsafeCliIdentifier);
        }
        match (&self.model_key, &self.provider_model_id) {
            (None, None) => {}
            (Some(model_key), Some(provider_model_id)) => {
                if model_key.trim().is_empty() || provider_model_id.trim().is_empty() {
                    return Err(AgentSessionValidationError::EmptyModelId);
                }
                if validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_err()
                    || validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_err()
                {
                    return Err(AgentSessionValidationError::UnsafeCliIdentifier);
                }
            }
            _ => return Err(AgentSessionValidationError::UnpairedModelIdentity),
        }
        if self.recorded_at.trim().is_empty() {
            return Err(AgentSessionValidationError::EmptyTimestamp);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionContinuationV2 {
    pub schema_version: String,
    pub checkpoint_id: String,
    pub sequence: u64,
    pub session_id: String,
    /// The same allowlisted, non-secret identifier captured by the checkpoint.
    pub provider_session_id: String,
    pub binding: AgentExecutionBindingV2,
    #[serde(default)]
    pub selection_index: u32,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    /// A resolved pair pins the model for resume. Both fields may be absent
    /// only when resuming an unresolved `auto` selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_model_id: Option<String>,
}

impl AgentSessionContinuationV2 {
    pub fn candidate_pin(&self) -> AgentCandidatePinV2 {
        AgentCandidatePinV2 {
            selection_index: self.selection_index,
            executor: self.executor,
            provider: self.provider,
            model_key: self.model_key.clone(),
            provider_model_id: self.provider_model_id.clone(),
        }
    }

    pub fn resolved_model(&self) -> Option<(&str, &str)> {
        self.model_key
            .as_deref()
            .zip(self.provider_model_id.as_deref())
    }

    pub fn matches_checkpoint(&self, checkpoint: &AgentSessionCheckpointV2) -> bool {
        self.schema_version == AGENT_SESSION_SCHEMA_V2
            && self.checkpoint_id == checkpoint.checkpoint_id
            && self.sequence == checkpoint.sequence
            && self.session_id == checkpoint.session_id
            && self.provider_session_id == checkpoint.provider_session_id
            && self.binding == checkpoint.binding
            && self.candidate_pin() == checkpoint.candidate_pin()
    }

    pub fn matches_request(&self, request: &AgentTaskRequestV2) -> bool {
        if self.schema_version != AGENT_SESSION_SCHEMA_V2
            || self.checkpoint_id.trim().is_empty()
            || self.session_id.trim().is_empty()
            || self.provider_session_id.trim().is_empty()
            || self.sequence == 0
            || !self.binding.is_valid()
            || self.binding != request.binding
            || validate_cli_identifier(&self.provider_session_id, MAX_PROVIDER_SESSION_ID_LENGTH)
                .is_err()
        {
            return false;
        }

        let resolved_model = match (&self.model_key, &self.provider_model_id) {
            (None, None) => None,
            (Some(model_key), Some(provider_model_id))
                if validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_ok()
                    && validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_ok() =>
            {
                Some((model_key.as_str(), provider_model_id.as_str()))
            }
            _ => return false,
        };

        let _ = resolved_model;
        request
            .selection
            .allows_candidate_pin(&self.candidate_pin())
    }
}

impl From<&AgentSessionCheckpointV2> for AgentSessionContinuationV2 {
    fn from(checkpoint: &AgentSessionCheckpointV2) -> Self {
        Self {
            schema_version: AGENT_SESSION_SCHEMA_V2.to_string(),
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            sequence: checkpoint.sequence,
            session_id: checkpoint.session_id.clone(),
            provider_session_id: checkpoint.provider_session_id.clone(),
            binding: checkpoint.binding.clone(),
            selection_index: checkpoint.selection_index,
            executor: checkpoint.executor,
            provider: checkpoint.provider,
            model_key: checkpoint.model_key.clone(),
            provider_model_id: checkpoint.provider_model_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentOutput {
    pub format: AgentOutputFormat,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
}

impl AgentOutput {
    pub fn is_valid(&self) -> bool {
        match self.format {
            AgentOutputFormat::Text => !self.content.trim().is_empty() && self.structured.is_none(),
            AgentOutputFormat::Json => self.structured.as_ref().is_some_and(Value::is_object),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAttemptV2 {
    pub attempt_id: String,
    pub attempt_number: u32,
    /// Per-process task idempotency. This is distinct from the stable logical
    /// execution idempotency key and is immutable with the invocation payload.
    pub task_idempotency_key: String,
    /// Per-process terminal delivery idempotency, derived under a separate
    /// domain from `task_idempotency_key`.
    pub delivery_idempotency_key: String,
    /// SHA-256 of the canonical immutable process invocation envelope,
    /// including the candidate pin and optional resume continuation.
    pub payload_digest: String,
    pub state: AgentAttemptState,
    #[serde(default)]
    pub started_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_sequence: Option<u64>,
    #[serde(default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<AgentSessionCheckpointV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<AgentAttemptRetryV2>,
    pub delivery: AgentProcessDeliveryV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentRuntimeErrorEnvelopeV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAttemptRetryV2 {
    pub retry_kind: AgentProcessRetryKindV2,
    pub from_attempt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<AgentSessionContinuationV2>,
}

impl AgentAttemptV2 {
    pub fn candidate_pin(&self) -> AgentCandidatePinV2 {
        AgentCandidatePinV2 {
            selection_index: self.selection_index,
            executor: self.executor,
            provider: self.provider,
            model_key: self.resolved_model_key.clone(),
            provider_model_id: self.resolved_provider_model_id.clone(),
        }
    }
}

fn canonical_dispatch_rejection_context(
    execution_id: &str,
    attempt: &AgentAttemptV2,
    reason_code: &str,
) -> AgentErrorContext {
    AgentErrorContext {
        executor: Some(attempt.executor),
        provider: Some(attempt.provider),
        requested_model_key: attempt.requested_model_key.clone(),
        requested_provider_model_id: attempt.requested_provider_model_id.clone(),
        // A pre-spawn rejection does not claim provider-side resolution. The
        // exact candidate remains preserved on the trusted attempt itself.
        resolved_model_key: None,
        resolved_provider_model_id: None,
        execution_id: Some(execution_id.to_string()),
        attempt_id: Some(attempt.attempt_id.clone()),
        session_id: None,
        safe_details: BTreeMap::from([("reasonCode".to_string(), reason_code.to_string())]),
    }
}

/// Builds the only valid terminal envelope for a malformed pre-spawn dispatch.
///
/// Backend must call the equivalent construction using only its persisted
/// execution, process-attempt, delivery, and candidate-pin identity. A raw
/// plugin message or context is diagnostic input only and must not be copied
/// into the durable terminal execution.
pub fn synthesize_malformed_dispatch_error(
    execution_id: &str,
    attempt: &AgentAttemptV2,
) -> AgentRuntimeErrorEnvelopeV2 {
    AgentRuntimeErrorEnvelopeV2 {
        schema_version: AGENT_ERROR_SCHEMA_V2.to_string(),
        code: AgentErrorCode::InvalidRequest,
        category: AgentErrorCategory::Validation,
        message: AGENT_MALFORMED_DISPATCH_MESSAGE.to_string(),
        retry: AgentRetryDisposition::Never,
        retry_after_seconds: None,
        remediation: Vec::new(),
        context: canonical_dispatch_rejection_context(
            execution_id,
            attempt,
            AGENT_MALFORMED_DISPATCH_REASON_CODE,
        ),
    }
}

fn is_canonical_dispatch_rejection_error(
    error: &AgentRuntimeErrorEnvelopeV2,
    execution_id: &str,
    attempt: &AgentAttemptV2,
) -> bool {
    let (expected_code, expected_message, expected_reason) = match error
        .context
        .safe_details
        .get("reasonCode")
        .map(String::as_str)
    {
        Some(AGENT_RUNTIME_V2_DISABLED_REASON_CODE) => (
            AgentErrorCode::AgentRuntimeV2Disabled,
            AGENT_RUNTIME_V2_DISABLED_MESSAGE,
            AGENT_RUNTIME_V2_DISABLED_REASON_CODE,
        ),
        Some(AGENT_MALFORMED_DISPATCH_REASON_CODE) => (
            AgentErrorCode::InvalidRequest,
            AGENT_MALFORMED_DISPATCH_MESSAGE,
            AGENT_MALFORMED_DISPATCH_REASON_CODE,
        ),
        _ => return false,
    };
    error.code == expected_code
        && error.category == expected_code.category()
        && error.message == expected_message
        && error.retry == AgentRetryDisposition::Never
        && error.retry_after_seconds.is_none()
        && error.remediation.is_empty()
        && error.context
            == canonical_dispatch_rejection_context(execution_id, attempt, expected_reason)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionV2 {
    pub schema_version: String,
    /// Unique logical agent-node execution ID, typically the persisted
    /// PluginAgentAttempt UUID. Multiple agent nodes in one workflow must not
    /// reuse their parent workflow execution ID here.
    pub execution_id: String,
    pub request_id: String,
    #[serde(default)]
    pub idempotency_key: String,
    #[serde(default)]
    pub sequence: u64,
    pub binding: AgentExecutionBindingV2,
    pub state: AgentExecutionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_attempt_id: Option<String>,
    #[serde(default)]
    pub attempts: Vec<AgentAttemptV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<AgentOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentRuntimeErrorEnvelopeV2>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentExecutionValidationError {
    WrongSchemaVersion,
    EmptyIdentity,
    InvalidIdempotencyKey,
    InvalidLifecycleSequence,
    TooManyAttempts,
    InvalidAttemptIdempotencyKey,
    InvalidAttemptPayloadDigest,
    InvalidAttemptDeliveryRoute,
    DuplicateAttemptIdempotencyKey,
    DuplicateAttemptDeliveryIdempotencyKey,
    DuplicateAttemptPayloadDigest,
    AttemptNumbersNotContiguous,
    AttemptSequenceInvalid,
    InvalidAttemptRetry,
    PinnedCandidateChanged,
    CandidateNotAllowed,
    LogicalIdentityMismatch,
    NonMonotonicUpdate,
    AttemptHistoryRewritten,
    EmptyExecutionTimestamp,
    ExecutionTimestampStateMismatch,
    InvalidBinding,
    DuplicateAttemptId,
    DuplicateAttemptNumber,
    EmptyAttemptIdentity,
    InvalidAttemptNumber,
    EmptyAttemptTimestamp,
    AttemptTimestampStateMismatch,
    AttemptErrorStateMismatch,
    AttemptExecutorProviderMismatch,
    UnpairedAttemptModelIdentity,
    UnsafeAttemptCliIdentifier,
    InvalidCheckpoint,
    CheckpointBindingMismatch,
    CheckpointCandidateMismatch,
    InvalidAttemptError,
    InvalidExecutionError,
    ErrorContextBindingMismatch,
    InvalidOutput,
    ActiveAttemptNotFound,
    ExecutionStateActiveAttemptMismatch,
    ExecutionStatePayloadMismatch,
    ExecutionTerminalAttemptMismatch,
    InvalidPrestartCancellationReplacement,
}

impl AgentExecutionV2 {
    pub fn validate_for_request(
        &self,
        request: &AgentTaskRequestV2,
    ) -> Result<(), AgentExecutionValidationError> {
        self.validate()?;
        if self.request_id != request.request_id
            || self.idempotency_key != request.idempotency_key
            || self.binding != request.binding
        {
            return Err(AgentExecutionValidationError::LogicalIdentityMismatch);
        }
        let mut previous_pin: Option<AgentCandidatePinV2> = None;
        let mut attempts: Vec<&AgentAttemptV2> = self.attempts.iter().collect();
        attempts.sort_by_key(|attempt| attempt.attempt_number);
        for attempt in attempts {
            let pin = attempt.candidate_pin();
            request
                .selection
                .validate_candidate_pin_transition(previous_pin.as_ref(), &pin)
                .map_err(|error| match error {
                    AgentCandidatePinValidationError::CandidateNotAllowed => {
                        AgentExecutionValidationError::CandidateNotAllowed
                    }
                    _ => AgentExecutionValidationError::PinnedCandidateChanged,
                })?;
            if let Some(checkpoint) = &attempt.session {
                checkpoint
                    .validate_for_request(request)
                    .map_err(|_| AgentExecutionValidationError::CandidateNotAllowed)?;
            }
            if attempt
                .retry
                .as_ref()
                .and_then(|retry| retry.continuation.as_ref())
                .is_some_and(|continuation| !continuation.matches_request(request))
            {
                return Err(AgentExecutionValidationError::InvalidAttemptRetry);
            }
            previous_pin = Some(pin);
        }
        Ok(())
    }

    pub fn validate_successor(
        &self,
        next: &Self,
        request: &AgentTaskRequestV2,
    ) -> Result<AgentExecutionUpdateKind, AgentExecutionValidationError> {
        self.validate_for_request(request)?;
        next.validate_for_request(request)?;
        if self == next {
            return Ok(AgentExecutionUpdateKind::IdempotentReplay);
        }
        if self.execution_id != next.execution_id
            || self.request_id != next.request_id
            || self.idempotency_key != next.idempotency_key
            || self.binding != next.binding
        {
            return Err(AgentExecutionValidationError::LogicalIdentityMismatch);
        }
        if next.sequence <= self.sequence || next.attempts.len() < self.attempts.len() {
            return Err(AgentExecutionValidationError::NonMonotonicUpdate);
        }
        if next.attempts.len() > self.attempts.len() + 1 {
            return Err(AgentExecutionValidationError::NonMonotonicUpdate);
        }
        if self.state.is_terminal()
            || (self.state == AgentExecutionState::Blocked
                && next.attempts.len() == self.attempts.len())
        {
            return Err(AgentExecutionValidationError::AttemptHistoryRewritten);
        }
        for previous_attempt in &self.attempts {
            let Some(next_attempt) = next
                .attempts
                .iter()
                .find(|attempt| attempt.attempt_id == previous_attempt.attempt_id)
            else {
                return Err(AgentExecutionValidationError::AttemptHistoryRewritten);
            };
            if previous_attempt.state.is_terminal() && previous_attempt != next_attempt {
                return Err(AgentExecutionValidationError::AttemptHistoryRewritten);
            }
            if previous_attempt.attempt_number != next_attempt.attempt_number
                || previous_attempt.task_idempotency_key != next_attempt.task_idempotency_key
                || previous_attempt.delivery_idempotency_key
                    != next_attempt.delivery_idempotency_key
                || previous_attempt.payload_digest != next_attempt.payload_digest
                || previous_attempt.started_sequence != next_attempt.started_sequence
                || previous_attempt.selection_index != next_attempt.selection_index
                || previous_attempt.executor != next_attempt.executor
                || previous_attempt.provider != next_attempt.provider
                || previous_attempt.requested_model_key != next_attempt.requested_model_key
                || previous_attempt.requested_provider_model_id
                    != next_attempt.requested_provider_model_id
                || previous_attempt.started_at != next_attempt.started_at
                || previous_attempt.retry != next_attempt.retry
                || previous_attempt.delivery != next_attempt.delivery
            {
                return Err(AgentExecutionValidationError::AttemptHistoryRewritten);
            }
            request
                .selection
                .validate_candidate_pin_transition(
                    Some(&previous_attempt.candidate_pin()),
                    &next_attempt.candidate_pin(),
                )
                .map_err(|_| AgentExecutionValidationError::AttemptHistoryRewritten)?;
        }
        Ok(AgentExecutionUpdateKind::Advanced)
    }

    /// Validates the sole same-sequence terminal replacement allowed before
    /// Backend acknowledgement: an unacknowledged local kill-switch rejection
    /// is replaced when a Backend cancellation has already linearized.
    pub fn validate_prestart_cancellation_replacement(
        &self,
        cancelled: &Self,
        request: &AgentTaskRequestV2,
    ) -> Result<AgentPrestartCancellationReplacement, AgentExecutionValidationError> {
        self.validate_for_request(request)?;
        cancelled.validate_for_request(request)?;

        let Some(rejected_attempt) = self.attempts.first() else {
            return Err(AgentExecutionValidationError::InvalidPrestartCancellationReplacement);
        };
        let Some(cancelled_attempt) = cancelled.attempts.first() else {
            return Err(AgentExecutionValidationError::InvalidPrestartCancellationReplacement);
        };
        let logical_identity_matches = self.schema_version == cancelled.schema_version
            && self.execution_id == cancelled.execution_id
            && self.request_id == cancelled.request_id
            && self.idempotency_key == cancelled.idempotency_key
            && self.binding == cancelled.binding
            && self.created_at == cancelled.created_at
            && self.sequence == 1
            && cancelled.sequence == 1;
        let terminal_shapes_match = self.state == AgentExecutionState::Failed
            && cancelled.state == AgentExecutionState::Cancelled
            && self.attempts.len() == 1
            && cancelled.attempts.len() == 1
            && rejected_attempt.state == AgentAttemptState::DispatchRejected
            && cancelled_attempt.state == AgentAttemptState::DispatchCancelled;
        let invocation_identity_matches = rejected_attempt.attempt_id
            == cancelled_attempt.attempt_id
            && rejected_attempt.attempt_number == cancelled_attempt.attempt_number
            && rejected_attempt.task_idempotency_key == cancelled_attempt.task_idempotency_key
            && rejected_attempt.delivery_idempotency_key
                == cancelled_attempt.delivery_idempotency_key
            && rejected_attempt.payload_digest == cancelled_attempt.payload_digest
            && rejected_attempt.started_sequence == cancelled_attempt.started_sequence
            && rejected_attempt.finished_sequence == cancelled_attempt.finished_sequence
            && rejected_attempt.delivery == cancelled_attempt.delivery
            && rejected_attempt.selection_index == cancelled_attempt.selection_index
            && rejected_attempt.executor == cancelled_attempt.executor
            && rejected_attempt.provider == cancelled_attempt.provider
            && rejected_attempt.requested_model_key == cancelled_attempt.requested_model_key
            && rejected_attempt.requested_provider_model_id
                == cancelled_attempt.requested_provider_model_id
            && rejected_attempt.resolved_model_key == cancelled_attempt.resolved_model_key
            && rejected_attempt.resolved_provider_model_id
                == cancelled_attempt.resolved_provider_model_id
            && rejected_attempt.retry.is_none()
            && cancelled_attempt.retry.is_none()
            && rejected_attempt.session.is_none()
            && cancelled_attempt.session.is_none();
        if !logical_identity_matches || !terminal_shapes_match || !invocation_identity_matches {
            return Err(AgentExecutionValidationError::InvalidPrestartCancellationReplacement);
        }

        Ok(AgentPrestartCancellationReplacement::CancellationWon)
    }

    pub fn validate(&self) -> Result<(), AgentExecutionValidationError> {
        if self.schema_version != AGENT_EXECUTION_SCHEMA_V2 {
            return Err(AgentExecutionValidationError::WrongSchemaVersion);
        }
        if self.execution_id.trim().is_empty() || self.request_id.trim().is_empty() {
            return Err(AgentExecutionValidationError::EmptyIdentity);
        }
        if validate_idempotency_key(&self.idempotency_key).is_err() {
            return Err(AgentExecutionValidationError::InvalidIdempotencyKey);
        }
        if self.sequence == 0 {
            return Err(AgentExecutionValidationError::InvalidLifecycleSequence);
        }
        if self.attempts.len() > MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION {
            return Err(AgentExecutionValidationError::TooManyAttempts);
        }
        if self.created_at.trim().is_empty()
            || self.updated_at.trim().is_empty()
            || self
                .started_at
                .as_ref()
                .is_some_and(|timestamp| timestamp.trim().is_empty())
            || self
                .finished_at
                .as_ref()
                .is_some_and(|timestamp| timestamp.trim().is_empty())
        {
            return Err(AgentExecutionValidationError::EmptyExecutionTimestamp);
        }
        let execution_timestamps_are_coherent = match self.state {
            AgentExecutionState::Queued => self.started_at.is_none() && self.finished_at.is_none(),
            AgentExecutionState::Probing
            | AgentExecutionState::Blocked
            | AgentExecutionState::Running => {
                self.started_at.is_some() && self.finished_at.is_none()
            }
            AgentExecutionState::Completed
            | AgentExecutionState::Failed
            | AgentExecutionState::Cancelled
            | AgentExecutionState::Indeterminate => {
                self.started_at.is_some() && self.finished_at.is_some()
            }
        };
        if !execution_timestamps_are_coherent {
            return Err(AgentExecutionValidationError::ExecutionTimestampStateMismatch);
        }
        if !self.binding.is_valid() {
            return Err(AgentExecutionValidationError::InvalidBinding);
        }

        let mut attempt_ids = BTreeSet::new();
        let mut attempt_numbers = BTreeSet::new();
        let mut task_idempotency_keys = BTreeSet::new();
        let mut delivery_idempotency_keys = BTreeSet::new();
        let mut payload_digests = BTreeSet::new();
        for attempt in &self.attempts {
            if attempt.attempt_id.trim().is_empty() {
                return Err(AgentExecutionValidationError::EmptyAttemptIdentity);
            }
            if attempt.attempt_number == 0 {
                return Err(AgentExecutionValidationError::InvalidAttemptNumber);
            }
            if validate_agent_attempt_task_idempotency_key(&attempt.task_idempotency_key).is_err()
                || validate_agent_attempt_delivery_idempotency_key(
                    &attempt.delivery_idempotency_key,
                )
                .is_err()
            {
                return Err(AgentExecutionValidationError::InvalidAttemptIdempotencyKey);
            }
            if validate_agent_payload_digest(&attempt.payload_digest).is_err() {
                return Err(AgentExecutionValidationError::InvalidAttemptPayloadDigest);
            }
            if !attempt.delivery.is_valid_for_binding(&self.binding) {
                return Err(AgentExecutionValidationError::InvalidAttemptDeliveryRoute);
            }
            if !task_idempotency_keys.insert(attempt.task_idempotency_key.as_str()) {
                return Err(AgentExecutionValidationError::DuplicateAttemptIdempotencyKey);
            }
            if !delivery_idempotency_keys.insert(attempt.delivery_idempotency_key.as_str()) {
                return Err(AgentExecutionValidationError::DuplicateAttemptDeliveryIdempotencyKey);
            }
            if !payload_digests.insert(attempt.payload_digest.as_str()) {
                return Err(AgentExecutionValidationError::DuplicateAttemptPayloadDigest);
            }
            let finished_sequence_is_valid = match (attempt.state, attempt.finished_sequence) {
                (
                    AgentAttemptState::DispatchRejected | AgentAttemptState::DispatchCancelled,
                    Some(sequence),
                ) => sequence == attempt.started_sequence && sequence == self.sequence,
                (_, Some(sequence)) => {
                    sequence > attempt.started_sequence && sequence <= self.sequence
                }
                (_, None) => !attempt.state.is_terminal(),
            };
            if attempt.started_sequence == 0
                || attempt.started_sequence > self.sequence
                || !finished_sequence_is_valid
                || attempt.state.is_terminal() != attempt.finished_sequence.is_some()
            {
                return Err(AgentExecutionValidationError::AttemptSequenceInvalid);
            }
            if attempt.started_at.trim().is_empty()
                || attempt
                    .finished_at
                    .as_ref()
                    .is_some_and(|timestamp| timestamp.trim().is_empty())
            {
                return Err(AgentExecutionValidationError::EmptyAttemptTimestamp);
            }
            if attempt.state.is_terminal() != attempt.finished_at.is_some() {
                return Err(AgentExecutionValidationError::AttemptTimestampStateMismatch);
            }
            if matches!(
                attempt.state,
                AgentAttemptState::DispatchRejected | AgentAttemptState::DispatchCancelled
            ) && attempt.finished_at.as_deref() != Some(attempt.started_at.as_str())
            {
                return Err(AgentExecutionValidationError::AttemptTimestampStateMismatch);
            }
            let error_is_coherent = match attempt.state {
                AgentAttemptState::DispatchRejected => {
                    attempt.error.as_ref().is_some_and(|error| {
                        is_canonical_dispatch_rejection_error(error, &self.execution_id, attempt)
                    }) && attempt.session.is_none()
                }
                AgentAttemptState::DispatchCancelled => {
                    attempt.error.as_ref().is_some_and(|error| {
                        error.code == AgentErrorCode::Cancelled
                            && error.retry == AgentRetryDisposition::Never
                            && error.remediation.is_empty()
                            && error
                                .context
                                .safe_details
                                .get("reasonCode")
                                .map(String::as_str)
                                == Some("prestart_cancellation_won")
                    }) && attempt.session.is_none()
                }
                AgentAttemptState::Blocked => attempt.error.is_some(),
                AgentAttemptState::Failed => attempt.error.as_ref().is_some_and(|error| {
                    !matches!(
                        error.code,
                        AgentErrorCode::Cancelled | AgentErrorCode::ExecutionIndeterminate
                    )
                }),
                AgentAttemptState::Cancelled => attempt
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code == AgentErrorCode::Cancelled),
                AgentAttemptState::Indeterminate => attempt
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code == AgentErrorCode::ExecutionIndeterminate),
                AgentAttemptState::RepairingOutput => attempt
                    .error
                    .as_ref()
                    .is_none_or(|error| error.code == AgentErrorCode::OutputInvalid),
                AgentAttemptState::Queued
                | AgentAttemptState::Probing
                | AgentAttemptState::Starting
                | AgentAttemptState::Running
                | AgentAttemptState::Completed => attempt.error.is_none(),
            };
            if !error_is_coherent {
                return Err(AgentExecutionValidationError::AttemptErrorStateMismatch);
            }
            if !attempt_ids.insert(attempt.attempt_id.as_str()) {
                return Err(AgentExecutionValidationError::DuplicateAttemptId);
            }
            if !attempt_numbers.insert(attempt.attempt_number) {
                return Err(AgentExecutionValidationError::DuplicateAttemptNumber);
            }
            if attempt.executor.provider() != attempt.provider {
                return Err(AgentExecutionValidationError::AttemptExecutorProviderMismatch);
            }
            let requested_model = match (
                &attempt.requested_model_key,
                &attempt.requested_provider_model_id,
            ) {
                (None, None) => None,
                (Some(model_key), Some(provider_model_id)) => {
                    Some((model_key.as_str(), provider_model_id.as_str()))
                }
                _ => {
                    return Err(AgentExecutionValidationError::UnpairedAttemptModelIdentity);
                }
            };
            let resolved_model = match (
                &attempt.resolved_model_key,
                &attempt.resolved_provider_model_id,
            ) {
                (None, None) => None,
                (Some(model_key), Some(provider_model_id)) => {
                    Some((model_key.as_str(), provider_model_id.as_str()))
                }
                _ => {
                    return Err(AgentExecutionValidationError::UnpairedAttemptModelIdentity);
                }
            };
            if requested_model.is_some_and(|(model_key, provider_model_id)| {
                validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_err()
                    || validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_err()
            }) || resolved_model.is_some_and(|(model_key, provider_model_id)| {
                validate_cli_identifier(model_key, MAX_MODEL_KEY_LENGTH).is_err()
                    || validate_cli_identifier(provider_model_id, MAX_PROVIDER_MODEL_ID_LENGTH)
                        .is_err()
            }) {
                return Err(AgentExecutionValidationError::UnsafeAttemptCliIdentifier);
            }
            if let Some(checkpoint) = &attempt.session {
                checkpoint
                    .validate()
                    .map_err(|_| AgentExecutionValidationError::InvalidCheckpoint)?;
                if checkpoint.execution_id != self.execution_id
                    || checkpoint.attempt_id != attempt.attempt_id
                    || checkpoint.binding != self.binding
                {
                    return Err(AgentExecutionValidationError::CheckpointBindingMismatch);
                }
                if checkpoint.candidate_pin() != attempt.candidate_pin()
                    || resolved_model
                        != checkpoint
                            .model_key
                            .as_deref()
                            .zip(checkpoint.provider_model_id.as_deref())
                {
                    return Err(AgentExecutionValidationError::CheckpointCandidateMismatch);
                }
            }
            if attempt
                .error
                .as_ref()
                .is_some_and(|error| error.validate().is_err())
            {
                return Err(AgentExecutionValidationError::InvalidAttemptError);
            }
            if attempt.error.as_ref().is_some_and(|error| {
                error
                    .context
                    .execution_id
                    .as_ref()
                    .is_some_and(|execution_id| execution_id != &self.execution_id)
                    || error
                        .context
                        .attempt_id
                        .as_ref()
                        .is_some_and(|attempt_id| attempt_id != &attempt.attempt_id)
            }) {
                return Err(AgentExecutionValidationError::ErrorContextBindingMismatch);
            }
        }

        let mut ordered_attempts: Vec<&AgentAttemptV2> = self.attempts.iter().collect();
        ordered_attempts.sort_by_key(|attempt| attempt.attempt_number);
        let mut lifecycle_sequences = BTreeSet::new();
        for (index, attempt) in ordered_attempts.iter().enumerate() {
            if attempt.attempt_number as usize != index + 1 {
                return Err(AgentExecutionValidationError::AttemptNumbersNotContiguous);
            }
            if !lifecycle_sequences.insert(attempt.started_sequence)
                || attempt.finished_sequence.is_some_and(|sequence| {
                    sequence != attempt.started_sequence && !lifecycle_sequences.insert(sequence)
                })
                || attempt.session.as_ref().is_some_and(|checkpoint| {
                    checkpoint.sequence <= attempt.started_sequence
                        || checkpoint.sequence > attempt.finished_sequence.unwrap_or(self.sequence)
                        || !lifecycle_sequences.insert(checkpoint.sequence)
                })
            {
                return Err(AgentExecutionValidationError::AttemptSequenceInvalid);
            }

            if index == 0 {
                if attempt.retry.is_some() {
                    return Err(AgentExecutionValidationError::InvalidAttemptRetry);
                }
                continue;
            }

            let previous = ordered_attempts[index - 1];
            let previous_finished_sequence = previous
                .finished_sequence
                .ok_or(AgentExecutionValidationError::InvalidAttemptRetry)?;
            if attempt.started_sequence <= previous_finished_sequence
                || !matches!(
                    previous.state,
                    AgentAttemptState::Blocked | AgentAttemptState::Indeterminate
                )
            {
                return Err(AgentExecutionValidationError::InvalidAttemptRetry);
            }
            let retry = attempt
                .retry
                .as_ref()
                .ok_or(AgentExecutionValidationError::InvalidAttemptRetry)?;
            if retry.from_attempt_id != previous.attempt_id {
                return Err(AgentExecutionValidationError::InvalidAttemptRetry);
            }
            let retry_is_valid = match retry.retry_kind {
                AgentProcessRetryKindV2::Initial => false,
                AgentProcessRetryKindV2::FreshAfterRemediation => {
                    previous.state == AgentAttemptState::Blocked
                        && previous.session.is_none()
                        && retry.continuation.is_none()
                }
                AgentProcessRetryKindV2::ResumeFromCheckpoint => previous
                    .session
                    .as_ref()
                    .zip(retry.continuation.as_ref())
                    .is_some_and(|(checkpoint, continuation)| {
                        continuation.matches_checkpoint(checkpoint)
                    }),
            };
            if !retry_is_valid {
                return Err(AgentExecutionValidationError::InvalidAttemptRetry);
            }
            let previous_pin = previous.candidate_pin();
            let next_pin = attempt.candidate_pin();
            if previous_pin.selection_index != next_pin.selection_index
                || previous_pin.executor != next_pin.executor
                || previous_pin.provider != next_pin.provider
                || matches!(
                    (previous_pin.resolved_model(), next_pin.resolved_model()),
                    (Some(previous), Some(next)) if previous != next
                )
                || matches!(
                    (previous_pin.resolved_model(), next_pin.resolved_model()),
                    (Some(_), None)
                )
            {
                return Err(AgentExecutionValidationError::PinnedCandidateChanged);
            }
        }

        if self
            .error
            .as_ref()
            .is_some_and(|error| error.validate().is_err())
        {
            return Err(AgentExecutionValidationError::InvalidExecutionError);
        }
        if self.error.as_ref().is_some_and(|error| {
            error
                .context
                .execution_id
                .as_ref()
                .is_some_and(|execution_id| execution_id != &self.execution_id)
        }) {
            return Err(AgentExecutionValidationError::ErrorContextBindingMismatch);
        }
        if self
            .output
            .as_ref()
            .is_some_and(|output| !output.is_valid())
        {
            return Err(AgentExecutionValidationError::InvalidOutput);
        }
        if self
            .active_attempt_id
            .as_ref()
            .is_some_and(|active_id| !attempt_ids.contains(active_id.as_str()))
        {
            return Err(AgentExecutionValidationError::ActiveAttemptNotFound);
        }

        let active_attempt = self.active_attempt_id.as_ref().and_then(|active_id| {
            self.attempts
                .iter()
                .find(|attempt| &attempt.attempt_id == active_id)
        });
        let active_is_coherent = match self.state {
            AgentExecutionState::Queued => active_attempt.is_none(),
            AgentExecutionState::Probing => {
                active_attempt.is_some_and(|attempt| attempt.state == AgentAttemptState::Probing)
            }
            AgentExecutionState::Blocked => active_attempt.is_none(),
            AgentExecutionState::Running => active_attempt.is_some_and(|attempt| {
                matches!(
                    attempt.state,
                    AgentAttemptState::Starting
                        | AgentAttemptState::Running
                        | AgentAttemptState::RepairingOutput
                )
            }),
            AgentExecutionState::Completed
            | AgentExecutionState::Failed
            | AgentExecutionState::Cancelled
            | AgentExecutionState::Indeterminate => active_attempt.is_none(),
        };
        if !active_is_coherent {
            return Err(AgentExecutionValidationError::ExecutionStateActiveAttemptMismatch);
        }

        let payload_is_coherent = match self.state {
            AgentExecutionState::Queued
            | AgentExecutionState::Probing
            | AgentExecutionState::Running => self.output.is_none() && self.error.is_none(),
            AgentExecutionState::Blocked => self.output.is_none() && self.error.is_some(),
            AgentExecutionState::Completed => self.output.is_some() && self.error.is_none(),
            AgentExecutionState::Failed => {
                self.output.is_none()
                    && self.error.as_ref().is_some_and(|error| {
                        !matches!(
                            error.code,
                            AgentErrorCode::Cancelled | AgentErrorCode::ExecutionIndeterminate
                        )
                    })
            }
            AgentExecutionState::Cancelled => {
                self.output.is_none()
                    && self
                        .error
                        .as_ref()
                        .is_some_and(|error| error.code == AgentErrorCode::Cancelled)
            }
            AgentExecutionState::Indeterminate => {
                self.output.is_none()
                    && self
                        .error
                        .as_ref()
                        .is_some_and(|error| error.code == AgentErrorCode::ExecutionIndeterminate)
            }
        };
        if !payload_is_coherent {
            return Err(AgentExecutionValidationError::ExecutionStatePayloadMismatch);
        }

        if self.state.is_terminal() {
            let latest_attempt = self
                .attempts
                .iter()
                .max_by_key(|attempt| attempt.attempt_number);
            let terminal_attempt_is_coherent = match self.state {
                AgentExecutionState::Completed => latest_attempt
                    .is_some_and(|attempt| attempt.state == AgentAttemptState::Completed),
                AgentExecutionState::Failed => latest_attempt.is_some_and(|attempt| {
                    attempt.state == AgentAttemptState::Failed
                        || (attempt.state == AgentAttemptState::DispatchRejected
                            && self.error.as_ref() == attempt.error.as_ref())
                }),
                AgentExecutionState::Cancelled => latest_attempt.is_some_and(|attempt| {
                    attempt.state == AgentAttemptState::Cancelled
                        || (attempt.state == AgentAttemptState::DispatchCancelled
                            && self.error.as_ref() == attempt.error.as_ref())
                }),
                AgentExecutionState::Indeterminate => latest_attempt
                    .is_some_and(|attempt| attempt.state == AgentAttemptState::Indeterminate),
                AgentExecutionState::Queued
                | AgentExecutionState::Probing
                | AgentExecutionState::Blocked
                | AgentExecutionState::Running => true,
            };
            if !terminal_attempt_is_coherent {
                return Err(AgentExecutionValidationError::ExecutionTerminalAttemptMismatch);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExecutionUpdateKind {
    IdempotentReplay,
    Advanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPrestartCancellationReplacement {
    CancellationWon,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_provider_mapping_is_stable_and_uses_agy() {
        assert_eq!(ExecutorKind::CodexCli.provider(), AgentProvider::OpenAi);
        assert_eq!(ExecutorKind::ClaudeCli.provider(), AgentProvider::Anthropic);
        assert_eq!(ExecutorKind::AgyCli.provider(), AgentProvider::Google);
        assert_eq!(
            serde_json::to_string(&ExecutorKind::AgyCli).unwrap(),
            "\"agy_cli\""
        );
        assert_eq!(
            serde_json::from_str::<ExecutorKind>("\"agy_cli\"").unwrap(),
            ExecutorKind::AgyCli
        );
    }

    #[test]
    fn cli_identifier_grammar_accepts_realistic_provider_model_and_session_ids() {
        for value in [
            "openai/gpt-5.2-codex:high",
            "claude-sonnet-4-6@20260727",
            "gemini-2.5-pro-preview-06-05",
            "019f9fd8-0a33-7002-98e9-9103e64ceb58",
            "provider_session:01+resume",
        ] {
            validate_cli_identifier(value, MAX_PROVIDER_SESSION_ID_LENGTH).unwrap();
        }
    }

    #[test]
    fn cli_identifier_grammar_rejects_flags_controls_oversize_and_traversal() {
        assert_eq!(
            validate_cli_identifier("-gpt-5.2", MAX_PROVIDER_MODEL_ID_LENGTH),
            Err(CliIdentifierValidationError::UnsafeFirstCharacter)
        );
        assert_eq!(
            validate_cli_identifier("gpt-5.2\n--help", MAX_PROVIDER_MODEL_ID_LENGTH),
            Err(CliIdentifierValidationError::UnsafeCharacter { index: 7 })
        );
        assert_eq!(
            validate_cli_identifier("gpt 5.2", MAX_PROVIDER_MODEL_ID_LENGTH),
            Err(CliIdentifierValidationError::UnsafeCharacter { index: 3 })
        );
        assert_eq!(
            validate_cli_identifier(
                &"a".repeat(MAX_PROVIDER_MODEL_ID_LENGTH + 1),
                MAX_PROVIDER_MODEL_ID_LENGTH,
            ),
            Err(CliIdentifierValidationError::TooLong {
                max: MAX_PROVIDER_MODEL_ID_LENGTH
            })
        );
        assert_eq!(
            validate_cli_identifier("openai/../secret", MAX_MODEL_KEY_LENGTH),
            Err(CliIdentifierValidationError::TraversalLikeSegment)
        );
        assert_eq!(
            validate_cli_identifier("model\0id", MAX_PROVIDER_MODEL_ID_LENGTH),
            Err(CliIdentifierValidationError::UnsafeCharacter { index: 5 })
        );
    }

    #[test]
    fn idempotency_key_enforces_backend_160_byte_boundary() {
        let mut request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();

        request.idempotency_key = "a".repeat(MAX_IDEMPOTENCY_KEY_LENGTH);
        request.validate().unwrap();

        request.idempotency_key = "a".repeat(MAX_IDEMPOTENCY_KEY_LENGTH + 1);
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::UnsafeIdempotencyKey(
                CliIdentifierValidationError::TooLong {
                    max: MAX_IDEMPOTENCY_KEY_LENGTH
                }
            ))
        );
    }

    #[test]
    fn idempotency_key_accepts_domain_separators_and_rejects_unsafe_bytes() {
        validate_idempotency_key("workflow/run:node_1@attempt+2.key-id").unwrap();

        for (value, expected) in [
            (
                "-workflow:attempt",
                CliIdentifierValidationError::UnsafeFirstCharacter,
            ),
            (
                "workflow attempt",
                CliIdentifierValidationError::UnsafeCharacter { index: 8 },
            ),
            (
                "workflow\0attempt",
                CliIdentifierValidationError::UnsafeCharacter { index: 8 },
            ),
            (
                "workflow\nattempt",
                CliIdentifierValidationError::UnsafeCharacter { index: 8 },
            ),
        ] {
            assert_eq!(validate_idempotency_key(value), Err(expected));
        }

        let mut request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        request.idempotency_key = "-workflow:attempt".to_string();
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::UnsafeIdempotencyKey(
                CliIdentifierValidationError::UnsafeFirstCharacter
            ))
        );
    }

    #[test]
    fn model_target_and_provider_session_apply_cli_identifier_validation() {
        let mut request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let ModelSelectionMode::Exact { target } = &mut request.selection.primary else {
            panic!("fixture must use exact selection");
        };
        target.provider_model_id = "--help".to_string();
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::InvalidSelection(
                ModelSelectionValidationError::UnsafeExactProviderModelId(
                    CliIdentifierValidationError::UnsafeFirstCharacter
                )
            ))
        );

        let mut checkpoint: AgentSessionCheckpointV2 =
            serde_json::from_str(include_str!("../fixtures/agent_session_checkpoint_v2.json"))
                .unwrap();
        checkpoint.provider_session_id = "session/../other".to_string();
        assert_eq!(
            checkpoint.validate(),
            Err(AgentSessionValidationError::UnsafeCliIdentifier)
        );

        checkpoint.provider_session_id = "019f9fd8-0a33-7002-98e9-9103e64ceb58".to_string();
        checkpoint.checkpoint_id = "019f9fd8-0a33-7002-98e9-9103e64ceb59".to_string();
        checkpoint.validate().unwrap();
    }

    #[test]
    fn legacy_gemini_executor_identity_is_rejected() {
        let error = serde_json::from_str::<ExecutorKind>("\"gemini_cli\"").unwrap_err();

        assert!(error.to_string().contains("unknown variant"));
        assert!(error.to_string().contains("agy_cli"));
    }

    #[test]
    fn exact_selection_never_accepts_an_empty_model() {
        let selection = ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: ModelTarget {
                    executor: ExecutorKind::CodexCli,
                    provider: AgentProvider::OpenAi,
                    model_key: " ".to_string(),
                    provider_model_id: "gpt-5.2".to_string(),
                },
            },
            fallback: ModelFallbackPolicy::None,
        };

        assert_eq!(
            selection.validate(),
            Err(ModelSelectionValidationError::EmptyExactModelKey)
        );
    }

    #[test]
    fn exact_selection_requires_the_provider_model_id_too() {
        let selection = ModelSelection {
            primary: ModelSelectionMode::Exact {
                target: ModelTarget {
                    executor: ExecutorKind::CodexCli,
                    provider: AgentProvider::OpenAi,
                    model_key: "openai/gpt-5.2".to_string(),
                    provider_model_id: " ".to_string(),
                },
            },
            fallback: ModelFallbackPolicy::None,
        };

        assert_eq!(
            selection.validate(),
            Err(ModelSelectionValidationError::EmptyExactProviderModelId)
        );
    }

    #[test]
    fn ordered_fallback_must_be_nonempty_and_unique() {
        let target = ModelTarget {
            executor: ExecutorKind::ClaudeCli,
            provider: AgentProvider::Anthropic,
            model_key: "claude-sonnet".to_string(),
            provider_model_id: "claude-sonnet-4-6".to_string(),
        };
        let empty = ModelSelection {
            primary: ModelSelectionMode::Auto {
                executor: ExecutorKind::ClaudeCli,
                provider: AgentProvider::Anthropic,
            },
            fallback: ModelFallbackPolicy::Ordered { targets: vec![] },
        };
        assert_eq!(
            empty.validate(),
            Err(ModelSelectionValidationError::EmptyFallbackList)
        );

        let duplicate = ModelSelection {
            primary: ModelSelectionMode::Auto {
                executor: ExecutorKind::ClaudeCli,
                provider: AgentProvider::Anthropic,
            },
            fallback: ModelFallbackPolicy::Ordered {
                targets: vec![target.clone(), target],
            },
        };
        assert_eq!(
            duplicate.validate(),
            Err(ModelSelectionValidationError::DuplicateFallbackTarget { index: 1 })
        );
    }

    #[test]
    fn ordered_fallback_can_cross_providers_only_with_an_explicit_executor() {
        let fixture = include_str!("../fixtures/agent_task_v2_ordered_fallback.json");
        let request: AgentTaskRequestV2 = serde_json::from_str(fixture).unwrap();

        request.validate().unwrap();
        assert!(request.is_for_binding(&AgentExecutionBindingV2 {
            workspace_binding_id: "binding_loomex_workspace_01".to_string(),
            workspace_binding_generation: 7,
            runner_id: "runner_local_01".to_string(),
        }));
        assert!(!request.is_for_binding(&AgentExecutionBindingV2 {
            workspace_binding_id: "binding_loomex_workspace_01".to_string(),
            workspace_binding_generation: 8,
            runner_id: "runner_local_01".to_string(),
        }));
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
        let ModelFallbackPolicy::Ordered { targets } = request.selection.fallback else {
            panic!("fixture must use ordered fallback");
        };
        assert_eq!(targets[0].executor, ExecutorKind::ClaudeCli);
        assert_eq!(targets[1].executor, ExecutorKind::AgyCli);
    }

    #[test]
    fn v2_task_fixture_is_valid_and_has_no_implicit_fallback() {
        let fixture = include_str!("../fixtures/agent_task_v2.json");
        let request: AgentTaskRequestV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(request.schema_version, AGENT_TASK_SCHEMA_V2);
        assert!(matches!(
            request.selection.primary,
            ModelSelectionMode::Exact {
                target: ModelTarget {
                    executor: ExecutorKind::CodexCli,
                    ..
                }
            }
        ));
        assert!(matches!(
            request.selection.fallback,
            ModelFallbackPolicy::None
        ));
        request.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn structured_output_contract_accepts_only_explicit_object_root_schema() {
        let object_schema: Value = serde_json::from_str(include_str!(
            "../fixtures/agent_structured_output_schema_object_v1.json"
        ))
        .unwrap();
        let array_schema: Value = serde_json::from_str(include_str!(
            "../fixtures/agent_structured_output_schema_array_v1.json"
        ))
        .unwrap();
        let scalar_schema: Value = serde_json::from_str(include_str!(
            "../fixtures/agent_structured_output_schema_scalar_v1.json"
        ))
        .unwrap();

        assert_eq!(object_schema, default_agent_structured_output_schema());
        validate_agent_structured_output_schema(&object_schema).unwrap();
        assert_eq!(
            validate_agent_structured_output_schema(&array_schema),
            Err(AgentStructuredOutputSchemaValidationError::RootTypeMustBeObject)
        );
        assert_eq!(
            validate_agent_structured_output_schema(&scalar_schema),
            Err(AgentStructuredOutputSchemaValidationError::RootTypeMustBeObject)
        );
        assert_eq!(
            validate_agent_structured_output_schema(&serde_json::json!({})),
            Err(AgentStructuredOutputSchemaValidationError::RootTypeMustBeObject)
        );
    }

    #[test]
    fn task_and_terminal_output_enforce_object_shape_for_structured_mode() {
        let mut request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();

        request.output_schema = Some(serde_json::json!({}));
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::InvalidStructuredOutputSchema(
                AgentStructuredOutputSchemaValidationError::RootTypeMustBeObject
            ))
        );

        request.output_schema = None;
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::MissingStructuredOutputSchema)
        );

        request.output_schema = Some(default_agent_structured_output_schema());
        request.validate().unwrap();

        for invalid in [serde_json::json!("scalar"), serde_json::json!([1, 2, 3])] {
            assert!(!AgentOutput {
                format: AgentOutputFormat::Json,
                content: invalid.to_string(),
                structured: Some(invalid),
            }
            .is_valid());
        }
        assert!(AgentOutput {
            format: AgentOutputFormat::Json,
            content: "{\"ok\":true}".to_string(),
            structured: Some(serde_json::json!({"ok": true})),
        }
        .is_valid());
    }

    #[test]
    fn v2_capability_fixture_covers_all_three_executors() {
        let fixture = include_str!("../fixtures/agent_capabilities_v2.json");
        let snapshot: AgentRuntimeCapabilitySnapshotV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(snapshot.schema_version, AGENT_CAPABILITY_SCHEMA_V2);
        assert_eq!(snapshot.executors.len(), 3);
        assert!(snapshot
            .executors
            .iter()
            .any(|capability| capability.executor == ExecutorKind::AgyCli));
        snapshot.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn v2_execution_fixture_preserves_checkpoint_and_typed_error() {
        let fixture = include_str!("../fixtures/agent_execution_v2.json");
        let execution: AgentExecutionV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(execution.schema_version, AGENT_EXECUTION_SCHEMA_V2);
        assert_eq!(execution.state, AgentExecutionState::Blocked);
        let error = execution.error.as_ref().unwrap();
        assert_eq!(error.schema_version, AGENT_ERROR_SCHEMA_V2);
        assert_eq!(error.code, AgentErrorCode::ProviderNotAuthenticated);
        assert_eq!(error.retry, AgentRetryDisposition::UserActionRequired);
        assert!(execution.attempts[0].session.is_some());
        execution.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&execution).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn v2_error_fixture_has_a_stable_category_and_remediation() {
        let fixture = include_str!("../fixtures/agent_error_v2.json");
        let error: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(error.code, AgentErrorCode::ModelNotAvailable);
        assert_eq!(error.category, AgentErrorCategory::Availability);
        assert_eq!(
            error.remediation,
            vec![AgentRemediationAction::SelectDifferentModel]
        );
        error.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn error_context_resolved_model_identity_is_an_atomic_safe_pair() {
        let resolved_fixture = include_str!("../fixtures/agent_error_v2.json");
        let resolved: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(resolved_fixture).unwrap();
        assert_eq!(
            resolved.context.resolved_model_key.as_deref(),
            Some("openai/gpt-5.2")
        );
        assert_eq!(
            resolved.context.resolved_provider_model_id.as_deref(),
            Some("gpt-5.2")
        );
        resolved.validate().unwrap();

        let pre_resolution: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_error_refresh_executor_discovery_v2.json"
        ))
        .unwrap();
        assert!(pre_resolution.context.resolved_model_key.is_none());
        assert!(pre_resolution.context.resolved_provider_model_id.is_none());
        pre_resolution.validate().unwrap();

        let mut missing_key = resolved.clone();
        missing_key.context.resolved_model_key = None;
        assert_eq!(
            missing_key.validate(),
            Err(AgentErrorValidationError::UnpairedResolvedModelIdentity)
        );

        let mut missing_provider_id = resolved.clone();
        missing_provider_id.context.resolved_provider_model_id = None;
        assert_eq!(
            missing_provider_id.validate(),
            Err(AgentErrorValidationError::UnpairedResolvedModelIdentity)
        );

        for unsafe_value in ["", "--model", "openai/../gpt-5.2"] {
            let mut unsafe_key = resolved.clone();
            unsafe_key.context.resolved_model_key = Some(unsafe_value.to_string());
            assert_eq!(
                unsafe_key.validate(),
                Err(AgentErrorValidationError::UnsafeResolvedModelIdentity)
            );
        }

        let mut oversized_provider_id = resolved;
        oversized_provider_id.context.resolved_provider_model_id =
            Some("m".repeat(MAX_PROVIDER_MODEL_ID_LENGTH + 1));
        assert_eq!(
            oversized_provider_id.validate(),
            Err(AgentErrorValidationError::UnsafeResolvedModelIdentity)
        );
    }

    #[test]
    fn provider_not_eligible_error_is_typed_sanitized_and_backward_additive() {
        let fixture = include_str!("../fixtures/agent_error_provider_not_eligible_v2.json");
        let error: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(error.schema_version, AGENT_ERROR_SCHEMA_V2);
        assert_eq!(error.code, AgentErrorCode::ProviderNotEligible);
        assert_eq!(error.category, AgentErrorCategory::Authorization);
        assert_eq!(
            error.remediation,
            vec![
                AgentRemediationAction::VerifyProviderAccess,
                AgentRemediationAction::ContactSupport,
            ]
        );
        assert_eq!(
            error
                .context
                .safe_details
                .get("reasonCode")
                .map(String::as_str),
            Some("account_not_eligible")
        );
        assert!(!error.message.contains('@'));
        error.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn refresh_executor_discovery_is_distinct_and_sanitized() {
        let fixture = include_str!("../fixtures/agent_error_refresh_executor_discovery_v2.json");
        let error: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(error.code, AgentErrorCode::RuntimeUnavailable);
        assert_eq!(
            error.remediation,
            vec![AgentRemediationAction::RefreshExecutorDiscovery]
        );
        assert!(!error
            .remediation
            .contains(&AgentRemediationAction::InstallExecutor));
        assert!(!error
            .context
            .safe_details
            .values()
            .any(|value| value.contains('/') || value.contains('\\')));
        error.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn executor_version_gate_requires_upgrade_and_refresh_remediation() {
        let fixture = include_str!("../fixtures/agent_error_upgrade_executor_v2.json");
        let error: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(fixture).unwrap();

        assert_eq!(error.code, AgentErrorCode::UnsupportedCapability);
        assert_eq!(
            error.remediation,
            vec![
                AgentRemediationAction::UpgradeExecutor,
                AgentRemediationAction::RefreshExecutorDiscovery,
            ]
        );
        assert!(!error
            .remediation
            .contains(&AgentRemediationAction::ReconfigureWorkflow));
        assert_eq!(
            error
                .context
                .safe_details
                .get("reasonCode")
                .map(String::as_str),
            Some("executor_version_unverified")
        );
        error.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );

        let mut generic = error.clone();
        generic.remediation = vec![AgentRemediationAction::ReconfigureWorkflow];
        assert_eq!(
            generic.validate(),
            Err(AgentErrorValidationError::VersionGateRemediationMismatch)
        );

        let mut upgrade_only = error;
        upgrade_only.remediation = vec![AgentRemediationAction::UpgradeExecutor];
        assert_eq!(
            upgrade_only.validate(),
            Err(AgentErrorValidationError::VersionGateRemediationMismatch)
        );
    }

    #[test]
    fn continuation_is_bound_to_executor_provider_and_exact_model() {
        let mut request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let checkpoint: AgentSessionCheckpointV2 =
            serde_json::from_str(include_str!("../fixtures/agent_session_checkpoint_v2.json"))
                .unwrap();
        let continuation = AgentSessionContinuationV2::from(&checkpoint);

        assert_eq!(checkpoint.model_key.as_deref(), Some("openai/gpt-5.2"));
        assert_eq!(checkpoint.provider_model_id.as_deref(), Some("gpt-5.2"));
        assert_eq!(
            continuation.resolved_model(),
            Some(("openai/gpt-5.2", "gpt-5.2"))
        );
        request.continuation = Some(continuation);
        request.validate().unwrap();

        let mut rebound_request = request.clone();
        rebound_request.binding.workspace_binding_generation += 1;
        assert_eq!(
            rebound_request.validate(),
            Err(AgentTaskValidationError::InvalidContinuation)
        );

        let ModelSelectionMode::Exact { target } = &mut request.selection.primary else {
            panic!("fixture must use exact selection");
        };
        target.executor = ExecutorKind::ClaudeCli;
        assert_eq!(
            request.validate(),
            Err(AgentTaskValidationError::InvalidSelection(
                ModelSelectionValidationError::PrimaryExecutorProviderMismatch
            ))
        );
    }

    #[test]
    fn unresolved_auto_session_omits_both_model_fields_and_can_resume() {
        let checkpoint_fixture =
            include_str!("../fixtures/agent_session_checkpoint_v2_auto_unresolved.json");
        let checkpoint: AgentSessionCheckpointV2 =
            serde_json::from_str(checkpoint_fixture).unwrap();
        checkpoint.validate().unwrap();
        assert_eq!(checkpoint.model_key, None);
        assert_eq!(checkpoint.provider_model_id, None);
        assert_eq!(
            serde_json::to_value(&checkpoint).unwrap(),
            serde_json::from_str::<Value>(checkpoint_fixture).unwrap()
        );

        let continuation_fixture =
            include_str!("../fixtures/agent_session_continuation_v2_auto_unresolved.json");
        let continuation: AgentSessionContinuationV2 =
            serde_json::from_str(continuation_fixture).unwrap();
        assert_eq!(continuation.resolved_model(), None);

        let mut auto_request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        auto_request.selection.primary = ModelSelectionMode::Auto {
            executor: ExecutorKind::AgyCli,
            provider: AgentProvider::Google,
        };
        auto_request.continuation = Some(continuation.clone());
        auto_request.validate().unwrap();

        let mut exact_request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        exact_request.continuation = Some(continuation);
        assert_eq!(
            exact_request.validate(),
            Err(AgentTaskValidationError::InvalidContinuation)
        );
    }

    #[test]
    fn session_model_identity_rejects_one_sided_pairs_and_pins_resolved_auto() {
        let mut checkpoint: AgentSessionCheckpointV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_session_checkpoint_v2_auto_unresolved.json"
        ))
        .unwrap();
        checkpoint.model_key = Some("google/gemini-2.5-pro".to_string());
        assert_eq!(
            checkpoint.validate(),
            Err(AgentSessionValidationError::UnpairedModelIdentity)
        );

        checkpoint.provider_model_id = Some("gemini-2.5-pro".to_string());
        checkpoint.validate().unwrap();
        let continuation = AgentSessionContinuationV2::from(&checkpoint);
        assert_eq!(
            continuation.resolved_model(),
            Some(("google/gemini-2.5-pro", "gemini-2.5-pro"))
        );

        let mut auto_request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        auto_request.selection.primary = ModelSelectionMode::Auto {
            executor: ExecutorKind::AgyCli,
            provider: AgentProvider::Google,
        };
        auto_request.continuation = Some(continuation);
        auto_request.validate().unwrap();
    }

    #[test]
    fn ordered_fallback_checkpoint_and_continuation_pin_explicit_member() {
        let request: AgentTaskRequestV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_task_v2_ordered_fallback.json"
        ))
        .unwrap();
        let checkpoint: AgentSessionCheckpointV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_session_checkpoint_v2_ordered_fallback.json"
        ))
        .unwrap();
        let continuation: AgentSessionContinuationV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_session_continuation_v2_ordered_fallback.json"
        ))
        .unwrap();

        checkpoint.validate_for_request(&request).unwrap();
        assert!(continuation.matches_request(&request));
        assert_eq!(checkpoint.candidate_pin(), continuation.candidate_pin());
        assert_eq!(checkpoint.selection_index, 1);
        assert_eq!(checkpoint.executor, ExecutorKind::ClaudeCli);

        let mut wrong_index = continuation.clone();
        wrong_index.selection_index = 0;
        assert!(!wrong_index.matches_request(&request));

        let mut unlisted_model = continuation;
        unlisted_model.model_key = Some("anthropic/claude-opus-unlisted".to_string());
        unlisted_model.provider_model_id = Some("claude-opus-unlisted".to_string());
        assert!(!unlisted_model.matches_request(&request));
    }

    #[test]
    fn candidate_pin_transition_is_single_assignment_and_replay_deterministic() {
        let exact_and_fallback: AgentTaskRequestV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_task_v2_ordered_fallback.json"
        ))
        .unwrap();
        let fallback: AgentSessionContinuationV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_session_continuation_v2_ordered_fallback.json"
        ))
        .unwrap();
        let fallback_pin = fallback.candidate_pin();

        exact_and_fallback
            .selection
            .validate_candidate_pin_transition(None, &fallback_pin)
            .unwrap();
        exact_and_fallback
            .selection
            .validate_candidate_pin_transition(Some(&fallback_pin), &fallback_pin)
            .unwrap();

        let mut changed_index = fallback_pin.clone();
        changed_index.selection_index = 2;
        assert_eq!(
            exact_and_fallback
                .selection
                .validate_candidate_pin_transition(Some(&fallback_pin), &changed_index),
            Err(AgentCandidatePinValidationError::CandidateNotAllowed)
        );

        let mut auto_request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        auto_request.selection.primary = ModelSelectionMode::Auto {
            executor: ExecutorKind::AgyCli,
            provider: AgentProvider::Google,
        };
        let unresolved = AgentCandidatePinV2 {
            selection_index: 0,
            executor: ExecutorKind::AgyCli,
            provider: AgentProvider::Google,
            model_key: None,
            provider_model_id: None,
        };
        let resolved = AgentCandidatePinV2 {
            model_key: Some("google/gemini-2.5-pro".to_string()),
            provider_model_id: Some("gemini-2.5-pro".to_string()),
            ..unresolved.clone()
        };
        auto_request
            .selection
            .validate_candidate_pin_transition(Some(&unresolved), &resolved)
            .unwrap();

        let changed_model = AgentCandidatePinV2 {
            model_key: Some("google/gemini-2.5-flash".to_string()),
            provider_model_id: Some("gemini-2.5-flash".to_string()),
            ..resolved.clone()
        };
        assert_eq!(
            auto_request
                .selection
                .validate_candidate_pin_transition(Some(&resolved), &changed_model),
            Err(AgentCandidatePinValidationError::PinnedCandidateChanged)
        );
        assert_eq!(
            auto_request
                .selection
                .validate_candidate_pin_transition(Some(&resolved), &unresolved),
            Err(AgentCandidatePinValidationError::ResolvedModelCleared)
        );
    }

    #[test]
    fn completed_execution_has_coherent_terminal_attempt_output_and_timestamps() {
        let mut execution: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        let prior_attempt_error = execution.attempts[0].error.clone().unwrap();
        execution.state = AgentExecutionState::Completed;
        execution.active_attempt_id = None;
        execution.error = None;
        execution.finished_at = Some("2026-07-26T10:31:12Z".to_string());
        execution.output = Some(AgentOutput {
            format: AgentOutputFormat::Text,
            content: "completed".to_string(),
            structured: None,
        });
        let attempt = &mut execution.attempts[0];
        attempt.state = AgentAttemptState::Completed;
        attempt.finished_at = Some("2026-07-26T10:31:12Z".to_string());
        attempt.error = None;
        attempt.session.as_mut().unwrap().state = AgentSessionState::Completed;

        execution.validate().unwrap();

        let mut terminal_with_active_attempt = execution.clone();
        terminal_with_active_attempt.active_attempt_id = Some("attempt_01".to_string());
        assert_eq!(
            terminal_with_active_attempt.validate(),
            Err(AgentExecutionValidationError::ExecutionStateActiveAttemptMismatch)
        );

        let mut completed_without_output = execution.clone();
        completed_without_output.output = None;
        assert_eq!(
            completed_without_output.validate(),
            Err(AgentExecutionValidationError::ExecutionStatePayloadMismatch)
        );

        let mut terminal_attempt_mismatch = execution.clone();
        terminal_attempt_mismatch.attempts[0].state = AgentAttemptState::Failed;
        terminal_attempt_mismatch.attempts[0].error = Some(prior_attempt_error);
        assert_eq!(
            terminal_attempt_mismatch.validate(),
            Err(AgentExecutionValidationError::ExecutionTerminalAttemptMismatch)
        );
    }

    #[test]
    fn execution_rejects_incoherent_attempt_timestamp_and_active_id() {
        let mut execution: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        execution.attempts[0].finished_at = None;
        assert_eq!(
            execution.validate(),
            Err(AgentExecutionValidationError::AttemptTimestampStateMismatch)
        );

        let mut terminal_without_finished_at: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        terminal_without_finished_at.state = AgentExecutionState::Failed;
        terminal_without_finished_at.active_attempt_id = None;
        terminal_without_finished_at.attempts[0].state = AgentAttemptState::Failed;
        terminal_without_finished_at.attempts[0].finished_at =
            Some("2026-07-26T10:31:12Z".to_string());
        assert_eq!(
            terminal_without_finished_at.validate(),
            Err(AgentExecutionValidationError::ExecutionTimestampStateMismatch)
        );

        let mut unknown_active: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        unknown_active.active_attempt_id = Some("attempt_missing".to_string());
        assert_eq!(
            unknown_active.validate(),
            Err(AgentExecutionValidationError::ActiveAttemptNotFound)
        );

        let mut rebound_checkpoint: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        rebound_checkpoint.attempts[0]
            .session
            .as_mut()
            .unwrap()
            .binding
            .workspace_binding_generation += 1;
        assert_eq!(
            rebound_checkpoint.validate(),
            Err(AgentExecutionValidationError::CheckpointBindingMismatch)
        );

        let mut one_sided_resolved_model: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        one_sided_resolved_model.attempts[0].resolved_model_key = None;
        assert_eq!(
            one_sided_resolved_model.validate(),
            Err(AgentExecutionValidationError::UnpairedAttemptModelIdentity)
        );
    }

    #[test]
    fn blocked_resume_appends_one_process_attempt_to_same_logical_execution() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let blocked: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        let resumed: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_blocked_resumed.json"
        ))
        .unwrap();

        blocked.validate_for_request(&request).unwrap();
        resumed.validate_for_request(&request).unwrap();
        assert_eq!(
            blocked.validate_successor(&blocked, &request),
            Ok(AgentExecutionUpdateKind::IdempotentReplay)
        );
        assert_eq!(
            blocked.validate_successor(&resumed, &request),
            Ok(AgentExecutionUpdateKind::Advanced)
        );
        assert_eq!(blocked.execution_id, resumed.execution_id);
        assert_eq!(blocked.request_id, resumed.request_id);
        assert_eq!(blocked.idempotency_key, resumed.idempotency_key);
        assert_eq!(resumed.attempts[1].attempt_number, 2);
        assert_eq!(
            resumed.attempts[1].retry.as_ref().unwrap().from_attempt_id,
            blocked.attempts[0].attempt_id
        );
        assert_eq!(
            resumed.attempts[1].retry.as_ref().unwrap().retry_kind,
            AgentProcessRetryKindV2::ResumeFromCheckpoint
        );
        assert_ne!(
            resumed.attempts[0].task_idempotency_key,
            resumed.attempts[1].task_idempotency_key
        );
        assert_ne!(
            resumed.attempts[0].delivery_idempotency_key,
            resumed.attempts[1].delivery_idempotency_key
        );
        assert_ne!(
            resumed.attempts[0].payload_digest,
            resumed.attempts[1].payload_digest
        );
    }

    #[test]
    fn process_dispatch_separates_logical_and_per_attempt_idempotency() {
        let initial: AgentProcessDispatchV2 =
            serde_json::from_str(include_str!("../fixtures/agent_process_dispatch_v2.json"))
                .unwrap();
        let resumed: AgentProcessDispatchV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_process_dispatch_v2_resumed.json"
        ))
        .unwrap();
        let fresh: AgentProcessDispatchV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_process_dispatch_v2_fresh_after_remediation.json"
        ))
        .unwrap();

        initial.validate().unwrap();
        resumed.validate().unwrap();
        fresh.validate().unwrap();
        assert_eq!(
            agent_attempt_task_idempotency_preimage("execution_01", 1),
            b"loomex.agent-attempt/v2\x00execution_01\x001"
        );
        assert_eq!(
            agent_attempt_delivery_idempotency_preimage("execution_01", 2),
            b"loomex.agent-delivery/v2\x00execution_01\x002"
        );
        assert!(initial
            .payload_digest_input()
            .unwrap()
            .get("payloadDigest")
            .is_none());
        assert_eq!(initial.execution_id, resumed.execution_id);
        assert_eq!(initial.task.request_id, resumed.task.request_id);
        assert_eq!(initial.task.idempotency_key, resumed.task.idempotency_key);
        assert_ne!(initial.task_idempotency_key, resumed.task_idempotency_key);
        assert_ne!(
            initial.delivery_idempotency_key,
            resumed.delivery_idempotency_key
        );
        assert_ne!(initial.payload_digest, resumed.payload_digest);
        assert!(initial.task.continuation.is_none());
        assert!(resumed.task.continuation.is_some());
        assert!(fresh.task.continuation.is_none());
        assert_eq!(
            fresh.retry_kind,
            AgentProcessRetryKindV2::FreshAfterRemediation
        );

        let mut bad_first = initial.clone();
        bad_first.task.continuation = resumed.task.continuation.clone();
        bad_first.payload_digest = bad_first.computed_payload_digest().unwrap();
        assert_eq!(
            bad_first.validate(),
            Err(AgentProcessDispatchValidationError::InvalidRetrySource)
        );

        let mut uppercase_digest = resumed;
        uppercase_digest.payload_digest =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_eq!(
            uppercase_digest.validate(),
            Err(AgentProcessDispatchValidationError::InvalidPayloadDigest)
        );
    }

    #[test]
    fn dispatch_delivery_route_is_digest_bound_and_channel_owned() {
        let runner_dispatch: AgentProcessDispatchV2 =
            serde_json::from_str(include_str!("../fixtures/agent_process_dispatch_v2.json"))
                .unwrap();
        let direct_dispatch: AgentProcessDispatchV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_process_dispatch_v2_jcs_edge.json"
        ))
        .unwrap();

        runner_dispatch
            .validate_for_runner_job("runner_job_01", "runner_local_01")
            .unwrap();
        direct_dispatch.validate_for_direct_control().unwrap();
        assert_eq!(
            runner_dispatch.validate_for_direct_control(),
            Err(AgentProcessDispatchValidationError::DeliveryRouteOwnershipMismatch)
        );
        assert_eq!(
            direct_dispatch.validate_for_runner_job("runner_job_01", "runner_local_01"),
            Err(AgentProcessDispatchValidationError::DeliveryRouteOwnershipMismatch)
        );

        let mut missing_lease = runner_dispatch.clone();
        missing_lease.delivery.lease_target_runner_id = None;
        assert_eq!(
            missing_lease.validate(),
            Err(AgentProcessDispatchValidationError::InvalidDeliveryRoute)
        );

        let mut route_rewritten = runner_dispatch;
        route_rewritten.delivery = AgentProcessDeliveryV2 {
            route: AgentDeliveryRouteV2::DirectControl,
            runner_job_id: None,
            lease_target_runner_id: None,
        };
        assert_eq!(
            route_rewritten.validate(),
            Err(AgentProcessDispatchValidationError::PayloadDigestMismatch)
        );
    }

    #[test]
    fn dispatch_jcs_vector_pins_numbers_unicode_and_utf16_key_order() {
        let dispatch: AgentProcessDispatchV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_process_dispatch_v2_jcs_edge.json"
        ))
        .unwrap();
        let canonical = dispatch.canonical_payload_digest_input().unwrap();
        let expected = include_bytes!("../fixtures/agent_process_dispatch_v2_jcs_edge.canonical");
        assert_eq!(
            canonical.as_slice(),
            expected.strip_suffix(b"\n").unwrap_or(expected)
        );
        assert_eq!(
            dispatch.computed_payload_digest().unwrap(),
            "sha256:ee7749b1f1553fddaf3857ce18d9e98af4f95e5cca4c8542dcaf472b70f3f6ec"
        );
        dispatch.validate().unwrap();

        let canonical_text = std::str::from_utf8(&canonical).unwrap();
        assert!(canonical_text.contains(
            r#""large":1e+21,"negativeZero":0,"one":1,"small":1e-7,"threshold":0.000001"#
        ));
        assert!(
            canonical_text.find("\"😀\"").unwrap() < canonical_text.find("\"\u{e000}\"").unwrap()
        );

        assert!(canonicalize_agent_payload(&f64::NAN).is_err());
        assert!(canonicalize_agent_payload(&f64::INFINITY).is_err());
        assert!(canonicalize_agent_payload(&f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn pre_session_blocked_retry_is_fresh_and_never_fabricates_continuity() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let blocked: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_pre_session_blocked.json"
        ))
        .unwrap();
        let retried: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_fresh_after_remediation.json"
        ))
        .unwrap();

        blocked.validate_for_request(&request).unwrap();
        retried.validate_for_request(&request).unwrap();
        assert_eq!(
            blocked.validate_successor(&retried, &request),
            Ok(AgentExecutionUpdateKind::Advanced)
        );
        assert!(blocked.attempts[0].session.is_none());
        let retry = retried.attempts[1].retry.as_ref().unwrap();
        assert_eq!(
            retry.retry_kind,
            AgentProcessRetryKindV2::FreshAfterRemediation
        );
        assert!(retry.continuation.is_none());
        assert_eq!(
            retried.attempts[0].candidate_pin(),
            retried.attempts[1].candidate_pin()
        );

        let mut fabricated_resume = retried.clone();
        fabricated_resume.attempts[1]
            .retry
            .as_mut()
            .unwrap()
            .retry_kind = AgentProcessRetryKindV2::ResumeFromCheckpoint;
        assert_eq!(
            fabricated_resume.validate(),
            Err(AgentExecutionValidationError::InvalidAttemptRetry)
        );

        let mut discarded_checkpoint: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_blocked_resumed.json"
        ))
        .unwrap();
        let retry = discarded_checkpoint.attempts[1].retry.as_mut().unwrap();
        retry.retry_kind = AgentProcessRetryKindV2::FreshAfterRemediation;
        retry.continuation = None;
        assert_eq!(
            discarded_checkpoint.validate(),
            Err(AgentExecutionValidationError::InvalidAttemptRetry)
        );
    }

    #[test]
    fn disabled_runtime_rejects_valid_dispatch_as_one_seq1_terminal_event() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let rejected: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_dispatch_rejected.json"
        ))
        .unwrap();

        rejected.validate_for_request(&request).unwrap();
        assert_eq!(rejected.state, AgentExecutionState::Failed);
        assert_eq!(rejected.sequence, 1);
        assert!(rejected.active_attempt_id.is_none());
        assert_eq!(rejected.attempts.len(), 1);
        let attempt = &rejected.attempts[0];
        assert_eq!(attempt.state, AgentAttemptState::DispatchRejected);
        assert_eq!(attempt.started_sequence, 1);
        assert_eq!(attempt.finished_sequence, Some(1));
        assert_eq!(attempt.started_at, attempt.finished_at.as_deref().unwrap());
        assert!(attempt.session.is_none());
        assert!(attempt.retry.is_none());
        assert_eq!(
            attempt.error.as_ref().unwrap().code,
            AgentErrorCode::AgentRuntimeV2Disabled
        );
        assert_eq!(
            rejected.error.as_ref().unwrap().code,
            AgentErrorCode::AgentRuntimeV2Disabled
        );

        let mut seq2_gap = rejected.clone();
        seq2_gap.sequence = 2;
        seq2_gap.attempts[0].finished_sequence = Some(2);
        assert_eq!(
            seq2_gap.validate(),
            Err(AgentExecutionValidationError::AttemptSequenceInvalid)
        );

        let mut trailing_execution_sequence = rejected.clone();
        trailing_execution_sequence.sequence = 2;
        assert_eq!(
            trailing_execution_sequence.validate(),
            Err(AgentExecutionValidationError::AttemptSequenceInvalid)
        );

        let mut differing_timestamps = rejected.clone();
        differing_timestamps.attempts[0].finished_at = Some("2026-07-27T10:00:01Z".to_string());
        assert_eq!(
            differing_timestamps.validate(),
            Err(AgentExecutionValidationError::AttemptTimestampStateMismatch)
        );

        let mut fake_failed_process = rejected.clone();
        fake_failed_process.attempts[0].state = AgentAttemptState::Failed;
        assert_eq!(
            fake_failed_process.validate(),
            Err(AgentExecutionValidationError::AttemptSequenceInvalid)
        );

        let mut wrong_error = rejected.clone();
        let attempt_error = wrong_error.attempts[0].error.as_mut().unwrap();
        attempt_error.code = AgentErrorCode::RuntimeUnavailable;
        assert_eq!(
            wrong_error.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );

        let mut fabricated_session = rejected;
        fabricated_session.attempts[0].session = Some(
            serde_json::from_str(include_str!("../fixtures/agent_session_checkpoint_v2.json"))
                .unwrap(),
        );
        assert_eq!(
            fabricated_session.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );
    }

    #[test]
    fn backend_synthesizes_malformed_dispatch_rejection_from_trusted_identity_only() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let rejected: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_malformed_dispatch_rejected.json"
        ))
        .unwrap();
        let fixture_error: AgentRuntimeErrorEnvelopeV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_error_malformed_dispatch.json"
        ))
        .unwrap();

        rejected.validate_for_request(&request).unwrap();
        assert_eq!(rejected.state, AgentExecutionState::Failed);
        assert_eq!(rejected.sequence, 1);
        assert!(rejected.active_attempt_id.is_none());
        assert_eq!(rejected.attempts.len(), 1);
        let attempt = &rejected.attempts[0];
        assert_eq!(attempt.state, AgentAttemptState::DispatchRejected);
        assert_eq!(attempt.started_sequence, 1);
        assert_eq!(attempt.finished_sequence, Some(1));
        assert_eq!(attempt.started_at, attempt.finished_at.as_deref().unwrap());
        assert!(attempt.session.is_none());
        assert!(attempt.retry.is_none());
        assert_eq!(
            synthesize_malformed_dispatch_error(&rejected.execution_id, attempt),
            fixture_error
        );
        assert_eq!(attempt.error.as_ref(), Some(&fixture_error));
        assert_eq!(rejected.error.as_ref(), Some(&fixture_error));

        let mut raw_plugin_error = fixture_error.clone();
        raw_plugin_error.message = "raw plugin parser text: /private/path".to_string();
        raw_plugin_error.context = AgentErrorContext::default();
        assert_ne!(
            synthesize_malformed_dispatch_error(&rejected.execution_id, attempt),
            raw_plugin_error
        );
        let mut copied_raw_plugin_error = rejected.clone();
        copied_raw_plugin_error.attempts[0].error = Some(raw_plugin_error.clone());
        copied_raw_plugin_error.error = Some(raw_plugin_error);
        assert_eq!(
            copied_raw_plugin_error.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );

        let mut extra_untrusted_detail = rejected.clone();
        for error in [
            extra_untrusted_detail.attempts[0].error.as_mut().unwrap(),
            extra_untrusted_detail.error.as_mut().unwrap(),
        ] {
            error
                .context
                .safe_details
                .insert("rawPath".to_string(), "/private/path".to_string());
        }
        assert_eq!(
            extra_untrusted_detail.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );

        let mut wrong_reason = rejected.clone();
        for error in [
            wrong_reason.attempts[0].error.as_mut().unwrap(),
            wrong_reason.error.as_mut().unwrap(),
        ] {
            error
                .context
                .safe_details
                .insert("reasonCode".to_string(), "invalid_request".to_string());
        }
        assert_eq!(
            wrong_reason.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );

        let mut mismatched_terminal_error = rejected.clone();
        mismatched_terminal_error.error.as_mut().unwrap().message =
            AGENT_RUNTIME_V2_DISABLED_MESSAGE.to_string();
        assert_eq!(
            mismatched_terminal_error.validate(),
            Err(AgentExecutionValidationError::ExecutionTerminalAttemptMismatch)
        );

        let mut seq2_gap = rejected;
        seq2_gap.sequence = 2;
        seq2_gap.attempts[0].finished_sequence = Some(2);
        assert_eq!(
            seq2_gap.validate(),
            Err(AgentExecutionValidationError::AttemptSequenceInvalid)
        );
    }

    #[test]
    fn prestart_cancellation_replaces_only_unacknowledged_rejection_and_wins() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let rejected: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_dispatch_rejected.json"
        ))
        .unwrap();
        let cancelled: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_dispatch_cancelled.json"
        ))
        .unwrap();

        rejected.validate_for_request(&request).unwrap();
        cancelled.validate_for_request(&request).unwrap();
        assert_eq!(
            rejected.validate_prestart_cancellation_replacement(&cancelled, &request),
            Ok(AgentPrestartCancellationReplacement::CancellationWon)
        );
        assert_eq!(cancelled.state, AgentExecutionState::Cancelled);
        assert_eq!(cancelled.sequence, 1);
        let attempt = &cancelled.attempts[0];
        assert_eq!(attempt.state, AgentAttemptState::DispatchCancelled);
        assert_eq!(attempt.started_sequence, 1);
        assert_eq!(attempt.finished_sequence, Some(1));
        assert_eq!(attempt.started_at, attempt.finished_at.as_deref().unwrap());
        assert!(attempt.session.is_none());
        assert!(attempt.retry.is_none());
        assert_eq!(attempt.delivery, rejected.attempts[0].delivery);
        assert_eq!(
            attempt.task_idempotency_key,
            rejected.attempts[0].task_idempotency_key
        );
        assert_eq!(attempt.payload_digest, rejected.attempts[0].payload_digest);
        assert_eq!(
            attempt
                .error
                .as_ref()
                .unwrap()
                .context
                .safe_details
                .get("reasonCode")
                .map(String::as_str),
            Some("prestart_cancellation_won")
        );

        assert_eq!(
            rejected.validate_successor(&cancelled, &request),
            Err(AgentExecutionValidationError::NonMonotonicUpdate)
        );
        assert_eq!(
            cancelled.validate_successor(&cancelled, &request),
            Ok(AgentExecutionUpdateKind::IdempotentReplay)
        );

        let mut changed_dispatch = cancelled.clone();
        changed_dispatch.attempts[0].payload_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        assert_eq!(
            rejected.validate_prestart_cancellation_replacement(&changed_dispatch, &request),
            Err(AgentExecutionValidationError::InvalidPrestartCancellationReplacement)
        );

        let mut wrong_reason = cancelled.clone();
        wrong_reason.attempts[0]
            .error
            .as_mut()
            .unwrap()
            .context
            .safe_details
            .insert("reasonCode".to_string(), "provider_cancelled".to_string());
        assert_eq!(
            wrong_reason.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );

        let mut fabricated_session = cancelled;
        fabricated_session.attempts[0].session = Some(
            serde_json::from_str(include_str!("../fixtures/agent_session_checkpoint_v2.json"))
                .unwrap(),
        );
        assert_eq!(
            fabricated_session.validate(),
            Err(AgentExecutionValidationError::AttemptErrorStateMismatch)
        );
    }

    #[test]
    fn resumed_process_attempt_rejects_rebinding_repinning_and_checkpoint_drift() {
        let request: AgentTaskRequestV2 =
            serde_json::from_str(include_str!("../fixtures/agent_task_v2.json")).unwrap();
        let blocked: AgentExecutionV2 =
            serde_json::from_str(include_str!("../fixtures/agent_execution_v2.json")).unwrap();
        let resumed: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_blocked_resumed.json"
        ))
        .unwrap();

        let mut rebound = resumed.clone();
        rebound.binding.workspace_binding_generation += 1;
        rebound.attempts[0]
            .session
            .as_mut()
            .unwrap()
            .binding
            .workspace_binding_generation += 1;
        rebound.attempts[1]
            .retry
            .as_mut()
            .unwrap()
            .continuation
            .as_mut()
            .unwrap()
            .binding
            .workspace_binding_generation += 1;
        assert_eq!(
            blocked.validate_successor(&rebound, &request),
            Err(AgentExecutionValidationError::LogicalIdentityMismatch)
        );

        let mut repinned = resumed.clone();
        repinned.attempts[1].selection_index = 1;
        assert_eq!(
            blocked.validate_successor(&repinned, &request),
            Err(AgentExecutionValidationError::PinnedCandidateChanged)
        );

        let mut drifted = resumed;
        drifted.attempts[1]
            .retry
            .as_mut()
            .unwrap()
            .continuation
            .as_mut()
            .unwrap()
            .sequence += 1;
        assert_eq!(
            blocked.validate_successor(&drifted, &request),
            Err(AgentExecutionValidationError::InvalidAttemptRetry)
        );

        let mut key_reused: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_blocked_resumed.json"
        ))
        .unwrap();
        key_reused.attempts[1].task_idempotency_key =
            key_reused.attempts[0].task_idempotency_key.clone();
        assert_eq!(
            key_reused.validate(),
            Err(AgentExecutionValidationError::DuplicateAttemptIdempotencyKey)
        );

        let mut rewritten_digest: AgentExecutionV2 = serde_json::from_str(include_str!(
            "../fixtures/agent_execution_v2_blocked_resumed.json"
        ))
        .unwrap();
        rewritten_digest.attempts[0].payload_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        assert_eq!(
            blocked.validate_successor(&rewritten_digest, &request),
            Err(AgentExecutionValidationError::AttemptHistoryRewritten)
        );
    }

    #[test]
    fn execution_terminal_state_is_explicit() {
        assert!(AgentExecutionState::Completed.is_terminal());
        assert!(AgentExecutionState::Indeterminate.is_terminal());
        assert!(!AgentExecutionState::Blocked.is_terminal());
        assert!(!AgentExecutionState::Running.is_terminal());
        assert!(AgentAttemptState::Blocked.is_terminal());
        assert_eq!(MAX_AGENT_PROCESS_ATTEMPTS_PER_EXECUTION, 8);
    }
}
