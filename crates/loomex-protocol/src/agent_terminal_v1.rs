//! Versioned size contract for durable terminal delivery of agent executions.
//!
//! Process stdout/stderr capture limits are runtime concerns and intentionally
//! are not defined here. These limits apply only after output parsing, when an
//! `AgentOutput`, its `AgentExecutionV2` envelope, and the complete HTTP
//! terminal submission are serialized for durable Backend delivery.

use serde::{Deserialize, Serialize};

use crate::{AgentExecutionV2, AgentOutput};

pub const AGENT_TERMINAL_PAYLOAD_LIMITS_SCHEMA_V1: &str = "loomex.agent-terminal-payload-limits/v1";

/// Backend's authoritative runner-job terminal request cap.
pub const BACKEND_RUNNER_TERMINAL_REQUEST_MAX_BYTES: usize = 8_000_000;
/// Complete serialized HTTP submission, including wrapper fields and result.
pub const AGENT_TERMINAL_SUBMISSION_MAX_BYTES: usize = 7_900_000;
/// Serialized `AgentExecutionV2` carried in the submission's `result`.
pub const AGENT_TERMINAL_EXECUTION_MAX_BYTES: usize = 7_750_000;
/// Serialized terminal `AgentOutput` nested inside the execution.
pub const AGENT_TERMINAL_OUTPUT_MAX_BYTES: usize = 7_000_000;

pub const AGENT_TERMINAL_BACKEND_SAFETY_RESERVE_BYTES: usize =
    BACKEND_RUNNER_TERMINAL_REQUEST_MAX_BYTES - AGENT_TERMINAL_SUBMISSION_MAX_BYTES;
pub const AGENT_TERMINAL_WRAPPER_RESERVE_BYTES: usize =
    AGENT_TERMINAL_SUBMISSION_MAX_BYTES - AGENT_TERMINAL_EXECUTION_MAX_BYTES;
pub const AGENT_TERMINAL_EXECUTION_ENVELOPE_RESERVE_BYTES: usize =
    AGENT_TERMINAL_EXECUTION_MAX_BYTES - AGENT_TERMINAL_OUTPUT_MAX_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTerminalPayloadLimitsV1 {
    pub schema_version: String,
    pub backend_request_max_bytes: usize,
    pub submission_max_bytes: usize,
    pub execution_max_bytes: usize,
    pub output_max_bytes: usize,
    pub backend_safety_reserve_bytes: usize,
    pub wrapper_reserve_bytes: usize,
    pub execution_envelope_reserve_bytes: usize,
}

impl Default for AgentTerminalPayloadLimitsV1 {
    fn default() -> Self {
        Self {
            schema_version: AGENT_TERMINAL_PAYLOAD_LIMITS_SCHEMA_V1.to_string(),
            backend_request_max_bytes: BACKEND_RUNNER_TERMINAL_REQUEST_MAX_BYTES,
            submission_max_bytes: AGENT_TERMINAL_SUBMISSION_MAX_BYTES,
            execution_max_bytes: AGENT_TERMINAL_EXECUTION_MAX_BYTES,
            output_max_bytes: AGENT_TERMINAL_OUTPUT_MAX_BYTES,
            backend_safety_reserve_bytes: AGENT_TERMINAL_BACKEND_SAFETY_RESERVE_BYTES,
            wrapper_reserve_bytes: AGENT_TERMINAL_WRAPPER_RESERVE_BYTES,
            execution_envelope_reserve_bytes: AGENT_TERMINAL_EXECUTION_ENVELOPE_RESERVE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTerminalLimitsValidationError {
    WrongSchemaVersion,
    NonAuthoritativeValue,
}

impl AgentTerminalPayloadLimitsV1 {
    pub fn validate(&self) -> Result<(), AgentTerminalLimitsValidationError> {
        if self.schema_version != AGENT_TERMINAL_PAYLOAD_LIMITS_SCHEMA_V1 {
            return Err(AgentTerminalLimitsValidationError::WrongSchemaVersion);
        }
        if self != &Self::default() {
            return Err(AgentTerminalLimitsValidationError::NonAuthoritativeValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentTerminalPayloadSizes {
    pub output_bytes: usize,
    pub execution_bytes: usize,
    pub submission_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTerminalPayloadValidationError {
    JsonSerializationFailed,
    OutputTooLarge { actual: usize, max: usize },
    ExecutionTooLarge { actual: usize, max: usize },
    SubmissionTooLarge { actual: usize, max: usize },
    NestedSizeOrderInvalid,
}

impl AgentTerminalPayloadSizes {
    pub fn validate(&self) -> Result<(), AgentTerminalPayloadValidationError> {
        if self.output_bytes > AGENT_TERMINAL_OUTPUT_MAX_BYTES {
            return Err(AgentTerminalPayloadValidationError::OutputTooLarge {
                actual: self.output_bytes,
                max: AGENT_TERMINAL_OUTPUT_MAX_BYTES,
            });
        }
        if self.execution_bytes > AGENT_TERMINAL_EXECUTION_MAX_BYTES {
            return Err(AgentTerminalPayloadValidationError::ExecutionTooLarge {
                actual: self.execution_bytes,
                max: AGENT_TERMINAL_EXECUTION_MAX_BYTES,
            });
        }
        if self.submission_bytes > AGENT_TERMINAL_SUBMISSION_MAX_BYTES {
            return Err(AgentTerminalPayloadValidationError::SubmissionTooLarge {
                actual: self.submission_bytes,
                max: AGENT_TERMINAL_SUBMISSION_MAX_BYTES,
            });
        }
        if self.output_bytes > self.execution_bytes || self.execution_bytes > self.submission_bytes
        {
            return Err(AgentTerminalPayloadValidationError::NestedSizeOrderInvalid);
        }
        Ok(())
    }
}

pub fn serialized_agent_output_bytes(
    output: &AgentOutput,
) -> Result<usize, AgentTerminalPayloadValidationError> {
    serde_json::to_vec(output)
        .map(|encoded| encoded.len())
        .map_err(|_| AgentTerminalPayloadValidationError::JsonSerializationFailed)
}

pub fn validate_agent_terminal_output(
    output: &AgentOutput,
) -> Result<usize, AgentTerminalPayloadValidationError> {
    let actual = serialized_agent_output_bytes(output)?;
    if actual > AGENT_TERMINAL_OUTPUT_MAX_BYTES {
        return Err(AgentTerminalPayloadValidationError::OutputTooLarge {
            actual,
            max: AGENT_TERMINAL_OUTPUT_MAX_BYTES,
        });
    }
    Ok(actual)
}

pub fn serialized_agent_execution_bytes(
    execution: &AgentExecutionV2,
) -> Result<usize, AgentTerminalPayloadValidationError> {
    serde_json::to_vec(execution)
        .map(|encoded| encoded.len())
        .map_err(|_| AgentTerminalPayloadValidationError::JsonSerializationFailed)
}

pub fn validate_agent_terminal_execution(
    execution: &AgentExecutionV2,
) -> Result<usize, AgentTerminalPayloadValidationError> {
    let actual = serialized_agent_execution_bytes(execution)?;
    if actual > AGENT_TERMINAL_EXECUTION_MAX_BYTES {
        return Err(AgentTerminalPayloadValidationError::ExecutionTooLarge {
            actual,
            max: AGENT_TERMINAL_EXECUTION_MAX_BYTES,
        });
    }
    Ok(actual)
}

/// Validates the exact serialized HTTP request value immediately before send.
/// This final guard, rather than reserve estimates alone, guarantees that the
/// complete wrapper plus execution remains below Backend's request cap.
pub fn validate_agent_terminal_submission<T: Serialize>(
    submission: &T,
) -> Result<usize, AgentTerminalPayloadValidationError> {
    let actual = serde_json::to_vec(submission)
        .map_err(|_| AgentTerminalPayloadValidationError::JsonSerializationFailed)?
        .len();
    if actual > AGENT_TERMINAL_SUBMISSION_MAX_BYTES {
        return Err(AgentTerminalPayloadValidationError::SubmissionTooLarge {
            actual,
            max: AGENT_TERMINAL_SUBMISSION_MAX_BYTES,
        });
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::AgentOutputFormat;

    fn text_output_with_serialized_size(target: usize) -> AgentOutput {
        let empty = AgentOutput {
            format: AgentOutputFormat::Text,
            content: String::new(),
            structured: None,
        };
        let overhead = serialized_agent_output_bytes(&empty).unwrap();
        assert!(target >= overhead);
        AgentOutput {
            content: "a".repeat(target - overhead),
            ..empty
        }
    }

    fn json_value_with_serialized_size(target: usize) -> Value {
        let empty = json!({"payload": ""});
        let overhead = serde_json::to_vec(&empty).unwrap().len();
        assert!(target >= overhead);
        json!({"payload": "a".repeat(target - overhead)})
    }

    #[test]
    fn limits_fixture_is_the_authoritative_versioned_contract() {
        let fixture = include_str!("../fixtures/agent_terminal_payload_limits_v1.json");
        let limits: AgentTerminalPayloadLimitsV1 = serde_json::from_str(fixture).unwrap();

        limits.validate().unwrap();
        assert_eq!(limits, AgentTerminalPayloadLimitsV1::default());
        assert_eq!(
            serde_json::to_value(limits).unwrap(),
            serde_json::from_str::<Value>(fixture).unwrap()
        );
    }

    #[test]
    fn output_limit_accepts_exact_boundary_and_rejects_one_more_byte() {
        let exact = text_output_with_serialized_size(AGENT_TERMINAL_OUTPUT_MAX_BYTES);
        assert_eq!(
            validate_agent_terminal_output(&exact).unwrap(),
            AGENT_TERMINAL_OUTPUT_MAX_BYTES
        );

        let oversized = text_output_with_serialized_size(AGENT_TERMINAL_OUTPUT_MAX_BYTES + 1);
        assert_eq!(
            validate_agent_terminal_output(&oversized),
            Err(AgentTerminalPayloadValidationError::OutputTooLarge {
                actual: AGENT_TERMINAL_OUTPUT_MAX_BYTES + 1,
                max: AGENT_TERMINAL_OUTPUT_MAX_BYTES,
            })
        );
    }

    #[test]
    fn full_submission_limit_accepts_exact_boundary_and_rejects_one_more_byte() {
        let exact = json_value_with_serialized_size(AGENT_TERMINAL_SUBMISSION_MAX_BYTES);
        assert_eq!(
            validate_agent_terminal_submission(&exact).unwrap(),
            AGENT_TERMINAL_SUBMISSION_MAX_BYTES
        );

        let oversized = json_value_with_serialized_size(AGENT_TERMINAL_SUBMISSION_MAX_BYTES + 1);
        assert_eq!(
            validate_agent_terminal_submission(&oversized),
            Err(AgentTerminalPayloadValidationError::SubmissionTooLarge {
                actual: AGENT_TERMINAL_SUBMISSION_MAX_BYTES + 1,
                max: AGENT_TERMINAL_SUBMISSION_MAX_BYTES,
            })
        );
    }

    #[test]
    fn nested_boundaries_reserve_space_for_each_wire_layer() {
        AgentTerminalPayloadSizes {
            output_bytes: AGENT_TERMINAL_OUTPUT_MAX_BYTES,
            execution_bytes: AGENT_TERMINAL_EXECUTION_MAX_BYTES,
            submission_bytes: AGENT_TERMINAL_SUBMISSION_MAX_BYTES,
        }
        .validate()
        .unwrap();

        assert_eq!(AGENT_TERMINAL_BACKEND_SAFETY_RESERVE_BYTES, 100_000);
        assert_eq!(AGENT_TERMINAL_WRAPPER_RESERVE_BYTES, 150_000);
        assert_eq!(AGENT_TERMINAL_EXECUTION_ENVELOPE_RESERVE_BYTES, 750_000);
    }
}
