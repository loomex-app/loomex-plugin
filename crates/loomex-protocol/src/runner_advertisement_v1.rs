//! Fail-closed runner manifest projection for agent-runtime cutover.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{AgentRuntimeCapabilitySnapshotV2, AGENT_RUNTIME_CAPABILITY_V2};

pub const RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1: &str = "loomex.runner-agent-advertisement/v1";
pub const LEGACY_AGENT_TASK_DRAIN_CAPABILITY: &str = "agent.task.v1.drain";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyAgentTaskMode {
    DrainOnly,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyAgentTasksAdvertisementV1 {
    pub mode: LegacyAgentTaskMode,
}

/// Agent-related fields projected from the runner manifest. Other manifest
/// fields are intentionally ignored during deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerAgentAdvertisementV1 {
    pub agent_advertisement_schema_version: String,
    pub agent_runtime_v2_enabled: bool,
    pub legacy_agent_tasks: LegacyAgentTasksAdvertisementV1,
    pub capabilities: BTreeMap<String, bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_non_null"
    )]
    pub agent_runtimes: Option<AgentRuntimeCapabilitySnapshotV2>,
}

fn deserialize_present_non_null<'de, D>(
    deserializer: D,
) -> Result<Option<AgentRuntimeCapabilitySnapshotV2>, D::Error>
where
    D: Deserializer<'de>,
{
    AgentRuntimeCapabilitySnapshotV2::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerAgentAdvertisementValidationError {
    WrongSchemaVersion,
    LegacyDrainCapabilityMismatch,
    RuntimeV2CapabilityMismatch,
    RuntimeV2SnapshotMismatch,
    InvalidRuntimeV2Snapshot,
    RuntimeV2RunnerMismatch,
}

impl RunnerAgentAdvertisementV1 {
    pub fn validate(&self) -> Result<(), RunnerAgentAdvertisementValidationError> {
        if self.agent_advertisement_schema_version != RUNNER_AGENT_ADVERTISEMENT_SCHEMA_V1 {
            return Err(RunnerAgentAdvertisementValidationError::WrongSchemaVersion);
        }

        let drain_capability = self.capabilities.get(LEGACY_AGENT_TASK_DRAIN_CAPABILITY);
        let drain_capability_is_valid = match self.legacy_agent_tasks.mode {
            LegacyAgentTaskMode::DrainOnly => drain_capability == Some(&true),
            LegacyAgentTaskMode::Disabled => drain_capability.is_none(),
        };
        if !drain_capability_is_valid {
            return Err(RunnerAgentAdvertisementValidationError::LegacyDrainCapabilityMismatch);
        }

        let runtime_capability = self.capabilities.get(AGENT_RUNTIME_CAPABILITY_V2);
        let runtime_capability_is_valid = if self.agent_runtime_v2_enabled {
            runtime_capability == Some(&true)
        } else {
            runtime_capability.is_none()
        };
        if !runtime_capability_is_valid {
            return Err(RunnerAgentAdvertisementValidationError::RuntimeV2CapabilityMismatch);
        }

        match (self.agent_runtime_v2_enabled, &self.agent_runtimes) {
            (false, None) => {}
            (true, Some(snapshot)) => snapshot
                .validate()
                .map_err(|_| RunnerAgentAdvertisementValidationError::InvalidRuntimeV2Snapshot)?,
            _ => {
                return Err(RunnerAgentAdvertisementValidationError::RuntimeV2SnapshotMismatch);
            }
        }

        Ok(())
    }

    pub fn validate_for_runner_id(
        &self,
        runner_id: &str,
    ) -> Result<(), RunnerAgentAdvertisementValidationError> {
        self.validate()?;
        if self
            .agent_runtimes
            .as_ref()
            .is_some_and(|snapshot| snapshot.runner_id != runner_id)
        {
            return Err(RunnerAgentAdvertisementValidationError::RuntimeV2RunnerMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_enabled() -> RunnerAgentAdvertisementV1 {
        serde_json::from_str(include_str!(
            "../fixtures/runner_agent_advertisement_v1_drain_enabled.json"
        ))
        .unwrap()
    }

    fn disabled() -> RunnerAgentAdvertisementV1 {
        serde_json::from_str(include_str!(
            "../fixtures/runner_agent_advertisement_v1_disabled.json"
        ))
        .unwrap()
    }

    #[test]
    fn legacy_and_v2_modes_form_a_valid_four_way_matrix() {
        let drain_v2 = drain_enabled();
        drain_v2.validate_for_runner_id("runner_local_01").unwrap();

        let mut disabled_v2 = drain_v2.clone();
        disabled_v2.legacy_agent_tasks.mode = LegacyAgentTaskMode::Disabled;
        disabled_v2
            .capabilities
            .remove(LEGACY_AGENT_TASK_DRAIN_CAPABILITY);
        disabled_v2.validate().unwrap();

        let disabled_no_v2 = disabled();
        disabled_no_v2.validate().unwrap();

        let mut drain_no_v2 = disabled_no_v2.clone();
        drain_no_v2.legacy_agent_tasks.mode = LegacyAgentTaskMode::DrainOnly;
        drain_no_v2
            .capabilities
            .insert(LEGACY_AGENT_TASK_DRAIN_CAPABILITY.to_string(), true);
        drain_no_v2.validate().unwrap();
    }

    #[test]
    fn legacy_drain_capability_is_present_if_and_only_if_drain_only() {
        let mut missing = drain_enabled();
        missing
            .capabilities
            .remove(LEGACY_AGENT_TASK_DRAIN_CAPABILITY);
        assert_eq!(
            missing.validate(),
            Err(RunnerAgentAdvertisementValidationError::LegacyDrainCapabilityMismatch)
        );

        let mut disabled_but_present = disabled();
        disabled_but_present
            .capabilities
            .insert(LEGACY_AGENT_TASK_DRAIN_CAPABILITY.to_string(), false);
        assert_eq!(
            disabled_but_present.validate(),
            Err(RunnerAgentAdvertisementValidationError::LegacyDrainCapabilityMismatch)
        );
    }

    #[test]
    fn disabled_v2_omits_capability_and_snapshot_instead_of_advertising_false_or_null() {
        let mut capability_false = disabled();
        capability_false
            .capabilities
            .insert(AGENT_RUNTIME_CAPABILITY_V2.to_string(), false);
        assert_eq!(
            capability_false.validate(),
            Err(RunnerAgentAdvertisementValidationError::RuntimeV2CapabilityMismatch)
        );

        let mut snapshot_present = disabled();
        snapshot_present.agent_runtimes = drain_enabled().agent_runtimes;
        assert_eq!(
            snapshot_present.validate(),
            Err(RunnerAgentAdvertisementValidationError::RuntimeV2SnapshotMismatch)
        );

        let null_snapshot = r#"{
            "agentAdvertisementSchemaVersion":"loomex.runner-agent-advertisement/v1",
            "agentRuntimeV2Enabled":false,
            "legacyAgentTasks":{"mode":"disabled"},
            "capabilities":{},
            "agentRuntimes":null
        }"#;
        assert!(serde_json::from_str::<RunnerAgentAdvertisementV1>(null_snapshot).is_err());
    }

    #[test]
    fn enabled_v2_requires_true_capability_and_valid_snapshot() {
        let mut capability_missing = drain_enabled();
        capability_missing
            .capabilities
            .remove(AGENT_RUNTIME_CAPABILITY_V2);
        assert_eq!(
            capability_missing.validate(),
            Err(RunnerAgentAdvertisementValidationError::RuntimeV2CapabilityMismatch)
        );

        let mut snapshot_missing = drain_enabled();
        snapshot_missing.agent_runtimes = None;
        assert_eq!(
            snapshot_missing.validate(),
            Err(RunnerAgentAdvertisementValidationError::RuntimeV2SnapshotMismatch)
        );

        let mut wrong_snapshot_schema = drain_enabled();
        wrong_snapshot_schema
            .agent_runtimes
            .as_mut()
            .unwrap()
            .schema_version = "loomex.agent-capabilities.v999".to_string();
        assert_eq!(
            wrong_snapshot_schema.validate(),
            Err(RunnerAgentAdvertisementValidationError::InvalidRuntimeV2Snapshot)
        );
    }

    #[test]
    fn unknown_schema_mode_and_missing_legacy_field_fail_closed() {
        let mut unknown_schema = disabled();
        unknown_schema.agent_advertisement_schema_version =
            "loomex.runner-agent-advertisement/v999".to_string();
        assert_eq!(
            unknown_schema.validate(),
            Err(RunnerAgentAdvertisementValidationError::WrongSchemaVersion)
        );

        let unknown_mode = r#"{
            "agentAdvertisementSchemaVersion":"loomex.runner-agent-advertisement/v1",
            "agentRuntimeV2Enabled":false,
            "legacyAgentTasks":{"mode":"legacy_forever"},
            "capabilities":{}
        }"#;
        assert!(serde_json::from_str::<RunnerAgentAdvertisementV1>(unknown_mode).is_err());

        let missing_legacy = r#"{
            "agentAdvertisementSchemaVersion":"loomex.runner-agent-advertisement/v1",
            "agentRuntimeV2Enabled":false,
            "capabilities":{}
        }"#;
        assert!(serde_json::from_str::<RunnerAgentAdvertisementV1>(missing_legacy).is_err());
    }
}
