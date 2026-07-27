//! Stable contracts shared by Loomex runner implementations.
//!
//! This crate intentionally contains no transport, filesystem, process, UI, or
//! authentication implementation. Those concerns belong to the runtime that
//! consumes these contracts.

use serde::{Deserialize, Serialize};

pub mod agent_runtime_v2;
pub mod agent_terminal_v1;
pub mod runner_advertisement_v1;

pub use agent_runtime_v2::*;
pub use agent_terminal_v1::*;
pub use runner_advertisement_v1::*;

pub const RUNNER_PROTOCOL_V1: &str = "runner.v1";
pub const PROTOCOL_VERSION: &str = RUNNER_PROTOCOL_V1;
pub const MINIMUM_SUPPORTED_PROTOCOL_VERSION: &str = RUNNER_PROTOCOL_V1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunnerSurface {
    Desktop,
    Plugin,
}

impl RunnerSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Plugin => "plugin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunnerPlatform {
    Macos,
    Windows,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerIdentity {
    pub surface: RunnerSurface,
    pub runner_version: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub platform: RunnerPlatform,
    pub architecture: String,
}

impl RunnerIdentity {
    pub fn supports_protocol(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolCompatibility {
    Compatible,
    UnsupportedVersion {
        received: String,
        expected: &'static str,
    },
}

pub fn check_protocol_compatibility(version: &str) -> ProtocolCompatibility {
    if version == PROTOCOL_VERSION {
        ProtocolCompatibility::Compatible
    } else {
        ProtocolCompatibility::UnsupportedVersion {
            received: version.to_string(),
            expected: PROTOCOL_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_serializes_stable_runner_metadata() {
        let identity = RunnerIdentity {
            surface: RunnerSurface::Desktop,
            runner_version: "1.4.0".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: vec!["fs.read".to_string()],
            platform: RunnerPlatform::Macos,
            architecture: "arm64".to_string(),
        };

        let value = serde_json::to_value(identity).unwrap();
        assert_eq!(value["surface"], "desktop");
        assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["architecture"], "arm64");
    }

    #[test]
    fn rejects_unreleased_transport_protocol_versions() {
        assert_eq!(
            check_protocol_compatibility("runner.v2"),
            ProtocolCompatibility::UnsupportedVersion {
                received: "runner.v2".to_string(),
                expected: PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn v1_identity_fixture_remains_compatible() {
        let fixture = include_str!("../fixtures/runner_identity_v1.json");
        let identity: RunnerIdentity = serde_json::from_str(fixture).unwrap();

        assert_eq!(identity.protocol_version, RUNNER_PROTOCOL_V1);
        assert!(identity.supports_protocol());
        assert_eq!(identity.surface, RunnerSurface::Plugin);
        assert_eq!(
            serde_json::to_value(identity).unwrap(),
            serde_json::from_str::<serde_json::Value>(fixture).unwrap()
        );
    }
}
