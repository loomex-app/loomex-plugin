//! Stable contracts shared by Loomex runner implementations.
//!
//! This crate intentionally contains no transport, filesystem, process, UI, or
//! authentication implementation. Those concerns belong to the runtime that
//! consumes these contracts.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "runner.v1";
pub const MINIMUM_SUPPORTED_PROTOCOL_VERSION: &str = PROTOCOL_VERSION;
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION];

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
        matches!(
            check_protocol_compatibility(&self.protocol_version),
            ProtocolCompatibility::Compatible
        )
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
    if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
        ProtocolCompatibility::Compatible
    } else {
        ProtocolCompatibility::UnsupportedVersion {
            received: version.to_string(),
            expected: PROTOCOL_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolNegotiationError {
    pub offered: Vec<String>,
    pub supported: &'static [&'static str],
}

impl std::fmt::Display for ProtocolNegotiationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "no compatible runner protocol: offered [{}], supported [{}]",
            self.offered.join(", "),
            self.supported.join(", ")
        )
    }
}

impl std::error::Error for ProtocolNegotiationError {}

/// Select the first protocol supported by both peers.
///
/// The caller owns the ordering of `offered`; this lets a future peer offer a
/// preferred newer version while retaining a compatible fallback. A breaking
/// version is accepted only after it is added to this crate's explicit
/// compatibility set.
pub fn negotiate_protocol_version(
    offered: &[&str],
) -> Result<&'static str, ProtocolNegotiationError> {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|version| offered.contains(version))
        .copied()
        .ok_or_else(|| ProtocolNegotiationError {
            offered: offered
                .iter()
                .map(|version| (*version).to_string())
                .collect(),
            supported: SUPPORTED_PROTOCOL_VERSIONS,
        })
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
    fn rejects_unknown_protocol_versions() {
        assert_eq!(
            check_protocol_compatibility("runner.v2"),
            ProtocolCompatibility::UnsupportedVersion {
                received: "runner.v2".to_string(),
                expected: PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn negotiation_matrix_accepts_current_and_rejects_breaking_versions() {
        assert_eq!(
            negotiate_protocol_version(&["runner.v2", PROTOCOL_VERSION]),
            Ok(PROTOCOL_VERSION)
        );

        let error = negotiate_protocol_version(&["runner.v2"]).unwrap_err();
        assert_eq!(error.offered, vec!["runner.v2"]);
        assert_eq!(error.supported, SUPPORTED_PROTOCOL_VERSIONS);
        assert!(error.to_string().contains("runner.v2"));
    }
}
