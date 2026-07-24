use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CoreError, CoreResult};

pub const RELEASE_MANIFEST_SCHEMA_VERSION: &str = "loomex.runner.releaseManifest/v1";
pub const ARTIFACT_SIGNATURE_CONTEXT: &str = "loomex.runner.artifactSignature/v1";
pub const MANIFEST_SIGNATURE_CONTEXT: &str = "loomex.runner.manifestSignature/v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Dev,
    Beta,
    Stable,
    NightlyInternal,
    EnterprisePinned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseArtifact {
    pub name: String,
    pub os: String,
    pub arch: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildProvenance {
    pub builder_id: String,
    pub source_repository: String,
    pub source_revision: String,
    pub build_started_at: String,
    pub build_finished_at: String,
    pub workflow_run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub product: String,
    pub version: String,
    pub channel: ReleaseChannel,
    pub rollout_percent: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_to_version: Option<String>,
    pub previous_versions: Vec<String>,
    pub artifacts: Vec<ReleaseArtifact>,
    pub sbom: Vec<SbomPackage>,
    pub provenance: BuildProvenance,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePolicy {
    pub current_version: String,
    pub channel: ReleaseChannel,
    pub rollout_bucket: u8,
    pub enterprise_pinned_version: Option<String>,
    pub allow_downgrade_for_rollback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision {
    Install {
        from_version: String,
        to_version: String,
        channel: ReleaseChannel,
    },
    Rollback {
        from_version: String,
        to_version: String,
    },
    StayPinned {
        version: String,
    },
    NotInRollout {
        rollout_percent: u8,
        rollout_bucket: u8,
    },
    AlreadyCurrent {
        version: String,
    },
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sign_release_artifact(
    name: impl Into<String>,
    os: impl Into<String>,
    arch: impl Into<String>,
    bytes: &[u8],
    signing_key_hex: &str,
) -> CoreResult<ReleaseArtifact> {
    let name = name.into();
    let os = os.into();
    let arch = arch.into();
    let sha256 = sha256_hex(bytes);
    let payload = artifact_signature_payload(&name, &os, &arch, &sha256, bytes.len() as u64);
    Ok(ReleaseArtifact {
        name,
        os,
        arch,
        sha256,
        size_bytes: bytes.len() as u64,
        signature: sign_payload(signing_key_hex, &payload)?,
    })
}

pub fn verify_release_artifact(
    artifact: &ReleaseArtifact,
    bytes: &[u8],
    public_key_hex: &str,
) -> CoreResult<()> {
    let actual_sha256 = sha256_hex(bytes);
    if actual_sha256 != artifact.sha256 {
        return Err(CoreError::new(
            "RELEASE_ARTIFACT_CHECKSUM_MISMATCH",
            "release artifact checksum does not match manifest",
        ));
    }
    if bytes.len() as u64 != artifact.size_bytes {
        return Err(CoreError::new(
            "RELEASE_ARTIFACT_SIZE_MISMATCH",
            "release artifact size does not match manifest",
        ));
    }
    let payload = artifact_signature_payload(
        &artifact.name,
        &artifact.os,
        &artifact.arch,
        &artifact.sha256,
        artifact.size_bytes,
    );
    verify_payload(public_key_hex, &payload, &artifact.signature).map_err(|_| {
        CoreError::new(
            "RELEASE_ARTIFACT_SIGNATURE_INVALID",
            "release artifact signature is invalid",
        )
    })
}

pub fn sign_release_manifest(
    mut manifest: ReleaseManifest,
    signing_key_hex: &str,
) -> CoreResult<ReleaseManifest> {
    validate_manifest_for_signing(&manifest)?;
    let payload = manifest_signature_payload(&manifest)?;
    manifest.signature = Some(sign_payload(signing_key_hex, &payload)?);
    Ok(manifest)
}

pub fn verify_release_manifest(manifest: &ReleaseManifest, public_key_hex: &str) -> CoreResult<()> {
    validate_manifest_for_signing(manifest)?;
    let signature = manifest.signature.as_deref().ok_or_else(|| {
        CoreError::new(
            "RELEASE_MANIFEST_SIGNATURE_MISSING",
            "release manifest signature is required",
        )
    })?;
    let payload = manifest_signature_payload(manifest)?;
    verify_payload(public_key_hex, &payload, signature).map_err(|_| {
        CoreError::new(
            "RELEASE_MANIFEST_SIGNATURE_INVALID",
            "release manifest signature is invalid",
        )
    })
}

pub fn plan_update(
    manifest: &ReleaseManifest,
    public_key_hex: &str,
    policy: &UpdatePolicy,
) -> CoreResult<UpdateDecision> {
    verify_release_manifest(manifest, public_key_hex)?;
    if manifest.channel != policy.channel {
        return Err(CoreError::new(
            "RELEASE_CHANNEL_MISMATCH",
            "release manifest channel does not match selected update channel",
        ));
    }
    if let Some(pinned) = &policy.enterprise_pinned_version {
        if pinned != &manifest.version {
            return Ok(UpdateDecision::StayPinned {
                version: pinned.clone(),
            });
        }
    }
    if let Some(rollback_to) = &manifest.rollback_to_version {
        if !manifest.previous_versions.contains(rollback_to) {
            return Err(CoreError::new(
                "RELEASE_ROLLBACK_TARGET_INVALID",
                "rollback target must be listed in previous_versions",
            ));
        }
        if !policy.allow_downgrade_for_rollback {
            return Err(CoreError::new(
                "RELEASE_ROLLBACK_DENIED",
                "rollback requires explicit downgrade approval",
            ));
        }
        return Ok(UpdateDecision::Rollback {
            from_version: policy.current_version.clone(),
            to_version: rollback_to.clone(),
        });
    }
    if policy.current_version == manifest.version {
        return Ok(UpdateDecision::AlreadyCurrent {
            version: policy.current_version.clone(),
        });
    }
    if policy.rollout_bucket >= manifest.rollout_percent {
        return Ok(UpdateDecision::NotInRollout {
            rollout_percent: manifest.rollout_percent,
            rollout_bucket: policy.rollout_bucket,
        });
    }
    if compare_versions(&manifest.version, &policy.current_version).is_lt() {
        return Err(CoreError::new(
            "RELEASE_DOWNGRADE_DENIED",
            "release manifest version is older than current version",
        ));
    }
    Ok(UpdateDecision::Install {
        from_version: policy.current_version.clone(),
        to_version: manifest.version.clone(),
        channel: manifest.channel.clone(),
    })
}

pub fn generate_sbom(packages: Vec<SbomPackage>) -> CoreResult<Vec<SbomPackage>> {
    if packages.is_empty() {
        return Err(CoreError::new(
            "RELEASE_SBOM_EMPTY",
            "release SBOM must contain at least one package",
        ));
    }
    let mut seen = BTreeMap::new();
    let mut sorted = packages;
    sorted.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });
    for package in &sorted {
        if package.name.trim().is_empty() || package.version.trim().is_empty() {
            return Err(CoreError::new(
                "RELEASE_SBOM_PACKAGE_INVALID",
                "SBOM package name and version are required",
            ));
        }
        if seen
            .insert((package.name.clone(), package.version.clone()), true)
            .is_some()
        {
            return Err(CoreError::new(
                "RELEASE_SBOM_DUPLICATE_PACKAGE",
                "SBOM package entries must be unique",
            ));
        }
    }
    Ok(sorted)
}

pub fn verifying_key_hex_from_signing_key(signing_key_hex: &str) -> CoreResult<String> {
    let signing_key = parse_signing_key(signing_key_hex)?;
    Ok(hex_encode(signing_key.verifying_key().as_bytes()))
}

fn validate_manifest_for_signing(manifest: &ReleaseManifest) -> CoreResult<()> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
        return Err(CoreError::new(
            "RELEASE_MANIFEST_SCHEMA_INVALID",
            "release manifest schema_version is not supported",
        ));
    }
    if manifest.version.trim().is_empty()
        || manifest.product.trim().is_empty()
        || manifest.created_at.trim().is_empty()
    {
        return Err(CoreError::new(
            "RELEASE_MANIFEST_INVALID",
            "release manifest product, version, and created_at are required",
        ));
    }
    if manifest.rollout_percent > 100 {
        return Err(CoreError::new(
            "RELEASE_ROLLOUT_INVALID",
            "release rollout_percent must be between 0 and 100",
        ));
    }
    if manifest.artifacts.is_empty() {
        return Err(CoreError::new(
            "RELEASE_ARTIFACTS_EMPTY",
            "release manifest must include at least one artifact",
        ));
    }
    generate_sbom(manifest.sbom.clone())?;
    if manifest.provenance.builder_id.trim().is_empty()
        || manifest.provenance.source_repository.trim().is_empty()
        || manifest.provenance.source_revision.trim().is_empty()
        || manifest.provenance.workflow_run_id.trim().is_empty()
    {
        return Err(CoreError::new(
            "RELEASE_PROVENANCE_INVALID",
            "release provenance is incomplete",
        ));
    }
    Ok(())
}

fn artifact_signature_payload(
    name: &str,
    os: &str,
    arch: &str,
    sha256: &str,
    size_bytes: u64,
) -> Vec<u8> {
    format!("{ARTIFACT_SIGNATURE_CONTEXT}\n{name}\n{os}\n{arch}\n{sha256}\n{size_bytes}\n")
        .into_bytes()
}

fn manifest_signature_payload(manifest: &ReleaseManifest) -> CoreResult<Vec<u8>> {
    let mut value = serde_json::to_value(manifest).map_err(json_error)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    let canonical = serde_json::to_vec(&value).map_err(json_error)?;
    let mut payload = MANIFEST_SIGNATURE_CONTEXT.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend(canonical);
    Ok(payload)
}

fn sign_payload(signing_key_hex: &str, payload: &[u8]) -> CoreResult<String> {
    let signing_key = parse_signing_key(signing_key_hex)?;
    let signature = signing_key.sign(payload);
    Ok(hex_encode(&signature.to_bytes()))
}

fn verify_payload(public_key_hex: &str, payload: &[u8], signature_hex: &str) -> CoreResult<()> {
    let verifying_key = parse_verifying_key(public_key_hex)?;
    let signature_bytes = hex_decode_exact::<64>(signature_hex, "RELEASE_SIGNATURE_INVALID")?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload, &signature)
        .map_err(|error| CoreError::new("RELEASE_SIGNATURE_INVALID", error.to_string()))
}

fn parse_signing_key(signing_key_hex: &str) -> CoreResult<SigningKey> {
    let bytes = hex_decode_exact::<32>(signing_key_hex, "RELEASE_SIGNING_KEY_INVALID")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn parse_verifying_key(public_key_hex: &str) -> CoreResult<VerifyingKey> {
    let bytes = hex_decode_exact::<32>(public_key_hex, "RELEASE_PUBLIC_KEY_INVALID")?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| CoreError::new("RELEASE_PUBLIC_KEY_INVALID", error.to_string()))
}

fn hex_decode_exact<const N: usize>(value: &str, code: &'static str) -> CoreResult<[u8; N]> {
    let bytes = hex_decode(value).map_err(|message| CoreError::new(code, message))?;
    bytes
        .try_into()
        .map_err(|_| CoreError::new(code, format!("expected {} bytes", N)))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if !value.len().is_multiple_of(2) {
        return Err("hex value must contain an even number of characters".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "hex value contains non-hex characters".to_string())
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = version_parts(left);
    let right_parts = version_parts(right);
    for index in 0..left_parts.len().max(right_parts.len()) {
        let left = *left_parts.get(index).unwrap_or(&0);
        let right = *right_parts.get(index).unwrap_or(&0);
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .split(['.', '-'])
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

fn json_error(error: serde_json::Error) -> CoreError {
    CoreError::new("RELEASE_JSON_INVALID", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn signature_verification_success() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let bytes = b"loomex-cli-binary";
        let artifact =
            sign_release_artifact("loomex", "macos", "aarch64", bytes, SIGNING_KEY).unwrap();
        let manifest =
            sign_release_manifest(manifest(vec![artifact.clone()]), SIGNING_KEY).unwrap();

        verify_release_artifact(&artifact, bytes, &public_key).unwrap();
        verify_release_manifest(&manifest, &public_key).unwrap();
    }

    #[test]
    fn tampered_binary_is_rejected() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let artifact =
            sign_release_artifact("loomex", "linux", "x86_64", b"original", SIGNING_KEY).unwrap();

        let error = verify_release_artifact(&artifact, b"tampered", &public_key).unwrap_err();

        assert_eq!("RELEASE_ARTIFACT_CHECKSUM_MISMATCH", error.code);
    }

    #[test]
    fn tampered_update_manifest_is_rejected() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let artifact =
            sign_release_artifact("loomex", "windows", "x86_64", b"binary", SIGNING_KEY).unwrap();
        let mut manifest = sign_release_manifest(manifest(vec![artifact]), SIGNING_KEY).unwrap();
        manifest.version = "9.9.9".to_string();

        let error = verify_release_manifest(&manifest, &public_key).unwrap_err();

        assert_eq!("RELEASE_MANIFEST_SIGNATURE_INVALID", error.code);
    }

    #[test]
    fn rollback_to_previous_version_is_explicit_decision() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let artifact =
            sign_release_artifact("loomex", "macos", "aarch64", b"binary", SIGNING_KEY).unwrap();
        let mut manifest = manifest(vec![artifact]);
        manifest.rollback_to_version = Some("1.2.2".to_string());
        let manifest = sign_release_manifest(manifest, SIGNING_KEY).unwrap();

        let decision = plan_update(
            &manifest,
            &public_key,
            &UpdatePolicy {
                current_version: "1.2.3".to_string(),
                channel: ReleaseChannel::Stable,
                rollout_bucket: 0,
                enterprise_pinned_version: None,
                allow_downgrade_for_rollback: true,
            },
        )
        .unwrap();

        assert_eq!(
            UpdateDecision::Rollback {
                from_version: "1.2.3".to_string(),
                to_version: "1.2.2".to_string()
            },
            decision
        );
    }

    #[test]
    fn pinned_enterprise_version_does_not_auto_upgrade() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let artifact =
            sign_release_artifact("loomex", "macos", "aarch64", b"binary", SIGNING_KEY).unwrap();
        let mut manifest = manifest(vec![artifact]);
        manifest.channel = ReleaseChannel::EnterprisePinned;
        let manifest = sign_release_manifest(manifest, SIGNING_KEY).unwrap();

        let decision = plan_update(
            &manifest,
            &public_key,
            &UpdatePolicy {
                current_version: "1.2.2".to_string(),
                channel: ReleaseChannel::EnterprisePinned,
                rollout_bucket: 0,
                enterprise_pinned_version: Some("1.2.2".to_string()),
                allow_downgrade_for_rollback: false,
            },
        )
        .unwrap();

        assert_eq!(
            UpdateDecision::StayPinned {
                version: "1.2.2".to_string()
            },
            decision
        );
    }

    #[test]
    fn staged_rollout_can_hold_update() {
        let public_key = verifying_key_hex_from_signing_key(SIGNING_KEY).unwrap();
        let artifact =
            sign_release_artifact("loomex", "macos", "aarch64", b"binary", SIGNING_KEY).unwrap();
        let mut manifest = manifest(vec![artifact]);
        manifest.rollout_percent = 10;
        let manifest = sign_release_manifest(manifest, SIGNING_KEY).unwrap();

        let decision = plan_update(
            &manifest,
            &public_key,
            &UpdatePolicy {
                current_version: "1.2.2".to_string(),
                channel: ReleaseChannel::Stable,
                rollout_bucket: 50,
                enterprise_pinned_version: None,
                allow_downgrade_for_rollback: false,
            },
        )
        .unwrap();

        assert_eq!(
            UpdateDecision::NotInRollout {
                rollout_percent: 10,
                rollout_bucket: 50
            },
            decision
        );
    }

    #[test]
    fn sbom_generated_and_provenance_attached() {
        let sbom = generate_sbom(vec![
            SbomPackage {
                name: "loomex-core".to_string(),
                version: "0.1.0".to_string(),
                license: None,
            },
            SbomPackage {
                name: "loomex-cli".to_string(),
                version: "0.1.0".to_string(),
                license: None,
            },
        ])
        .unwrap();
        let artifact =
            sign_release_artifact("loomex", "macos", "aarch64", b"binary", SIGNING_KEY).unwrap();
        let mut manifest = manifest(vec![artifact]);
        manifest.sbom = sbom;
        let signed = sign_release_manifest(manifest, SIGNING_KEY).unwrap();

        assert_eq!("loomex-cli", signed.sbom[0].name);
        assert_eq!("github-actions:loomex-runner", signed.provenance.builder_id);
        assert_eq!("abcdef123456", signed.provenance.source_revision);
    }

    fn manifest(artifacts: Vec<ReleaseArtifact>) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: RELEASE_MANIFEST_SCHEMA_VERSION.to_string(),
            product: "loomex-runner".to_string(),
            version: "1.2.3".to_string(),
            channel: ReleaseChannel::Stable,
            rollout_percent: 100,
            rollback_to_version: None,
            previous_versions: vec!["1.2.2".to_string()],
            artifacts,
            sbom: vec![SbomPackage {
                name: "loomex-core".to_string(),
                version: "0.1.0".to_string(),
                license: Some("UNLICENSED".to_string()),
            }],
            provenance: BuildProvenance {
                builder_id: "github-actions:loomex-runner".to_string(),
                source_repository: "https://github.com/loomex-app/runner".to_string(),
                source_revision: "abcdef123456".to_string(),
                build_started_at: "2026-06-29T00:00:00Z".to_string(),
                build_finished_at: "2026-06-29T00:01:00Z".to_string(),
                workflow_run_id: "run_123".to_string(),
            },
            created_at: "2026-06-29T00:02:00Z".to_string(),
            signature: None,
        }
    }
}
