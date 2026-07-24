use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult, ReleaseChannel};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    HomebrewTap,
    DirectBinary,
    MacDmg,
    MacPkg,
    LinuxDeb,
    LinuxRpm,
    LinuxTar,
    WindowsMsi,
    WindowsExe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseChannelPolicy {
    pub channel: ReleaseChannel,
    pub display_name: String,
    pub auto_update_allowed: bool,
    pub rollback_allowed: bool,
    pub promotion_gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionInstaller {
    pub kind: InstallerKind,
    pub os: String,
    pub arch: String,
    pub artifact_name: String,
    pub install_command: String,
    pub uninstall_command: String,
    pub admin_required: bool,
    pub preserves_user_data: bool,
    pub channel: ReleaseChannel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMatrixEntry {
    pub cli_app_version: String,
    pub channel: ReleaseChannel,
    pub platform: String,
    pub arch: String,
    pub runner_protocol_version: String,
    pub backend_minimum_version: String,
    pub workflow_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibilityMatrix {
    pub schema_version: String,
    pub entries: Vec<CompatibilityMatrixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyDeprecationNotice {
    pub legacy_binary: String,
    pub replacement_binary: String,
    pub compatibility_window: String,
    pub removal_condition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseDistributionPlan {
    pub schema_version: String,
    pub channels: Vec<ReleaseChannelPolicy>,
    pub installers: Vec<DistributionInstaller>,
    pub compatibility_matrix: ReleaseCompatibilityMatrix,
    pub legacy_deprecation: LegacyDeprecationNotice,
}

pub const RELEASE_DISTRIBUTION_PLAN_SCHEMA_VERSION: &str =
    "loomex.runner.releaseDistributionPlan/v1";
pub const RELEASE_COMPATIBILITY_MATRIX_SCHEMA_VERSION: &str =
    "loomex.runner.releaseCompatibilityMatrix/v1";

pub fn official_release_distribution_plan(version: &str) -> ReleaseDistributionPlan {
    ReleaseDistributionPlan {
        schema_version: RELEASE_DISTRIBUTION_PLAN_SCHEMA_VERSION.to_string(),
        channels: official_release_channel_policies(),
        installers: official_distribution_installers(version),
        compatibility_matrix: official_compatibility_matrix(version),
        legacy_deprecation: LegacyDeprecationNotice {
            legacy_binary: "loomex-runner".to_string(),
            replacement_binary: "loomex".to_string(),
            compatibility_window: "through enterprise acceptance plus one stable release"
                .to_string(),
            removal_condition:
                "remove after the stable loomex CLI has shipped and CI smoke paths have migrated"
                    .to_string(),
        },
    }
}

pub fn validate_release_distribution_plan(plan: &ReleaseDistributionPlan) -> CoreResult<()> {
    if plan.schema_version != RELEASE_DISTRIBUTION_PLAN_SCHEMA_VERSION {
        return Err(CoreError::new(
            "RELEASE_DISTRIBUTION_PLAN_SCHEMA_INVALID",
            "release distribution plan schema_version is not supported",
        ));
    }
    validate_release_channels(&plan.channels)?;
    validate_distribution_installers(&plan.installers)?;
    validate_compatibility_matrix(&plan.compatibility_matrix)?;
    if plan.legacy_deprecation.legacy_binary != "loomex-runner"
        || plan.legacy_deprecation.replacement_binary != "loomex"
    {
        return Err(CoreError::new(
            "RELEASE_LEGACY_DEPRECATION_INVALID",
            "legacy deprecation notice must map loomex-runner to loomex",
        ));
    }
    Ok(())
}

pub fn official_release_channel_policies() -> Vec<ReleaseChannelPolicy> {
    vec![
        ReleaseChannelPolicy {
            channel: ReleaseChannel::Stable,
            display_name: "stable".to_string(),
            auto_update_allowed: true,
            rollback_allowed: true,
            promotion_gate:
                "signed manifest, artifact verification, smoke tests, and release approval"
                    .to_string(),
        },
        ReleaseChannelPolicy {
            channel: ReleaseChannel::Beta,
            display_name: "beta".to_string(),
            auto_update_allowed: true,
            rollback_allowed: true,
            promotion_gate: "signed manifest plus beta smoke acceptance".to_string(),
        },
        ReleaseChannelPolicy {
            channel: ReleaseChannel::NightlyInternal,
            display_name: "nightly/internal".to_string(),
            auto_update_allowed: true,
            rollback_allowed: true,
            promotion_gate: "internal CI build with signed manifest".to_string(),
        },
        ReleaseChannelPolicy {
            channel: ReleaseChannel::EnterprisePinned,
            display_name: "enterprise pinned".to_string(),
            auto_update_allowed: false,
            rollback_allowed: true,
            promotion_gate: "customer-controlled policy pin".to_string(),
        },
    ]
}

pub fn official_distribution_installers(version: &str) -> Vec<DistributionInstaller> {
    let version = normalized_version(version);
    vec![
        DistributionInstaller {
            kind: InstallerKind::HomebrewTap,
            os: "macos".to_string(),
            arch: "universal".to_string(),
            artifact_name: format!("loomex-cli-{version}-homebrew.rb"),
            install_command: "brew install loomex/tap/loomex".to_string(),
            uninstall_command: "brew uninstall loomex".to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::DirectBinary,
            os: "any".to_string(),
            arch: "multi".to_string(),
            artifact_name: format!("loomex-cli-{version}-{{os}}-{{arch}}.tar.gz"),
            install_command:
                "download, verify manifest/signature/checksum, then place loomex on PATH"
                    .to_string(),
            uninstall_command:
                "remove the loomex binary from PATH; keep ~/.loomex unless explicitly purged"
                    .to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::MacDmg,
            os: "macos".to_string(),
            arch: "universal".to_string(),
            artifact_name: format!("Loomex-{version}-universal.dmg"),
            install_command: "open signed/notarized DMG and drag Loomex.app to Applications"
                .to_string(),
            uninstall_command: "remove /Applications/Loomex.app; keep ~/.loomex and logs"
                .to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::MacPkg,
            os: "macos".to_string(),
            arch: "universal".to_string(),
            artifact_name: format!("Loomex-{version}-universal.pkg"),
            install_command: "installer -pkg Loomex.pkg -target CurrentUserHomeDirectory"
                .to_string(),
            uninstall_command: "pkgutil forget app.loomex.runner; remove app bundle only"
                .to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::LinuxDeb,
            os: "linux".to_string(),
            arch: "x86_64/aarch64".to_string(),
            artifact_name: format!("loomex_{version}_{{arch}}.deb"),
            install_command: "sudo apt install ./loomex_<version>_<arch>.deb".to_string(),
            uninstall_command: "sudo apt remove loomex; keep /var/lib/loomex and user config"
                .to_string(),
            admin_required: true,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::LinuxRpm,
            os: "linux".to_string(),
            arch: "x86_64/aarch64".to_string(),
            artifact_name: format!("loomex-{version}.{{arch}}.rpm"),
            install_command: "sudo dnf install ./loomex-<version>.<arch>.rpm".to_string(),
            uninstall_command: "sudo dnf remove loomex; keep /var/lib/loomex and user config"
                .to_string(),
            admin_required: true,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::LinuxTar,
            os: "linux".to_string(),
            arch: "x86_64/aarch64".to_string(),
            artifact_name: format!("loomex-{version}-linux-{{arch}}.tar.gz"),
            install_command:
                "tar -xzf loomex-linux.tar.gz && install -m 0755 loomex ~/.local/bin/loomex"
                    .to_string(),
            uninstall_command: "rm ~/.local/bin/loomex; keep ~/.loomex".to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::WindowsMsi,
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            artifact_name: format!("Loomex-{version}-x64.msi"),
            install_command: "msiexec /i Loomex-x64.msi".to_string(),
            uninstall_command:
                "Apps & Features uninstall or msiexec /x; keep %USERPROFILE%\\.loomex".to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
        DistributionInstaller {
            kind: InstallerKind::WindowsExe,
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
            artifact_name: format!("Loomex-{version}-x64.exe"),
            install_command: "Start-Process .\\Loomex-x64.exe".to_string(),
            uninstall_command: "run Loomex uninstaller; keep %USERPROFILE%\\.loomex".to_string(),
            admin_required: false,
            preserves_user_data: true,
            channel: ReleaseChannel::Stable,
        },
    ]
}

pub fn official_compatibility_matrix(version: &str) -> ReleaseCompatibilityMatrix {
    ReleaseCompatibilityMatrix {
        schema_version: RELEASE_COMPATIBILITY_MATRIX_SCHEMA_VERSION.to_string(),
        entries: vec![CompatibilityMatrixEntry {
            cli_app_version: normalized_version(version),
            channel: ReleaseChannel::Stable,
            platform: "any".to_string(),
            arch: "multi".to_string(),
            runner_protocol_version: "1".to_string(),
            backend_minimum_version: "2026.06.29".to_string(),
            workflow_features: vec![
                "local_provider_mvp".to_string(),
                "managed_policy".to_string(),
                "signed_release_update".to_string(),
                "fleet_compliance_audit".to_string(),
            ],
        }],
    }
}

pub fn validate_compatibility_matrix(matrix: &ReleaseCompatibilityMatrix) -> CoreResult<()> {
    if matrix.schema_version != RELEASE_COMPATIBILITY_MATRIX_SCHEMA_VERSION {
        return Err(CoreError::new(
            "RELEASE_COMPATIBILITY_SCHEMA_INVALID",
            "compatibility matrix schema_version is not supported",
        ));
    }
    if matrix.entries.is_empty() {
        return Err(CoreError::new(
            "RELEASE_COMPATIBILITY_EMPTY",
            "compatibility matrix must include at least one entry",
        ));
    }
    let mut versions = BTreeSet::new();
    for entry in &matrix.entries {
        validate_version_field(
            &entry.cli_app_version,
            "RELEASE_COMPATIBILITY_VERSION_INVALID",
        )?;
        validate_compatibility_channel(&entry.channel)?;
        validate_compatibility_platform(&entry.platform)?;
        validate_compatibility_arch(&entry.arch)?;
        validate_version_field(
            &entry.backend_minimum_version,
            "RELEASE_BACKEND_VERSION_INVALID",
        )?;
        if entry.runner_protocol_version.trim().is_empty()
            || entry
                .workflow_features
                .iter()
                .any(|feature| feature.trim().is_empty())
        {
            return Err(CoreError::new(
                "RELEASE_COMPATIBILITY_ENTRY_INVALID",
                "protocol version and workflow features are required",
            ));
        }
        if !versions.insert(entry.cli_app_version.clone()) {
            return Err(CoreError::new(
                "RELEASE_COMPATIBILITY_DUPLICATE_VERSION",
                "compatibility matrix cannot contain duplicate CLI/app versions",
            ));
        }
    }
    Ok(())
}

fn validate_compatibility_channel(channel: &ReleaseChannel) -> CoreResult<()> {
    match channel {
        ReleaseChannel::Stable
        | ReleaseChannel::Beta
        | ReleaseChannel::NightlyInternal
        | ReleaseChannel::EnterprisePinned => Ok(()),
        ReleaseChannel::Dev => Err(CoreError::new(
            "RELEASE_COMPATIBILITY_CHANNEL_INVALID",
            "compatibility matrix channel must be stable, beta, nightly_internal, or enterprise_pinned",
        )),
    }
}

fn validate_compatibility_platform(platform: &str) -> CoreResult<()> {
    match platform.trim() {
        "macos" | "linux" | "windows" | "any" => Ok(()),
        _ => Err(CoreError::new(
            "RELEASE_COMPATIBILITY_PLATFORM_INVALID",
            "compatibility matrix platform must be macos, linux, windows, or any",
        )),
    }
}

fn validate_compatibility_arch(arch: &str) -> CoreResult<()> {
    match arch.trim() {
        "x86_64" | "aarch64" | "universal" | "multi" => Ok(()),
        _ => Err(CoreError::new(
            "RELEASE_COMPATIBILITY_ARCH_INVALID",
            "compatibility matrix arch must be x86_64, aarch64, universal, or multi",
        )),
    }
}

fn validate_release_channels(channels: &[ReleaseChannelPolicy]) -> CoreResult<()> {
    let required = BTreeSet::from([
        ReleaseChannel::Stable,
        ReleaseChannel::Beta,
        ReleaseChannel::NightlyInternal,
        ReleaseChannel::EnterprisePinned,
    ]);
    let observed = channels
        .iter()
        .map(|policy| policy.channel.clone())
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&observed) {
        return Err(CoreError::new(
            "RELEASE_CHANNELS_INCOMPLETE",
            "stable, beta, nightly/internal, and enterprise pinned channels are required",
        ));
    }
    for policy in channels {
        if policy.channel == ReleaseChannel::EnterprisePinned && policy.auto_update_allowed {
            return Err(CoreError::new(
                "RELEASE_ENTERPRISE_PINNED_AUTO_UPDATE_INVALID",
                "enterprise pinned channel must not auto-update",
            ));
        }
    }
    Ok(())
}

fn validate_distribution_installers(installers: &[DistributionInstaller]) -> CoreResult<()> {
    let required = BTreeSet::from([
        InstallerKind::HomebrewTap,
        InstallerKind::DirectBinary,
        InstallerKind::MacDmg,
        InstallerKind::MacPkg,
        InstallerKind::LinuxDeb,
        InstallerKind::LinuxRpm,
        InstallerKind::LinuxTar,
        InstallerKind::WindowsMsi,
        InstallerKind::WindowsExe,
    ]);
    let observed = installers
        .iter()
        .map(|installer| installer.kind.clone())
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&observed) {
        return Err(CoreError::new(
            "RELEASE_INSTALLERS_INCOMPLETE",
            "all official installer kinds must be present",
        ));
    }
    for installer in installers {
        if installer.artifact_name.trim().is_empty()
            || installer.install_command.trim().is_empty()
            || installer.uninstall_command.trim().is_empty()
        {
            return Err(CoreError::new(
                "RELEASE_INSTALLER_INVALID",
                "installer artifact and install/uninstall commands are required",
            ));
        }
        if !installer.preserves_user_data {
            return Err(CoreError::new(
                "RELEASE_UNINSTALL_DATA_LOSS_RISK",
                "official uninstall paths must preserve user config, logs, and audit data",
            ));
        }
    }
    Ok(())
}

fn validate_version_field(value: &str, code: &'static str) -> CoreResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
        || !trimmed.chars().any(|character| character.is_ascii_digit())
    {
        return Err(CoreError::new(code, "version field is invalid"));
    }
    Ok(())
}

fn normalized_version(version: &str) -> String {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_plan_covers_required_installers_and_channels() {
        let plan = official_release_distribution_plan("1.2.3");

        validate_release_distribution_plan(&plan).unwrap();
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::HomebrewTap
                && installer.install_command.contains("brew install")));
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::MacDmg));
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::MacPkg));
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::LinuxDeb));
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::LinuxRpm));
        assert!(plan
            .installers
            .iter()
            .any(|installer| installer.kind == InstallerKind::WindowsMsi));
        assert!(plan
            .channels
            .iter()
            .any(|policy| policy.channel == ReleaseChannel::EnterprisePinned
                && !policy.auto_update_allowed));
    }

    #[test]
    fn uninstall_paths_preserve_user_data() {
        let plan = official_release_distribution_plan("1.2.3");

        for installer in plan.installers {
            assert!(installer.preserves_user_data);
            assert!(!installer.uninstall_command.contains("rm -rf ~/.loomex"));
        }
    }

    #[test]
    fn compatibility_matrix_rejects_duplicate_or_incomplete_entries() {
        let mut matrix = official_compatibility_matrix("1.2.3");
        validate_compatibility_matrix(&matrix).unwrap();

        matrix.entries.push(matrix.entries[0].clone());
        let error = validate_compatibility_matrix(&matrix).unwrap_err();

        assert_eq!("RELEASE_COMPATIBILITY_DUPLICATE_VERSION", error.code);
    }

    #[test]
    fn compatibility_matrix_rejects_invalid_targeting_fields() {
        let mut matrix = official_compatibility_matrix("1.2.3");

        matrix.entries[0].channel = ReleaseChannel::Dev;
        let error = validate_compatibility_matrix(&matrix).unwrap_err();
        assert_eq!("RELEASE_COMPATIBILITY_CHANNEL_INVALID", error.code);

        matrix = official_compatibility_matrix("1.2.3");
        matrix.entries[0].platform = "beos".to_string();
        let error = validate_compatibility_matrix(&matrix).unwrap_err();
        assert_eq!("RELEASE_COMPATIBILITY_PLATFORM_INVALID", error.code);

        matrix = official_compatibility_matrix("1.2.3");
        matrix.entries[0].arch = "mips".to_string();
        let error = validate_compatibility_matrix(&matrix).unwrap_err();
        assert_eq!("RELEASE_COMPATIBILITY_ARCH_INVALID", error.code);
    }

    #[test]
    fn enterprise_pinned_channel_cannot_auto_update() {
        let mut plan = official_release_distribution_plan("1.2.3");
        let pinned = plan
            .channels
            .iter_mut()
            .find(|policy| policy.channel == ReleaseChannel::EnterprisePinned)
            .unwrap();
        pinned.auto_update_allowed = true;

        let error = validate_release_distribution_plan(&plan).unwrap_err();

        assert_eq!("RELEASE_ENTERPRISE_PINNED_AUTO_UPDATE_INVALID", error.code);
    }
}
