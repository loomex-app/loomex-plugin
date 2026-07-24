use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use reqwest::Url;

use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalSecurityPolicy {
    pub network: NetworkSecurityPolicy,
    pub sandbox: SandboxProfile,
    pub child_environment: ChildEnvironmentPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSecurityPolicy {
    pub allowed_domains: Vec<String>,
    pub denied_ip_ranges: Vec<IpNetworkRange>,
    pub allow_localhost: bool,
    pub allow_private_network: bool,
}

impl Default for NetworkSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_localhost: true,
            allow_private_network: true,
        }
    }
}

impl NetworkSecurityPolicy {
    pub fn enterprise_restricted(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains,
            denied_ip_ranges: Vec::new(),
            allow_localhost: false,
            allow_private_network: false,
        }
    }

    pub fn validate_url(&self, url: &Url) -> CoreResult<()> {
        let host = url
            .host_str()
            .ok_or_else(|| CoreError::new("NETWORK_HOST_MISSING", "network host is required"))?;
        if !self.allowed_domains.is_empty() && !domain_is_allowed(host, &self.allowed_domains) {
            return Err(CoreError::new(
                "NETWORK_DOMAIN_NOT_ALLOWED",
                "network destination is not in the egress allowlist",
            ));
        }
        for ip in resolve_url_ips(url)? {
            self.validate_ip(ip)?;
        }
        Ok(())
    }

    pub fn validate_ip(&self, ip: IpAddr) -> CoreResult<()> {
        if self.denied_ip_ranges.iter().any(|range| range.contains(ip)) {
            return Err(CoreError::new(
                "NETWORK_RANGE_DENIED",
                "network destination is denied by enterprise policy",
            ));
        }
        if is_loopback_ip(ip) && !self.allow_localhost {
            return Err(CoreError::new(
                "NETWORK_LOCALHOST_DENIED",
                "localhost network access is disabled by enterprise policy",
            ));
        }
        if is_private_network_ip(ip) && !self.allow_private_network {
            return Err(CoreError::new(
                "NETWORK_PRIVATE_DENIED",
                "private network access is disabled by enterprise policy",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNetworkRange {
    V4 { base: Ipv4Addr, prefix: u8 },
    V6 { base: Ipv6Addr, prefix: u8 },
}

impl IpNetworkRange {
    pub fn parse(value: &str) -> CoreResult<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            CoreError::new(
                "NETWORK_RANGE_INVALID",
                "network range must use CIDR notation",
            )
        })?;
        if let Ok(ip) = address.parse::<Ipv4Addr>() {
            let prefix = parse_prefix(prefix, 32)?;
            return Ok(Self::V4 { base: ip, prefix });
        }
        if let Ok(ip) = address.parse::<Ipv6Addr>() {
            let prefix = parse_prefix(prefix, 128)?;
            return Ok(Self::V6 { base: ip, prefix });
        }
        Err(CoreError::new(
            "NETWORK_RANGE_INVALID",
            "network range address is invalid",
        ))
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { base, prefix }, IpAddr::V4(ip)) => {
                let mask = prefix_mask_v4(*prefix);
                u32::from(*base) & mask == u32::from(ip) & mask
            }
            (Self::V6 { base, prefix }, IpAddr::V6(ip)) => {
                let mask = prefix_mask_v6(*prefix);
                u128::from(*base) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxProfile {
    pub denied_workspace_prefixes: Vec<String>,
}

impl SandboxProfile {
    pub fn new(denied_workspace_prefixes: Vec<String>) -> CoreResult<Self> {
        let mut prefixes = Vec::new();
        for prefix in denied_workspace_prefixes {
            prefixes.push(normalize_relative_workspace_path(&prefix)?);
        }
        Ok(Self {
            denied_workspace_prefixes: prefixes,
        })
    }

    pub fn validate_relative_path(&self, requested_path: &str) -> CoreResult<()> {
        let normalized = normalize_relative_workspace_path(requested_path)?;
        let requested_parts = path_parts(&normalized);
        for prefix in &self.denied_workspace_prefixes {
            let prefix_parts = path_parts(prefix);
            if requested_parts == prefix_parts
                || (requested_parts.len() > prefix_parts.len()
                    && requested_parts[..prefix_parts.len()] == prefix_parts)
            {
                return Err(CoreError::new(
                    "SANDBOX_PATH_DENIED",
                    "workspace path is denied by sandbox profile",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChildEnvironmentPolicy {
    pub allowed_secret_env_names: Vec<String>,
}

impl ChildEnvironmentPolicy {
    pub fn with_allowed_secret_env_names(allowed_secret_env_names: Vec<String>) -> Self {
        Self {
            allowed_secret_env_names,
        }
    }

    pub fn filter_env(
        &self,
        env: BTreeMap<String, String>,
        secret_env_names: &[String],
    ) -> BTreeMap<String, String> {
        env.into_iter()
            .filter(|(key, _)| {
                !is_secret_env_name(key, secret_env_names)
                    || self
                        .allowed_secret_env_names
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(key))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDevicePosture {
    pub runner_device_id: String,
    pub os: String,
    pub arch: String,
    pub runner_version: String,
    pub secure_storage: bool,
    pub sandbox_profile: Option<String>,
    pub network_policy_enforced: bool,
    pub collected_at_epoch_ms: u64,
}

impl RunnerDevicePosture {
    pub fn validate(&self) -> CoreResult<()> {
        for (field, value) in [
            ("runner_device_id", &self.runner_device_id),
            ("os", &self.os),
            ("arch", &self.arch),
            ("runner_version", &self.runner_version),
        ] {
            if value.trim().is_empty() {
                return Err(CoreError::new("DEVICE_POSTURE_INVALID", field));
            }
        }
        if self.collected_at_epoch_ms == 0 {
            return Err(CoreError::new(
                "DEVICE_POSTURE_INVALID",
                "collected_at_epoch_ms is required",
            ));
        }
        Ok(())
    }
}

pub fn is_secret_env_name(key: &str, secret_env_names: &[String]) -> bool {
    let normalized = normalize_env_name(key);
    if secret_env_names
        .iter()
        .any(|secret| normalized == normalize_env_name(secret))
    {
        return true;
    }
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.iter().any(|part| {
        matches!(
            *part,
            "TOKEN" | "SECRET" | "PASSWORD" | "AUTHORIZATION" | "COOKIE" | "CREDENTIAL"
        )
    }) || contains_pair(&parts, "API", "KEY")
        || contains_pair(&parts, "ACCESS", "KEY")
        || contains_pair(&parts, "PRIVATE", "KEY")
}

fn normalize_env_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn contains_pair(parts: &[&str], left: &str, right: &str) -> bool {
    parts.contains(&left) && parts.contains(&right)
}

fn resolve_url_ips(url: &Url) -> CoreResult<Vec<IpAddr>> {
    let host = url
        .host_str()
        .ok_or_else(|| CoreError::new("NETWORK_HOST_MISSING", "network host is required"))?;
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| CoreError::new("NETWORK_DNS_FAILED", error.to_string()))?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(CoreError::new(
            "NETWORK_DNS_FAILED",
            "network host did not resolve",
        ));
    }
    Ok(resolved)
}

fn domain_is_allowed(host: &str, allowed_domains: &[String]) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    allowed_domains.iter().any(|allowed| {
        let allowed = allowed.trim_start_matches('.').to_ascii_lowercase();
        let host = host.to_ascii_lowercase();
        host == allowed || host.ends_with(&format!(".{allowed}"))
    })
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn is_private_network_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_link_local()
                || ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 64
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00 || is_ipv6_link_local(ip),
    }
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn parse_prefix(value: &str, max: u8) -> CoreResult<u8> {
    let prefix = value.parse::<u8>().map_err(|_| {
        CoreError::new(
            "NETWORK_RANGE_INVALID",
            "network range prefix length is invalid",
        )
    })?;
    if prefix > max {
        return Err(CoreError::new(
            "NETWORK_RANGE_INVALID",
            "network range prefix length is out of bounds",
        ));
    }
    Ok(prefix)
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn normalize_relative_workspace_path(value: &str) -> CoreResult<String> {
    let value = value.replace('\\', "/");
    if value.trim().is_empty()
        || value.starts_with('/')
        || value.starts_with('~')
        || value.contains(':')
    {
        return Err(CoreError::new(
            "SANDBOX_PATH_INVALID",
            "sandbox path must be a relative workspace path",
        ));
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.trim() != part || part.chars().any(char::is_whitespace) {
            return Err(CoreError::new(
                "SANDBOX_PATH_INVALID",
                "sandbox path cannot contain traversal or ambiguous segments",
            ));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Ok(".".to_string());
    }
    Ok(parts.join("/"))
}

fn path_parts(value: &str) -> Vec<&str> {
    if value == "." {
        Vec::new()
    } else {
        value.split('/').collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_allowlist_accepts_exact_and_child_domains() {
        let policy = NetworkSecurityPolicy::enterprise_restricted(vec!["example.com".to_string()]);

        policy
            .validate_url(&Url::parse("https://www.example.com/health").unwrap())
            .unwrap();
    }

    #[test]
    fn network_allowlist_rejects_unlisted_domain() {
        let policy = NetworkSecurityPolicy::enterprise_restricted(vec!["example.com".to_string()]);

        let error = policy
            .validate_url(&Url::parse("https://example.org/health").unwrap())
            .unwrap_err();

        assert_eq!("NETWORK_DOMAIN_NOT_ALLOWED", error.code);
    }

    #[test]
    fn denied_network_range_blocks_destination() {
        let mut policy = NetworkSecurityPolicy::default();
        policy
            .denied_ip_ranges
            .push(IpNetworkRange::parse("203.0.113.0/24").unwrap());

        let error = policy
            .validate_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
            .unwrap_err();

        assert_eq!("NETWORK_RANGE_DENIED", error.code);
    }

    #[test]
    fn private_network_policy_blocks_private_and_localhost() {
        let policy = NetworkSecurityPolicy {
            allow_localhost: false,
            allow_private_network: false,
            ..NetworkSecurityPolicy::default()
        };

        assert_eq!(
            "NETWORK_PRIVATE_DENIED",
            policy
                .validate_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
                .unwrap_err()
                .code
        );
        assert_eq!(
            "NETWORK_LOCALHOST_DENIED",
            policy
                .validate_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn sandbox_denies_forbidden_workspace_path() {
        let sandbox = SandboxProfile::new(vec!["secrets".to_string()]).unwrap();

        let error = sandbox
            .validate_relative_path("secrets/token.txt")
            .unwrap_err();

        assert_eq!("SANDBOX_PATH_DENIED", error.code);
    }

    #[test]
    fn child_env_secrets_are_removed_unless_explicitly_allowed() {
        let mut env = BTreeMap::new();
        env.insert("API_KEY".to_string(), "hidden".to_string());
        env.insert("SAFE".to_string(), "visible".to_string());
        let secret_names = vec!["API_KEY".to_string()];

        let filtered = ChildEnvironmentPolicy::default().filter_env(env.clone(), &secret_names);
        let allowed =
            ChildEnvironmentPolicy::with_allowed_secret_env_names(vec!["API_KEY".to_string()])
                .filter_env(env, &secret_names);

        assert!(!filtered.contains_key("API_KEY"));
        assert_eq!("visible", filtered["SAFE"]);
        assert_eq!("hidden", allowed["API_KEY"]);
    }

    #[test]
    fn child_env_filters_common_secret_like_names() {
        let mut env = BTreeMap::new();
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "DATABASE_PASSWORD",
            "OPENAI_API_KEY",
            "API_TOKEN",
        ] {
            env.insert(name.to_string(), "hidden".to_string());
        }
        env.insert("VISIBLE_CONFIG".to_string(), "ok".to_string());

        let filtered = ChildEnvironmentPolicy::default().filter_env(env, &[]);

        assert_eq!(
            vec!["VISIBLE_CONFIG".to_string()],
            filtered.keys().cloned().collect::<Vec<_>>()
        );
    }

    #[test]
    fn device_posture_requires_identity_fields() {
        let posture = RunnerDevicePosture {
            runner_device_id: "device_123".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            runner_version: "1.0.0".to_string(),
            secure_storage: true,
            sandbox_profile: Some("macos-hardened-runtime".to_string()),
            network_policy_enforced: true,
            collected_at_epoch_ms: 1_000,
        };

        posture.validate().unwrap();
    }
}
