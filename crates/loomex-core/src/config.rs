use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{CoreError, CoreResult};

pub const CONFIG_DIR_NAME: &str = ".loomex";
pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const LEGACY_CONFIG_DIR_NAME: &str = ".loomex-runner";
pub const CLI_CONFIG_VERSION: u32 = 2;
pub const DEFAULT_PROFILE_NAME: &str = "default";
pub const DEFAULT_SERVER_URL: &str = "https://loomex.app";
pub const STAGE_SERVER_URL: &str = "https://stage.loomex.app";
pub const LOCAL_SERVER_URL: &str = "http://127.0.0.1:28000";
const LEGACY_LOCAL_SERVER_URL: &str = "http://127.0.0.1:28080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerConfig {
    pub organization_id: String,
    pub project_id: String,
    pub runner_id: String,
    pub runner_device_id: String,
    pub binding_id: String,
    pub local_root_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliConfig {
    pub config_version: u32,
    pub selected_profile: String,
    pub profiles: BTreeMap<String, CliProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliProfile {
    pub server_url: String,
    pub host_header: Option<String>,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub runner_id: Option<String>,
    pub binding_id: Option<String>,
    pub workspace_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CliConfigOverrides {
    pub profile: Option<String>,
    pub server_url: Option<String>,
    pub host_header: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCliSettings {
    pub profile: String,
    pub server_url: String,
    pub host_header: Option<String>,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub runner_id: Option<String>,
    pub binding_id: Option<String>,
    pub workspace_path: Option<String>,
}

pub fn default_config_path(home_dir: &Path) -> PathBuf {
    home_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME)
}

pub fn legacy_config_path(home_dir: &Path) -> PathBuf {
    home_dir.join(LEGACY_CONFIG_DIR_NAME).join(CONFIG_FILE_NAME)
}

impl RunnerConfig {
    pub fn load(path: &Path) -> CoreResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|err| CoreError::new("CONFIG_READ_FAILED", err.to_string()))?;
        Self::parse(&content)
    }

    pub fn save(&self, path: &Path) -> CoreResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| CoreError::new("CONFIG_DIR_CREATE_FAILED", err.to_string()))?;
        }
        let temp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("toml")
        ));
        fs::write(&temp_path, self.to_document())
            .map_err(|err| CoreError::new("CONFIG_WRITE_FAILED", err.to_string()))?;
        fs::rename(&temp_path, path)
            .map_err(|err| CoreError::new("CONFIG_WRITE_FAILED", err.to_string()))
    }

    pub fn parse(content: &str) -> CoreResult<Self> {
        let mut values = BTreeMap::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(CoreError::new(
                    "CONFIG_PARSE_FAILED",
                    "expected key = \"value\"",
                ));
            };
            values.insert(key.trim().to_string(), unquote(value.trim())?);
        }

        Ok(Self {
            organization_id: take_required(&mut values, "organization_id")?,
            project_id: take_required(&mut values, "project_id")?,
            runner_id: take_required(&mut values, "runner_id")?,
            runner_device_id: take_required(&mut values, "runner_device_id")?,
            binding_id: take_required(&mut values, "binding_id")?,
            local_root_path: take_required(&mut values, "local_root_path")?,
        })
    }

    pub fn parse_legacy(content: &str, runner_device_id: String) -> CoreResult<Self> {
        let mut config = Self::parse_legacy_without_device(content)?;
        if runner_device_id.trim().is_empty() {
            return Err(CoreError::new("CONFIG_MISSING_FIELD", "runner_device_id"));
        }
        config.runner_device_id = runner_device_id;
        Ok(config)
    }

    pub fn migrate_from_legacy(
        legacy_path: &Path,
        target_path: &Path,
        runner_device_id: String,
    ) -> CoreResult<Option<Self>> {
        if target_path.exists() {
            return Ok(None);
        }
        if !legacy_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(legacy_path)
            .map_err(|err| CoreError::new("CONFIG_READ_FAILED", err.to_string()))?;
        let config = Self::parse_legacy(&content, runner_device_id)?;
        config.save(target_path)?;
        Ok(Some(config))
    }

    pub fn to_document(&self) -> String {
        [
            toml_line("organization_id", &self.organization_id),
            toml_line("project_id", &self.project_id),
            toml_line("runner_id", &self.runner_id),
            toml_line("runner_device_id", &self.runner_device_id),
            toml_line("binding_id", &self.binding_id),
            toml_line("local_root_path", &self.local_root_path),
        ]
        .join("")
    }

    fn parse_legacy_without_device(content: &str) -> CoreResult<Self> {
        let mut values = BTreeMap::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(CoreError::new(
                    "CONFIG_PARSE_FAILED",
                    "expected key = \"value\"",
                ));
            };
            values.insert(key.trim().to_string(), unquote(value.trim())?);
        }

        Ok(Self {
            organization_id: take_required(&mut values, "organization_id")?,
            project_id: take_required(&mut values, "project_id")?,
            runner_id: take_required(&mut values, "runner_id")?,
            runner_device_id: String::new(),
            binding_id: take_required(&mut values, "binding_id")?,
            local_root_path: take_required(&mut values, "local_root_path")?,
        })
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(DEFAULT_PROFILE_NAME.to_string(), CliProfile::default_prod());
        profiles.insert("prod".to_string(), CliProfile::default_prod());
        profiles.insert("stage".to_string(), CliProfile::stage());
        profiles.insert("local".to_string(), CliProfile::local());
        Self {
            config_version: CLI_CONFIG_VERSION,
            selected_profile: DEFAULT_PROFILE_NAME.to_string(),
            profiles,
        }
    }
}

impl CliConfig {
    pub fn load_or_default(path: &Path) -> CoreResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .map_err(|err| CoreError::new("CONFIG_READ_FAILED", err.to_string()))?;
        if content.trim().is_empty() {
            return Ok(Self::default());
        }
        Self::parse(&content)
    }

    pub fn save(&self, path: &Path) -> CoreResult<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| CoreError::new("CONFIG_DIR_CREATE_FAILED", err.to_string()))?;
        }
        let temp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("toml")
        ));
        fs::write(&temp_path, self.to_document())
            .map_err(|err| CoreError::new("CONFIG_WRITE_FAILED", err.to_string()))?;
        fs::rename(&temp_path, path)
            .map_err(|err| CoreError::new("CONFIG_WRITE_FAILED", err.to_string()))
    }

    pub fn parse(content: &str) -> CoreResult<Self> {
        let mut config = Self::default();
        let mut current_profile: Option<String> = None;
        let mut saw_config_version = false;
        let mut saw_profile = false;

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                current_profile = Some(parse_profile_header(line)?);
                saw_profile = true;
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(CoreError::new(
                    "CONFIG_PARSE_FAILED",
                    "expected key = \"value\"",
                ));
            };
            let key = key.trim();
            let value = value.trim();
            if let Some(profile_name) = &current_profile {
                let parsed = unquote(value)?;
                config.set_profile_key(profile_name, key, parsed)?;
                continue;
            }
            match key {
                "configVersion" | "config_version" => {
                    saw_config_version = true;
                    config.config_version = value.parse::<u32>().map_err(|_| {
                        CoreError::new("CONFIG_PARSE_FAILED", "configVersion must be an integer")
                    })?;
                }
                "selectedProfile" | "defaultProfile" | "selected_profile" => {
                    config.selected_profile = unquote(value)?;
                }
                _ => {
                    return Err(CoreError::new(
                        "CONFIG_PARSE_FAILED",
                        format!("unknown root config key: {key}"),
                    ));
                }
            }
        }

        let source_config_version = if saw_config_version {
            config.config_version
        } else {
            1
        };
        if source_config_version > 0 && source_config_version < CLI_CONFIG_VERSION {
            config.migrate_from_version(source_config_version);
        }
        if !saw_profile && !content.trim().is_empty() {
            return Err(CoreError::new(
                "CONFIG_PARSE_FAILED",
                "config must contain at least one profile section",
            ));
        }
        config.validate()?;
        Ok(config)
    }

    fn migrate_from_version(&mut self, source_version: u32) {
        if source_version < 2 {
            if let Some(local_profile) = self.profiles.get_mut("local") {
                if local_profile.server_url == LEGACY_LOCAL_SERVER_URL {
                    local_profile.server_url = LOCAL_SERVER_URL.to_string();
                }
            }
        }
        self.config_version = CLI_CONFIG_VERSION;
    }

    pub fn to_document(&self) -> String {
        let mut document = String::new();
        document.push_str(&format!("configVersion = {}\n", self.config_version));
        document.push_str(&toml_line("selectedProfile", &self.selected_profile));
        for (name, profile) in &self.profiles {
            document.push('\n');
            document.push_str(&format!("[profiles.\"{}\"]\n", escape_toml_string(name)));
            document.push_str(&toml_line("serverUrl", &profile.server_url));
            if let Some(host_header) = &profile.host_header {
                document.push_str(&toml_line("hostHeader", host_header));
            }
            if let Some(organization_id) = &profile.organization_id {
                document.push_str(&toml_line("organizationId", organization_id));
            }
            if let Some(project_id) = &profile.project_id {
                document.push_str(&toml_line("projectId", project_id));
            }
            if let Some(runner_id) = &profile.runner_id {
                document.push_str(&toml_line("runnerId", runner_id));
            }
            if let Some(binding_id) = &profile.binding_id {
                document.push_str(&toml_line("bindingId", binding_id));
            }
            if let Some(workspace_path) = &profile.workspace_path {
                document.push_str(&toml_line("workspacePath", workspace_path));
            }
        }
        document
    }

    pub fn resolve<F>(
        &self,
        overrides: CliConfigOverrides,
        read_env: F,
    ) -> CoreResult<ResolvedCliSettings>
    where
        F: Fn(&str) -> Option<String>,
    {
        let profile = first_non_empty([
            overrides.profile,
            read_env("LOOMEX_PROFILE"),
            Some(self.selected_profile.clone()),
        ])
        .unwrap_or_else(|| DEFAULT_PROFILE_NAME.to_string());
        let base = self.profiles.get(&profile).cloned().ok_or_else(|| {
            CoreError::new(
                "PROFILE_NOT_FOUND",
                format!("profile {profile} does not exist"),
            )
        })?;
        let server_url = first_non_empty([
            overrides.server_url,
            read_env("LOOMEX_SERVER_URL"),
            Some(base.server_url.clone()),
        ])
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());
        let host_header = first_non_empty([
            overrides.host_header,
            read_env("LOOMEX_HOST_HEADER"),
            base.host_header.clone(),
        ]);
        validate_server_url(&server_url)?;
        validate_host_header(&profile, host_header.as_deref())?;
        Ok(ResolvedCliSettings {
            profile,
            server_url,
            host_header,
            organization_id: base.organization_id,
            project_id: base.project_id,
            runner_id: base.runner_id,
            binding_id: base.binding_id,
            workspace_path: base.workspace_path,
        })
    }

    pub fn get_key(&self, key: &str) -> CoreResult<Option<String>> {
        if key == "configVersion" {
            return Ok(Some(self.config_version.to_string()));
        }
        if key == "selectedProfile" {
            return Ok(Some(self.selected_profile.clone()));
        }
        let Some((profile_name, profile_key)) = parse_profile_key(key) else {
            return Ok(None);
        };
        let Some(profile) = self.profiles.get(profile_name) else {
            return Ok(None);
        };
        Ok(match profile_key {
            "serverUrl" => Some(profile.server_url.clone()),
            "hostHeader" => profile.host_header.clone(),
            "organizationId" => profile.organization_id.clone(),
            "projectId" => profile.project_id.clone(),
            "runnerId" => profile.runner_id.clone(),
            "bindingId" => profile.binding_id.clone(),
            "workspacePath" => profile.workspace_path.clone(),
            _ => None,
        })
    }

    pub fn set_key(&mut self, key: &str, value: String) -> CoreResult<()> {
        if key == "selectedProfile" {
            if value.trim().is_empty() {
                return Err(CoreError::new(
                    "CONFIG_VALUE_INVALID",
                    "selectedProfile cannot be empty",
                ));
            }
            self.selected_profile = value;
            return self.validate();
        }
        let Some((profile_name, profile_key)) = parse_profile_key(key) else {
            return Err(CoreError::new("CONFIG_KEY_UNSUPPORTED", key));
        };
        self.set_profile_key(profile_name, profile_key, value)?;
        self.validate()
    }

    pub fn list_entries(&self) -> Vec<(String, String)> {
        let mut entries = vec![
            ("configVersion".to_string(), self.config_version.to_string()),
            ("selectedProfile".to_string(), self.selected_profile.clone()),
        ];
        for (name, profile) in &self.profiles {
            entries.push((
                format!("profiles.{name}.serverUrl"),
                profile.server_url.clone(),
            ));
            if let Some(host_header) = &profile.host_header {
                entries.push((format!("profiles.{name}.hostHeader"), host_header.clone()));
            }
            if let Some(organization_id) = &profile.organization_id {
                entries.push((
                    format!("profiles.{name}.organizationId"),
                    organization_id.clone(),
                ));
            }
            if let Some(project_id) = &profile.project_id {
                entries.push((format!("profiles.{name}.projectId"), project_id.clone()));
            }
            if let Some(runner_id) = &profile.runner_id {
                entries.push((format!("profiles.{name}.runnerId"), runner_id.clone()));
            }
            if let Some(binding_id) = &profile.binding_id {
                entries.push((format!("profiles.{name}.bindingId"), binding_id.clone()));
            }
            if let Some(workspace_path) = &profile.workspace_path {
                entries.push((
                    format!("profiles.{name}.workspacePath"),
                    workspace_path.clone(),
                ));
            }
        }
        entries
    }

    fn set_profile_key(&mut self, profile_name: &str, key: &str, value: String) -> CoreResult<()> {
        let profile = self
            .profiles
            .entry(profile_name.to_string())
            .or_insert_with(CliProfile::default_prod);
        match key {
            "serverUrl" | "server_url" | "server" => profile.server_url = value,
            "hostHeader" | "host_header" => profile.host_header = optional_value(value),
            "organizationId" | "organization_id" => profile.organization_id = optional_value(value),
            "projectId" | "project_id" => profile.project_id = optional_value(value),
            "runnerId" | "runner_id" => profile.runner_id = optional_value(value),
            "bindingId" | "binding_id" => profile.binding_id = optional_value(value),
            "workspacePath" | "workspace_path" => profile.workspace_path = optional_value(value),
            _ => return Err(CoreError::new("CONFIG_KEY_UNSUPPORTED", key)),
        }
        validate_server_url(&profile.server_url)?;
        validate_host_header(profile_name, profile.host_header.as_deref())
    }

    fn validate(&self) -> CoreResult<()> {
        if self.config_version == 0 {
            return Err(CoreError::new(
                "CONFIG_VERSION_UNSUPPORTED",
                "configVersion must be positive",
            ));
        }
        if self.selected_profile.trim().is_empty() {
            return Err(CoreError::new(
                "CONFIG_VALUE_INVALID",
                "selectedProfile cannot be empty",
            ));
        }
        for (name, profile) in &self.profiles {
            validate_server_url(&profile.server_url)?;
            validate_host_header(name, profile.host_header.as_deref())?;
        }
        Ok(())
    }
}

impl CliProfile {
    pub fn default_prod() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            host_header: None,
            organization_id: None,
            project_id: None,
            runner_id: None,
            binding_id: None,
            workspace_path: None,
        }
    }

    pub fn stage() -> Self {
        Self {
            server_url: STAGE_SERVER_URL.to_string(),
            host_header: None,
            organization_id: None,
            project_id: None,
            runner_id: None,
            binding_id: None,
            workspace_path: None,
        }
    }

    pub fn local() -> Self {
        Self {
            server_url: LOCAL_SERVER_URL.to_string(),
            host_header: Some("loomex.localhost".to_string()),
            organization_id: None,
            project_id: None,
            runner_id: None,
            binding_id: None,
            workspace_path: None,
        }
    }
}

fn take_required(values: &mut BTreeMap<String, String>, key: &'static str) -> CoreResult<String> {
    values
        .remove(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CoreError::new("CONFIG_MISSING_FIELD", key))
}

fn parse_profile_header(line: &str) -> CoreResult<String> {
    let Some(inner) = line
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(CoreError::new(
            "CONFIG_PARSE_FAILED",
            "invalid section header",
        ));
    };
    let Some(profile) = inner
        .strip_prefix("profiles.\"")
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(CoreError::new(
            "CONFIG_PARSE_FAILED",
            "expected [profiles.\"name\"] section",
        ));
    };
    if profile.trim().is_empty() {
        return Err(CoreError::new(
            "CONFIG_PARSE_FAILED",
            "profile name cannot be empty",
        ));
    }
    Ok(profile.replace("\\\"", "\""))
}

fn parse_profile_key(key: &str) -> Option<(&str, &str)> {
    let mut parts = key.split('.');
    if parts.next()? != "profiles" {
        return None;
    }
    let profile = parts.next()?;
    let profile_key = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((profile, profile_key))
}

fn first_non_empty(values: [Option<String>; 3]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn optional_value(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn validate_server_url(value: &str) -> CoreResult<()> {
    let trimmed = value.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err(CoreError::new(
            "CONFIG_SERVER_URL_INVALID",
            "server URL must include http:// or https://",
        ));
    }
    Ok(())
}

fn validate_host_header(profile_name: &str, host_header: Option<&str>) -> CoreResult<()> {
    if host_header
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Ok(());
    }
    if matches!(profile_name, "local" | "dev") {
        return Ok(());
    }
    Err(CoreError::new(
        "CONFIG_HOST_HEADER_NOT_ALLOWED",
        "hostHeader is only allowed for local/dev profiles",
    ))
}

fn unquote(value: &str) -> CoreResult<String> {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(CoreError::new(
            "CONFIG_PARSE_FAILED",
            "expected quoted string",
        ));
    }
    Ok(value[1..value.len() - 1].replace("\\\"", "\""))
}

fn toml_line(key: &str, value: &str) -> String {
    format!("{key} = \"{}\"\n", escape_toml_string(value))
}

fn escape_toml_string(value: &str) -> String {
    value.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn sample_config() -> RunnerConfig {
        RunnerConfig {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            runner_id: "runner_123".to_string(),
            runner_device_id: "device_123".to_string(),
            binding_id: "bind_123".to_string(),
            local_root_path: "/Users/example/My App".to_string(),
        }
    }

    #[test]
    fn config_load_save_round_trip() {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("loomex-config-{id}.toml"));
        let config = sample_config();

        config.save(&path).unwrap();
        let loaded = RunnerConfig::load(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(config, loaded);
    }

    #[test]
    fn corrupt_config_returns_parse_error() {
        let err = RunnerConfig::parse("organization_id = org_123").unwrap_err();
        assert_eq!("CONFIG_PARSE_FAILED", err.code);
    }

    #[test]
    fn default_config_path_uses_final_location() {
        let home = Path::new("/Users/example");
        assert_eq!(
            PathBuf::from("/Users/example/.loomex/config.toml"),
            default_config_path(home)
        );
    }

    #[test]
    fn migration_from_old_path_writes_new_config_with_device_id() {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("loomex-config-migration-{id}"));
        let legacy = root.join(".loomex-runner").join("config.toml");
        let target = root.join(".loomex").join("config.toml");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(
            &legacy,
            [
                "organization_id = \"org_123\"\n",
                "project_id = \"prj_123\"\n",
                "runner_id = \"runner_123\"\n",
                "binding_id = \"bind_123\"\n",
                "local_root_path = \"/Users/example/My App\"\n",
            ]
            .join(""),
        )
        .unwrap();

        let migrated =
            RunnerConfig::migrate_from_legacy(&legacy, &target, "device_123".to_string())
                .unwrap()
                .unwrap();

        assert_eq!("device_123", migrated.runner_device_id);
        assert_eq!(migrated, RunnerConfig::load(&target).unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cli_config_loads_missing_and_empty_as_default_profiles() {
        let config = CliConfig::parse("").unwrap();

        assert_eq!(CLI_CONFIG_VERSION, config.config_version);
        assert_eq!(DEFAULT_PROFILE_NAME, config.selected_profile);
        assert_eq!(DEFAULT_SERVER_URL, config.profiles["default"].server_url);
        assert_eq!(STAGE_SERVER_URL, config.profiles["stage"].server_url);
        assert_eq!(LOCAL_SERVER_URL, config.profiles["local"].server_url);
    }

    #[test]
    fn local_profile_targets_the_direct_local_backend_port() {
        let config = CliConfig::default();
        let resolved = config
            .resolve(
                CliConfigOverrides {
                    profile: Some("local".to_string()),
                    ..CliConfigOverrides::default()
                },
                |_| None,
            )
            .unwrap();

        assert_eq!("http://127.0.0.1:28000", resolved.server_url);
        assert_eq!(Some("loomex.localhost"), resolved.host_header.as_deref());
    }

    #[test]
    fn persisted_v1_local_default_migrates_to_the_direct_backend_port() {
        let path = std::env::temp_dir().join(format!(
            "loomex-cli-v1-local-port-migration-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(
            &path,
            r#"configVersion = 1
selectedProfile = "local"

[profiles."local"]
serverUrl = "http://127.0.0.1:28080"
hostHeader = "loomex.localhost"
"#,
        )
        .unwrap();

        let config = CliConfig::load_or_default(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(CLI_CONFIG_VERSION, config.config_version);
        assert_eq!(LOCAL_SERVER_URL, config.profiles["local"].server_url);
        assert_eq!(
            Some("loomex.localhost"),
            config.profiles["local"].host_header.as_deref()
        );
    }

    #[test]
    fn v1_migration_preserves_custom_local_and_non_local_urls() {
        let config = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "local"

[profiles."local"]
serverUrl = "http://localhost:28080"

[profiles."dev"]
serverUrl = "http://127.0.0.1:28080"
"#,
        )
        .unwrap();

        assert_eq!(CLI_CONFIG_VERSION, config.config_version);
        assert_eq!(
            "http://localhost:28080",
            config.profiles["local"].server_url
        );
        assert_eq!("http://127.0.0.1:28080", config.profiles["dev"].server_url);
    }

    #[test]
    fn v2_config_preserves_explicit_legacy_router_url() {
        let config = CliConfig::parse(
            r#"configVersion = 2
selectedProfile = "local"

[profiles."local"]
serverUrl = "http://127.0.0.1:28080"
hostHeader = "loomex.localhost"
"#,
        )
        .unwrap();

        assert_eq!(
            "http://127.0.0.1:28080",
            config.profiles["local"].server_url
        );
    }

    #[test]
    fn readme_default_profile_matches_canonical_server_url() {
        let readme = include_str!("../../../README.md");
        let expected = format!("serverUrl = \"{DEFAULT_SERVER_URL}\"");

        assert!(
            readme.contains(&expected),
            "README default profile must document {expected}"
        );
    }

    #[test]
    fn cli_config_round_trip_profile_shape() {
        let document = [
            "configVersion = 1\n",
            "selectedProfile = \"local\"\n",
            "\n",
            "[profiles.\"local\"]\n",
            "serverUrl = \"http://127.0.0.1:28000\"\n",
            "hostHeader = \"loomex.localhost\"\n",
            "organizationId = \"org_123\"\n",
            "projectId = \"prj_123\"\n",
        ]
        .join("");

        let config = CliConfig::parse(&document).unwrap();

        assert_eq!("local", config.selected_profile);
        assert_eq!(
            "org_123",
            config.profiles["local"].organization_id.as_deref().unwrap()
        );
        assert_eq!(config, CliConfig::parse(&config.to_document()).unwrap());
    }

    #[test]
    fn cli_config_supports_custom_profile_without_host_header() {
        let config = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "sandbox"

[profiles."sandbox"]
serverUrl = "https://sandbox.example.com"
"#,
        )
        .unwrap();

        assert_eq!(
            "https://sandbox.example.com",
            config.profiles["sandbox"].server_url
        );
    }

    #[test]
    fn cli_config_rejects_invalid_toml_with_clear_error() {
        let err = CliConfig::parse("configVersion = nope").unwrap_err();

        assert_eq!("CONFIG_PARSE_FAILED", err.code);
        assert!(err.message.contains("configVersion"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_config_rejects_unreadable_file_with_clear_error() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "loomex-cli-unreadable-config-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, "configVersion = 1\nselectedProfile = \"default\"\n").unwrap();
        let original_permissions = fs::metadata(&path).unwrap().permissions();
        let mut unreadable_permissions = original_permissions.clone();
        unreadable_permissions.set_mode(0o000);
        fs::set_permissions(&path, unreadable_permissions).unwrap();

        let err = CliConfig::load_or_default(&path).unwrap_err();

        fs::set_permissions(&path, original_permissions).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!("CONFIG_READ_FAILED", err.code);
    }

    #[test]
    fn cli_config_rejects_server_without_scheme() {
        let err = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "default"

[profiles."default"]
serverUrl = "loomex.app"
"#,
        )
        .unwrap_err();

        assert_eq!("CONFIG_SERVER_URL_INVALID", err.code);
    }

    #[test]
    fn cli_config_rejects_host_header_outside_local_or_dev_profiles() {
        let err = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "prod"

[profiles."prod"]
serverUrl = "https://loomex.app"
hostHeader = "loomex.localhost"
"#,
        )
        .unwrap_err();

        assert_eq!("CONFIG_HOST_HEADER_NOT_ALLOWED", err.code);
    }

    #[test]
    fn cli_config_precedence_is_flag_then_env_then_config_then_default() {
        let config = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "stage"

[profiles."stage"]
serverUrl = "https://stage-config.example.com"
"#,
        )
        .unwrap();

        let resolved = config
            .resolve(
                CliConfigOverrides {
                    profile: None,
                    server_url: None,
                    host_header: None,
                },
                |key| match key {
                    "LOOMEX_PROFILE" => Some("stage".to_string()),
                    "LOOMEX_SERVER_URL" => Some("https://stage-env.example.com".to_string()),
                    _ => None,
                },
            )
            .unwrap();
        assert_eq!("https://stage-env.example.com", resolved.server_url);

        let resolved = config
            .resolve(
                CliConfigOverrides {
                    profile: Some("default".to_string()),
                    server_url: Some("https://flag.example.com".to_string()),
                    host_header: None,
                },
                |_| None,
            )
            .unwrap();
        assert_eq!("default", resolved.profile);
        assert_eq!("https://flag.example.com", resolved.server_url);
    }

    #[test]
    fn cli_config_resolve_rejects_unknown_profile_without_defaulting() {
        let config = CliConfig::parse(
            r#"configVersion = 1
selectedProfile = "ghost"

[profiles."default"]
serverUrl = "https://loomex.app"
"#,
        )
        .unwrap();

        let err = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap_err();

        assert_eq!("PROFILE_NOT_FOUND", err.code);
        assert!(err.message.contains("ghost"));
    }

    #[test]
    fn cli_config_migrates_legacy_default_profile_key_to_versioned_document() {
        let config = CliConfig::parse(
            r#"defaultProfile = "local"

[profiles."local"]
serverUrl = "http://127.0.0.1:28000"
hostHeader = "loomex.localhost"
"#,
        )
        .unwrap();

        assert_eq!(CLI_CONFIG_VERSION, config.config_version);
        assert!(config.to_document().starts_with("configVersion = 2\n"));
    }

    #[test]
    fn cli_config_get_set_list_profile_keys() {
        let mut config = CliConfig::default();

        config
            .set_key(
                "profiles.dev.serverUrl",
                "http://127.0.0.1:28000".to_string(),
            )
            .unwrap();
        config
            .set_key("profiles.dev.hostHeader", "loomex.localhost".to_string())
            .unwrap();
        config
            .set_key("selectedProfile", "dev".to_string())
            .unwrap();

        assert_eq!(
            Some("loomex.localhost".to_string()),
            config.get_key("profiles.dev.hostHeader").unwrap()
        );
        assert!(config.list_entries().contains(&(
            "profiles.dev.serverUrl".to_string(),
            "http://127.0.0.1:28000".to_string()
        )));
    }
}
