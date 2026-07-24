use std::path::{Path, PathBuf};

use crate::{CoreError, CoreResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerServicePlatform {
    MacOsLaunchAgent,
    LinuxUserSystemd,
    LinuxSystemSystemd,
}

impl RunnerServicePlatform {
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "macos" | "macos-launch-agent" | "launch-agent" | "launchd-user" => {
                Ok(Self::MacOsLaunchAgent)
            }
            "linux-user" | "systemd-user" => Ok(Self::LinuxUserSystemd),
            "linux-system" | "systemd-system" => Ok(Self::LinuxSystemSystemd),
            "windows" | "windows-service" => Err(CoreError::new(
                "RUNNER_SERVICE_PLATFORM_UNSUPPORTED",
                "Windows local-control support is unavailable until the named-pipe server is implemented",
            )),
            _ => Err(CoreError::new(
                "RUNNER_SERVICE_PLATFORM_UNSUPPORTED",
                format!("unsupported service platform {value}"),
            )),
        }
    }

    pub fn current() -> CoreResult<Self> {
        #[cfg(windows)]
        {
            return Err(CoreError::new(
                "RUNNER_SERVICE_PLATFORM_UNSUPPORTED",
                "Windows local-control support is unavailable until the named-pipe server is implemented",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Self::MacOsLaunchAgent)
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            Ok(Self::LinuxUserSystemd)
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacOsLaunchAgent => "macos",
            Self::LinuxUserSystemd => "linux-user",
            Self::LinuxSystemSystemd => "linux-system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerServiceSpec {
    pub service_name: String,
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub profile: Option<String>,
    pub log_path: Option<PathBuf>,
    pub working_directory: Option<PathBuf>,
}

impl RunnerServiceSpec {
    pub fn validate(&self) -> CoreResult<()> {
        validate_service_name(&self.service_name)?;
        validate_absolute_path(&self.binary_path, "RUNNER_SERVICE_BINARY_INVALID")?;
        validate_absolute_path(&self.config_path, "RUNNER_SERVICE_CONFIG_INVALID")?;
        if let Some(path) = &self.log_path {
            validate_absolute_path(path, "RUNNER_SERVICE_LOG_PATH_INVALID")?;
        }
        if let Some(path) = &self.working_directory {
            validate_absolute_path(path, "RUNNER_SERVICE_WORKDIR_INVALID")?;
        }
        if self
            .profile
            .as_ref()
            .is_some_and(|profile| profile.trim().is_empty())
        {
            return Err(CoreError::new(
                "RUNNER_SERVICE_PROFILE_INVALID",
                "profile cannot be empty",
            ));
        }
        Ok(())
    }

    pub fn render(&self, platform: RunnerServicePlatform) -> CoreResult<RunnerServiceManifest> {
        self.validate()?;
        match platform {
            RunnerServicePlatform::MacOsLaunchAgent => Ok(RunnerServiceManifest::launch_agent(
                &self.service_name,
                render_launch_agent(self)?,
            )),
            RunnerServicePlatform::LinuxUserSystemd => Ok(RunnerServiceManifest::systemd_user(
                render_systemd_unit(self, "default.target"),
            )),
            RunnerServicePlatform::LinuxSystemSystemd => Ok(RunnerServiceManifest::systemd_system(
                render_systemd_unit(self, "multi-user.target"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerServiceManifest {
    pub platform: RunnerServicePlatform,
    pub install_path: String,
    pub uninstall_path: Option<String>,
    pub content: String,
    pub uninstall_content: Option<String>,
}

impl RunnerServiceManifest {
    fn launch_agent(service_name: &str, content: String) -> Self {
        Self {
            platform: RunnerServicePlatform::MacOsLaunchAgent,
            install_path: format!("~/Library/LaunchAgents/{service_name}.plist"),
            uninstall_path: None,
            content,
            uninstall_content: None,
        }
    }

    fn systemd_user(content: String) -> Self {
        Self {
            platform: RunnerServicePlatform::LinuxUserSystemd,
            install_path: "~/.config/systemd/user/loomex-runner.service".to_string(),
            uninstall_path: None,
            content,
            uninstall_content: None,
        }
    }

    fn systemd_system(content: String) -> Self {
        Self {
            platform: RunnerServicePlatform::LinuxSystemSystemd,
            install_path: "/etc/systemd/system/loomex-runner.service".to_string(),
            uninstall_path: None,
            content,
            uninstall_content: None,
        }
    }
}

pub fn validate_cross_platform_relative_path(path: &str) -> CoreResult<()> {
    if path.trim().is_empty() || path.contains('\0') || path.contains('\n') || path.contains('\r') {
        return Err(CoreError::new(
            "WORKSPACE_PATH_INVALID",
            "workspace path is invalid",
        ));
    }
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("//") || looks_like_windows_drive_path(path) {
        return Err(CoreError::new(
            "WORKSPACE_PATH_ESCAPE",
            "workspace path escapes the binding root",
        ));
    }
    if normalized.starts_with('/') {
        return Err(CoreError::new(
            "WORKSPACE_PATH_ABSOLUTE",
            "workspace path must be relative",
        ));
    }
    if normalized.contains("/../")
        || normalized == ".."
        || normalized.starts_with("../")
        || normalized.ends_with("/..")
    {
        return Err(CoreError::new(
            "WORKSPACE_PATH_OUTSIDE_ROOT",
            "workspace path escapes the binding root",
        ));
    }
    Ok(())
}

fn render_systemd_unit(spec: &RunnerServiceSpec, wanted_by: &str) -> String {
    let mut args = vec![
        systemd_quote(spec.binary_path.as_path()),
        "runner".to_string(),
        "service".to_string(),
        "run".to_string(),
        "--config".to_string(),
        systemd_quote(spec.config_path.as_path()),
    ];
    if let Some(profile) = &spec.profile {
        args.push("--profile".to_string());
        args.push(systemd_quote_text(profile));
    }
    let working_directory = spec
        .working_directory
        .as_deref()
        .or_else(|| spec.config_path.parent())
        .map(systemd_quote)
        .unwrap_or_else(|| "\"/\"".to_string());
    let mut unit = format!(
        "[Unit]\n\
Description=Loomex Runner\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
WorkingDirectory={working_directory}\n\
ExecStart={}\n\
Restart=always\n\
RestartSec=5\n\
StandardOutput=journal\n\
StandardError=journal\n",
        args.join(" ")
    );
    if let Some(log_path) = &spec.log_path {
        unit.push_str(&format!(
            "Environment=LOOMEX_RUNNER_LOG_PATH={}\n",
            systemd_quote(log_path)
        ));
    }
    unit.push_str(&format!("\n[Install]\nWantedBy={wanted_by}\n"));
    unit
}

fn render_launch_agent(spec: &RunnerServiceSpec) -> CoreResult<String> {
    let mut arguments = vec![
        xml_escape_path(&spec.binary_path)?,
        "runner".to_string(),
        "service".to_string(),
        "run".to_string(),
        "--config".to_string(),
        xml_escape_path(&spec.config_path)?,
    ];
    if let Some(profile) = &spec.profile {
        arguments.push("--profile".to_string());
        arguments.push(xml_escape(profile)?);
    }

    let working_directory = spec
        .working_directory
        .as_deref()
        .or_else(|| spec.config_path.parent())
        .unwrap_or_else(|| Path::new("/"));
    let argument_elements = arguments
        .into_iter()
        .map(|argument| format!("    <string>{argument}</string>\n"))
        .collect::<String>();

    let mut plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>{label}</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
{argument_elements}\
  </array>\n\
  <key>WorkingDirectory</key>\n\
  <string>{working_directory}</string>\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
  <key>ThrottleInterval</key>\n\
  <integer>5</integer>\n",
        label = xml_escape(&spec.service_name)?,
        working_directory = xml_escape_path(working_directory)?,
    );

    if let Some(log_path) = &spec.log_path {
        let escaped_log_path = xml_escape_path(log_path)?;
        plist.push_str(&format!(
            "  <key>EnvironmentVariables</key>\n\
  <dict>\n\
    <key>LOOMEX_RUNNER_LOG_PATH</key>\n\
    <string>{escaped_log_path}</string>\n\
  </dict>\n\
  <key>StandardOutPath</key>\n\
  <string>{escaped_log_path}</string>\n\
  <key>StandardErrorPath</key>\n\
  <string>{escaped_log_path}</string>\n"
        ));
    }
    plist.push_str("</dict>\n</plist>\n");
    Ok(plist)
}

fn validate_service_name(value: &str) -> CoreResult<()> {
    if value.trim().is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(CoreError::new(
            "RUNNER_SERVICE_NAME_INVALID",
            "service name must contain only letters, numbers, dot, dash, or underscore",
        ));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, code: &'static str) -> CoreResult<()> {
    if path.as_os_str().is_empty() || !is_absolute_cross_platform(path) {
        return Err(CoreError::new(code, "path must be absolute"));
    }
    Ok(())
}

fn is_absolute_cross_platform(path: &Path) -> bool {
    path.is_absolute() || path.to_str().is_some_and(looks_like_windows_absolute_path)
}

fn looks_like_windows_drive_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn looks_like_windows_absolute_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    normalized.starts_with("//")
        || (looks_like_windows_drive_path(value)
            && normalized
                .as_bytes()
                .get(2)
                .is_some_and(|byte| *byte == b'/'))
}

fn systemd_quote(path: &Path) -> String {
    systemd_quote_text(&path.to_string_lossy())
}

fn systemd_quote_text(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn xml_escape_path(path: &Path) -> CoreResult<String> {
    let value = path.to_str().ok_or_else(|| {
        CoreError::new(
            "RUNNER_SERVICE_PATH_ENCODING_INVALID",
            "service paths must be valid UTF-8",
        )
    })?;
    xml_escape(value)
}

fn xml_escape(value: &str) -> CoreResult<String> {
    if value.chars().any(|ch| {
        !matches!(ch, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    }) {
        return Err(CoreError::new(
            "RUNNER_SERVICE_PLIST_VALUE_INVALID",
            "service plist values must contain only valid XML characters",
        ));
    }

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_launch_agent_renders_persistent_service_and_escapes_xml() {
        let spec = RunnerServiceSpec {
            service_name: "com.loomex.runner".to_string(),
            binary_path: PathBuf::from("/Applications/Loomex & Tools/loomex"),
            config_path: PathBuf::from("/Users/dev/.loomex/config <work>.toml"),
            profile: Some("R&D <primary> \"team\"".to_string()),
            log_path: Some(PathBuf::from("/Users/dev/Library/Logs/Loomex & Runner.log")),
            working_directory: Some(PathBuf::from("/Users/dev/Code/A&B")),
        };

        let manifest = spec
            .render(RunnerServicePlatform::MacOsLaunchAgent)
            .unwrap();

        assert_eq!(RunnerServicePlatform::MacOsLaunchAgent, manifest.platform);
        assert_eq!(
            "~/Library/LaunchAgents/com.loomex.runner.plist",
            manifest.install_path
        );
        assert_eq!(None, manifest.uninstall_path);
        assert!(manifest.content.contains("<key>RunAtLoad</key>\n<true/>"));
        assert!(manifest.content.contains("<key>KeepAlive</key>\n<true/>"));
        assert!(manifest
            .content
            .contains("<key>ThrottleInterval</key>\n<integer>5</integer>"));
        assert!(manifest
            .content
            .contains("/Applications/Loomex &amp; Tools/loomex"));
        assert!(manifest
            .content
            .contains("/Users/dev/.loomex/config &lt;work&gt;.toml"));
        assert!(manifest
            .content
            .contains("R&amp;D &lt;primary&gt; &quot;team&quot;"));
        assert!(manifest
            .content
            .contains("<key>LOOMEX_RUNNER_LOG_PATH</key>"));
        assert!(manifest.content.contains("<key>StandardOutPath</key>"));
        assert!(manifest.content.contains("<key>StandardErrorPath</key>"));
        assert!(manifest
            .content
            .contains("/Users/dev/Library/Logs/Loomex &amp; Runner.log"));
        assert!(manifest.content.ends_with("</dict>\n</plist>\n"));
    }

    #[test]
    fn macos_platform_aliases_and_current_detection_are_stable() {
        for alias in [
            "macos",
            "macos-launch-agent",
            "launch-agent",
            "launchd-user",
        ] {
            assert_eq!(
                RunnerServicePlatform::MacOsLaunchAgent,
                RunnerServicePlatform::parse(alias).unwrap()
            );
        }
        assert_eq!("macos", RunnerServicePlatform::MacOsLaunchAgent.as_str());
        if cfg!(target_os = "macos") {
            assert_eq!(
                RunnerServicePlatform::MacOsLaunchAgent,
                RunnerServicePlatform::current().unwrap()
            );
        }
    }

    #[test]
    fn macos_launch_agent_rejects_xml_control_characters() {
        let spec = RunnerServiceSpec {
            service_name: "com.loomex.runner".to_string(),
            binary_path: PathBuf::from("/opt/loomex/loomex"),
            config_path: PathBuf::from("/Users/dev/.loomex/config.toml"),
            profile: Some("invalid\0profile".to_string()),
            log_path: None,
            working_directory: None,
        };

        assert_eq!(
            "RUNNER_SERVICE_PLIST_VALUE_INVALID",
            spec.render(RunnerServicePlatform::MacOsLaunchAgent)
                .unwrap_err()
                .code
        );
    }

    #[test]
    fn linux_user_unit_quotes_paths_with_spaces_and_uses_journal() {
        let spec = RunnerServiceSpec {
            service_name: "loomex-runner".to_string(),
            binary_path: PathBuf::from("/opt/Loomex/bin/loomex"),
            config_path: PathBuf::from("/home/dev/My App/.loomex/config.toml"),
            profile: Some("default".to_string()),
            log_path: Some(PathBuf::from("/home/dev/.loomex/runner log.jsonl")),
            working_directory: None,
        };

        let manifest = spec
            .render(RunnerServicePlatform::LinuxUserSystemd)
            .unwrap();

        assert_eq!(RunnerServicePlatform::LinuxUserSystemd, manifest.platform);
        assert!(manifest.content.contains("ExecStart=\"/opt/Loomex/bin/loomex\" runner service run --config \"/home/dev/My App/.loomex/config.toml\" --profile \"default\""));
        assert!(manifest.content.contains("StandardOutput=journal"));
        assert!(manifest
            .content
            .contains("Environment=LOOMEX_RUNNER_LOG_PATH=\"/home/dev/.loomex/runner log.jsonl\""));
        assert!(manifest.content.ends_with("WantedBy=default.target\n"));
    }

    #[test]
    fn windows_service_is_not_advertised_without_named_pipe_server() {
        assert_eq!(
            "RUNNER_SERVICE_PLATFORM_UNSUPPORTED",
            RunnerServicePlatform::parse("windows").unwrap_err().code
        );
    }

    #[test]
    fn cross_platform_relative_path_rejects_windows_drive_and_unc_escape() {
        assert!(validate_cross_platform_relative_path("src/app.rs").is_ok());
        assert!(validate_cross_platform_relative_path("dir with spaces/file.txt").is_ok());
        assert_eq!(
            "WORKSPACE_PATH_ESCAPE",
            validate_cross_platform_relative_path("C:\\Users\\dev\\secret.txt")
                .unwrap_err()
                .code
        );
        assert_eq!(
            "WORKSPACE_PATH_ESCAPE",
            validate_cross_platform_relative_path("\\\\server\\share\\secret.txt")
                .unwrap_err()
                .code
        );
        assert_eq!(
            "WORKSPACE_PATH_OUTSIDE_ROOT",
            validate_cross_platform_relative_path("../secret.txt")
                .unwrap_err()
                .code
        );
    }
}
