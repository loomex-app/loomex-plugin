mod setup_transaction;

use std::{
    collections::{hash_map::DefaultHasher, HashSet},
    env, fs,
    fs::OpenOptions,
    hash::{Hash, Hasher},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{self, Command},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use loomex_core::release_security::sha256_hex;
#[cfg(unix)]
use loomex_core::UnixLocalControlServer;
use loomex_core::{
    acquire_runner_runtime_guard,
    config::default_config_path,
    enforce_policy_decision,
    execution::{
        JobRecoveryAction, JobReplaySafety, RecoverableJobPhase, RecoverableRunnerJob,
        RemoteRunnerJobSnapshot, RemoteRunnerJobStatus, RunnerJobRecoveryJournal,
    },
    grpc::{GrpcClientConfig, StreamCredential},
    protocol::{StreamIdentity, PROTOCOL_VERSION},
    read_local_control_token, read_recent_log_entries, release_runner_runtime_guard_for_surface,
    runner_runtime_guard_path, user_credential_profile, AuthTokenResponse, BindingStatus,
    BindingValidationContext, BundledRuntimeInstall, CapabilityExecutor, CapabilityRequest,
    CliConfig, CliConfigOverrides, CredentialKind, CredentialStorageBackend, CredentialStore,
    DeviceLoginChallenge, FileLogSink, FsListInput, FsReadInput, FsWriteInput,
    HttpManagementApiClient, HumanRequestSummary, LocalCapabilityExecutor, LocalControlDispatcher,
    LocalControlPaths, LocalControlRequest, LocalControlResponse, LogEntry, ManagementApiClient,
    ManagementCredential, ManagementProjectRunnerBinding, Organization, PolicyDecision,
    PolicyEngine, PolicyEvaluationInput, PolicyLayer, PolicyRule, PolicySource, Project,
    ProjectRunnerBinding, ProjectRunnerBindingCreateRequest, Runner, RunnerCapabilityGrant,
    RunnerServiceManifest, RunnerServicePlatform, RunnerServiceSpec, RunnerSession,
    RunnerSessionStatus, RunnerTransportRuntime, RunnerUpsertRequest, RuntimeInstaller,
    SbomPackage, ShellCancellationToken, ShellExecInput, StreamCredentialRequest,
    StreamCredentialResponse, StreamSupervisor, StreamSupervisorConfig, SystemCredentialStore,
    TransportClientConfig, TransportConnector, TransportNegotiationPolicy, WebSocketClientConfig,
    WebSocketProxyConfig, WorkflowRunStartRequest, WorkspacePath, LOCAL_CONTROL_PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use setup_transaction::{
    FileSnapshot, SetupTransactionJournal, SetupTransactionOperation, SetupTransactionPhase,
    SetupTransactionSnapshot, SetupTransactionStore,
};

const DEFAULT_LOG_LIMIT: usize = 100;
const LOG_PATH_ENV: &str = "LOOMEX_RUNNER_LOG_PATH";
const CONFIG_PATH_ENV: &str = "LOOMEX_CONFIG_PATH";
const CREDENTIAL_DIR_ENV: &str = "LOOMEX_CREDENTIAL_DIR";
const RUNNER_GUARD_PATH_ENV: &str = "LOOMEX_TAURI_GUARD_PATH";
const DEFAULT_DEVICE_LOGIN_TIMEOUT_SECONDS: u64 = 600;
const MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS: u64 = 300;
const DEFAULT_FOLLOW_POLL_INTERVAL_MS: u64 = 500;
const DEFAULT_FOLLOW_MAX_POLLS: usize = 1_200;
static NEXT_BINDING_CREATE_ATTEMPT: AtomicU64 = AtomicU64::new(1);

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let json_errors = args.iter().any(|arg| arg == "--json");
    match run(args.clone()) {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            let exit_code = exit_code_for_successful_output(&args, &output);
            if exit_code != 0 {
                process::exit(exit_code);
            }
        }
        Err(err) => {
            if json_errors {
                eprintln!("{}", error_json_envelope(&err));
            } else {
                eprintln!("{err}");
            }
            process::exit(exit_code_for_error(&err));
        }
    }
}

fn exit_code_for_successful_output(args: &[String], output: &str) -> i32 {
    if is_runner_doctor_invocation(args) {
        return doctor_exit_code_from_output(output).unwrap_or(0);
    }
    if is_runner_ops_release_gate_invocation(args) {
        return release_gate_exit_code_from_output(output).unwrap_or(0);
    }
    if is_runner_ops_enterprise_signoff_invocation(args) {
        return enterprise_signoff_exit_code_from_output(output).unwrap_or(0);
    }
    0
}

fn is_runner_doctor_invocation(args: &[String]) -> bool {
    GlobalOptions::parse(args.to_vec())
        .ok()
        .is_some_and(|parsed| {
            parsed.args.len() >= 2
                && parsed.args[0].as_str() == "runner"
                && parsed.args[1].as_str() == "doctor"
        })
}

fn is_runner_ops_release_gate_invocation(args: &[String]) -> bool {
    GlobalOptions::parse(args.to_vec())
        .ok()
        .is_some_and(|parsed| {
            parsed.args.len() >= 4
                && parsed.args[0].as_str() == "runner"
                && parsed.args[1].as_str() == "ops"
                && parsed.args[2].as_str() == "release-gate"
        })
}

fn is_runner_ops_enterprise_signoff_invocation(args: &[String]) -> bool {
    GlobalOptions::parse(args.to_vec())
        .ok()
        .is_some_and(|parsed| {
            parsed.args.len() >= 4
                && parsed.args[0].as_str() == "runner"
                && parsed.args[1].as_str() == "ops"
                && parsed.args[2].as_str() == "enterprise-signoff"
        })
}

fn release_gate_exit_code_from_output(output: &str) -> Option<i32> {
    if let Ok(value) = serde_json::from_str::<Value>(output) {
        if value.get("schemaVersion").and_then(Value::as_str)
            != Some("loomex.cli.operationalReleaseGate/v1")
        {
            return Some(0);
        }
        let allowed = value
            .get("decision")
            .and_then(|decision| decision.get("allowed"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        return Some(if allowed { 0 } else { 40 });
    }

    Some(if output.starts_with("operational release gate blocked:") {
        40
    } else {
        0
    })
}

fn enterprise_signoff_exit_code_from_output(output: &str) -> Option<i32> {
    if let Ok(value) = serde_json::from_str::<Value>(output) {
        if value.get("schemaVersion").and_then(Value::as_str)
            != Some("loomex.cli.enterpriseAcceptanceSignoff/v1")
        {
            return Some(0);
        }
        let allowed = value
            .get("decision")
            .and_then(|decision| decision.get("allowed"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        return Some(if allowed { 0 } else { 41 });
    }

    Some(
        if output.starts_with("enterprise acceptance sign-off blocked:") {
            41
        } else {
            0
        },
    )
}

fn doctor_exit_code_from_output(output: &str) -> Option<i32> {
    if let Ok(value) = serde_json::from_str::<Value>(output) {
        if value.get("schemaVersion").and_then(Value::as_str) != Some("loomex.cli.runnerDoctor/v1")
            || value.get("status").and_then(Value::as_str) != Some("failed")
        {
            return Some(0);
        }
        return value
            .get("checks")
            .and_then(Value::as_array)
            .and_then(|checks| {
                checks
                    .iter()
                    .filter(|check| check.get("status").and_then(Value::as_str) == Some("failed"))
                    .filter_map(|check| check.get("name").and_then(Value::as_str))
                    .map(doctor_failed_check_exit_code)
                    .min()
            })
            .or(Some(1));
    }

    output
        .lines()
        .find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            rest.trim_start()
                .starts_with("failed")
                .then(|| doctor_failed_check_exit_code(name.trim()))
        })
        .or_else(|| output.contains(": failed - ").then_some(1))
}

fn doctor_failed_check_exit_code(name: &str) -> i32 {
    match name {
        "auth" => 10,
        "server" | "runnerControl" => 20,
        "workspace" | "git" | "shell" | "sh" | "cmd" => 30,
        _ => 1,
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    let parsed = GlobalOptions::parse(args)?;
    if parsed.args.is_empty() {
        return Ok(wizard_start_output(parsed.options.json));
    }
    if parsed.args == ["--help"] || parsed.args == ["-h"] {
        return Ok(ROOT_HELP.to_string());
    }

    // Direct CLI lifecycle commands share the same transaction fence as MCP
    // plugin-control mutations. The lock is held across the mutation so setup
    // compensation cannot race a config, identity, binding, or service change.
    let direct_lifecycle_mutation = direct_cli_is_lifecycle_mutation(&parsed.args);
    let _direct_lifecycle_lock = direct_lifecycle_mutation
        .then(PluginSetupTransactionLock::acquire)
        .transpose()?;
    if direct_lifecycle_mutation {
        plugin_reject_unfinished_setup_transaction()?;
    }

    match parsed.args.as_slice() {
        [command] if is_help(command) => Ok(ROOT_HELP.to_string()),
        [command, rest @ ..] if command == "config" => run_config(rest, &parsed.options),
        [command, rest @ ..] if command == "completion" => run_completion(rest, &parsed.options),
        [command, rest @ ..] if command == "profile" => run_profile(rest, &parsed.options),
        [command, rest @ ..] if command == "runner" => run_runner(rest, &parsed.options),
        [command, rest @ ..] if command == "login" => run_login(rest, &parsed.options),
        [command, rest @ ..] if command == "logout" => run_logout(rest, &parsed.options),
        [command, rest @ ..] if command == "org" => run_org(rest, &parsed.options),
        [command, rest @ ..] if command == "project" => run_project(rest, &parsed.options),
        [command, rest @ ..] if command == "workflow" => run_workflow(rest, &parsed.options),
        [command, rest @ ..] if command == "bind" => run_bind(rest, &parsed.options),
        [command, rest @ ..] if command == "approval" => run_approval(rest, &parsed.options),
        [command, rest @ ..] if command == "support" => run_support(rest, &parsed.options),
        [command, rest @ ..] if command == "policy" => run_policy(rest, &parsed.options),
        [command, rest @ ..] if command == "trace" => run_trace(rest, &parsed.options),
        [command, ..] => Err(format!("unknown loomex command: {command}\n{ROOT_HELP}")),
        [] => Ok(wizard_start_output(parsed.options.json)),
    }
}

fn direct_cli_is_lifecycle_mutation(args: &[String]) -> bool {
    match args {
        [command, rest @ ..] if command == "login" || command == "logout" => {
            !rest.first().is_some_and(|value| is_help(value))
        }
        [command, subcommand, ..] if command == "config" => subcommand == "set",
        [command, subcommand, ..] if command == "profile" => {
            matches!(subcommand.as_str(), "use" | "switch")
        }
        [command, subcommand, ..] if command == "org" || command == "project" => {
            subcommand == "select"
        }
        [command, rest @ ..] if command == "bind" => !rest
            .first()
            .is_some_and(|value| value == "list" || is_help(value)),
        [command, subcommand] if command == "runner" => {
            matches!(subcommand.as_str(), "start" | "stop")
        }
        [command, service, subcommand, ..] if command == "runner" && service == "service" => {
            matches!(subcommand.as_str(), "install" | "uninstall")
        }
        _ => false,
    }
}

fn run_config(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    run_config_with_path(args, options, cli_config_path())
}

fn run_config_with_path(
    args: &[String],
    options: &GlobalOptions,
    path: PathBuf,
) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(CONFIG_HELP.to_string());
    }
    match args {
        [subcommand] if subcommand == "list" => {
            let config = load_cli_config_from(&path)?;
            let entries = config.list_entries();
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.configList/v1",
                    "entries": entries
                        .into_iter()
                        .map(|(key, value)| json!({"key": key, "value": value}))
                        .collect::<Vec<_>>()
                })
                .to_string());
            }
            Ok(entries
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        [subcommand, key] if subcommand == "get" => {
            let config = load_cli_config_from(&path)?;
            let value = config.get_key(key).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.configValue/v1",
                    "key": key,
                    "value": value
                })
                .to_string());
            }
            value.ok_or_else(|| format!("CONFIG_KEY_NOT_FOUND: {key}"))
        }
        [subcommand, key, value] if subcommand == "set" => {
            let mut config = load_cli_config_from(&path)?;
            config
                .set_key(key, value.clone())
                .map_err(format_core_error)?;
            config.save(&path).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.configSet/v1",
                    "key": key,
                    "updated": true
                })
                .to_string());
            }
            Ok(format!("updated {key}"))
        }
        [subcommand, ..] => Err(format!(
            "unknown config subcommand: {subcommand}\n{CONFIG_HELP}"
        )),
        [] => Ok(CONFIG_HELP.to_string()),
    }
}

fn run_completion(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(COMPLETION_HELP.to_string());
    }
    if args.len() != 1 {
        return Err(format!(
            "invalid completion command shape\n{COMPLETION_HELP}"
        ));
    }
    let shell = args[0].as_str();
    let script = completion_script(shell)?;
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.completion/v1",
            "shell": shell,
            "script": script
        })
        .to_string());
    }
    Ok(script)
}

fn completion_script(shell: &str) -> Result<String, String> {
    match shell {
        "bash" => Ok(
            r#"_loomex_complete()
{
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local commands="login logout config profile org project bind workflow runner approval policy trace support completion"
  COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
}
complete -F _loomex_complete loomex"#
                .to_string(),
        ),
        "zsh" => Ok(
            r#"#compdef loomex
_loomex() {
  local -a commands
  commands=(
    'login:Authenticate this profile'
    'logout:Remove local credential'
    'config:Read or write CLI config'
    'profile:List or switch profiles'
    'org:List or select organizations'
    'project:List or select projects'
    'bind:Bind a workspace to a project'
    'workflow:Run workflows'
    'runner:Control and diagnose the runner'
    'approval:List or resolve local approvals'
    'support:Export diagnostics bundle'
    'completion:Generate shell completions'
  )
  _describe 'loomex commands' commands
}
_loomex "$@""#
                .to_string(),
        ),
        "fish" => Ok(
            r#"complete -c loomex -f -a "login logout config profile org project bind workflow runner approval policy trace support completion""#
                .to_string(),
        ),
        _ => Err(format!(
            "COMPLETION_SHELL_UNSUPPORTED: expected bash, zsh, or fish; got {shell}"
        )),
    }
}

fn run_profile(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    run_profile_with_path(args, options, cli_config_path())
}

fn run_profile_with_path(
    args: &[String],
    options: &GlobalOptions,
    path: PathBuf,
) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(PROFILE_HELP.to_string());
    }
    let mut config = load_cli_config_from(&path)?;
    match args {
        [subcommand] if subcommand == "current" => {
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.profileCurrent/v1",
                    "profile": config.selected_profile
                })
                .to_string());
            }
            Ok(config.selected_profile)
        }
        [subcommand] if subcommand == "list" => {
            let mut profiles = config.profiles.keys().cloned().collect::<Vec<_>>();
            profiles.sort();
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.profileList/v1",
                    "selectedProfile": config.selected_profile,
                    "profiles": profiles
                })
                .to_string());
            }
            Ok(profiles
                .into_iter()
                .map(|profile| {
                    if profile == config.selected_profile {
                        format!("* {profile}")
                    } else {
                        format!("  {profile}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        [subcommand, profile] if matches!(subcommand.as_str(), "use" | "switch") => {
            if profile.trim().is_empty() {
                return Err("PROFILE_INPUT_INVALID: profile name is required".to_string());
            }
            if !config.profiles.contains_key(profile) {
                return Err(format!(
                    "PROFILE_NOT_FOUND: profile {profile} does not exist"
                ));
            }
            config
                .set_key("selectedProfile", profile.clone())
                .map_err(format_core_error)?;
            config.save(&path).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.profileSwitch/v1",
                    "selectedProfile": profile
                })
                .to_string());
            }
            Ok(format!("selected profile: {profile}"))
        }
        [subcommand, ..] => Err(format!(
            "unknown profile subcommand: {subcommand}\n{PROFILE_HELP}"
        )),
        [] => Ok(PROFILE_HELP.to_string()),
    }
}

fn run_login(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.iter().any(|value| is_help(value)) {
        return Ok(LOGIN_HELP.to_string());
    }
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let request = LoginRequest::parse(args)?;
    run_login_with(
        request,
        options,
        &mut config,
        &config_path,
        &store,
        &mut client,
        &resolved.profile,
        store.storage_backend(),
        present_device_login_challenge,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_login_with<C: ManagementApiClient, S: CredentialStore>(
    request: LoginRequest,
    options: &GlobalOptions,
    config: &mut CliConfig,
    config_path: &std::path::Path,
    store: &S,
    client: &mut C,
    profile: &str,
    storage_backend: CredentialStorageBackend,
    mut present_challenge: impl FnMut(&DeviceLoginChallenge),
) -> Result<String, String> {
    let organization_id = request.organization_id.clone().or_else(|| {
        config
            .profiles
            .get(profile)
            .and_then(|p| p.organization_id.clone())
    });
    let (token, organization_id, device_challenge, user_token) =
        if let (Some(api_key), Some(api_secret)) =
            (request.api_key.clone(), request.api_secret.clone())
        {
            let fallback_organization_id = organization_id.clone().unwrap_or_default();
            let exchange = client
                .exchange_api_key(&api_key, &api_secret, &fallback_organization_id)
                .map_err(format_core_error)?;
            let organization_id = exchange
                .organization_id
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(fallback_organization_id);
            (exchange.token, organization_id, None, false)
        } else if request.api_key.is_some() || request.api_secret.is_some() {
            return Err(
                "LOGIN_INPUT_INVALID: --api-key and --api-secret are required together".to_string(),
            );
        } else {
            if options.non_interactive {
                return Err(
                    "NON_INTERACTIVE_INPUT_REQUIRED: login requires --api-key and --api-secret"
                        .to_string(),
                );
            }
            let challenge = client.start_device_login().map_err(format_core_error)?;
            present_challenge(&challenge);
            let token = poll_device_login(
                client,
                &challenge.device_code,
                challenge.interval_seconds,
                request.device_timeout_seconds,
            )?;
            let organization_id = if let Some(organization_id) =
                organization_id.or_else(|| request.organization_id.clone())
            {
                organization_id
            } else {
                select_device_login_organization(client, profile, &token)?
            };
            (token, organization_id, Some(challenge), true)
        };

    let credential_profile = if user_token {
        user_credential_profile(profile)
    } else {
        profile.to_string()
    };
    let credential = if user_token {
        ManagementCredential::from_user_token_response(
            &credential_profile,
            organization_id.clone(),
            token,
            storage_backend,
        )
    } else {
        ManagementCredential::from_runner_token_response(
            &credential_profile,
            organization_id.clone(),
            token,
            storage_backend,
        )
    }
    .map_err(format_core_error)?;
    let storage_outcome = store.save(&credential).map_err(format_core_error)?;
    if user_token {
        // Device authorization returns a signed user token. Keep it separate from
        // the runner credential that runner-control issues after project selection.
        store.delete(profile).map_err(format_core_error)?;
    }
    config
        .set_key(
            &format!("profiles.{profile}.organizationId"),
            organization_id.clone(),
        )
        .map_err(format_core_error)?;
    config.save(config_path).map_err(format_core_error)?;

    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.login/v1",
            "authenticated": true,
            "profile": profile,
            "organizationId": organization_id,
            "tokenType": credential.token_type,
            "expiresAt": credential.expires_at,
            "storageBackend": storage_backend_name(storage_outcome.backend),
            "storageWarning": storage_outcome.warning,
            "userAuthenticated": user_token,
            "runnerAuthenticated": !user_token,
            "projectSelectionRequired": user_token,
            "deviceLogin": device_challenge.as_ref().map(|challenge| json!({
                "verificationUri": challenge.verification_uri,
                "userCode": challenge.user_code
            }))
        })
        .to_string());
    }

    let mut lines = vec![
        format!("authenticated profile: {profile}"),
        format!("organization: {organization_id}"),
        format!("expires_at: {}", credential.expires_at),
    ];
    if let Some(challenge) = device_challenge {
        lines.push(format!(
            "device login verified with code {} at {}",
            challenge.user_code, challenge.verification_uri
        ));
    }
    if let Some(warning) = storage_outcome.warning {
        lines.push(format!("warning: {warning}"));
    }
    Ok(lines.join("\n"))
}

fn present_device_login_challenge(challenge: &DeviceLoginChallenge) {
    eprintln!(
        "Open {} and enter {}",
        challenge.verification_uri, challenge.user_code
    );
}

fn poll_device_login<C: ManagementApiClient>(
    client: &mut C,
    device_code: &str,
    interval_seconds: u64,
    timeout_seconds: u64,
) -> Result<AuthTokenResponse, String> {
    let interval = interval_seconds.max(1);
    let attempts = (timeout_seconds / interval).max(1);
    for attempt in 0..attempts {
        match client.poll_device_token(device_code) {
            Ok(Some(token)) => return Ok(token),
            Ok(None) => {}
            Err(error) if error.code == "DEVICE_AUTHORIZATION_SLOW_DOWN" => {}
            Err(error) => return Err(format_core_error(error)),
        }
        if attempt + 1 < attempts {
            thread::sleep(Duration::from_secs(interval));
        }
    }
    Err("LOGIN_DEVICE_TIMEOUT: browser/device login timed out".to_string())
}

fn select_device_login_organization<C: ManagementApiClient>(
    client: &mut C,
    profile: &str,
    token: &AuthTokenResponse,
) -> Result<String, String> {
    let temporary_credential = ManagementCredential::from_user_token_response(
        profile,
        "",
        token.clone(),
        CredentialStorageBackend::LocalFileFallback,
    )
    .map_err(format_core_error)?;
    let organizations = client
        .list_organizations(&temporary_credential)
        .map_err(format_core_error)?;
    match organizations.as_slice() {
        [organization] => Ok(organization.id.clone()),
        [] => Err("ORG_ACCESS_EMPTY: authenticated user has no accessible organizations".to_string()),
        _ => Err(
            "ORG_SELECTION_REQUIRED: authenticated user has multiple organizations; rerun login with --organization ORG_ID"
                .to_string(),
        ),
    }
}

fn run_logout(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.first().is_some_and(|value| is_help(value)) {
        return Ok("usage:\n  loomex logout".to_string());
    }
    if !args.is_empty() {
        return Err("logout does not accept positional arguments".to_string());
    }
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    store.delete(&resolved.profile).map_err(format_core_error)?;
    store
        .delete(&user_credential_profile(&resolved.profile))
        .map_err(format_core_error)?;
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.logout/v1",
            "profile": resolved.profile,
            "localCredentialRemoved": true,
            "serverRevokeAttempted": false
        })
        .to_string());
    }
    Ok(format!(
        "logged out profile: {}\nlocal credential removed",
        resolved.profile
    ))
}

fn run_org(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    run_org_with(
        args,
        options,
        &mut config,
        &config_path,
        &credential,
        &mut client,
        &resolved.profile,
    )
}

fn run_org_with<C: ManagementApiClient>(
    args: &[String],
    options: &GlobalOptions,
    config: &mut CliConfig,
    config_path: &std::path::Path,
    credential: &ManagementCredential,
    client: &mut C,
    profile: &str,
) -> Result<String, String> {
    match args {
        [] => Ok(ORG_HELP.to_string()),
        [value] if is_help(value) => Ok(ORG_HELP.to_string()),
        [subcommand] if subcommand == "list" => {
            let organizations = client
                .list_organizations(credential)
                .map_err(format_core_error)?;
            format_organizations(&organizations, options)
        }
        [subcommand, organization_id] if subcommand == "select" => {
            let organizations = client
                .list_organizations(credential)
                .map_err(format_core_error)?;
            let Some(organization) = organizations
                .iter()
                .find(|organization| organization.id == *organization_id)
            else {
                return Err(format!("ORG_NOT_FOUND: {organization_id}"));
            };
            config
                .set_key(
                    &format!("profiles.{profile}.organizationId"),
                    organization.id.clone(),
                )
                .map_err(format_core_error)?;
            config
                .set_key(&format!("profiles.{profile}.projectId"), String::new())
                .map_err(format_core_error)?;
            config.save(config_path).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.orgSelection/v1",
                    "profile": profile,
                    "organization": organization
                })
                .to_string());
            }
            Ok(format!(
                "selected organization: {} ({})",
                organization.name, organization.id
            ))
        }
        [subcommand, ..] => Err(format!("unknown org subcommand: {subcommand}\n{ORG_HELP}")),
    }
}

fn run_project(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let organization_id = resolved
        .organization_id
        .clone()
        .or_else(|| Some(credential.organization_id.clone()))
        .ok_or_else(|| "PROJECT_CONTEXT_MISSING: select an organization first".to_string())?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let selected_project_id = match args {
        [subcommand, project_id] if subcommand == "select" => Some(project_id.clone()),
        _ => None,
    };
    let output = run_project_with(
        args,
        options,
        &mut config,
        &config_path,
        &credential,
        &mut client,
        &resolved.profile,
        &organization_id,
    )?;
    if let Some(project_id) = selected_project_id {
        bootstrap_cli_runner_for_project(
            &mut config,
            &config_path,
            &store,
            &credential,
            &mut client,
            &resolved.profile,
            &organization_id,
            &project_id,
            store.storage_backend(),
        )?;
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn bootstrap_cli_runner_for_project<C: ManagementApiClient, S: CredentialStore + ?Sized>(
    config: &mut CliConfig,
    config_path: &Path,
    store: &S,
    user_credential: &ManagementCredential,
    client: &mut C,
    profile: &str,
    organization_id: &str,
    project_id: &str,
    storage_backend: CredentialStorageBackend,
) -> Result<(), String> {
    let exchange = client
        .bootstrap_runner_with_workspace_token(
            &user_credential.access_token,
            organization_id,
            Some(project_id),
            None,
        )
        .map_err(format_core_error)?;
    let runner_id = exchange
        .runner_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "RUNNER_BOOTSTRAP_RESPONSE_INVALID: runnerId is required".to_string())?;
    let runner_credential = ManagementCredential::from_runner_token_response(
        profile,
        organization_id,
        exchange.token,
        storage_backend,
    )
    .map_err(format_core_error)?;
    store.save(&runner_credential).map_err(format_core_error)?;
    config
        .set_key(&format!("profiles.{profile}.runnerId"), runner_id.clone())
        .map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{profile}.bindingId"),
            exchange.binding_id.unwrap_or_default(),
        )
        .map_err(format_core_error)?;
    config
        .set_key(&format!("profiles.{profile}.workspacePath"), String::new())
        .map_err(format_core_error)?;
    config.save(config_path).map_err(format_core_error)
}

#[allow(clippy::too_many_arguments)]
fn run_project_with<C: ManagementApiClient>(
    args: &[String],
    options: &GlobalOptions,
    config: &mut CliConfig,
    config_path: &std::path::Path,
    credential: &ManagementCredential,
    client: &mut C,
    profile: &str,
    organization_id: &str,
) -> Result<String, String> {
    match args {
        [] => Ok(PROJECT_HELP.to_string()),
        [value] if is_help(value) => Ok(PROJECT_HELP.to_string()),
        [subcommand] if subcommand == "list" => {
            let projects = client
                .list_projects(credential, organization_id)
                .map_err(format_core_error)?;
            if projects.is_empty() {
                return Err(format!(
                    "PROJECT_ACCESS_EMPTY: organization {organization_id} has no accessible projects"
                ));
            }
            format_projects(&projects, options)
        }
        [subcommand, project_id] if subcommand == "select" => {
            let project = client
                .get_project(credential, project_id)
                .map_err(format_core_error)?;
            if project.organization_id != organization_id {
                return Err(
                    "PROJECT_ORGANIZATION_MISMATCH: project belongs to another organization"
                        .to_string(),
                );
            }
            if project.status != "active" {
                return Err(format!(
                    "PROJECT_UNAVAILABLE: project status is {}",
                    project.status
                ));
            }
            config
                .set_key(&format!("profiles.{profile}.projectId"), project.id.clone())
                .map_err(format_core_error)?;
            config.save(config_path).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.projectSelection/v1",
                    "profile": profile,
                    "project": project
                })
                .to_string());
            }
            Ok(format!(
                "selected project: {} ({})",
                project.name, project.id
            ))
        }
        [subcommand, ..] => Err(format!(
            "unknown project subcommand: {subcommand}\n{PROJECT_HELP}"
        )),
    }
}

fn format_organizations(
    organizations: &[Organization],
    options: &GlobalOptions,
) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.organizationList/v1",
            "items": organizations
        })
        .to_string());
    }
    Ok(organizations
        .iter()
        .map(|organization| format!("{}\t{}", organization.id, organization.name))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn format_projects(projects: &[Project], options: &GlobalOptions) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.projectList/v1",
            "items": projects
        })
        .to_string());
    }
    Ok(projects
        .iter()
        .map(|project| format!("{}\t{}\t{}", project.id, project.name, project.status))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn load_credential<S: CredentialStore + ?Sized>(
    store: &S,
    profile: &str,
) -> Result<ManagementCredential, String> {
    let credential = store
        .load(profile)
        .map_err(format_core_error)?
        .ok_or_else(|| format!("AUTH_REQUIRED: run `loomex login --profile {profile}` first"))?;
    credential
        .validate_not_expiring(
            current_epoch_seconds()?,
            MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS,
        )
        .map_err(format_core_error)?;
    Ok(credential)
}

fn load_user_credential<S: CredentialStore + ?Sized>(
    store: &S,
    profile: &str,
) -> Result<ManagementCredential, String> {
    let user_profile = user_credential_profile(profile);
    let credential = store
        .load(&user_profile)
        .map_err(format_core_error)?
        .ok_or_else(|| {
            "USER_AUTH_REQUIRED: authenticate with the Codex plugin before selecting an organization or project"
                .to_string()
        })?;
    credential
        .validate_not_expiring(
            current_epoch_seconds()?,
            MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS,
        )
        .map_err(format_core_error)?;
    Ok(credential)
}

fn current_epoch_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("SYSTEM_CLOCK_INVALID: {err}"))
        .map(|duration| duration.as_secs())
}

fn storage_backend_name(backend: CredentialStorageBackend) -> &'static str {
    match backend {
        CredentialStorageBackend::MacOsKeychain => "macos_keychain",
        CredentialStorageBackend::LocalFileFallback => "local_file_fallback",
    }
}

const RUNNER_REAUTH_GUIDANCE: &str = "stored runner credential predates runner-control v1 or lacks runner scopes; sign out and authenticate again, then reselect the project and workspace";

fn runner_credential_upgrade_reason(credential: &ManagementCredential) -> Option<&'static str> {
    (credential.kind != CredentialKind::RunnerControlV1).then_some(RUNNER_REAUTH_GUIDANCE)
}

fn validate_runner_credential_compatibility(
    credential: &ManagementCredential,
) -> Result<(), String> {
    match runner_credential_upgrade_reason(credential) {
        Some(reason) => Err(format!("RUNNER_CREDENTIAL_UPGRADE_REQUIRED: {reason}")),
        None => Ok(()),
    }
}

fn runner_credential_local_readiness(
    credential: Option<&ManagementCredential>,
    now_epoch_seconds: u64,
) -> (bool, Option<&'static str>) {
    let reauth_reason = credential.and_then(runner_credential_upgrade_reason);
    let ready = credential.is_some_and(|credential| {
        credential
            .validate_not_expiring(now_epoch_seconds, MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS)
            .is_ok()
            && reauth_reason.is_none()
    });
    (ready, reauth_reason)
}

trait Prompt {
    fn read(&mut self, label: &str) -> Result<String, String>;
}

struct StdioPrompt;

impl Prompt for StdioPrompt {
    fn read(&mut self, label: &str) -> Result<String, String> {
        print!("{label}: ");
        io::stdout()
            .flush()
            .map_err(|err| format!("PROMPT_WRITE_FAILED: {err}"))?;
        let mut value = String::new();
        io::stdin()
            .read_line(&mut value)
            .map_err(|err| format!("PROMPT_READ_FAILED: {err}"))?;
        Ok(value.trim().to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RunnerStatusReport {
    status: String,
    profile: String,
    server_url: String,
    host_header: Option<String>,
    selected_project_id: Option<String>,
    selected_binding_id: Option<String>,
    workspace_path: Option<String>,
    runner: Option<Runner>,
    active_binding: Option<ManagementProjectRunnerBinding>,
    active_runs: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorCheck {
    name: String,
    status: String,
    message: String,
}

impl DoctorCheck {
    fn ok(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "ok".to_string(),
            message: message.into(),
        }
    }

    fn warn(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "warning".to_string(),
            message: message.into(),
        }
    }

    fn fail(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "failed".to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindRequest {
    project_id: String,
    workspace_path: String,
}

impl BindRequest {
    fn parse(args: &[String], profile: Option<&loomex_core::CliProfile>) -> Result<Self, String> {
        let mut project_id = None;
        let mut workspace_path = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "." => workspace_path = Some(".".to_string()),
                "--project" => {
                    index += 1;
                    project_id = Some(required_value(args, index, "--project")?);
                }
                "--workspace" => {
                    index += 1;
                    workspace_path = Some(required_value(args, index, "--workspace")?);
                }
                value => return Err(format!("unknown bind option: {value}")),
            }
            index += 1;
        }
        let project_id = project_id
            .or_else(|| profile.and_then(|profile| profile.project_id.clone()))
            .ok_or_else(|| {
                "PROJECT_CONTEXT_MISSING: provide --project or select a project".to_string()
            })?;
        let workspace_path = workspace_path
            .or_else(|| profile.and_then(|profile| profile.workspace_path.clone()))
            .ok_or_else(|| "WORKSPACE_PATH_REQUIRED: provide --workspace PATH".to_string())?;
        Ok(Self {
            project_id,
            workspace_path,
        })
    }

    fn prompt(
        profile: Option<&loomex_core::CliProfile>,
        prompt: &mut dyn Prompt,
    ) -> Result<Self, String> {
        let project_id = profile
            .and_then(|profile| profile.project_id.clone())
            .filter(|value| !value.trim().is_empty())
            .map(Ok)
            .unwrap_or_else(|| prompt.read("Project ID"))?;
        let workspace_path = profile
            .and_then(|profile| profile.workspace_path.clone())
            .filter(|value| !value.trim().is_empty())
            .map(Ok)
            .unwrap_or_else(|| prompt.read("Workspace path"))?;
        if project_id.trim().is_empty() {
            return Err("PROJECT_CONTEXT_MISSING: project is required".to_string());
        }
        if workspace_path.trim().is_empty() {
            return Err("WORKSPACE_PATH_REQUIRED: workspace path is required".to_string());
        }
        Ok(Self {
            project_id,
            workspace_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedWorkspace {
    display_path: String,
    fingerprint: String,
}

fn validate_workspace_path(path: &str) -> Result<ValidatedWorkspace, String> {
    let input = PathBuf::from(path);
    if path.trim().is_empty() {
        return Err("WORKSPACE_PATH_REQUIRED: workspace path is required".to_string());
    }
    let metadata =
        fs::symlink_metadata(&input).map_err(|err| format!("WORKSPACE_PATH_INVALID: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err(
            "WORKSPACE_SYMLINK_NOT_ALLOWED: workspace root cannot be a symlink".to_string(),
        );
    }
    if !metadata.is_dir() {
        return Err("WORKSPACE_NOT_DIRECTORY: workspace path must be a directory".to_string());
    }
    let canonical = input
        .canonicalize()
        .map_err(|err| format!("WORKSPACE_PATH_INVALID: {err}"))?;
    if canonical.parent().is_none() {
        return Err("WORKSPACE_PATH_UNSAFE: refusing to bind filesystem root".to_string());
    }
    fs::read_dir(&canonical)
        .map_err(|err| format!("WORKSPACE_READ_FAILED: {err}"))?
        .next();
    let probe = canonical.join(".loomex-write-test.tmp");
    fs::write(&probe, b"loomex").map_err(|err| format!("WORKSPACE_WRITE_FAILED: {err}"))?;
    fs::remove_file(&probe).map_err(|err| format!("WORKSPACE_WRITE_FAILED: {err}"))?;
    let display_path = canonical.to_string_lossy().to_string();
    Ok(ValidatedWorkspace {
        fingerprint: stable_fingerprint(&display_path),
        display_path,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct WorkflowRunRequest {
    workflow_id: String,
    organization_id: String,
    project_id: String,
    binding_id: Option<String>,
    workspace_path: Option<String>,
    input: Option<Value>,
    human_input: Option<Value>,
    human_input_cancelled: bool,
    follow: bool,
}

impl WorkflowRunRequest {
    fn parse(
        workflow_id: &str,
        args: &[String],
        resolved: &loomex_core::ResolvedCliSettings,
        read_input: impl FnOnce(&str) -> Result<Value, String>,
    ) -> Result<Self, String> {
        let mut project_id = resolved.project_id.clone();
        let mut workspace_path = resolved.workspace_path.clone();
        let mut binding_id = resolved.binding_id.clone();
        let mut input_arg = None;
        let mut human_input = None;
        let mut human_input_cancelled = false;
        let mut follow = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--project" => {
                    index += 1;
                    project_id = Some(required_value(args, index, "--project")?);
                }
                "--workspace" => {
                    index += 1;
                    workspace_path = Some(required_value(args, index, "--workspace")?);
                }
                "--binding" | "--binding-id" => {
                    let option = args[index].clone();
                    index += 1;
                    binding_id = Some(required_value(args, index, &option)?);
                }
                "--input" => {
                    index += 1;
                    input_arg = Some(required_value(args, index, "--input")?);
                }
                "--human-input" => {
                    index += 1;
                    human_input = Some(parse_json_value(&required_value(
                        args,
                        index,
                        "--human-input",
                    )?)?);
                }
                "--human-input-cancel" => human_input_cancelled = true,
                "--follow" => follow = true,
                value => return Err(format!("unknown workflow run option: {value}")),
            }
            index += 1;
        }
        let organization_id = resolved
            .organization_id
            .clone()
            .ok_or_else(|| "ORG_CONTEXT_MISSING: select an organization first".to_string())?;
        let project_id = project_id.ok_or_else(|| {
            "PROJECT_CONTEXT_MISSING: provide --project or select a project".to_string()
        })?;
        let input = input_arg
            .map(|input_arg| {
                let input = read_input(&input_arg)?;
                if !input.is_object() {
                    return Err(
                        "WORKFLOW_INPUT_INVALID: workflow input must be a JSON object".to_string(),
                    );
                }
                Ok(input)
            })
            .transpose()?;
        Ok(Self {
            workflow_id: workflow_id.to_string(),
            organization_id,
            project_id,
            binding_id,
            workspace_path,
            input,
            human_input,
            human_input_cancelled,
            follow,
        })
    }
}

struct WorkflowInputReader;

impl WorkflowInputReader {
    fn from_runtime(value: &str) -> Result<Value, String> {
        if value == "-" {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|err| format!("WORKFLOW_INPUT_READ_FAILED: {err}"))?;
            return parse_json_value(&buffer);
        }
        if let Some(path) = value.strip_prefix('@') {
            let content = fs::read_to_string(path)
                .map_err(|err| format!("WORKFLOW_INPUT_READ_FAILED: {err}"))?;
            return parse_json_value(&content);
        }
        parse_json_value(value)
    }
}

fn parse_json_value(value: &str) -> Result<Value, String> {
    serde_json::from_str(value).map_err(|err| format!("WORKFLOW_INPUT_JSON_INVALID: {err}"))
}

fn prepare_workflow_input(
    input: Option<Value>,
    schema: Option<&Value>,
    options: &GlobalOptions,
    prompt: &mut dyn Prompt,
) -> Result<Value, String> {
    if let Some(input) = input {
        return Ok(input);
    }
    if options.non_interactive {
        return Err("NON_INTERACTIVE_INPUT_REQUIRED: workflow run requires --input".to_string());
    }
    if let Some(schema) = schema {
        return prompt_workflow_input_from_schema(schema, prompt);
    }
    let raw = prompt.read("Workflow input JSON")?;
    let input = parse_json_value(&raw)?;
    if !input.is_object() {
        return Err("WORKFLOW_INPUT_INVALID: workflow input must be a JSON object".to_string());
    }
    Ok(input)
}

fn prompt_workflow_input_from_schema(
    schema: &Value,
    prompt: &mut dyn Prompt,
) -> Result<Value, String> {
    let schema_object = schema
        .as_object()
        .ok_or_else(|| "WORKFLOW_INPUT_SCHEMA_INVALID: schema must be a JSON object".to_string())?;
    let required = schema_object
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let properties = schema_object
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut object = serde_json::Map::new();
    for field in required {
        let field = field.as_str().ok_or_else(|| {
            "WORKFLOW_INPUT_SCHEMA_INVALID: required field names must be strings".to_string()
        })?;
        let property_schema = properties.get(field);
        let raw = prompt.read(&format!("Input {field}"))?;
        let value = prompt_value_for_schema(&raw, property_schema)?;
        object.insert(field.to_string(), value);
    }
    Ok(Value::Object(object))
}

fn prompt_value_for_schema(raw: &str, property_schema: Option<&Value>) -> Result<Value, String> {
    let expected = property_schema
        .and_then(|schema| schema.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("string");
    if expected == "string" {
        return Ok(Value::String(raw.to_string()));
    }
    parse_json_value(raw)
}

fn apply_human_input_to_workflow_input(
    input: Value,
    human_input: Option<Value>,
    human_input_cancelled: bool,
    options: &GlobalOptions,
    schema: Option<&Value>,
) -> Result<Value, String> {
    let requires_human = schema.is_some_and(schema_requires_human_input);
    if requires_human && options.non_interactive && human_input.is_none() && !human_input_cancelled
    {
        return Err(
            "NON_INTERACTIVE_HUMAN_INPUT_PENDING: workflow requires human input".to_string(),
        );
    }
    if human_input.is_none() && !human_input_cancelled {
        return Ok(input);
    }
    let mut object = input.as_object().cloned().ok_or_else(|| {
        "WORKFLOW_INPUT_INVALID: workflow input must be a JSON object".to_string()
    })?;
    if human_input_cancelled {
        object.insert(
            "humanInput".to_string(),
            json!({
                "cancelled": true
            }),
        );
    } else if let Some(human_input) = human_input {
        object.insert("humanInput".to_string(), human_input);
    }
    Ok(Value::Object(object))
}

fn schema_requires_human_input(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    if object
        .get("x-loomex-human-input-required")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    object
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .any(|field| field.as_str() == Some("humanInput"))
        })
}

fn resolve_workflow_binding_id<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    project_id: &str,
    selected_binding_id: Option<&str>,
    workspace_path: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(workspace_path) = workspace_path else {
        return Ok(selected_binding_id.map(str::to_string));
    };
    let workspace = validate_workspace_path(workspace_path)?;
    let bindings = client
        .list_project_runner_bindings(credential, project_id)
        .map_err(format_core_error)?;
    let matching = bindings
        .iter()
        .find(|binding| {
            binding.status == "active"
                && binding.local_root_path == workspace.display_path
                && binding.local_root_fingerprint.as_deref() == Some(workspace.fingerprint.as_str())
        })
        .or_else(|| {
            bindings.iter().find(|binding| {
                binding.status == "active" && binding.local_root_path == workspace.display_path
            })
        })
        .ok_or_else(|| {
            format!(
                "PROJECT_RUNNER_BINDING_NOT_FOUND: no active binding for workspace {}",
                workspace.display_path
            )
        })?;
    if let Some(selected_binding_id) = selected_binding_id {
        if selected_binding_id != matching.id {
            return Err(format!(
                "PROJECT_RUNNER_BINDING_MISMATCH: selected binding {selected_binding_id} does not match workspace {}",
                workspace.display_path
            ));
        }
    }
    Ok(Some(matching.id.clone()))
}

#[allow(clippy::too_many_arguments)]
fn resolve_waiting_human_input<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    workflow_id: &str,
    execution_id: &str,
    status: &str,
    human_input: Option<Value>,
    human_input_cancelled: bool,
    options: &GlobalOptions,
    prompt: &mut dyn Prompt,
) -> Result<Option<Value>, String> {
    if status != "waiting" {
        return Ok(None);
    }
    let request = first_pending_human_request(client, credential, workflow_id, execution_id)?;
    let Some(request) = request else {
        return Ok(None);
    };
    if options.non_interactive && human_input.is_none() && !human_input_cancelled {
        return Err(format!(
            "NON_INTERACTIVE_HUMAN_INPUT_PENDING: {}",
            request.id
        ));
    }
    let answer = if human_input_cancelled {
        json!({"answer": {"cancelled": true}})
    } else if let Some(human_input) = human_input {
        json!({"answer": human_input})
    } else {
        let raw = prompt.read(&format!("Human input {}", request.title))?;
        json!({"answer": parse_human_input_value(&raw)})
    };
    let resolved = client
        .resolve_human_request(credential, &request.id, &answer)
        .map_err(format_core_error)?;
    Ok(Some(json!({
        "requestId": resolved.request_id,
        "requestStatus": resolved.request_status,
        "executionId": resolved.execution_id,
        "executionStatus": resolved.execution_status
    })))
}

fn first_pending_human_request<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    workflow_id: &str,
    execution_id: &str,
) -> Result<Option<HumanRequestSummary>, String> {
    let requests = client
        .list_human_requests(credential, workflow_id, Some(execution_id))
        .map_err(format_core_error)?;
    Ok(requests.into_iter().find(|request| {
        matches!(request.status.as_str(), "pending" | "waiting" | "open")
            && request
                .execution
                .as_ref()
                .is_none_or(|execution| execution.id == execution_id)
    }))
}

fn parse_human_input_value(raw: &str) -> Value {
    parse_json_value(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

fn validate_workflow_input_schema(input: &Value, schema: &Value) -> Result<(), String> {
    let object = input.as_object().ok_or_else(|| {
        "WORKFLOW_INPUT_INVALID: workflow input must be a JSON object".to_string()
    })?;
    let schema_object = schema
        .as_object()
        .ok_or_else(|| "WORKFLOW_INPUT_SCHEMA_INVALID: schema must be a JSON object".to_string())?;

    if let Some(required) = schema_object.get("required") {
        let required = required.as_array().ok_or_else(|| {
            "WORKFLOW_INPUT_SCHEMA_INVALID: required must be an array".to_string()
        })?;
        for field in required {
            let field = field.as_str().ok_or_else(|| {
                "WORKFLOW_INPUT_SCHEMA_INVALID: required field names must be strings".to_string()
            })?;
            if !object.contains_key(field) {
                return Err(format!("WORKFLOW_INPUT_REQUIRED_FIELD_MISSING: {field}"));
            }
        }
    }

    let properties = schema_object
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if schema_object
        .get("additionalProperties")
        .and_then(Value::as_bool)
        == Some(false)
    {
        for key in object.keys() {
            if !properties.contains_key(key) {
                return Err(format!(
                    "WORKFLOW_INPUT_SCHEMA_VALIDATION_FAILED: additional property {key} is not allowed"
                ));
            }
        }
    }

    for (field, property_schema) in properties {
        let Some(value) = object.get(&field) else {
            continue;
        };
        let Some(expected_type) = property_schema.get("type") else {
            continue;
        };
        if !json_value_matches_schema_type(value, expected_type) {
            return Err(format!(
                "WORKFLOW_INPUT_SCHEMA_VALIDATION_FAILED: {field} has invalid type"
            ));
        }
    }
    Ok(())
}

fn json_value_matches_schema_type(value: &Value, expected_type: &Value) -> bool {
    match expected_type {
        Value::String(kind) => json_value_matches_single_type(value, kind),
        Value::Array(kinds) => kinds
            .iter()
            .filter_map(Value::as_str)
            .any(|kind| json_value_matches_single_type(value, kind)),
        _ => true,
    }
}

fn json_value_matches_single_type(value: &Value, kind: &str) -> bool {
    match kind {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn format_bindings(
    bindings: &[ManagementProjectRunnerBinding],
    options: &GlobalOptions,
) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.bindingList/v1",
            "items": bindings
        })
        .to_string());
    }
    Ok(bindings
        .iter()
        .map(|binding| {
            format!(
                "{}\t{}\t{}\t{}",
                binding.id, binding.project_id, binding.status, binding.local_root_path
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn default_runner_capabilities() -> Vec<String> {
    [
        "fs.list",
        "fs.read",
        "fs.write",
        "fs.apply_patch",
        "shell.exec",
        "git.status",
        "git.diff",
        "git.log",
        "http.request",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn local_runner_display_name() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "loomex-cli-runner".to_string())
}

fn machine_fingerprint_hash() -> String {
    stable_fingerprint(&format!(
        "{}:{}:{}",
        local_runner_display_name(),
        env::consts::OS,
        env::consts::ARCH
    ))
}

fn stable_fingerprint(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn idempotency_key(prefix: &str, value: &str) -> String {
    format!("{prefix}:{}", stable_fingerprint(value))
}

fn binding_create_idempotency_key(
    project_id: &str,
    runner_id: &str,
    workspace_path: &str,
) -> String {
    let epoch_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let attempt = NEXT_BINDING_CREATE_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    idempotency_key(
        "plugin-binding-create",
        &format!(
            "{project_id}\u{1f}{runner_id}\u{1f}{workspace_path}\u{1f}{}\u{1f}{epoch_nanos}\u{1f}{attempt}",
            process::id()
        ),
    )
}

fn run_runner(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(RUNNER_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "logs" => print_runner_logs(rest, options),
        [subcommand] if subcommand == "status" => run_runner_status(options),
        [subcommand] if subcommand == "doctor" => run_runner_doctor(&[], options),
        [subcommand, rest @ ..] if subcommand == "doctor" => run_runner_doctor(rest, options),
        [subcommand] if subcommand == "start" => run_runner_start(options),
        [subcommand] if subcommand == "stop" => run_runner_stop(options),
        [subcommand, rest @ ..] if subcommand == "service" => run_runner_service(rest, options),
        [subcommand, rest @ ..] if subcommand == "plugin-control" => {
            run_runner_plugin_control(rest, options)
        }
        [subcommand, rest @ ..] if subcommand == "release" => run_runner_release(rest, options),
        [subcommand, rest @ ..] if subcommand == "ops" => run_runner_ops(rest, options),
        [subcommand, ..] => Err(format!(
            "unknown runner subcommand: {subcommand}\n{RUNNER_HELP}"
        )),
        [] => Ok(RUNNER_HELP.to_string()),
    }
}

const PLUGIN_CONTROL_SCHEMA_VERSION: &str = "loomex.cli.pluginControl/v1";
const PLUGIN_ROOT_ENV: &str = "LOOMEX_PLUGIN_ROOT";
const ALLOW_UNSIGNED_PLUGIN_ENV: &str = "LOOMEX_ALLOW_UNSIGNED_VALIDATION_PACKAGE";

fn run_runner_plugin_control(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if !options.json || !options.non_interactive {
        return Err(
            "PLUGIN_CONTROL_MODE_REQUIRED: plugin-control requires --json and --non-interactive"
                .to_string(),
        );
    }
    let method = args
        .first()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "PLUGIN_CONTROL_METHOD_REQUIRED: method is required".to_string())?;
    let params_text =
        option_value_optional(&args[1..], "--params-json").unwrap_or_else(|| "{}".to_string());
    let params: Value = serde_json::from_str(&params_text)
        .map_err(|err| format!("PLUGIN_CONTROL_PARAMS_INVALID: {err}"))?;
    if !params.is_object() {
        return Err("PLUGIN_CONTROL_PARAMS_INVALID: params must be a JSON object".to_string());
    }
    // Serialize every bootstrap mutation that can change setup readiness,
    // service state, identity, project, or workspace binding. Setup apply then
    // revalidates and consumes one stable reviewed snapshot under this lock.
    let lifecycle_mutation = plugin_control_is_lifecycle_mutation(method);
    let _lifecycle_lock = lifecycle_mutation
        .then(PluginSetupTransactionLock::acquire)
        .transpose()?;
    if lifecycle_mutation && !matches!(method.as_str(), "setup.apply" | "setup.rollback") {
        plugin_reject_unfinished_setup_transaction()?;
    }
    let result = match method.as_str() {
        "setup.status" => plugin_setup_status(options)?,
        "setup.plan" => plugin_setup_plan(&params, options)?,
        "setup.apply" => plugin_setup_apply(&params, options)?,
        "setup.rollback" => plugin_setup_rollback(&params, options)?,
        "auth.status" => plugin_auth_status(options)?,
        "auth.start" => plugin_auth_start(&params, options)?,
        "auth.wait" => plugin_auth_wait(&params, options)?,
        "auth.logout" => {
            plugin_confirmed(&params)?;
            let mut lifecycle = plugin_stop_service_and_invalidate_local_control(options)?;
            let remote_revocation =
                plugin_remote_revocation_outcome(plugin_revoke_remote_runner_token(options));
            if let Some(object) = lifecycle.as_object_mut() {
                object.insert(
                    "remoteTokenRevocation".to_string(),
                    remote_revocation.clone(),
                );
                object.insert("localLoggedOut".to_string(), json!(true));
            }
            plugin_finalize_logout_result(
                parse_json_output(run_logout(&[], options)?)?,
                lifecycle,
                remote_revocation,
            )
        }
        "org.list" => plugin_org_list(options)?,
        "org.select" => {
            let changing = plugin_validate_org_selection(&params, options)?;
            if changing {
                let lifecycle = plugin_stop_service_and_invalidate_local_control(options)?;
                match plugin_org_select(&params, options) {
                    Ok(result) => plugin_result_with_lifecycle(result, lifecycle),
                    Err(error) => return Err(plugin_transition_failure(error, options)),
                }
            } else {
                plugin_org_select(&params, options)?
            }
        }
        "project.list" => plugin_project_list(&params, options)?,
        "project.select" => {
            let changing = plugin_validate_project_selection(&params, options)?;
            if changing {
                let lifecycle = plugin_stop_service_and_invalidate_local_control(options)?;
                match plugin_project_select(&params, options) {
                    Ok(result) => plugin_result_with_lifecycle(result, lifecycle),
                    Err(error) => return Err(plugin_transition_failure(error, options)),
                }
            } else {
                plugin_project_select(&params, options)?
            }
        }
        "binding.list" => plugin_binding_list(&params, options)?,
        "binding.create" => plugin_binding_create(&params, options)?,
        "binding.revoke" => {
            plugin_confirmed(&params)?;
            let affects_selected = plugin_binding_revoke_affects_selected(&params, options)?;
            if affects_selected {
                let lifecycle = plugin_stop_service_and_invalidate_local_control(options)?;
                match plugin_binding_revoke(&params, options) {
                    Ok(result) => plugin_result_with_lifecycle(result, lifecycle),
                    Err(error) if error.starts_with("PLUGIN_BINDING_REVOKED_LOCAL_CLEAR_FAILED:") => {
                        return Err(format!(
                            "PLUGIN_CONTEXT_TRANSITION_PARTIAL: {error}; service remains stopped and local control credentials remain invalidated; retry binding.revoke to finish local cleanup"
                        ))
                    }
                    Err(error) => return Err(plugin_transition_failure(error, options)),
                }
            } else {
                plugin_binding_revoke(&params, options)?
            }
        }
        "runner.control" => plugin_runner_control(&params)?,
        "status" | "runner.status" => plugin_runner_status(options)?,
        "doctor" => {
            let args = params
                .get("verbose")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .then(|| "--deep".to_string())
                .into_iter()
                .collect::<Vec<_>>();
            parse_json_output(run_runner_doctor(&args, options)?)?
        }
        "logs.tail" => plugin_logs_tail(&params)?,
        _ => {
            return Err(format!(
                "PLUGIN_CONTROL_METHOD_UNSUPPORTED: unsupported bootstrap method {method}"
            ))
        }
    };
    Ok(json!({
        "schemaVersion": PLUGIN_CONTROL_SCHEMA_VERSION,
        "method": method,
        "result": result,
    })
    .to_string())
}

fn plugin_control_is_lifecycle_mutation(method: &str) -> bool {
    matches!(
        method,
        "setup.apply"
            | "setup.rollback"
            | "auth.start"
            | "auth.wait"
            | "auth.logout"
            | "org.select"
            | "project.select"
            | "binding.create"
            | "binding.revoke"
            | "runner.control"
    )
}

fn parse_json_output(output: String) -> Result<Value, String> {
    serde_json::from_str(&output)
        .map_err(|err| format!("PLUGIN_CONTROL_INTERNAL_JSON_INVALID: {err}"))
}

fn plugin_result_with_lifecycle(mut result: Value, lifecycle: Value) -> Value {
    if let Some(object) = result.as_object_mut() {
        object.insert("lifecycle".to_string(), lifecycle);
        result
    } else {
        json!({"result": result, "lifecycle": lifecycle})
    }
}

fn plugin_required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("PLUGIN_CONTROL_PARAMETER_REQUIRED: {key} is required"))
}

fn plugin_org_list(options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let items = client
        .list_organizations(&credential)
        .map_err(format_core_error)?;
    Ok(json!({"items": items}))
}

fn plugin_org_select(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let organization_id = plugin_required_string(params, "organizationId")?;
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let organization = client
        .list_organizations(&credential)
        .map_err(format_core_error)?
        .into_iter()
        .find(|item| item.id == organization_id)
        .ok_or_else(|| format!("ORG_NOT_FOUND: {organization_id}"))?;
    let scope_changed = resolved.organization_id.as_deref() != Some(organization_id);
    if !scope_changed {
        return Ok(json!({
            "profile": resolved.profile,
            "organization": organization,
            "changed": false,
        }));
    }
    if scope_changed {
        clear_plugin_runner_scope(&mut config, &resolved.profile, true)?;
    }
    config
        .set_key(
            &format!("profiles.{}.organizationId", resolved.profile),
            organization.id.clone(),
        )
        .map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{}.projectId", resolved.profile),
            String::new(),
        )
        .map_err(format_core_error)?;
    config.save(&config_path).map_err(format_core_error)?;
    store.delete(&resolved.profile).map_err(format_core_error)?;
    Ok(json!({"profile": resolved.profile, "organization": organization, "changed": true}))
}

fn plugin_validate_org_selection(params: &Value, options: &GlobalOptions) -> Result<bool, String> {
    let organization_id = plugin_required_string(params, "organizationId")?;
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let exists = client
        .list_organizations(&credential)
        .map_err(format_core_error)?
        .into_iter()
        .any(|organization| organization.id == organization_id);
    if !exists {
        return Err(format!("ORG_NOT_FOUND: {organization_id}"));
    }
    Ok(resolved.organization_id.as_deref() != Some(organization_id))
}

fn plugin_project_list(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let organization_id = params
        .get("organizationId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or(resolved.organization_id.as_deref())
        .ok_or_else(|| "PROJECT_CONTEXT_MISSING: select or provide an organization".to_string())?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let projects = client
        .list_projects(&credential, organization_id)
        .map_err(format_core_error)?;
    Ok(json!({"items": projects, "organizationId": organization_id}))
}

fn plugin_project_select(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let project_id = plugin_required_string(params, "projectId")?;
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let project = client
        .get_project(&credential, project_id)
        .map_err(format_core_error)?;
    if let Some(selected_organization_id) = resolved.organization_id.as_deref() {
        if project.organization_id != selected_organization_id {
            return Err(
                "PROJECT_ORGANIZATION_MISMATCH: project belongs to another organization"
                    .to_string(),
            );
        }
    }
    if project.status != "active" {
        return Err(format!(
            "PROJECT_UNAVAILABLE: project status is {}",
            project.status
        ));
    }
    let scope_changed = resolved.project_id.as_deref() != Some(project_id);
    if scope_changed {
        clear_plugin_runner_scope(&mut config, &resolved.profile, false)?;
    }
    config
        .set_key(
            &format!("profiles.{}.organizationId", resolved.profile),
            project.organization_id.clone(),
        )
        .map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{}.projectId", resolved.profile),
            project.id.clone(),
        )
        .map_err(format_core_error)?;
    config.save(&config_path).map_err(format_core_error)?;
    if scope_changed {
        store.delete(&resolved.profile).map_err(format_core_error)?;
    }
    Ok(json!({"profile": resolved.profile, "project": project, "changed": scope_changed}))
}

fn plugin_validate_project_selection(
    params: &Value,
    options: &GlobalOptions,
) -> Result<bool, String> {
    let project_id = plugin_required_string(params, "projectId")?;
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let project = client
        .get_project(&credential, project_id)
        .map_err(format_core_error)?;
    if resolved
        .organization_id
        .as_deref()
        .is_some_and(|organization_id| project.organization_id != organization_id)
    {
        return Err(
            "PROJECT_ORGANIZATION_MISMATCH: project belongs to another organization".to_string(),
        );
    }
    if project.status != "active" {
        return Err(format!(
            "PROJECT_UNAVAILABLE: project status is {}",
            project.status
        ));
    }
    Ok(resolved.project_id.as_deref() != Some(project_id))
}

fn clear_plugin_runner_scope(
    config: &mut CliConfig,
    profile: &str,
    clear_project: bool,
) -> Result<(), String> {
    let mut keys = vec!["runnerId", "bindingId", "workspacePath"];
    if clear_project {
        keys.push("projectId");
    }
    for key in keys {
        config
            .set_key(&format!("profiles.{profile}.{key}"), String::new())
            .map_err(format_core_error)?;
    }
    Ok(())
}

fn plugin_binding_create(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let project_id = plugin_required_string(params, "projectId")?;
    let workspace_path = params
        .get("workspacePath")
        .or_else(|| params.get("localRootPath"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            "PLUGIN_CONTROL_PARAMETER_REQUIRED: workspacePath is required".to_string()
        })?;
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let user_credential = load_user_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let mut result = create_plugin_binding_with(
        project_id,
        workspace_path,
        &resolved.profile,
        &mut config,
        &config_path,
        &store,
        &user_credential,
        &mut client,
    )?;
    let activation = match plugin_activate_installed_service_after_bootstrap(options) {
        Ok(value) => value,
        Err(error) => json!({
            "attempted": true,
            "healthy": false,
            "error": error,
        }),
    };
    if let Some(object) = result.as_object_mut() {
        object.insert("serviceActivation".to_string(), activation);
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn create_plugin_binding_with<C: ManagementApiClient, S: CredentialStore + ?Sized>(
    project_id: &str,
    workspace_path: &str,
    profile: &str,
    config: &mut CliConfig,
    config_path: &Path,
    store: &S,
    user_credential: &ManagementCredential,
    client: &mut C,
) -> Result<Value, String> {
    let workspace = validate_workspace_path(workspace_path)?;
    let project = client
        .get_project(user_credential, project_id)
        .map_err(format_core_error)?;
    if project.status != "active" {
        return Err(format!(
            "PROJECT_UNAVAILABLE: project status is {}",
            project.status
        ));
    }
    let existing_runner_credential = store.load(profile).map_err(format_core_error)?;
    let existing_authenticated_runner_id =
        if let Some(credential) = existing_runner_credential.as_ref() {
            credential
                .validate_not_expiring(
                    current_epoch_seconds()?,
                    MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS,
                )
                .map_err(format_core_error)?;
            validate_runner_credential_compatibility(credential)?;
            let runner = client
                .get_current_runner(credential, &project.organization_id)
                .map_err(format_core_error)?;
            let bindings = client
                .list_project_runner_bindings(credential, project_id)
                .map_err(format_core_error)?;
            if let Some(binding) = bindings.into_iter().find(|binding| {
                binding.status == "active"
                    && binding.organization_id == project.organization_id
                    && binding.project_id == project_id
                    && binding.runner_id == runner.id
                    && binding.local_root_path == workspace.display_path
            }) {
                persist_plugin_binding_context(
                    config,
                    config_path,
                    profile,
                    project_id,
                    &project.organization_id,
                    &binding.runner_id,
                    &binding.id,
                    &workspace.display_path,
                )?;
                return Ok(json!({
                    "profile": profile,
                    "projectId": project_id,
                    "organizationId": project.organization_id,
                    "runnerId": binding.runner_id,
                    "binding": binding,
                    "workspace": {
                        "path": workspace.display_path,
                        "fingerprint": workspace.fingerprint,
                    },
                    "bootstrapped": false,
                    "reused": true,
                }));
            }
            Some(runner.id)
        } else {
            None
        };

    let (runner_credential, runner_id, bootstrapped) = if let Some(credential) =
        existing_runner_credential
    {
        let runner_id = existing_authenticated_runner_id.ok_or_else(|| {
            "RUNNER_SELF_RESPONSE_INVALID: authenticated runner.id is required".to_string()
        })?;
        (credential, runner_id, false)
    } else {
        let exchange = client
            .bootstrap_runner_with_workspace_token(
                &user_credential.access_token,
                &project.organization_id,
                Some(project_id),
                Some(&workspace.display_path),
            )
            .map_err(format_core_error)?;
        let runner_id = exchange
            .runner_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "RUNNER_BOOTSTRAP_RESPONSE_INVALID: runnerId is required".to_string())?;
        let runner_credential = ManagementCredential::from_runner_token_response(
            profile,
            &project.organization_id,
            exchange.token,
            user_credential.storage_backend,
        )
        .map_err(format_core_error)?;
        store.save(&runner_credential).map_err(format_core_error)?;
        (runner_credential, runner_id, true)
    };
    let binding_request = ProjectRunnerBindingCreateRequest {
        organization_id: project.organization_id.clone(),
        runner_id: runner_id.clone(),
        local_root_path: workspace.display_path.clone(),
        local_root_fingerprint: Some(workspace.fingerprint.clone()),
    };
    // A binding lifecycle gets a fresh key. Reusing a path-only key after revoke would let the
    // backend replay the previous active response instead of creating the replacement binding.
    // Keep this key stable for this single POST/reconciliation attempt, and never retry the POST
    // after an uncertain outcome.
    let binding_create_key =
        binding_create_idempotency_key(project_id, &runner_id, &workspace.display_path);
    let (binding, reconciled) = match client.create_project_runner_binding(
        &runner_credential,
        project_id,
        &binding_request,
        &binding_create_key,
    ) {
        Ok(binding) => (binding, false),
        Err(error)
            if matches!(
                error.code,
                "MANAGEMENT_HTTP_FAILED" | "MANAGEMENT_RESPONSE_INVALID"
            ) =>
        {
            let original_error = format_core_error(error);
            let matches = client
                .list_project_runner_bindings(&runner_credential, project_id)
                .map_err(|reconciliation_error| {
                    format!(
                        "{original_error}; BINDING_RECONCILIATION_FAILED: {}",
                        format_core_error(reconciliation_error)
                    )
                })?
                .into_iter()
                .filter(|binding| {
                    binding.status == "active"
                        && binding.organization_id == binding_request.organization_id
                        && binding.project_id == project_id
                        && binding.runner_id == binding_request.runner_id
                        && binding.local_root_path == binding_request.local_root_path
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [binding] => (binding.clone(), true),
                [] => return Err(original_error),
                _ => {
                    return Err(format!(
                        "BINDING_RECONCILIATION_AMBIGUOUS: multiple active bindings match the authenticated runner, project, and workspace after an uncertain create outcome; originalError={original_error}"
                    ))
                }
            }
        }
        Err(error) => return Err(format_core_error(error)),
    };
    if binding.status != "active"
        || binding.organization_id != binding_request.organization_id
        || binding.project_id != project_id
        || binding.runner_id != binding_request.runner_id
        || binding.local_root_path != binding_request.local_root_path
    {
        return Err(
            "BINDING_RESPONSE_MISMATCH: created binding does not match the authenticated runner, project, and workspace"
                .to_string(),
        );
    }
    persist_plugin_binding_context(
        config,
        config_path,
        profile,
        project_id,
        &project.organization_id,
        &runner_id,
        &binding.id,
        &workspace.display_path,
    )?;

    Ok(json!({
        "profile": profile,
        "projectId": project_id,
        "organizationId": project.organization_id,
        "runnerId": runner_id,
        "binding": binding,
        "workspace": {
            "path": workspace.display_path,
            "fingerprint": workspace.fingerprint,
        },
        "bootstrapped": bootstrapped,
        "reused": false,
        "reconciled": reconciled,
    }))
}

#[allow(clippy::too_many_arguments)]
fn persist_plugin_binding_context(
    config: &mut CliConfig,
    config_path: &Path,
    profile: &str,
    project_id: &str,
    organization_id: &str,
    runner_id: &str,
    binding_id: &str,
    workspace_path: &str,
) -> Result<(), String> {
    for (key, value) in [
        ("organizationId", organization_id),
        ("projectId", project_id),
        ("runnerId", runner_id),
        ("bindingId", binding_id),
        ("workspacePath", workspace_path),
    ] {
        config
            .set_key(&format!("profiles.{profile}.{key}"), value.to_string())
            .map_err(format_core_error)?;
    }
    config.save(config_path).map_err(format_core_error)
}

fn plugin_binding_list(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let project_id = params
        .get("projectId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or(resolved.project_id.as_deref())
        .ok_or_else(|| "PROJECT_CONTEXT_MISSING: select or provide a project".to_string())?;
    let requested_status = params
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("all");
    let store = SystemCredentialStore::new(credential_dir());
    let Some(credential) = store.load(&resolved.profile).map_err(format_core_error)? else {
        return Ok(json!({
            "bindings": [],
            "projectId": project_id,
            "notBootstrapped": true,
        }));
    };
    credential
        .validate_not_expiring(
            current_epoch_seconds()?,
            MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS,
        )
        .map_err(format_core_error)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    let mut bindings = client
        .list_project_runner_bindings(&credential, project_id)
        .map_err(format_core_error)?;
    if requested_status != "all" {
        bindings.retain(|binding| binding.status == requested_status);
    }
    Ok(json!({
        "bindings": bindings,
        "projectId": project_id,
        "notBootstrapped": false,
    }))
}

fn plugin_binding_revoke(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let binding_id = plugin_required_string(params, "bindingId")?;
    let project_id = plugin_required_string(params, "projectId")?;
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_credential(&store, &resolved.profile)?;
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    client
        .revoke_project_runner_binding(
            &credential,
            project_id,
            binding_id,
            &idempotency_key("plugin-binding-revoke", binding_id),
        )
        .map_err(format_core_error)?;
    let selected_binding_cleared = resolved.binding_id.as_deref() == Some(binding_id);
    if selected_binding_cleared {
        for key in ["bindingId", "workspacePath"] {
            config
                .set_key(
                    &format!("profiles.{}.{}", resolved.profile, key),
                    String::new(),
                )
                .map_err(|error| {
                    format!(
                        "PLUGIN_BINDING_REVOKED_LOCAL_CLEAR_FAILED: {}",
                        format_core_error(error)
                    )
                })?;
        }
        config.save(&config_path).map_err(|error| {
            format!(
                "PLUGIN_BINDING_REVOKED_LOCAL_CLEAR_FAILED: {}",
                format_core_error(error)
            )
        })?;
    }
    Ok(json!({
        "revoked": true,
        "bindingId": binding_id,
        "projectId": project_id,
        "selectedBindingCleared": selected_binding_cleared,
    }))
}

fn plugin_binding_revoke_affects_selected(
    params: &Value,
    options: &GlobalOptions,
) -> Result<bool, String> {
    let binding_id = plugin_required_string(params, "bindingId")?;
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    Ok(resolved.binding_id.as_deref() == Some(binding_id))
}

fn plugin_logs_tail(params: &Value) -> Result<Value, String> {
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 200) as usize;
    let offset = params
        .get("cursor")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let level = params.get("level").and_then(Value::as_str);
    let mut entries =
        read_recent_log_entries(default_log_path(), 1_000).map_err(format_core_error)?;
    if let Some(level) = level {
        entries.retain(|entry| entry.level == level);
    }
    entries.reverse();
    let total = entries.len();
    let entries = entries
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(redact_log_entry_for_output)
        .collect::<Vec<_>>();
    let next_cursor =
        (offset + entries.len() < total).then(|| (offset + entries.len()).to_string());
    Ok(json!({"entries": entries, "nextCursor": next_cursor}))
}

fn plugin_confirmed(params: &Value) -> Result<(), String> {
    if params.get("confirm").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err("PLUGIN_CONTROL_CONFIRMATION_REQUIRED: confirm must be true".to_string())
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct PluginSetupTransactionLock {
    file: fs::File,
}

#[cfg(unix)]
impl PluginSetupTransactionLock {
    fn acquire() -> Result<Self, String> {
        Self::acquire_with_attempts(50)
    }

    fn acquire_with_attempts(attempts: usize) -> Result<Self, String> {
        Self::acquire_at_with_attempts(&plugin_lifecycle_root()?, attempts)
    }

    fn acquire_at_with_attempts(root: &Path, attempts: usize) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(
                    "PLUGIN_SETUP_LOCK_UNSAFE: lifecycle root must be a real directory".to_string(),
                );
            }
            Ok(metadata) => {
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o777 != 0o700
                {
                    return Err("PLUGIN_SETUP_LOCK_PERMISSIONS_UNSAFE: lifecycle root must be owned by the effective user with mode 0700".to_string());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(root)
                    .map_err(|error| format!("PLUGIN_SETUP_LOCK_CREATE_FAILED: {error}"))?;
                let metadata = fs::symlink_metadata(root)
                    .map_err(|error| format!("PLUGIN_SETUP_LOCK_CREATE_FAILED: {error}"))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(
                        "PLUGIN_SETUP_LOCK_UNSAFE: lifecycle root must be a real directory"
                            .to_string(),
                    );
                }
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("PLUGIN_SETUP_LOCK_CREATE_FAILED: {error}"))?;
            }
            Err(error) => {
                return Err(format!("PLUGIN_SETUP_LOCK_INSPECTION_FAILED: {error}"));
            }
        }
        let path = root.join(".setup.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| format!("PLUGIN_SETUP_LOCK_OPEN_FAILED: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("PLUGIN_SETUP_LOCK_INSPECTION_FAILED: {error}"))?;
        if !metadata.is_file() {
            return Err("PLUGIN_SETUP_LOCK_UNSAFE: lock must be a regular file".to_string());
        }
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("PLUGIN_SETUP_LOCK_PERMISSIONS_UNSAFE: lock must be owned by the effective user with mode 0600".to_string());
        }
        for attempt in 0..attempts.max(1) {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { file });
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(format!("PLUGIN_SETUP_LOCK_FAILED: {error}"));
            }
            if attempt + 1 < attempts.max(1) {
                thread::sleep(Duration::from_millis(100));
            }
        }
        Err("PLUGIN_SETUP_BUSY: another Loomex setup or rollback is in progress".to_string())
    }
}

fn plugin_lifecycle_root() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            "PLUGIN_SETUP_HOME_UNAVAILABLE: HOME is required for the per-user lifecycle fence"
                .to_string()
        })?;
    Ok(plugin_lifecycle_root_for_home(&home))
}

fn plugin_lifecycle_root_for_home(home: &Path) -> PathBuf {
    home.join(".loomex").join("lifecycle")
}

fn plugin_setup_transaction_store() -> Result<SetupTransactionStore, String> {
    Ok(SetupTransactionStore::new(&plugin_lifecycle_root()?))
}

#[cfg(unix)]
impl Drop for PluginSetupTransactionLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(not(unix))]
struct PluginSetupTransactionLock;

#[cfg(not(unix))]
impl PluginSetupTransactionLock {
    fn acquire() -> Result<Self, String> {
        Err("LOCAL_CONTROL_PLATFORM_UNSUPPORTED: setup lock requires macOS or Linux".to_string())
    }
}

fn plugin_setup_status(options: &GlobalOptions) -> Result<Value, String> {
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let active = installer.active_runtime().map_err(format_core_error)?;
    let service = parse_json_output(run_runner_service_status(&[], options)?)?;
    let supported = cfg!(unix);
    let bundled = plugin_package_runtime();
    let service_registered = service
        .get("installed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_active = service
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let runtime_matches_bundle = bundled
        .as_ref()
        .ok()
        .zip(active.as_ref())
        .is_some_and(|(package, runtime)| plugin_runtime_matches_bundle(package, runtime));
    let service_readiness =
        if supported && bundled.is_ok() && runtime_matches_bundle && service_registered {
            Some(
                plugin_service_bootstrap_readiness(options).unwrap_or_else(|error| {
                    json!({
                        "ready": false,
                        "available": false,
                        "error": plugin_structured_error(&error),
                        "reason": "bootstrap readiness could not be determined",
                    })
                }),
            )
        } else {
            None
        };
    let readiness_ready = service_readiness
        .as_ref()
        .and_then(|readiness| readiness.get("ready"))
        .and_then(Value::as_bool);
    let identity_mismatch = service_readiness
        .as_ref()
        .and_then(|readiness| readiness.pointer("/identity/matched"))
        .and_then(Value::as_bool)
        == Some(false);
    let (setup_required, recommended_next_action, recommendation_reason) =
        plugin_setup_recommendation(
            supported,
            bundled.is_ok(),
            runtime_matches_bundle,
            service_registered,
            service_active,
            readiness_ready,
            identity_mismatch,
        );
    let bundled_runtime = match bundled.as_ref() {
        Ok(package) => {
            json!({
                "available": true,
                "version": package.runtime_version,
                "pluginVersion": package.plugin_version,
                "channel": package.channel,
                "target": package.target,
            })
        }
        Err(error) => json!({
            "available": false,
            "error": plugin_structured_error(error),
        }),
    };
    let durable_runtime = json!({
        "installed": active.is_some(),
        "runtime": active,
        "runtimeRoot": installer.layout().root,
        "runtimeMatchesBundle": runtime_matches_bundle,
        "serviceRegistered": service_registered,
        "serviceActive": service_active,
        "serviceReadiness": service_readiness,
    });
    Ok(json!({
        "installed": durable_runtime["installed"],
        "runtime": durable_runtime["runtime"],
        "runtimeRoot": durable_runtime["runtimeRoot"],
        "service": service,
        "supported": supported,
        "bundledRuntime": bundled_runtime,
        "durableRuntime": durable_runtime,
        "setupRequired": setup_required,
        "recommendedNextAction": recommended_next_action,
        "recommendationReason": recommendation_reason,
    }))
}

fn plugin_setup_recommendation(
    supported: bool,
    bundled_available: bool,
    runtime_matches_bundle: bool,
    service_registered: bool,
    service_active: bool,
    readiness_ready: Option<bool>,
    identity_mismatch: bool,
) -> (bool, &'static str, &'static str) {
    if !supported {
        (false, "unsupported", "platform_unsupported")
    } else if !bundled_available {
        (false, "package.error", "bundled_package_error")
    } else if !runtime_matches_bundle {
        (true, "setup.plan", "runtime_mismatch")
    } else if !service_registered {
        (true, "setup.plan", "service_not_registered")
    } else if identity_mismatch {
        (false, "binding.create", "runner_identity_mismatch")
    } else if service_active {
        if readiness_ready == Some(false) {
            (false, "auth.status", "service_active_context_incomplete")
        } else {
            (false, "auth.status", "setup_complete")
        }
    } else if readiness_ready == Some(true) {
        (true, "setup.plan", "service_ready_but_inactive")
    } else {
        // A registered service may intentionally remain inactive until auth
        // and workspace binding complete. Do not turn that into a repair loop.
        (false, "auth.status", "continue_authentication_and_binding")
    }
}

fn plugin_runtime_matches_bundle(
    package: &PluginPackageRuntime,
    runtime: &loomex_core::runtime_install::InstalledRuntime,
) -> bool {
    let installed_target = match (runtime.artifact_os.as_str(), runtime.artifact_arch.as_str()) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    };
    package.runtime_version == runtime.version
        && package.sha256 == runtime.artifact_sha256
        && installed_target == Some(package.target.as_str())
}

fn plugin_structured_error(error: &str) -> Value {
    let (code, message) = error
        .split_once(':')
        .map_or(("PLUGIN_PACKAGE_UNAVAILABLE", error), |(code, message)| {
            (code.trim(), message.trim())
        });
    json!({
        "code": code,
        "message": if message.is_empty() { error } else { message },
    })
}

fn plugin_setup_plan(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let package = plugin_package_runtime()?;
    if let Some(version) = params.get("version").and_then(Value::as_str) {
        if version != package.runtime_version && version != package.plugin_version {
            return Err(format!(
                "PLUGIN_RUNTIME_VERSION_UNAVAILABLE: package contains runtime {} (plugin {}), not {version}",
                package.runtime_version, package.plugin_version
            ));
        }
    }
    let requested_channel = params
        .get("channel")
        .and_then(Value::as_str)
        .unwrap_or(&package.channel);
    if requested_channel != package.channel {
        return Err(format!(
            "PLUGIN_RUNTIME_CHANNEL_UNAVAILABLE: package contains {}, not {requested_channel}",
            package.channel
        ));
    }
    let install_service = params
        .get("installService")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let status = plugin_setup_status(options)?;
    let active_version = status.pointer("/runtime/version").and_then(Value::as_str);
    let action = match active_version {
        None => "install",
        Some(version) if version == package.runtime_version => "repair",
        Some(_) => "update",
    };
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let versioned_runtime_path = installer
        .layout()
        .version_dir(&package.runtime_version)
        .join("bin")
        .join(plugin_runtime_executable_name());
    let config_path = cli_config_path();
    let mut service_options = RunnerServiceOptions::parse(&[], options)?;
    service_options.binary_path = package.stable_executable.clone();
    service_options.config_path = config_path.clone();
    let service_path = default_service_install_path(&service_options)?;
    let service_installed = status
        .pointer("/service/installed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_active = status
        .pointer("/service/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let readiness = install_service
        .then(|| plugin_service_bootstrap_readiness(options))
        .transpose()?;
    let ready = readiness
        .as_ref()
        .and_then(|value| value.get("ready"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_action = match (install_service, service_installed, service_active, ready) {
        (false, _, _, _) => "preserve",
        (true, false, _, false) => "register_deferred",
        (true, false, _, true) => "register_start_healthcheck",
        (true, true, false, false) => "remain_deferred",
        (true, true, false, true) => "start_healthcheck",
        (true, true, true, false) => "stop_and_defer",
        (true, true, true, true) => "restart_healthcheck",
    };
    let previous_runtime = installer.previous_version().map_err(format_core_error)?;
    let mut plan = json!({
        "action": action,
        "version": package.runtime_version,
        "pluginVersion": package.plugin_version,
        "packageSigningState": package.signing_state,
        "channel": package.channel,
        "target": package.target,
        "runtimePath": package.stable_executable,
        "versionedRuntimePath": versioned_runtime_path,
        "configPath": config_path,
        "servicePlatform": RunnerServicePlatform::current().map_err(format_core_error)?.as_str(),
        "servicePath": service_path,
        "serviceAction": service_action,
        "serviceInstalled": service_installed,
        "serviceActive": service_active,
        "serviceReadiness": readiness,
        "installService": install_service,
        "requiresConfirmation": true,
        "previousVersion": active_version,
        "rollback": {
            "available": previous_runtime.is_some(),
            "targetVersion": previous_runtime,
        },
        "migrations": [],
        "runningExecutions": {
            "available": false,
            "count": null,
            "items": [],
            "reason": "active execution telemetry is not exposed by runner-control",
        },
        "actions": [
            "verify package integrity and target",
            "run bundled runtime self-test before activation",
            "atomically publish and activate the versioned runtime",
            service_action,
        ],
    });
    let plan_id = plugin_setup_plan_id(&plan)?;
    if let Some(object) = plan.as_object_mut() {
        object.insert("planId".to_string(), json!(plan_id));
    }
    Ok(plan)
}

fn plugin_setup_plan_id(reviewed_plan: &Value) -> Result<String, String> {
    Ok(format!(
        "loomex-setup-v1-{}",
        sha256_hex(
            &serde_json::to_vec(reviewed_plan)
                .map_err(|error| format!("PLUGIN_SETUP_PLAN_SERIALIZE_FAILED: {error}"))?
        )
    ))
}

fn plugin_setup_apply(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    plugin_confirmed(params)?;
    plugin_recover_interrupted_setup(options)?;
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let (store, mut journal) =
        plugin_begin_setup_transaction(SetupTransactionOperation::Apply, &installer, options)?;
    match plugin_setup_apply_transaction(params, options, &store, &mut journal) {
        Ok(result) => {
            store.update_phase(&mut journal, SetupTransactionPhase::Committed)?;
            store.clear()?;
            Ok(result)
        }
        Err(operation_error) => {
            match plugin_compensate_setup_transaction(&journal, options) {
                Ok(()) => {
                    store.update_phase(&mut journal, SetupTransactionPhase::Compensated)?;
                    store.clear()?;
                    Err(format!(
                        "PLUGIN_SETUP_FAILED_RESTORED: setup failed and prior state was restored: {operation_error}"
                    ))
                }
                Err(compensation_error) => Err(format!(
                    "PLUGIN_SETUP_RECOVERY_PENDING: setup failed ({operation_error}); compensation failed ({compensation_error}); retry setup or rollback to resume recovery"
                )),
            }
        }
    }
}

fn plugin_setup_apply_transaction(
    params: &Value,
    options: &GlobalOptions,
    transaction_store: &SetupTransactionStore,
    journal: &mut SetupTransactionJournal,
) -> Result<Value, String> {
    plugin_confirmed(params)?;
    if !cfg!(unix) {
        return Err("LOCAL_CONTROL_PLATFORM_UNSUPPORTED: durable local control currently requires macOS or Linux".to_string());
    }
    let package = plugin_package_runtime()?;
    let plan_id = plugin_required_string(params, "planId")?;
    let channel = plugin_required_string(params, "channel")?;
    let install_service = params
        .get("installService")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            "PLUGIN_CONTROL_PARAMETER_REQUIRED: installService is required".to_string()
        })?;
    if channel != package.channel {
        return Err(
            "PLUGIN_SETUP_PLAN_STALE: planId/options do not match the installed plugin package"
                .to_string(),
        );
    }
    let expected_plan = plugin_setup_plan(
        &json!({
            "version": package.plugin_version,
            "channel": channel,
            "installService": install_service,
        }),
        options,
    )?;
    if expected_plan.get("planId").and_then(Value::as_str) != Some(plan_id) {
        return Err(
            "PLUGIN_SETUP_PLAN_STALE: reviewed setup state changed; generate and approve a new plan"
                .to_string(),
        );
    }
    let service_was_installed = expected_plan
        .get("serviceInstalled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_was_active = expected_plan
        .get("serviceActive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_readiness = expected_plan.get("serviceReadiness").cloned();
    let service_ready = service_readiness
        .as_ref()
        .and_then(|value| value.get("ready"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stopped_for_deferred_start = if install_service && service_was_active && !service_ready {
        Some(plugin_runner_control(&json!({
            "action": "stop",
            "confirm": true,
        }))?)
    } else {
        None
    };
    let bytes = fs::read(&package.source_executable)
        .map_err(|err| format!("PLUGIN_RUNTIME_READ_FAILED: {err}"))?;
    plugin_self_test_runtime_bytes(&bytes, &package.sha256)?;
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let outcome = installer
        .install_bundled(BundledRuntimeInstall {
            version: &package.runtime_version,
            artifact_name: "loomex-plugin-runtime",
            artifact_sha256: &package.sha256,
            artifact_os: env::consts::OS,
            artifact_arch: env::consts::ARCH,
            artifact_bytes: &bytes,
            executable_name: plugin_runtime_executable_name(),
        })
        .map_err(format_core_error)?;
    transaction_store.update_phase(journal, SetupTransactionPhase::RuntimeActivated)?;

    let config_path = cli_config_path();
    if !config_path.exists() {
        CliConfig::default()
            .save(&config_path)
            .map_err(format_core_error)?;
    }
    transaction_store.update_phase(journal, SetupTransactionPhase::ConfigSaved)?;

    // The stable runtime is published before service registration. If service
    // activation fails, restore the prior active pointer when one exists and
    // return an explicit recoverable partial-state error otherwise.
    let service_result = (|| -> Result<Value, String> {
        Ok(
            match plugin_setup_service_disposition(install_service, service_was_installed) {
                PluginSetupServiceDisposition::Preserve => json!({
                    "installed": service_was_installed,
                    "changed": false,
                    "skipped": true,
                    "reason": "installService=false",
                }),
                PluginSetupServiceDisposition::ActivateExisting => {
                    if service_ready {
                        let action = if service_was_active {
                            "restart"
                        } else {
                            "start"
                        };
                        let control =
                            plugin_runner_control(&json!({"action": action, "confirm": true}))?;
                        transaction_store
                            .update_phase(journal, SetupTransactionPhase::HealthChecked)?;
                        control
                    } else {
                        json!({
                            "installed": true,
                            "started": false,
                            "deferredStart": true,
                            "readiness": service_readiness,
                            "stop": stopped_for_deferred_start,
                        })
                    }
                }
                PluginSetupServiceDisposition::Install => {
                    let service_args = vec![
                        "--binary".to_string(),
                        package.stable_executable.display().to_string(),
                        "--config".to_string(),
                        config_path.display().to_string(),
                    ]
                    .into_iter()
                    .chain((!service_ready).then(|| "--defer-start".to_string()))
                    .collect::<Vec<_>>();
                    let mut installed =
                        parse_json_output(run_runner_service_install(&service_args, options)?)?;
                    transaction_store
                        .update_phase(journal, SetupTransactionPhase::ServiceRegistered)?;
                    if service_ready {
                        transaction_store
                            .update_phase(journal, SetupTransactionPhase::ServiceStarted)?;
                        let health =
                            plugin_wait_for_local_control_health(20, Duration::from_millis(250))?;
                        transaction_store
                            .update_phase(journal, SetupTransactionPhase::HealthChecked)?;
                        if let Some(object) = installed.as_object_mut() {
                            object.insert("health".to_string(), health);
                        }
                    }
                    installed
                }
            },
        )
    })();
    let service = service_result?;
    Ok(json!({
        "installed": true,
        "version": outcome.activation.active.version,
        "previousVersion": outcome.activation.previous_version,
        "reusedExistingVersion": outcome.reused_existing_version,
        "runtimePath": package.stable_executable,
        "channel": package.channel,
        "installService": install_service,
        "serviceReadiness": service_readiness,
        "stoppedForDeferredStart": stopped_for_deferred_start,
        "service": service,
    }))
}

fn plugin_begin_setup_transaction(
    operation: SetupTransactionOperation,
    installer: &RuntimeInstaller,
    options: &GlobalOptions,
) -> Result<(SetupTransactionStore, SetupTransactionJournal), String> {
    let store = plugin_setup_transaction_store()?;
    let service_options = RunnerServiceOptions::parse(&[], options)?;
    let mut probe = OsTransactionServiceStatusProbe;
    plugin_begin_setup_transaction_with_probe(
        operation,
        installer,
        &service_options,
        store,
        &mut probe,
    )
}

fn plugin_begin_setup_transaction_with_probe(
    operation: SetupTransactionOperation,
    installer: &RuntimeInstaller,
    service_options: &RunnerServiceOptions,
    store: SetupTransactionStore,
    probe: &mut dyn TransactionServiceStatusProbe,
) -> Result<(SetupTransactionStore, SetupTransactionJournal), String> {
    // Probe before capturing or persisting any transaction state. Unknown
    // manager/command failures must never be serialized as false booleans.
    let service_state = probe.probe(service_options)?;
    let config = FileSnapshot::capture(cli_config_path())?;
    let service_file = FileSnapshot::capture(default_service_install_path(service_options)?)?;
    if service_state.installed && service_file.bytes.is_none() {
        return Err(
            "PLUGIN_SETUP_SNAPSHOT_INCONSISTENT: managed service is installed but its service file is missing"
                .to_string(),
        );
    }
    let (active_runtime_version, previous_runtime_version) =
        plugin_capture_runtime_pointer_state(installer)?;
    let snapshot = SetupTransactionSnapshot {
        runtime_root: installer.layout().root.clone(),
        active_runtime_version,
        previous_runtime_version,
        config,
        service_file,
        service_installed: service_state.installed,
        service_enabled: service_state.enabled,
        service_active: service_state.active,
    };
    let journal = store.begin(operation, snapshot)?;
    Ok((store, journal))
}

fn plugin_capture_runtime_pointer_state(
    installer: &RuntimeInstaller,
) -> Result<(Option<String>, Option<String>), String> {
    Ok((
        installer.active_version().map_err(format_core_error)?,
        installer.previous_version().map_err(format_core_error)?,
    ))
}

fn plugin_reject_unfinished_setup_transaction() -> Result<(), String> {
    let store = plugin_setup_transaction_store()?;
    plugin_reject_unfinished_setup_transaction_at(&store)
}

fn plugin_reject_unfinished_setup_transaction_at(
    store: &SetupTransactionStore,
) -> Result<(), String> {
    let Some(journal) = store.load()? else {
        return Ok(());
    };
    if matches!(
        journal.phase,
        SetupTransactionPhase::Committed | SetupTransactionPhase::Compensated
    ) {
        return store.clear();
    }
    Err(format!(
        "PLUGIN_SETUP_RECOVERY_REQUIRED: an unfinished {:?} transaction at {:?} must be recovered by setup.apply or setup.rollback before changing lifecycle state",
        journal.operation, journal.phase
    ))
}

fn plugin_recover_interrupted_setup(options: &GlobalOptions) -> Result<Option<Value>, String> {
    let store = plugin_setup_transaction_store()?;
    let Some(mut journal) = store.load()? else {
        return Ok(None);
    };
    if matches!(
        journal.phase,
        SetupTransactionPhase::Committed | SetupTransactionPhase::Compensated
    ) {
        store.clear()?;
        return Ok(Some(json!({
            "recovered": true,
            "action": "cleared_completed_journal",
        })));
    }
    plugin_compensate_setup_transaction(&journal, options).map_err(|error| {
        format!(
            "PLUGIN_SETUP_RECOVERY_FAILED: unfinished {:?} transaction at {:?} could not be compensated: {error}",
            journal.operation, journal.phase
        )
    })?;
    store.update_phase(&mut journal, SetupTransactionPhase::Compensated)?;
    store.clear()?;
    Ok(Some(json!({
        "recovered": true,
        "action": "compensated_interrupted_transaction",
    })))
}

fn plugin_compensate_setup_transaction(
    journal: &SetupTransactionJournal,
    options: &GlobalOptions,
) -> Result<(), String> {
    let mut probe = OsTransactionServiceStatusProbe;
    let mut runner = OsServiceCommandRunner;
    plugin_compensate_setup_transaction_with(journal, options, &mut probe, &mut runner)
}

fn plugin_compensate_setup_transaction_with(
    journal: &SetupTransactionJournal,
    options: &GlobalOptions,
    probe: &mut dyn TransactionServiceStatusProbe,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    let snapshot = &journal.snapshot;
    let mut errors = Vec::new();
    let service_options = RunnerServiceOptions::parse(&[], options)?;
    let current = probe.probe(&service_options)?;

    if current.installed || current.enabled || current.active {
        let commands = service_compensation_quiesce_commands(
            &service_options,
            current.active,
            current.enabled,
        )?;
        if let Err(error) = plugin_quiesce_service_for_compensation_with_runner(&commands, runner) {
            errors.push(format!("quiesce current service: {error}"));
        }
    }

    let installer = RuntimeInstaller::new(&snapshot.runtime_root);
    if let Err(error) = installer
        .restore_active_version(snapshot.active_runtime_version.as_deref())
        .map_err(format_core_error)
    {
        errors.push(format!("restore runtime pointer: {error}"));
    }
    if let Err(error) = installer
        .restore_previous_version(snapshot.previous_runtime_version.as_deref())
        .map_err(format_core_error)
    {
        errors.push(format!("restore previous runtime pointer: {error}"));
    }
    match installer.active_runtime().map_err(format_core_error) {
        Ok(restored) => {
            let restored_version = restored.as_ref().map(|runtime| runtime.version.as_str());
            if restored_version != snapshot.active_runtime_version.as_deref() {
                errors.push(format!(
                    "restored runtime identity mismatch: expected {:?}, got {:?}",
                    snapshot.active_runtime_version, restored_version
                ));
            }
        }
        Err(error) => errors.push(format!("verify restored runtime executable: {error}")),
    }
    match installer.previous_version().map_err(format_core_error) {
        Ok(restored) if restored != snapshot.previous_runtime_version => errors.push(format!(
            "restored previous runtime identity mismatch: expected {:?}, got {restored:?}",
            snapshot.previous_runtime_version
        )),
        Ok(_) => {}
        Err(error) => errors.push(format!("verify restored previous runtime pointer: {error}")),
    }
    if let Err(error) = snapshot.config.restore() {
        errors.push(format!("restore config: {error}"));
    }
    if let Err(error) = snapshot.service_file.restore() {
        errors.push(format!("restore service file: {error}"));
    }
    // The service manager must observe the exact restored/deleted unit file,
    // so reload strictly follows FileSnapshot::restore in both branches.
    if let Err(error) = plugin_reload_service_registration_with_runner(options, runner) {
        errors.push(format!("reload restored service registration: {error}"));
    }
    if let Err(error) = plugin_restore_service_enablement_with_runner(snapshot, options, runner) {
        errors.push(format!("restore service enablement: {error}"));
    }
    if let Err(error) = plugin_restore_service_activity_with_runner(snapshot, options, runner) {
        errors.push(format!("restore active service: {error}"));
    }

    match probe.probe(&service_options) {
        Ok(restored) => {
            if restored.installed != snapshot.service_installed
                || restored.enabled != snapshot.service_enabled
                || restored.active != snapshot.service_active
            {
                errors.push(format!(
                    "service state mismatch after compensation: expected installed={} enabled={} active={}, got installed={} enabled={} active={}",
                    snapshot.service_installed, snapshot.service_enabled, snapshot.service_active,
                    restored.installed, restored.enabled, restored.active
                ));
            }
        }
        Err(error) => errors.push(format!("verify restored service state: {error}")),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn plugin_reload_service_registration_with_runner(
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    let service_options = RunnerServiceOptions::parse(&[], options)?;
    if matches!(
        service_options.platform,
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd
    ) {
        runner.run(&systemctl_command(
            service_options.platform,
            &["daemon-reload"],
        ))?;
    }
    Ok(())
}

fn plugin_run_service_commands_with_runner(
    commands: &[ServiceCommand],
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    for command in commands {
        runner.run(command)?;
    }
    Ok(())
}

fn plugin_quiesce_service_for_compensation_with_runner(
    commands: &[ServiceCommand],
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    for command in commands {
        runner.run(command)?;
    }
    Ok(())
}

fn plugin_restore_service_enablement_with_runner(
    snapshot: &SetupTransactionSnapshot,
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    let service_options = RunnerServiceOptions::parse(&[], options)?;
    let commands = service_compensation_enablement_commands(
        &service_options,
        snapshot.service_installed,
        snapshot.service_enabled,
    )?;
    plugin_run_service_commands_with_runner(&commands, runner)
}

fn plugin_restore_service_activity_with_runner(
    snapshot: &SetupTransactionSnapshot,
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<(), String> {
    let service_options = RunnerServiceOptions::parse(&[], options)?;
    let commands = service_compensation_activity_commands(
        &service_options,
        snapshot.service_installed,
        snapshot.service_active,
    )?;
    plugin_run_service_commands_with_runner(&commands, runner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginSetupServiceDisposition {
    Preserve,
    ActivateExisting,
    Install,
}

fn plugin_setup_service_disposition(
    install_service: bool,
    service_was_installed: bool,
) -> PluginSetupServiceDisposition {
    match (install_service, service_was_installed) {
        (false, _) => PluginSetupServiceDisposition::Preserve,
        (true, true) => PluginSetupServiceDisposition::ActivateExisting,
        (true, false) => PluginSetupServiceDisposition::Install,
    }
}

fn plugin_setup_rollback(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    plugin_confirmed(params)?;
    plugin_recover_interrupted_setup(options)?;
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let (store, mut journal) =
        plugin_begin_setup_transaction(SetupTransactionOperation::Rollback, &installer, options)?;
    match plugin_setup_rollback_transaction(params, options, &store, &mut journal) {
        Ok(result) => {
            store.update_phase(&mut journal, SetupTransactionPhase::Committed)?;
            store.clear()?;
            Ok(result)
        }
        Err(operation_error) => {
            match plugin_compensate_setup_transaction(&journal, options) {
                Ok(()) => {
                    store.update_phase(&mut journal, SetupTransactionPhase::Compensated)?;
                    store.clear()?;
                    Err(format!(
                        "PLUGIN_ROLLBACK_FAILED_RESTORED: rollback failed and prior state was restored: {operation_error}"
                    ))
                }
                Err(compensation_error) => Err(format!(
                    "PLUGIN_SETUP_RECOVERY_PENDING: rollback failed ({operation_error}); compensation failed ({compensation_error}); retry setup or rollback to resume recovery"
                )),
            }
        }
    }
}

fn plugin_setup_rollback_transaction(
    params: &Value,
    options: &GlobalOptions,
    transaction_store: &SetupTransactionStore,
    journal: &mut SetupTransactionJournal,
) -> Result<Value, String> {
    plugin_confirmed(params)?;
    let setup_status = plugin_setup_status(options)?;
    let service_installed = setup_status
        .pointer("/service/installed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let service_active = setup_status
        .pointer("/service/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Resolve readiness before mutating the active pointer. A diagnostic error
    // must not turn a requested rollback into an unreported partial rollback.
    let readiness = service_installed
        .then(|| plugin_service_bootstrap_readiness(options))
        .transpose()?;
    let ready = readiness
        .as_ref()
        .and_then(|value| value.get("ready"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stopped_for_deferred_start = if service_active && !ready {
        Some(plugin_runner_control(&json!({
            "action": "stop",
            "confirm": true,
        }))?)
    } else {
        None
    };
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let activation_result =
        if let Some(version) = params.get("targetVersion").and_then(Value::as_str) {
            installer.rollback_to(version)
        } else {
            installer.rollback_to_previous()
        };
    let activation = match activation_result {
        Ok(activation) => activation,
        Err(error) => {
            if stopped_for_deferred_start.is_some() {
                return Err(format!(
                    "PLUGIN_ROLLBACK_FAILED_SERVICE_STOPPED: rollback failed ({}); prior runtime pointer is unchanged and the unauthenticated/unbound service remains stopped until bootstrap completes",
                    format_core_error(error)
                ));
            }
            return Err(format_core_error(error));
        }
    };
    transaction_store.update_phase(journal, SetupTransactionPhase::RuntimeActivated)?;
    let control = if service_installed && ready {
        match plugin_activate_installed_service_after_bootstrap(options) {
            Ok(value) => {
                transaction_store.update_phase(journal, SetupTransactionPhase::HealthChecked)?;
                Some(value)
            }
            Err(restart_error) => return Err(restart_error),
        }
    } else if service_installed {
        Some(json!({
            "installed": true,
            "started": false,
            "deferredStart": true,
            "reason": readiness.as_ref().and_then(|value| value.get("reason")),
        }))
    } else {
        None
    };
    Ok(json!({
        "rolledBack": true,
        "version": activation.active.version,
        "previousVersion": activation.previous_version,
        "service": control,
        "serviceReadiness": readiness,
        "stoppedForDeferredStart": stopped_for_deferred_start,
    }))
}

#[derive(Debug)]
struct PluginPackageRuntime {
    plugin_version: String,
    runtime_version: String,
    channel: String,
    signing_state: String,
    target: String,
    sha256: String,
    source_executable: PathBuf,
    stable_executable: PathBuf,
}

fn plugin_package_runtime() -> Result<PluginPackageRuntime, String> {
    let root = env::var_os(PLUGIN_ROOT_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| "PLUGIN_ROOT_REQUIRED: LOOMEX_PLUGIN_ROOT is not configured".to_string())?;
    let root = fs::canonicalize(&root).map_err(|err| format!("PLUGIN_ROOT_INVALID: {err}"))?;
    let manifest_path = root.join("packaging/runtime-manifest.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|err| format!("PLUGIN_RUNTIME_MANIFEST_READ_FAILED: {err}"))?,
    )
    .map_err(|err| format!("PLUGIN_RUNTIME_MANIFEST_INVALID: {err}"))?;
    if manifest.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err("PLUGIN_RUNTIME_MANIFEST_INVALID: schemaVersion must be 1".to_string());
    }
    let distribution_kind = manifest
        .get("distributionKind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "PLUGIN_RUNTIME_MANIFEST_INVALID: distributionKind is required".to_string()
        })?;
    if manifest
        .get("developmentOverridesAllowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(
            "PLUGIN_RUNTIME_MANIFEST_INVALID: development overrides must be disabled".to_string(),
        );
    }
    let plugin_version = manifest
        .get("pluginVersion")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "PLUGIN_RUNTIME_MANIFEST_INVALID: pluginVersion is required".to_string())?
        .to_string();
    let runtime_version = manifest
        .get("runtimeVersion")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "PLUGIN_RUNTIME_MANIFEST_INVALID: runtimeVersion is required".to_string())?
        .to_string();
    let channel = manifest
        .get("channel")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "stable" | "beta"))
        .ok_or_else(|| {
            "PLUGIN_RUNTIME_MANIFEST_INVALID: channel must be stable or beta".to_string()
        })?
        .to_string();
    let signing_state = manifest
        .get("packageSigningState")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "unsigned-validation" | "unsigned-release"))
        .ok_or_else(|| {
            "PLUGIN_RUNTIME_MANIFEST_INVALID: packageSigningState is invalid".to_string()
        })?
        .to_string();
    validate_plugin_distribution(
        distribution_kind,
        &signing_state,
        env::var(ALLOW_UNSIGNED_PLUGIN_ENV).ok().as_deref() == Some("1"),
    )?;
    if plugin_version.split('+').next() != Some(runtime_version.as_str()) {
        return Err(
            "PLUGIN_RUNTIME_MANIFEST_INVALID: runtimeVersion must match plugin base version"
                .to_string(),
        );
    }
    let plugin_manifest: Value = serde_json::from_slice(
        &fs::read(root.join(".codex-plugin/plugin.json"))
            .map_err(|err| format!("PLUGIN_MANIFEST_READ_FAILED: {err}"))?,
    )
    .map_err(|err| format!("PLUGIN_MANIFEST_INVALID: {err}"))?;
    if plugin_manifest.get("version").and_then(Value::as_str) != Some(plugin_version.as_str()) {
        return Err(
            "PLUGIN_RUNTIME_MANIFEST_INVALID: pluginVersion differs from plugin.json".to_string(),
        );
    }
    let target = plugin_target_key()?;
    let entry = manifest
        .pointer(&format!("/artifacts/{target}/runtime"))
        .ok_or_else(|| format!("PLUGIN_RUNTIME_TARGET_UNAVAILABLE: {target}"))?;
    let relative = entry
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "PLUGIN_RUNTIME_MANIFEST_INVALID: runtime.path is required".to_string())?;
    let sha256 = entry
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "PLUGIN_RUNTIME_MANIFEST_INVALID: runtime.sha256 is required".to_string())?
        .to_string();
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err("PLUGIN_RUNTIME_PATH_UNSAFE: runtime path escapes plugin root".to_string());
    }
    let source = root.join(relative_path);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|err| format!("PLUGIN_RUNTIME_INSPECTION_FAILED: {err}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(
            "PLUGIN_RUNTIME_PATH_UNSAFE: runtime must be a regular non-symlink file".to_string(),
        );
    }
    let canonical_source = fs::canonicalize(&source)
        .map_err(|err| format!("PLUGIN_RUNTIME_INSPECTION_FAILED: {err}"))?;
    if !canonical_source.starts_with(&root) {
        return Err("PLUGIN_RUNTIME_PATH_UNSAFE: runtime path escapes plugin root".to_string());
    }
    let installer = RuntimeInstaller::for_current_user().map_err(format_core_error)?;
    let stable = installer
        .layout()
        .current
        .join("bin")
        .join(plugin_runtime_executable_name());
    Ok(PluginPackageRuntime {
        plugin_version,
        runtime_version,
        channel,
        signing_state,
        target,
        sha256,
        source_executable: canonical_source,
        stable_executable: stable,
    })
}

fn validate_plugin_distribution(
    distribution_kind: &str,
    signing_state: &str,
    allow_unsigned_validation: bool,
) -> Result<(), String> {
    match (distribution_kind, signing_state) {
        ("release", "unsigned-release") => Ok(()),
        ("validation", "unsigned-validation") if allow_unsigned_validation => Ok(()),
        ("validation", "unsigned-validation") => Err(format!(
            "PLUGIN_PACKAGE_UNSIGNED_VALIDATION_ONLY: set {ALLOW_UNSIGNED_PLUGIN_ENV}=1 only in an isolated release-validation environment"
        )),
        _ => Err(
            "PLUGIN_RUNTIME_MANIFEST_INVALID: distributionKind and packageSigningState disagree"
                .to_string(),
        ),
    }
}

fn plugin_self_test_runtime_bytes(bytes: &[u8], expected_sha256: &str) -> Result<(), String> {
    if sha256_hex(bytes) != expected_sha256 {
        return Err(
            "PLUGIN_RUNTIME_CHECKSUM_MISMATCH: bundled runtime differs from the integrity manifest"
                .to_string(),
        );
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: random staging: {error}"))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let directory = env::temp_dir().join(format!("loomex-runtime-self-test-{suffix}"));
    fs::create_dir(&directory)
        .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: create staging: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: secure staging: {error}"))?;
    }
    let executable = directory.join(plugin_runtime_executable_name());
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&executable)
            .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: stage runtime: {error}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: stage runtime: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).map_err(
                |error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: secure runtime: {error}"),
            )?;
        }
        let status = Command::new(&executable)
            .arg("--help")
            .stdin(process::Stdio::null())
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .status()
            .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_FAILED: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "PLUGIN_RUNTIME_SELF_TEST_FAILED: bundled runtime exited with {status}"
            ))
        }
    })();
    let cleanup = fs::remove_dir_all(&directory)
        .map_err(|error| format!("PLUGIN_RUNTIME_SELF_TEST_CLEANUP_FAILED: {error}"));
    result.and(cleanup)
}

fn plugin_target_key() -> Result<String, String> {
    let platform = match env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        _ => {
            return Err(
                "LOCAL_CONTROL_PLATFORM_UNSUPPORTED: plugin runtime supports macOS and Linux"
                    .to_string(),
            )
        }
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => {
            return Err(format!(
                "PLUGIN_RUNTIME_TARGET_UNAVAILABLE: {}/{}",
                env::consts::OS,
                env::consts::ARCH
            ))
        }
    };
    Ok(format!("{platform}-{arch}"))
}

fn plugin_runtime_executable_name() -> &'static str {
    if cfg!(windows) {
        "loomex.exe"
    } else {
        "loomex"
    }
}

#[derive(Debug, Clone)]
struct PluginAuthFlow {
    login_id: String,
    profile: String,
    server_url: String,
    host_header: Option<String>,
    challenge: DeviceLoginChallenge,
    created_at_epoch_seconds: u64,
}

fn plugin_auth_status(options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let runner_credential = store.load(&resolved.profile).map_err(format_core_error)?;
    let user_credential = store
        .load(&user_credential_profile(&resolved.profile))
        .map_err(format_core_error)?;
    let now = current_epoch_seconds()?;
    let credential_status = |credential: Option<ManagementCredential>| match credential {
        Some(credential) => {
            match credential.validate_not_expiring(now, MANAGEMENT_TOKEN_CLOCK_SKEW_SECONDS) {
                Ok(()) => (
                    true,
                    Some(credential.expires_at),
                    credential.storage_warning,
                ),
                Err(error) => (
                    false,
                    Some(credential.expires_at),
                    Some(format_core_error(error)),
                ),
            }
        }
        None => (false, None, None),
    };
    let runner_credential_present = runner_credential.is_some();
    let runner_upgrade_reason = runner_credential
        .as_ref()
        .and_then(runner_credential_upgrade_reason);
    let (mut runner_authenticated, runner_expires_at, runner_warning) =
        credential_status(runner_credential);
    if runner_upgrade_reason.is_some() {
        runner_authenticated = false;
    }
    let (user_authenticated, user_expires_at, user_warning) = credential_status(user_credential);
    let warning = runner_upgrade_reason
        .map(|reason| format!("RUNNER_CREDENTIAL_UPGRADE_REQUIRED: {reason}"))
        .or(runner_warning)
        .or(user_warning);
    Ok(json!({
        "authenticated": runner_authenticated || user_authenticated,
        "userAuthenticated": user_authenticated,
        "runnerAuthenticated": runner_authenticated,
        "runnerCredentialPresent": runner_credential_present,
        "reauthRequired": runner_upgrade_reason.is_some(),
        "upgradeRequired": runner_upgrade_reason.is_some(),
        "reauthReason": runner_upgrade_reason,
        "profile": resolved.profile,
        "organizationId": resolved.organization_id,
        "projectId": resolved.project_id,
        "expiresAt": runner_expires_at.as_ref().or(user_expires_at.as_ref()),
        "userExpiresAt": user_expires_at,
        "runnerExpiresAt": runner_expires_at,
        "warning": warning,
    }))
}

fn plugin_auth_start(params: &Value, options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let mut overrides = options.config_overrides();
    if let Some(server_url) = params.get("serverUrl").and_then(Value::as_str) {
        overrides.server_url = Some(server_url.to_string());
    }
    let resolved = config
        .resolve(overrides, |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    if store
        .load(&resolved.profile)
        .map_err(format_core_error)?
        .is_some()
        || store
            .load(&user_credential_profile(&resolved.profile))
            .map_err(format_core_error)?
            .is_some()
    {
        return Err(
            "AUTH_LOGOUT_REQUIRED: logout before starting a new device authorization".to_string(),
        );
    }
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let challenge = client.start_device_login().map_err(format_core_error)?;
    let flow = allocate_plugin_auth_flow(PluginAuthFlow {
        login_id: String::new(),
        profile: resolved.profile,
        server_url: resolved.server_url,
        host_header: resolved.host_header,
        challenge: challenge.clone(),
        created_at_epoch_seconds: current_epoch_seconds()?,
    })?;
    Ok(json!({
        "loginId": flow.login_id,
        "verificationUri": challenge.verification_uri,
        "userCode": challenge.user_code,
        "expiresInSeconds": challenge.expires_in_seconds,
        "intervalSeconds": challenge.interval_seconds,
    }))
}

fn plugin_auth_wait(params: &Value, _options: &GlobalOptions) -> Result<Value, String> {
    let login_id = plugin_required_string(params, "loginId")?;
    let flow = read_plugin_auth_flow(login_id)?;
    let now = current_epoch_seconds()?;
    if now
        > flow
            .created_at_epoch_seconds
            .saturating_add(flow.challenge.expires_in_seconds)
    {
        remove_plugin_auth_flow(login_id)?;
        return Err("AUTH_DEVICE_FLOW_EXPIRED: start authentication again".to_string());
    }
    let requested_timeout = params
        .get("timeoutSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .clamp(1, 45);
    let remaining = flow
        .created_at_epoch_seconds
        .saturating_add(flow.challenge.expires_in_seconds)
        .saturating_sub(now);
    let timeout_seconds = requested_timeout.min(remaining.max(1));
    let mut client = HttpManagementApiClient::new(&flow.server_url, flow.host_header.clone())
        .map_err(format_core_error)?;
    let token = match poll_device_login(
        &mut client,
        &flow.challenge.device_code,
        flow.challenge.interval_seconds,
        timeout_seconds,
    ) {
        Ok(token) => token,
        Err(error) if error.starts_with("LOGIN_DEVICE_TIMEOUT:") => {
            return Ok(json!({
                "authenticated": false,
                "pending": true,
                "loginId": login_id,
            }));
        }
        Err(error) => return Err(error),
    };
    let config_path = cli_config_path();
    let store = SystemCredentialStore::new(credential_dir());
    let result = complete_plugin_auth_flow(&flow, token, &config_path, &store)?;
    remove_plugin_auth_flow(login_id)?;
    Ok(result)
}

fn complete_plugin_auth_flow<S: CredentialStore + ?Sized>(
    flow: &PluginAuthFlow,
    token: AuthTokenResponse,
    config_path: &Path,
    store: &S,
) -> Result<Value, String> {
    let mut config = load_cli_config_from(config_path)?;
    let configured_org = config
        .profiles
        .get(&flow.profile)
        .and_then(|profile| profile.organization_id.clone())
        .unwrap_or_default();
    let credential_profile = user_credential_profile(&flow.profile);
    let credential = ManagementCredential::from_user_token_response(
        &credential_profile,
        configured_org.clone(),
        token,
        CredentialStorageBackend::LocalFileFallback,
    )
    .map_err(format_core_error)?;
    let storage = store.save(&credential).map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{}.serverUrl", flow.profile),
            flow.server_url.clone(),
        )
        .map_err(format_core_error)?;
    if let Err(error) = config.save(config_path) {
        let _ = store.delete(&credential_profile);
        return Err(format_core_error(error));
    }
    Ok(json!({
        "authenticated": true,
        "userAuthenticated": true,
        "runnerAuthenticated": false,
        "pending": false,
        "profile": flow.profile,
        "serverUrl": flow.server_url,
        "organizationId": configured_org,
        "organizationSelectionRequired": configured_org.is_empty(),
        "expiresAt": credential.expires_at,
        "storageBackend": storage_backend_name(storage.backend),
        "storageWarning": storage.warning,
    }))
}

fn plugin_auth_flow_dir() -> Result<PathBuf, String> {
    Ok(RuntimeInstaller::for_current_user()
        .map_err(format_core_error)?
        .layout()
        .root
        .join("auth-flows"))
}

fn plugin_auth_flow_path(login_id: &str) -> Result<PathBuf, String> {
    if login_id.is_empty()
        || !login_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("AUTH_LOGIN_ID_INVALID: loginId is invalid".to_string());
    }
    Ok(plugin_auth_flow_dir()?.join(format!("{login_id}.json")))
}

fn allocate_plugin_auth_flow(mut flow: PluginAuthFlow) -> Result<PluginAuthFlow, String> {
    let directory = plugin_auth_flow_dir()?;
    allocate_plugin_auth_flow_in(&directory, &mut flow)
}

fn allocate_plugin_auth_flow_in(
    directory: &Path,
    flow: &mut PluginAuthFlow,
) -> Result<PluginAuthFlow, String> {
    fs::create_dir_all(directory).map_err(|err| format!("AUTH_FLOW_WRITE_FAILED: {err}"))?;
    set_cli_private_dir(directory)?;
    for _attempt in 0..16 {
        flow.login_id = random_plugin_login_id()?;
        if try_create_plugin_auth_flow_file(directory, flow)? {
            return Ok(flow.clone());
        }
    }
    Err("AUTH_FLOW_ID_ALLOCATION_FAILED: could not allocate a unique loginId".to_string())
}

fn random_plugin_login_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| format!("AUTH_FLOW_RANDOM_FAILED: {err}"))?;
    Ok(format!(
        "login-{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn try_create_plugin_auth_flow_file(
    directory: &Path,
    flow: &PluginAuthFlow,
) -> Result<bool, String> {
    let path = directory.join(format!("{}.json", flow.login_id));
    let payload = serde_json::to_vec(&json!({
        "loginId": flow.login_id,
        "profile": flow.profile,
        "serverUrl": flow.server_url,
        "hostHeader": flow.host_header,
        "challenge": flow.challenge,
        "createdAtEpochSeconds": flow.created_at_epoch_seconds,
    }))
    .map_err(|err| format!("AUTH_FLOW_WRITE_FAILED: {err}"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(format!("AUTH_FLOW_WRITE_FAILED: {error}")),
    };
    if let Err(error) = file
        .write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("AUTH_FLOW_WRITE_FAILED: {error}"))
    {
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    set_cli_private_file(&path)?;
    Ok(true)
}

fn read_plugin_auth_flow(login_id: &str) -> Result<PluginAuthFlow, String> {
    let path = plugin_auth_flow_path(login_id)?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|err| format!("AUTH_FLOW_NOT_FOUND: {err}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("AUTH_FLOW_PATH_UNSAFE: flow state must be a regular file".to_string());
    }
    validate_cli_private_file(&metadata)?;
    let value: Value = serde_json::from_slice(
        &fs::read(path).map_err(|err| format!("AUTH_FLOW_READ_FAILED: {err}"))?,
    )
    .map_err(|err| format!("AUTH_FLOW_INVALID: {err}"))?;
    let required = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("AUTH_FLOW_INVALID: {key} is required"))
    };
    Ok(PluginAuthFlow {
        login_id: required("loginId")?,
        profile: required("profile")?,
        server_url: required("serverUrl")?,
        host_header: value
            .get("hostHeader")
            .and_then(Value::as_str)
            .map(str::to_string),
        challenge: serde_json::from_value(
            value
                .get("challenge")
                .cloned()
                .ok_or_else(|| "AUTH_FLOW_INVALID: challenge is required".to_string())?,
        )
        .map_err(|err| format!("AUTH_FLOW_INVALID: {err}"))?,
        created_at_epoch_seconds: value
            .get("createdAtEpochSeconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| "AUTH_FLOW_INVALID: createdAtEpochSeconds is required".to_string())?,
    })
}

fn remove_plugin_auth_flow(login_id: &str) -> Result<(), String> {
    let path = plugin_auth_flow_path(login_id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("AUTH_FLOW_REMOVE_FAILED: {error}")),
    }
}

#[cfg(unix)]
fn set_cli_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("AUTH_FLOW_PERMISSIONS_FAILED: {err}"))
}

#[cfg(not(unix))]
fn set_cli_private_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_cli_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("AUTH_FLOW_PERMISSIONS_FAILED: {err}"))
}

#[cfg(not(unix))]
fn set_cli_private_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_cli_private_file(metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "AUTH_FLOW_PERMISSIONS_UNSAFE: flow state must be private to this user".to_string(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_cli_private_file(_metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

fn plugin_runner_control(params: &Value) -> Result<Value, String> {
    plugin_confirmed(params)?;
    if !cfg!(unix) {
        return Err("LOCAL_CONTROL_PLATFORM_UNSUPPORTED: runner service control currently requires macOS or Linux".to_string());
    }
    let action = plugin_required_string(params, "action")?;
    if !matches!(action, "start" | "stop" | "restart") {
        return Err(
            "RUNNER_CONTROL_ACTION_INVALID: action must be start, stop, or restart".to_string(),
        );
    }
    if action != "stop" {
        let readiness = plugin_service_bootstrap_readiness(&GlobalOptions::default())?;
        if readiness.get("ready").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "RUNNER_SERVICE_BOOTSTRAP_REQUIRED: {}",
                readiness
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("authenticate and create a workspace binding first")
            ));
        }
    }
    let options = RunnerServiceOptions::parse(&[], &GlobalOptions::default())?;
    let service_status = parse_json_output(run_runner_service_status(
        &[],
        &GlobalOptions {
            json: true,
            ..Default::default()
        },
    )?)?;
    let active = service_status
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let commands = plugin_service_control_commands(&options, action, active)?;
    let mut runner = OsServiceCommandRunner;
    let mut results = Vec::new();
    for command in &commands {
        let output = runner.run(command)?;
        results.push(json!({
            "program": command.program,
            "args": command.args,
            "success": output.success,
            "stdout": output.stdout,
            "stderr": output.stderr,
        }));
    }
    let health = if action == "stop" {
        plugin_invalidate_local_control_files()?;
        json!({"healthy": false, "status": "stopped"})
    } else {
        plugin_wait_for_local_control_health(20, Duration::from_millis(250))?
    };
    Ok(json!({
        "action": action,
        "success": true,
        "results": results,
        "health": health,
    }))
}

fn plugin_service_control_commands(
    options: &RunnerServiceOptions,
    action: &str,
    active: bool,
) -> Result<Vec<ServiceCommand>, String> {
    if action == "stop" && !active {
        return Ok(Vec::new());
    }
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            let domain = launchctl_user_domain();
            let path = default_service_install_path(options)?;
            match action {
                "start" if active => Ok(vec![ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "kickstart".to_string(),
                        "-k".to_string(),
                        format!("{domain}/{}", options.service_name),
                    ],
                }]),
                "start" => Ok(vec![
                    ServiceCommand {
                        program: "launchctl".to_string(),
                        args: vec![
                            "bootstrap".to_string(),
                            domain.clone(),
                            path.display().to_string(),
                        ],
                    },
                    ServiceCommand {
                        program: "launchctl".to_string(),
                        args: vec![
                            "kickstart".to_string(),
                            "-k".to_string(),
                            format!("{domain}/{}", options.service_name),
                        ],
                    },
                ]),
                "stop" => Ok(vec![ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "bootout".to_string(),
                        format!("{domain}/{}", options.service_name),
                    ],
                }]),
                "restart" if active => Ok(vec![ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "kickstart".to_string(),
                        "-k".to_string(),
                        format!("{domain}/{}", options.service_name),
                    ],
                }]),
                "restart" => plugin_service_control_commands(options, "start", false),
                _ => Err("RUNNER_CONTROL_ACTION_INVALID: unsupported action".to_string()),
            }
        }
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            let unit = format!("{}.service", options.service_name);
            match action {
                "start" => Ok(vec![systemctl_command(
                    options.platform,
                    &["enable", "--now", &unit],
                )]),
                "restart" if !active => plugin_service_control_commands(options, "start", false),
                "restart" | "stop" => {
                    Ok(vec![systemctl_command(options.platform, &[action, &unit])])
                }
                _ => Err("RUNNER_CONTROL_ACTION_INVALID: unsupported action".to_string()),
            }
        }
    }
}

fn plugin_stop_service_and_invalidate_local_control(
    options: &GlobalOptions,
) -> Result<Value, String> {
    let service = parse_json_output(run_runner_service_status(&[], options)?)?;
    let active = service
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !active && plugin_local_control_ping_once().is_ok() {
        return Err(
            "RUNNER_SERVICE_UNMANAGED_ACTIVE: a healthy local daemon is not owned by the configured service; stop it before changing identity or binding"
                .to_string(),
        );
    }
    let control = if active {
        Some(plugin_runner_control(&json!({
            "action": "stop",
            "confirm": true,
        }))?)
    } else {
        plugin_invalidate_local_control_files()?;
        None
    };
    Ok(json!({
        "runnerStopped": active,
        "localControlInvalidated": true,
        "control": control,
    }))
}

fn plugin_revoke_remote_runner_token(options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let Some(credential) = store.load(&resolved.profile).map_err(format_core_error)? else {
        return Ok(json!({"revoked": false, "reason": "runner token is not present"}));
    };
    let mut client = HttpManagementApiClient::new(&resolved.server_url, resolved.host_header)
        .map_err(format_core_error)?;
    client
        .revoke_current_runner_token(&credential)
        .map_err(format_core_error)
}

fn plugin_remote_revocation_outcome(result: Result<Value, String>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => json!({
            "revoked": false,
            "retryRequired": true,
            "warning": error,
        }),
    }
}

fn plugin_finalize_logout_result(
    mut result: Value,
    lifecycle: Value,
    remote_revocation: Value,
) -> Value {
    if let Some(object) = result.as_object_mut() {
        object.insert("serverRevokeAttempted".to_string(), json!(true));
        object.insert(
            "serverRevokeSucceeded".to_string(),
            json!(remote_revocation.get("revoked").and_then(Value::as_bool) == Some(true)),
        );
        object.insert("remoteTokenRevocation".to_string(), remote_revocation);
    }
    plugin_result_with_lifecycle(result, lifecycle)
}

fn plugin_transition_failure(error: String, options: &GlobalOptions) -> String {
    let recovery = plugin_activate_installed_service_after_bootstrap(options)
        .unwrap_or_else(|recovery_error| json!({"recovered": false, "error": recovery_error}));
    format!(
        "PLUGIN_CONTEXT_TRANSITION_FAILED: {error}; serviceRecovery={}",
        serde_json::to_string(&recovery).unwrap_or_else(|_| "unavailable".to_string())
    )
}

fn plugin_invalidate_local_control_files() -> Result<(), String> {
    let paths = LocalControlPaths::from_environment().map_err(format_core_error)?;
    plugin_invalidate_local_control_files_at(&paths)
}

fn plugin_invalidate_local_control_files_at(paths: &LocalControlPaths) -> Result<(), String> {
    for path in [&paths.socket_path, &paths.token_path] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "LOCAL_CONTROL_INVALIDATION_FAILED: {}: {error}",
                    path.display()
                ))
            }
        }
    }
    Ok(())
}

fn plugin_runner_status(options: &GlobalOptions) -> Result<Value, String> {
    let setup = plugin_setup_status(options)?;
    let auth = plugin_auth_status(options)?;
    let service_active = setup
        .pointer("/service/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let health = if service_active {
        plugin_local_control_ping_once().unwrap_or_else(
            |error| json!({"healthy": false, "status": "unavailable", "error": error}),
        )
    } else {
        json!({"healthy": false, "status": "inactive"})
    };
    Ok(plugin_runner_status_value(setup, auth, health))
}

fn plugin_runner_status_value(setup: Value, auth: Value, health: Value) -> Value {
    let service_active = setup
        .pointer("/service/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "running": service_active && health.get("healthy").and_then(Value::as_bool) == Some(true),
        "installed": setup.get("installed").and_then(Value::as_bool).unwrap_or(false),
        "runtimeVersion": setup.pointer("/runtime/version"),
        "runtime": setup.get("runtime"),
        "service": setup.get("service"),
        "auth": auth,
        "health": health,
        "connection": {
            "available": service_active,
            "status": if service_active { "service_active" } else { "service_inactive" },
        },
        "queue": {
            "available": false,
            "depth": null,
            "reason": "queue telemetry is not exposed by runner-control",
        },
        "activeExecutions": {
            "available": false,
            "count": null,
            "items": [],
            "reason": "active execution telemetry is not exposed by runner-control",
        },
        "updateHealth": {
            "available": false,
            "status": "unknown",
            "reason": "update telemetry is not exposed by runner-control",
        },
    })
}

fn plugin_service_bootstrap_readiness(options: &GlobalOptions) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let now = current_epoch_seconds()?;
    let runner_credential = store.load(&resolved.profile).map_err(format_core_error)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    Ok(plugin_service_bootstrap_readiness_with(
        &resolved,
        runner_credential.as_ref(),
        now,
        &mut client,
    ))
}

fn plugin_service_bootstrap_readiness_with<C: ManagementApiClient>(
    resolved: &loomex_core::ResolvedCliSettings,
    runner_credential: Option<&ManagementCredential>,
    now: u64,
    client: &mut C,
) -> Value {
    let (credential_ready, reauth_reason) =
        runner_credential_local_readiness(runner_credential, now);
    let missing_context = [
        ("organizationId", resolved.organization_id.as_deref()),
        ("projectId", resolved.project_id.as_deref()),
        ("runnerId", resolved.runner_id.as_deref()),
        ("bindingId", resolved.binding_id.as_deref()),
        ("workspacePath", resolved.workspace_path.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value
            .filter(|value| !value.trim().is_empty())
            .is_none()
            .then_some(name)
    })
    .collect::<Vec<_>>();
    let workspace_ready = resolved
        .workspace_path
        .as_deref()
        .is_some_and(|path| validate_workspace_path(path).is_ok());
    let identity = if credential_ready {
        match (
            runner_credential,
            resolved.organization_id.as_deref(),
            resolved.runner_id.as_deref(),
        ) {
            (Some(credential), Some(organization_id), Some(configured_runner_id)) => {
                match client.get_current_runner(credential, organization_id) {
                    Ok(runner) => json!({
                        "checked": true,
                        "matched": runner.id == configured_runner_id,
                        "configuredRunnerId": configured_runner_id,
                        "authenticatedRunnerId": runner.id,
                    }),
                    Err(error) => json!({
                        "checked": true,
                        "matched": null,
                        "configuredRunnerId": configured_runner_id,
                        "authenticatedRunnerId": null,
                        "error": {"code": error.code, "message": error.message},
                    }),
                }
            }
            _ => json!({
                "checked": false,
                "matched": null,
                "reason": "runner identity check waits for authentication and runner context",
            }),
        }
    } else {
        json!({
            "checked": false,
            "matched": null,
            "reason": "runner identity check waits for authentication",
        })
    };
    let identity_ready = identity.get("matched").and_then(Value::as_bool) == Some(true);
    let ready = credential_ready && missing_context.is_empty() && workspace_ready && identity_ready;
    let reason = if let Some(reason) = reauth_reason {
        reason
    } else if !credential_ready {
        "runner authentication is not established"
    } else if !missing_context.is_empty() {
        "organization, project, runner, binding, and workspace must be selected"
    } else if !workspace_ready {
        "selected workspace is not currently readable and writable"
    } else if identity.get("matched").and_then(Value::as_bool) == Some(false) {
        "authenticated runner does not match configured runnerId; recreate or reuse the exact binding for this runner"
    } else if !identity_ready {
        "authenticated runner identity could not be verified"
    } else {
        "bootstrap is complete"
    };
    json!({
        "ready": ready,
        "authenticated": credential_ready,
        "reauthRequired": reauth_reason.is_some(),
        "upgradeRequired": reauth_reason.is_some(),
        "reauthReason": reauth_reason,
        "missingContext": missing_context,
        "workspaceReady": workspace_ready,
        "identity": identity,
        "reason": reason,
    })
}

fn plugin_activate_installed_service_after_bootstrap(
    options: &GlobalOptions,
) -> Result<Value, String> {
    let service = parse_json_output(run_runner_service_status(&[], options)?)?;
    if service.get("installed").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "attempted": false,
            "healthy": false,
            "status": "not_installed",
        }));
    }
    let readiness = plugin_service_bootstrap_readiness(options)?;
    if readiness.get("ready").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "attempted": false,
            "healthy": false,
            "status": "waiting_for_bootstrap",
            "readiness": readiness,
        }));
    }
    let action = if service.get("active").and_then(Value::as_bool) == Some(true) {
        "restart"
    } else {
        "start"
    };
    let control = plugin_runner_control(&json!({"action": action, "confirm": true}))?;
    Ok(json!({
        "attempted": true,
        "healthy": control
            .pointer("/health/healthy")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "status": "activated",
        "action": action,
        "control": control,
    }))
}

fn plugin_wait_for_local_control_health(
    attempts: usize,
    retry_delay: Duration,
) -> Result<Value, String> {
    let mut last_error = "local control service did not become ready".to_string();
    for attempt in 1..=attempts.max(1) {
        match plugin_local_control_ping_once() {
            Ok(mut health) => {
                if let Some(object) = health.as_object_mut() {
                    object.insert("attempts".to_string(), json!(attempt));
                }
                return Ok(health);
            }
            Err(error) => last_error = error,
        }
        if attempt < attempts {
            thread::sleep(retry_delay);
        }
    }
    Err(format!("RUNNER_SERVICE_HEALTHCHECK_FAILED: {last_error}"))
}

#[cfg(unix)]
fn plugin_local_control_ping_once() -> Result<Value, String> {
    let paths = LocalControlPaths::from_environment().map_err(format_core_error)?;
    plugin_local_control_ping_once_at(&paths)
}

#[cfg(unix)]
fn plugin_local_control_ping_once_at(paths: &LocalControlPaths) -> Result<Value, String> {
    use std::os::unix::net::UnixStream;

    let token = read_local_control_token(paths).map_err(format_core_error)?;
    let mut stream = UnixStream::connect(&paths.socket_path)
        .map_err(|error| format!("LOCAL_CONTROL_CONNECT_FAILED: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(1))))
        .map_err(|error| format!("LOCAL_CONTROL_TIMEOUT_FAILED: {error}"))?;
    let request_id = format!("health-{}", std::process::id());
    let request = LocalControlRequest {
        protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION.to_string(),
        id: request_id.clone(),
        auth_token: token,
        method: "ping".to_string(),
        params: json!({}),
    };
    serde_json::to_writer(&mut stream, &request)
        .map_err(|error| format!("LOCAL_CONTROL_REQUEST_FAILED: {error}"))?;
    stream
        .write_all(b"\n")
        .and_then(|_| stream.flush())
        .map_err(|error| format!("LOCAL_CONTROL_REQUEST_FAILED: {error}"))?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| format!("LOCAL_CONTROL_RESPONSE_FAILED: {error}"))?;
    let response: LocalControlResponse = serde_json::from_str(&line)
        .map_err(|error| format!("LOCAL_CONTROL_RESPONSE_INVALID: {error}"))?;
    if response.protocol_version != LOCAL_CONTROL_PROTOCOL_VERSION
        || response.id != request_id
        || !response.ok
        || response
            .result
            .as_ref()
            .and_then(|result| result.get("pong"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("LOCAL_CONTROL_HEALTHCHECK_INVALID: ping response was not healthy".to_string());
    }
    Ok(json!({
        "healthy": true,
        "status": "ok",
        "protocolVersion": LOCAL_CONTROL_PROTOCOL_VERSION,
    }))
}

#[cfg(not(unix))]
fn plugin_local_control_ping_once() -> Result<Value, String> {
    Err("LOCAL_CONTROL_PLATFORM_UNSUPPORTED: health check requires macOS or Linux".to_string())
}

fn run_runner_ops(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(RUNNER_OPS_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "readiness-plan" => {
            let expected_runners = option_value_optional(rest, "--expected-runners")
                .map(|value| {
                    value.parse::<u64>().map_err(|_| {
                        "OPERATIONAL_READINESS_INPUT_INVALID: --expected-runners must be an integer"
                            .to_string()
                    })
                })
                .transpose()?
                .unwrap_or(10_000);
            let plan = loomex_core::official_operational_readiness_plan(expected_runners);
            loomex_core::validate_operational_readiness_plan(&plan).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.operationalReadinessPlan/v1",
                    "plan": plan
                })
                .to_string());
            }
            serde_json::to_string_pretty(&plan).map_err(|err| err.to_string())
        }
        [subcommand, rest @ ..] if subcommand == "release-gate" => {
            let report_path = option_value(rest, "--report")?;
            let report = read_operational_readiness_report(Path::new(&report_path))?;
            let decision =
                loomex_core::evaluate_release_gate(&report).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.operationalReleaseGate/v1",
                    "decision": decision
                })
                .to_string());
            }
            if decision.allowed {
                Ok("operational release gate passed".to_string())
            } else {
                Ok(format!(
                    "operational release gate blocked:\n{}",
                    decision.blockers.join("\n")
                ))
            }
        }
        [subcommand] if subcommand == "enterprise-plan" => {
            let plan = loomex_core::official_enterprise_acceptance_plan();
            loomex_core::validate_enterprise_acceptance_plan(&plan).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.enterpriseAcceptancePlan/v1",
                    "plan": plan
                })
                .to_string());
            }
            serde_json::to_string_pretty(&plan).map_err(|err| err.to_string())
        }
        [subcommand, rest @ ..] if subcommand == "enterprise-signoff" => {
            let report_path = option_value(rest, "--report")?;
            let report = read_enterprise_acceptance_report(Path::new(&report_path))?;
            let decision = loomex_core::evaluate_enterprise_acceptance_report(&report)
                .map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.enterpriseAcceptanceSignoff/v1",
                    "decision": decision
                })
                .to_string());
            }
            if decision.allowed {
                Ok("enterprise acceptance sign-off passed".to_string())
            } else {
                Ok(format!(
                    "enterprise acceptance sign-off blocked:\n{}",
                    decision.blockers.join("\n")
                ))
            }
        }
        [subcommand, ..] => Err(format!(
            "unknown runner ops subcommand: {subcommand}\n{RUNNER_OPS_HELP}"
        )),
        [] => Ok(RUNNER_OPS_HELP.to_string()),
    }
}

fn read_enterprise_acceptance_report(
    path: &Path,
) -> Result<loomex_core::EnterpriseAcceptanceReport, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("ENTERPRISE_ACCEPTANCE_REPORT_READ_FAILED: {err}"))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("ENTERPRISE_ACCEPTANCE_REPORT_JSON_INVALID: {err}"))
}

fn read_operational_readiness_report(
    path: &Path,
) -> Result<loomex_core::OperationalReadinessReport, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("OPERATIONAL_READINESS_REPORT_READ_FAILED: {err}"))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("OPERATIONAL_READINESS_REPORT_JSON_INVALID: {err}"))
}

fn run_runner_start(options: &GlobalOptions) -> Result<String, String> {
    let config_path = cli_config_path();
    run_runner_start_with_config_path(options, &config_path)
}

fn run_runner_release(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(RUNNER_RELEASE_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "sign-manifest" => {
            let manifest_path = option_value(rest, "--manifest")?;
            let signing_key = release_signing_key(rest)?;
            let manifest = read_release_manifest(Path::new(&manifest_path))?;
            let signed = loomex_core::sign_release_manifest(manifest, &signing_key)
                .map_err(format_core_error)?;
            let encoded = serde_json::to_string_pretty(&signed).map_err(|err| err.to_string())?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseSignManifest/v1",
                    "manifest": signed
                })
                .to_string());
            }
            Ok(encoded)
        }
        [subcommand, rest @ ..] if subcommand == "verify-manifest" => {
            let manifest_path = option_value(rest, "--manifest")?;
            let public_key = option_value(rest, "--public-key")?;
            let manifest = read_release_manifest(Path::new(&manifest_path))?;
            loomex_core::verify_release_manifest(&manifest, &public_key)
                .map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseVerifyManifest/v1",
                    "verified": true,
                    "version": manifest.version,
                    "channel": manifest.channel
                })
                .to_string());
            }
            Ok(format!("release manifest verified: {}", manifest.version))
        }
        [subcommand, rest @ ..] if subcommand == "sign-artifact" => {
            let name = option_value(rest, "--name")?;
            let os = option_value(rest, "--os")?;
            let arch = option_value(rest, "--arch")?;
            let path = option_value(rest, "--path")?;
            let signing_key = release_signing_key(rest)?;
            let bytes =
                fs::read(&path).map_err(|err| format!("RELEASE_ARTIFACT_READ_FAILED: {err}"))?;
            let artifact = loomex_core::sign_release_artifact(name, os, arch, &bytes, &signing_key)
                .map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseSignArtifact/v1",
                    "artifact": artifact
                })
                .to_string());
            }
            serde_json::to_string_pretty(&artifact).map_err(|err| err.to_string())
        }
        [subcommand, rest @ ..] if subcommand == "verify-artifact" => {
            let manifest_path = option_value(rest, "--manifest")?;
            let artifact_name = option_value(rest, "--name")?;
            let path = option_value(rest, "--path")?;
            let public_key = option_value(rest, "--public-key")?;
            let manifest = read_release_manifest(Path::new(&manifest_path))?;
            loomex_core::verify_release_manifest(&manifest, &public_key)
                .map_err(format_core_error)?;
            let artifact = manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.name == artifact_name)
                .ok_or_else(|| format!("RELEASE_ARTIFACT_NOT_FOUND: {artifact_name}"))?;
            let bytes =
                fs::read(&path).map_err(|err| format!("RELEASE_ARTIFACT_READ_FAILED: {err}"))?;
            loomex_core::verify_release_artifact(artifact, &bytes, &public_key)
                .map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseVerifyArtifact/v1",
                    "verified": true,
                    "artifact": artifact.name,
                    "sha256": artifact.sha256
                })
                .to_string());
            }
            Ok(format!("release artifact verified: {}", artifact.name))
        }
        [subcommand, rest @ ..] if subcommand == "sbom" => {
            let packages = parse_sbom_packages(rest)?;
            let sbom = loomex_core::generate_sbom(packages).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseSbom/v1",
                    "packages": sbom
                })
                .to_string());
            }
            serde_json::to_string_pretty(&sbom).map_err(|err| err.to_string())
        }
        [subcommand, rest @ ..] if subcommand == "installer-plan" => {
            let version = option_value_optional(rest, "--version")
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
            let plan = loomex_core::official_release_distribution_plan(&version);
            loomex_core::validate_release_distribution_plan(&plan).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseInstallerPlan/v1",
                    "plan": plan
                })
                .to_string());
            }
            serde_json::to_string_pretty(&plan).map_err(|err| err.to_string())
        }
        [subcommand, rest @ ..] if subcommand == "validate-compatibility" => {
            let matrix_path = option_value(rest, "--matrix")?;
            let matrix = read_release_compatibility_matrix(Path::new(&matrix_path))?;
            loomex_core::validate_compatibility_matrix(&matrix).map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.releaseCompatibilityValidation/v1",
                    "valid": true,
                    "entries": matrix.entries.len()
                })
                .to_string());
            }
            Ok(format!(
                "release compatibility matrix verified: {} entries",
                matrix.entries.len()
            ))
        }
        [subcommand, ..] => Err(format!(
            "unknown runner release subcommand: {subcommand}\n{RUNNER_RELEASE_HELP}"
        )),
        [] => Ok(RUNNER_RELEASE_HELP.to_string()),
    }
}

fn read_release_manifest(path: &Path) -> Result<loomex_core::ReleaseManifest, String> {
    let content =
        fs::read_to_string(path).map_err(|err| format!("RELEASE_MANIFEST_READ_FAILED: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("RELEASE_MANIFEST_JSON_INVALID: {err}"))
}

fn read_release_compatibility_matrix(
    path: &Path,
) -> Result<loomex_core::ReleaseCompatibilityMatrix, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("RELEASE_COMPATIBILITY_READ_FAILED: {err}"))?;
    serde_json::from_str(&content)
        .map_err(|err| format!("RELEASE_COMPATIBILITY_JSON_INVALID: {err}"))
}

fn release_signing_key(args: &[String]) -> Result<String, String> {
    if args.iter().any(|arg| arg == "--signing-key") {
        return Err(
            "RELEASE_SIGNING_KEY_ARG_UNSAFE: use --signing-key-env, --signing-key-file, or --signing-key-stdin"
                .to_string(),
        );
    }
    let env_name = option_value_optional(args, "--signing-key-env");
    let file_path = option_value_optional(args, "--signing-key-file");
    let stdin_requested = args.iter().any(|arg| arg == "--signing-key-stdin");
    let method_count = usize::from(env_name.is_some())
        + usize::from(file_path.is_some())
        + usize::from(stdin_requested);
    if method_count == 0 {
        return Err(
            "RELEASE_SIGNING_KEY_INPUT_REQUIRED: use --signing-key-env, --signing-key-file, or --signing-key-stdin"
                .to_string(),
        );
    }
    if method_count > 1 {
        return Err(
            "RELEASE_SIGNING_KEY_INPUT_AMBIGUOUS: use exactly one signing key input method"
                .to_string(),
        );
    }
    if let Some(name) = env_name {
        return env::var(name.trim())
            .map(|value| value.trim().to_string())
            .map_err(|_| {
                "RELEASE_SIGNING_KEY_ENV_MISSING: signing key environment variable is not set"
                    .to_string()
            });
    }
    if let Some(path) = file_path {
        return fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(|err| format!("RELEASE_SIGNING_KEY_FILE_READ_FAILED: {err}"));
    }
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .map_err(|err| format!("RELEASE_SIGNING_KEY_STDIN_READ_FAILED: {err}"))?;
    Ok(value.trim().to_string())
}

fn option_value(args: &[String], name: &str) -> Result<String, String> {
    option_value_optional(args, name).ok_or_else(|| format!("RELEASE_OPTION_REQUIRED: {name}"))
}

fn option_value_optional(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn parse_sbom_packages(args: &[String]) -> Result<Vec<SbomPackage>, String> {
    let mut packages = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--package" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "RELEASE_SBOM_PACKAGE_REQUIRED: --package requires name=version".to_string()
                })?;
                let (name, version) = value.split_once('=').ok_or_else(|| {
                    "RELEASE_SBOM_PACKAGE_INVALID: package must be name=version".to_string()
                })?;
                packages.push(SbomPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    license: None,
                });
                index += 2;
            }
            value => return Err(format!("unknown runner release sbom option: {value}")),
        }
    }
    Ok(packages)
}

fn run_runner_start_with_config_path(
    options: &GlobalOptions,
    config_path: &Path,
) -> Result<String, String> {
    let config = load_cli_config_from(config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let Some(binding_id) = resolved.binding_id.as_deref() else {
        return parsed_stub("runner start", &[], options);
    };
    let guard = acquire_runner_runtime_guard(config_path, binding_id, "loomex-cli")
        .map_err(format_core_error)?;
    let guard_path = guard.persist();
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerStart/v1",
            "started": true,
            "profile": resolved.profile.clone(),
            "bindingId": binding_id,
            "guardPath": guard_path
        })
        .to_string());
    }
    Ok(format!(
        "runner start guard acquired\nbinding: {binding_id}\nguard: {}",
        guard_path.display()
    ))
}

fn run_runner_stop(options: &GlobalOptions) -> Result<String, String> {
    let config_path = cli_config_path();
    run_runner_stop_with_config_path(options, &config_path)
}

fn run_runner_stop_with_config_path(
    options: &GlobalOptions,
    config_path: &Path,
) -> Result<String, String> {
    let config = load_cli_config_from(config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let Some(binding_id) = resolved.binding_id.as_deref() else {
        return parsed_stub("runner stop", &[], options);
    };
    let guard_path = runner_runtime_guard_path(config_path, binding_id);
    release_runner_runtime_guard_for_surface(&guard_path, binding_id, "loomex-cli")
        .map_err(format_core_error)?;
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerStop/v1",
            "stopped": true,
            "profile": resolved.profile.clone(),
            "bindingId": binding_id,
            "guardPath": guard_path
        })
        .to_string());
    }
    Ok(format!(
        "runner start guard released\nbinding: {binding_id}\nguard: {}",
        guard_path.display()
    ))
}

fn run_runner_service(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(RUNNER_SERVICE_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "unit" => run_runner_service_unit(rest, options),
        [subcommand, rest @ ..] if subcommand == "install" => {
            run_runner_service_install(rest, options)
        }
        [subcommand, rest @ ..] if subcommand == "uninstall" => {
            run_runner_service_uninstall(rest, options)
        }
        [subcommand, rest @ ..] if subcommand == "status" => {
            run_runner_service_status(rest, options)
        }
        [subcommand, rest @ ..] if subcommand == "run" => run_runner_service_run(rest, options),
        [subcommand, ..] => Err(format!(
            "unknown runner service subcommand: {subcommand}\n{RUNNER_SERVICE_HELP}"
        )),
        [] => Ok(RUNNER_SERVICE_HELP.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerServiceOptions {
    platform: RunnerServicePlatform,
    service_name: String,
    binary_path: PathBuf,
    config_path: PathBuf,
    profile: Option<String>,
    log_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    uninstall_output_path: Option<PathBuf>,
    dry_run: bool,
    once: bool,
    defer_start: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceCommand {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceCommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait ServiceCommandRunner {
    fn run(&mut self, command: &ServiceCommand) -> Result<ServiceCommandOutput, String>;
}

struct OsServiceCommandRunner;

impl ServiceCommandRunner for OsServiceCommandRunner {
    fn run(&mut self, command: &ServiceCommand) -> Result<ServiceCommandOutput, String> {
        let output = Command::new(&command.program)
            .args(&command.args)
            .output()
            .map_err(|err| format!("RUNNER_SERVICE_COMMAND_FAILED: {err}"))?;
        let result = ServiceCommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        };
        if result.success {
            Ok(result)
        } else {
            Err(format!(
                "RUNNER_SERVICE_COMMAND_FAILED: {} {} failed: {}",
                command.program,
                command.args.join(" "),
                if result.stderr.is_empty() {
                    result.stdout.clone()
                } else {
                    result.stderr.clone()
                }
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StrictServiceState {
    installed: bool,
    enabled: bool,
    active: bool,
}

trait TransactionServiceStatusProbe {
    fn probe(&mut self, options: &RunnerServiceOptions) -> Result<StrictServiceState, String>;
}

struct OsTransactionServiceStatusProbe;

impl TransactionServiceStatusProbe for OsTransactionServiceStatusProbe {
    fn probe(&mut self, options: &RunnerServiceOptions) -> Result<StrictServiceState, String> {
        let path = default_service_install_path(options)?;
        let file_installed = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(format!(
                    "PLUGIN_SETUP_SERVICE_PROBE_UNSAFE: {} is not a regular service file",
                    path.display()
                ));
            }
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!("PLUGIN_SETUP_SERVICE_PROBE_FAILED: {error}"));
            }
        };
        match options.platform {
            RunnerServicePlatform::MacOsLaunchAgent => {
                let command = ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "print".to_string(),
                        format!("{}/{}", launchctl_user_domain(), options.service_name),
                    ],
                };
                let active = strict_probe_command(&command, StrictProbeKind::LaunchctlLoaded)?;
                Ok(StrictServiceState {
                    installed: file_installed || active,
                    enabled: file_installed || active,
                    active,
                })
            }
            RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
                let unit = format!("{}.service", options.service_name);
                let active = strict_probe_command(
                    &systemctl_command(options.platform, &["is-active", &unit]),
                    StrictProbeKind::SystemdActive,
                )?;
                let enabled = strict_probe_command(
                    &systemctl_command(options.platform, &["is-enabled", &unit]),
                    StrictProbeKind::SystemdEnabled,
                )?;
                Ok(StrictServiceState {
                    installed: file_installed || active || enabled,
                    enabled,
                    active,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum StrictProbeKind {
    LaunchctlLoaded,
    SystemdActive,
    SystemdEnabled,
}

fn strict_probe_command(command: &ServiceCommand, kind: StrictProbeKind) -> Result<bool, String> {
    let output = Command::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|error| format!("PLUGIN_SETUP_SERVICE_PROBE_FAILED: {error}"))?;
    let code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    let stderr = String::from_utf8_lossy(&output.stderr)
        .trim()
        .to_ascii_lowercase();
    classify_strict_probe_output(output.status.success(), code, &stdout, &stderr, kind).map_err(
        |detail| {
            format!(
                "PLUGIN_SETUP_SERVICE_PROBE_FAILED: {} {} exited {:?}: {detail}",
                command.program,
                command.args.join(" "),
                code,
            )
        },
    )
}

fn classify_strict_probe_output(
    success: bool,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    kind: StrictProbeKind,
) -> Result<bool, String> {
    match kind {
        StrictProbeKind::LaunchctlLoaded if success => Ok(true),
        StrictProbeKind::LaunchctlLoaded
            if code == Some(113)
                || stderr.contains("could not find service")
                || stderr.contains("service not found") =>
        {
            Ok(false)
        }
        StrictProbeKind::SystemdActive
            if success && matches!(stdout, "active" | "activating" | "reloading") =>
        {
            Ok(true)
        }
        StrictProbeKind::SystemdActive
            if code == Some(3) && matches!(stdout, "inactive" | "failed" | "deactivating")
                || code == Some(4) && stdout == "unknown" =>
        {
            Ok(false)
        }
        StrictProbeKind::SystemdEnabled
            if success
                && matches!(
                    stdout,
                    "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias"
                ) =>
        {
            Ok(true)
        }
        StrictProbeKind::SystemdEnabled
            if (success || code == Some(1))
                && matches!(
                    stdout,
                    "disabled" | "static" | "indirect" | "masked" | "generated" | "transient"
                )
                || code == Some(4) && matches!(stdout, "not-found" | "unknown") =>
        {
            Ok(false)
        }
        _ => Err(if stderr.is_empty() {
            if stdout.is_empty() {
                "service manager returned no diagnostic".to_string()
            } else {
                stdout.to_string()
            }
        } else {
            stderr.to_string()
        }),
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerServiceRuntimeConfig {
    profile: String,
    organization_id: String,
    project_id: String,
    runner_id: String,
    binding_id: String,
    local_root_path: String,
    runner_device_id: String,
    stream_credential: StreamCredentialResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerServiceRuntimeStart {
    transport: String,
    event: String,
    fallback: bool,
}

#[allow(dead_code)]
trait RunnerServiceRuntimeLauncher {
    fn start_once(
        &mut self,
        config: RunnerServiceRuntimeConfig,
    ) -> Result<RunnerServiceRuntimeStart, String>;
    fn run_until_disconnect(&mut self, config: RunnerServiceRuntimeConfig) -> Result<(), String>;
}

struct DefaultRunnerServiceRuntimeLauncher;

impl RunnerServiceRuntimeLauncher for DefaultRunnerServiceRuntimeLauncher {
    fn start_once(
        &mut self,
        config: RunnerServiceRuntimeConfig,
    ) -> Result<RunnerServiceRuntimeStart, String> {
        run_service_transport_once(config)
    }

    fn run_until_disconnect(&mut self, config: RunnerServiceRuntimeConfig) -> Result<(), String> {
        run_service_transport_until_disconnect(config)
    }
}

impl RunnerServiceOptions {
    fn parse(args: &[String], options: &GlobalOptions) -> Result<Self, String> {
        let mut service_options = Self {
            platform: RunnerServicePlatform::current().map_err(format_core_error)?,
            service_name: "loomex-runner".to_string(),
            binary_path: env::current_exe().unwrap_or_else(|_| PathBuf::from("loomex")),
            config_path: cli_config_path(),
            profile: options.profile.clone(),
            log_path: None,
            output_path: None,
            uninstall_output_path: None,
            dry_run: false,
            once: false,
            defer_start: false,
        };
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--platform" => {
                    index += 1;
                    service_options.platform =
                        RunnerServicePlatform::parse(&required_value(args, index, "--platform")?)
                            .map_err(format_core_error)?;
                }
                "--name" => {
                    index += 1;
                    service_options.service_name = required_value(args, index, "--name")?;
                }
                "--binary" => {
                    index += 1;
                    service_options.binary_path =
                        PathBuf::from(required_value(args, index, "--binary")?);
                }
                "--config" => {
                    index += 1;
                    service_options.config_path =
                        PathBuf::from(required_value(args, index, "--config")?);
                }
                "--profile" => {
                    index += 1;
                    service_options.profile = Some(required_value(args, index, "--profile")?);
                }
                "--log-path" => {
                    index += 1;
                    service_options.log_path =
                        Some(PathBuf::from(required_value(args, index, "--log-path")?));
                }
                "--output" => {
                    index += 1;
                    service_options.output_path =
                        Some(PathBuf::from(required_value(args, index, "--output")?));
                }
                "--uninstall-output" => {
                    index += 1;
                    service_options.uninstall_output_path = Some(PathBuf::from(required_value(
                        args,
                        index,
                        "--uninstall-output",
                    )?));
                }
                "--dry-run" => service_options.dry_run = true,
                "--once" => service_options.once = true,
                "--defer-start" => service_options.defer_start = true,
                value => return Err(format!("unknown runner service option: {value}")),
            }
            index += 1;
        }
        Ok(service_options)
    }

    fn spec(&self) -> RunnerServiceSpec {
        RunnerServiceSpec {
            service_name: self.service_name.clone(),
            binary_path: self.binary_path.clone(),
            config_path: self.config_path.clone(),
            profile: self.profile.clone(),
            log_path: self.log_path.clone(),
            working_directory: None,
        }
    }
}

fn run_runner_service_unit(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let service_options = RunnerServiceOptions::parse(args, options)?;
    let manifest = service_options
        .spec()
        .render(service_options.platform)
        .map_err(format_core_error)?;
    format_runner_service_manifest(&manifest, options)
}

fn run_runner_service_install(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let mut runner = OsServiceCommandRunner;
    run_runner_service_install_with_runner(args, options, &mut runner)
}

fn run_runner_service_install_with_runner(
    args: &[String],
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<String, String> {
    run_runner_service_install_with_runner_and_path(args, options, runner, None)
}

fn run_runner_service_install_with_runner_and_path(
    args: &[String],
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
    default_install_path_override: Option<&Path>,
) -> Result<String, String> {
    let service_options = RunnerServiceOptions::parse(args, options)?;
    let manifest = service_options
        .spec()
        .render(service_options.platform)
        .map_err(format_core_error)?;
    let mut written = Vec::new();
    let artifact_only = service_install_is_artifact_only(&service_options);
    let commands = if artifact_only {
        Vec::new()
    } else if service_options.defer_start {
        service_deferred_install_commands(&service_options)?
    } else {
        service_install_commands(&service_options)?
    };
    let command_plan = command_plan_json(&commands);
    if !service_options.dry_run {
        if let Some(path) = &service_options.output_path {
            write_service_file(path, &manifest.content)?;
            written.push(path.display().to_string());
        } else if matches!(
            service_options.platform,
            RunnerServicePlatform::MacOsLaunchAgent
                | RunnerServicePlatform::LinuxUserSystemd
                | RunnerServicePlatform::LinuxSystemSystemd
        ) {
            let path = default_install_path_override
                .map(Path::to_path_buf)
                .map(Ok)
                .unwrap_or_else(|| default_service_install_path(&service_options))?;
            write_service_file(&path, &manifest.content)?;
            written.push(path.display().to_string());
        }
        if let (Some(path), Some(content)) = (
            &service_options.uninstall_output_path,
            &manifest.uninstall_content,
        ) {
            write_service_file(path, content)?;
            written.push(path.display().to_string());
        }
        for command in &commands {
            runner.run(command)?;
        }
    }
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerServiceInstall/v1",
            "platform": manifest.platform.as_str(),
            "serviceName": service_options.service_name,
            "dryRun": service_options.dry_run,
            "artifactOnly": artifact_only,
            "deferredStart": service_options.defer_start,
            "installPath": manifest.install_path,
            "written": written,
            "commands": command_plan,
            "manifest": manifest.content,
            "uninstallManifest": manifest.uninstall_content
        })
        .to_string());
    }
    if service_options.dry_run {
        return Ok(manifest.content);
    }
    Ok(format!(
        "runner service install artifacts written:\n{}",
        written.join("\n")
    ))
}

fn run_runner_service_uninstall(
    args: &[String],
    options: &GlobalOptions,
) -> Result<String, String> {
    let mut runner = OsServiceCommandRunner;
    run_runner_service_uninstall_with_runner(args, options, &mut runner)
}

fn run_runner_service_uninstall_with_runner(
    args: &[String],
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<String, String> {
    let service_options = RunnerServiceOptions::parse(args, options)?;
    let manifest = service_options
        .spec()
        .render(service_options.platform)
        .map_err(format_core_error)?;
    let mut removed = Vec::new();
    let commands = service_uninstall_commands(&service_options)?;
    let command_plan = command_plan_json(&commands);
    if !service_options.dry_run {
        for command in &commands {
            runner.run(command)?;
        }
        if matches!(
            service_options.platform,
            RunnerServicePlatform::MacOsLaunchAgent
                | RunnerServicePlatform::LinuxUserSystemd
                | RunnerServicePlatform::LinuxSystemSystemd
        ) {
            let path = default_service_install_path(&service_options)?;
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|err| format!("RUNNER_SERVICE_UNINSTALL_FAILED: {err}"))?;
                removed.push(path.display().to_string());
            }
        } else if let Some(path) = &service_options.output_path {
            if let Some(content) = &manifest.uninstall_content {
                write_service_file(path, content)?;
                removed.push(path.display().to_string());
            }
        }
    }
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerServiceUninstall/v1",
            "platform": manifest.platform.as_str(),
            "serviceName": service_options.service_name,
            "dryRun": service_options.dry_run,
            "removed": removed,
            "commands": command_plan,
            "uninstallManifest": manifest.uninstall_content
        })
        .to_string());
    }
    if service_options.dry_run {
        return Ok(manifest
            .uninstall_content
            .unwrap_or_else(|| format!("remove {}", manifest.install_path)));
    }
    Ok(format!(
        "runner service uninstall complete: {}",
        removed.join("\n")
    ))
}

fn run_runner_service_status(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let mut runner = OsServiceCommandRunner;
    run_runner_service_status_with_runner(args, options, &mut runner)
}

fn run_runner_service_status_with_runner(
    args: &[String],
    options: &GlobalOptions,
    runner: &mut dyn ServiceCommandRunner,
) -> Result<String, String> {
    let service_options = RunnerServiceOptions::parse(args, options)?;
    let unit_path = default_service_install_path(&service_options).ok();
    let commands = service_status_commands(&service_options)?;
    let command_plan = command_plan_json(&commands);
    let mut command_results = Vec::new();
    if !service_options.dry_run {
        for command in &commands {
            match runner.run(command) {
                Ok(output) => command_results.push(json!({
                    "program": command.program,
                    "args": command.args,
                    "success": output.success,
                    "stdout": output.stdout,
                    "stderr": output.stderr
                })),
                Err(err) => command_results.push(json!({
                    "program": command.program,
                    "args": command.args,
                    "success": false,
                    "error": err
                })),
            }
        }
    }
    let active = !service_options.dry_run
        && command_results
            .first()
            .and_then(|result| result.get("success"))
            .and_then(Value::as_bool)
            == Some(true);
    let enabled = match service_options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            unit_path.as_ref().is_some_and(|path| path.exists()) || active
        }
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            !service_options.dry_run
                && command_results
                    .get(1)
                    .and_then(|result| result.get("success"))
                    .and_then(Value::as_bool)
                    == Some(true)
        }
    };
    let installed = unit_path.as_ref().is_some_and(|path| path.exists()) || active || enabled;
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerServiceStatus/v1",
            "platform": service_options.platform.as_str(),
            "serviceName": service_options.service_name,
            "installed": installed,
            "active": active,
            "enabled": enabled,
            "path": unit_path,
            "commands": command_plan,
            "results": command_results
        })
        .to_string());
    }
    Ok(format!(
        "runner service {} ({})",
        if installed {
            "installed"
        } else {
            "not installed"
        },
        unit_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "windows script mode".to_string())
    ))
}

fn run_runner_service_run(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let store = SystemCredentialStore::new(credential_dir());
    let mut launcher = DefaultRunnerServiceRuntimeLauncher;
    let mut service_options = RunnerServiceOptions::parse(args, options)?;
    if service_options.log_path.is_none() {
        service_options.log_path = Some(default_log_path());
    }
    let config = load_cli_config_from(&service_options.config_path)?;
    let resolved = config
        .resolve(
            CliConfigOverrides {
                profile: service_options.profile.clone(),
                server_url: options.server_url.clone(),
                host_header: options.host_header.clone(),
            },
            |key| env::var(key).ok(),
        )
        .map_err(format_core_error)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    if !service_options.once {
        let credential = load_credential(&store, &resolved.profile)?;
        start_local_control_server(
            client.clone(),
            credential,
            &resolved,
            service_options.log_path.clone(),
        )?;
    }
    run_runner_service_run_parsed(
        service_options,
        options,
        &resolved,
        &store,
        &mut client,
        &mut launcher,
    )
}

#[cfg(unix)]
fn start_local_control_server(
    client: HttpManagementApiClient,
    credential: ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    log_path: Option<PathBuf>,
) -> Result<(), String> {
    let paths = LocalControlPaths::from_environment().map_err(format_core_error)?;
    let dispatcher = LocalControlDispatcher::new(client, credential).with_context(
        resolved.project_id.clone(),
        resolved.runner_id.clone(),
        resolved.binding_id.clone(),
        resolved.workspace_path.clone(),
        log_path.or_else(|| env::var_os(LOG_PATH_ENV).map(PathBuf::from)),
    );
    let server = UnixLocalControlServer::bind(paths, dispatcher).map_err(format_core_error)?;
    thread::Builder::new()
        .name("loomex-local-control".to_string())
        .spawn(move || {
            if let Err(err) = server.serve() {
                eprintln!(
                    "local control service stopped: {}: {}",
                    err.code, err.message
                );
            }
        })
        .map_err(|err| format!("LOCAL_CONTROL_THREAD_FAILED: {err}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn start_local_control_server(
    _client: HttpManagementApiClient,
    _credential: ManagementCredential,
    _resolved: &loomex_core::ResolvedCliSettings,
    _log_path: Option<PathBuf>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
fn run_runner_service_run_with<C: ManagementApiClient>(
    args: &[String],
    options: &GlobalOptions,
    store: &dyn CredentialStore,
    client: &mut C,
    launcher: &mut dyn RunnerServiceRuntimeLauncher,
) -> Result<String, String> {
    let service_options = RunnerServiceOptions::parse(args, options)?;
    let config = load_cli_config_from(&service_options.config_path)?;
    let resolved = config
        .resolve(
            CliConfigOverrides {
                profile: service_options.profile.clone(),
                server_url: options.server_url.clone(),
                host_header: options.host_header.clone(),
            },
            |key| env::var(key).ok(),
        )
        .map_err(format_core_error)?;
    run_runner_service_run_parsed(service_options, options, &resolved, store, client, launcher)
}

fn run_runner_service_run_parsed<C: ManagementApiClient>(
    mut service_options: RunnerServiceOptions,
    options: &GlobalOptions,
    resolved: &loomex_core::ResolvedCliSettings,
    store: &dyn CredentialStore,
    client: &mut C,
    _launcher: &mut dyn RunnerServiceRuntimeLauncher,
) -> Result<String, String> {
    let log_path = service_options
        .log_path
        .clone()
        .unwrap_or_else(default_log_path);
    service_options.log_path = Some(log_path.clone());
    let credential = load_credential(store, &resolved.profile)?;
    append_runner_service_log(
        &log_path,
        &credential,
        "info",
        "runner.service.starting",
        "runner service is starting",
        json!({"profile": resolved.profile, "once": service_options.once}),
    )?;
    let Some(binding_id) = resolved.binding_id.as_deref() else {
        return Err(
            "RUNNER_SERVICE_BINDING_REQUIRED: selected profile has no bindingId".to_string(),
        );
    };
    let guard =
        acquire_runner_runtime_guard(&service_options.config_path, binding_id, "loomex-service")
            .map_err(format_core_error)?;
    let recovery_path = runner_job_recovery_path(guard.path());
    let mut recovery = RunnerJobRecoveryJournal::open(&recovery_path).map_err(format_core_error)?;
    if service_options.once {
        let start = run_runner_control_service_once(
            client,
            &credential,
            resolved,
            binding_id,
            &mut recovery,
        )?;
        append_runner_service_log(
            &log_path,
            &credential,
            "info",
            "runner.service.tick",
            "runner service completed one control tick",
            json!({"event": start.event, "transport": start.transport}),
        )?;
        if options.json {
            return Ok(json!({
                "schemaVersion": "loomex.cli.runnerServiceRun/v1",
                "running": true,
                "once": true,
                "transport": start.transport,
                "event": start.event,
                "fallback": false,
                "profile": resolved.profile,
                "bindingId": binding_id,
                "guardPath": guard.path()
            })
            .to_string());
        }
        return Ok(format!(
            "runner service ready\nbinding: {binding_id}\nguard: {}",
            guard.path().display()
        ));
    }
    run_runner_control_service_loop(
        client,
        &credential,
        resolved,
        binding_id,
        &mut recovery,
        &log_path,
    )?;
    drop(guard);
    Ok(String::new())
}

fn run_runner_control_service_once<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
) -> Result<RunnerServiceRuntimeStart, String> {
    let session = create_runner_control_session(client, credential, resolved, binding_id)?;
    let session_id = session_id_from_response(&session)?;
    write_runner_session_marker(&session_id);
    let recovered =
        recover_pending_runner_jobs(client, credential, resolved, &session_id, recovery)?;
    let event = if recovered {
        "job.recovered"
    } else if process_one_runner_control_job(client, credential, resolved, &session_id, recovery)? {
        "job.processed"
    } else {
        "idle"
    };
    Ok(RunnerServiceRuntimeStart {
        transport: "runner_control_long_poll".to_string(),
        event: event.to_string(),
        fallback: false,
    })
}

fn run_runner_control_service_loop<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
    log_path: &Path,
) -> Result<(), String> {
    let mut backoff = RunnerControlReconnectBackoff::new();
    loop {
        let mut session_healthy = false;
        let result = run_runner_control_session(
            client,
            credential,
            resolved,
            binding_id,
            recovery,
            log_path,
            &mut || session_healthy = true,
        );
        if session_healthy {
            backoff.control_operation_succeeded();
        }
        match result {
            Ok(()) => return Ok(()),
            Err(err) if is_terminal_service_runtime_error(&err) => return Err(err),
            Err(err) => {
                let retry_delay = backoff.next_retry_delay();
                let _ = append_runner_service_log(
                    log_path,
                    credential,
                    "warn",
                    "runner.service.disconnected",
                    "runner control session disconnected; retrying",
                    json!({"retryDelaySeconds": retry_delay.as_secs(), "error": err}),
                );
                eprintln!(
                    "runner control session disconnected; retrying in {}s: {err}",
                    retry_delay.as_secs()
                );
                thread::sleep(retry_delay);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerControlReconnectBackoff {
    retry_delay: Duration,
}

impl RunnerControlReconnectBackoff {
    fn new() -> Self {
        Self {
            retry_delay: Duration::from_secs(1),
        }
    }

    fn control_operation_succeeded(&mut self) {
        self.retry_delay = Duration::from_secs(1);
    }

    fn next_retry_delay(&mut self) -> Duration {
        let delay = self.retry_delay;
        self.retry_delay = self
            .retry_delay
            .saturating_mul(2)
            .min(Duration::from_secs(30));
        delay
    }
}

fn run_runner_control_session<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
    log_path: &Path,
    on_session_healthy: &mut dyn FnMut(),
) -> Result<(), String> {
    let session = create_runner_control_session(client, credential, resolved, binding_id)?;
    let session_id = session_id_from_response(&session)?;
    write_runner_session_marker(&session_id);
    let _ = append_runner_service_log(
        log_path,
        credential,
        "info",
        "runner.service.connected",
        "runner control session connected",
        json!({"sessionId": session_id}),
    );
    eprintln!("runner control session connected: {session_id}");
    recover_pending_runner_jobs(client, credential, resolved, &session_id, recovery)?;
    let mut idle_ticks = 0usize;
    let mut session_health_confirmed = false;
    loop {
        let processed =
            process_one_runner_control_job(client, credential, resolved, &session_id, recovery)?;
        if !session_health_confirmed {
            on_session_healthy();
            session_health_confirmed = true;
        }
        if processed {
            idle_ticks = 0;
            continue;
        }
        idle_ticks += 1;
        if idle_ticks.is_multiple_of(10) {
            client
                .heartbeat_runner_session(
                    credential,
                    &session_id,
                    runner_control_manifest(resolved, binding_id),
                )
                .map_err(format_core_error)?;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn append_runner_service_log(
    log_path: &Path,
    credential: &ManagementCredential,
    level: &str,
    event_type: &str,
    message: &str,
    metadata: Value,
) -> Result<(), String> {
    let mut secrets = vec![credential.access_token.clone()];
    if let Some(refresh_token) = credential.refresh_token.as_ref() {
        secrets.push(refresh_token.clone());
    }
    FileLogSink::new(log_path, loomex_core::redaction::Redactor::new(secrets))
        .append_result(LogEntry::new(level, event_type, message).with_metadata(metadata))
        .map_err(format_core_error)
}

fn create_runner_control_session<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
) -> Result<loomex_core::RunnerSessionResponse, String> {
    let workspace_root = resolved.workspace_path.as_deref().ok_or_else(|| {
        "RUNNER_SERVICE_WORKSPACE_REQUIRED: selected profile has no workspacePath".to_string()
    })?;
    client
        .create_runner_session(
            credential,
            workspace_root,
            runner_control_manifest(resolved, binding_id),
            "long_poll",
        )
        .map_err(format_core_error)
}

fn runner_control_manifest(resolved: &loomex_core::ResolvedCliSettings, binding_id: &str) -> Value {
    json!({
        "surface": "plugin",
        "runnerVersion": env!("CARGO_PKG_VERSION"),
        "bindingId": binding_id,
        "workspaceRoot": resolved.workspace_path.clone().unwrap_or_default(),
        "capabilities": {
            "file.list": true,
            "file.read_many": true,
            "file.write_many": true,
            "fs.list": true,
            "fs.read": true,
            "fs.write": true,
            "fs.apply_patch": true,
            "shell.exec": true,
            "git.status": true,
            "git.diff": true,
            "git.log": true,
            "http.request": true
        }
    })
}

fn session_id_from_response(
    response: &loomex_core::RunnerSessionResponse,
) -> Result<String, String> {
    response
        .session
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| "RUNNER_SERVICE_SESSION_INVALID: session id missing".to_string())
}

fn runner_session_marker_path(guard_path: &Path) -> PathBuf {
    guard_path.with_extension("session")
}

fn runner_job_recovery_path(guard_path: &Path) -> PathBuf {
    guard_path.with_extension("jobs.json")
}

fn write_runner_session_marker(session_id: &str) {
    let Ok(guard_path) = env::var(RUNNER_GUARD_PATH_ENV) else {
        return;
    };
    let marker_path = runner_session_marker_path(Path::new(&guard_path));
    if let Some(parent) = marker_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(marker_path, format!("session_id={session_id}\n"));
}

fn current_epoch_ms() -> Result<u64, String> {
    current_epoch_seconds().map(|seconds| seconds.saturating_mul(1_000))
}

fn recoverable_runner_job(
    job: &Value,
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    now_epoch_ms: u64,
) -> Result<RecoverableRunnerJob, String> {
    let remote = remote_runner_job(job)?;
    if remote.session_id.as_deref() != Some(session_id) {
        return Err(
            "RUNNER_JOB_INVALID: leased job is not owned by the current session".to_string(),
        );
    }
    if remote.status != RemoteRunnerJobStatus::Leased {
        return Err("RUNNER_JOB_INVALID: lease response status must be leased".to_string());
    }
    let runner_id = required_job_string(job, "runnerId").or_else(|_| {
        resolved
            .runner_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "RUNNER_JOB_INVALID: runnerId is required".to_string())
    })?;
    Ok(RecoverableRunnerJob {
        job_id: remote.job_id,
        runner_id,
        session_id: session_id.to_string(),
        kind: required_job_string(job, "kind")?,
        idempotency_key: required_job_string(job, "idempotencyKey")?,
        payload_fingerprint: remote.payload_fingerprint,
        attempt_count: remote.attempt_count,
        lease_version: remote.lease_version,
        leased_until_epoch_ms: remote.leased_until_epoch_ms.ok_or_else(|| {
            "RUNNER_JOB_INVALID: leasedUntilEpochMs is required for an active lease".to_string()
        })?,
        replay_safety: if job.get("replaySafe").and_then(Value::as_bool) == Some(true) {
            JobReplaySafety::Idempotent
        } else {
            JobReplaySafety::ManualReconciliation
        },
        phase: RecoverableJobPhase::Leased,
        terminal_payload: None,
        updated_at_epoch_ms: now_epoch_ms,
    })
}

fn remote_runner_job(job: &Value) -> Result<RemoteRunnerJobSnapshot, String> {
    let status = match required_job_string(job, "status")?.as_str() {
        "queued" => RemoteRunnerJobStatus::Queued,
        "leased" => RemoteRunnerJobStatus::Leased,
        "running" => RemoteRunnerJobStatus::Running,
        "succeeded" => RemoteRunnerJobStatus::Succeeded,
        "failed" => RemoteRunnerJobStatus::Failed,
        "canceling" => RemoteRunnerJobStatus::Canceling,
        "canceled" | "cancelled" => RemoteRunnerJobStatus::Canceled,
        "expired" => RemoteRunnerJobStatus::Expired,
        other => {
            return Err(format!(
                "RUNNER_JOB_INVALID: unsupported job status {other}"
            ))
        }
    };
    Ok(RemoteRunnerJobSnapshot {
        job_id: job_id(job)?,
        session_id: job
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        status,
        attempt_count: required_job_u64(job, "attemptCount")?
            .try_into()
            .map_err(|_| "RUNNER_JOB_INVALID: attemptCount exceeds u32".to_string())?,
        lease_version: required_job_u64(job, "leaseVersion")?,
        leased_until_epoch_ms: job.get("leasedUntilEpochMs").and_then(Value::as_u64),
        payload_fingerprint: required_job_string(job, "payloadDigest")?,
    })
}

fn required_job_string(job: &Value, field: &str) -> Result<String, String> {
    job.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("RUNNER_JOB_INVALID: {field} is required"))
}

fn required_job_u64(job: &Value, field: &str) -> Result<u64, String> {
    job.get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("RUNNER_JOB_INVALID: {field} must be positive"))
}

fn recover_pending_runner_jobs<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
) -> Result<bool, String> {
    let pending = recovery.pending_jobs().to_vec();
    let mut processed = false;
    for local in pending {
        let response = client
            .get_runner_job(credential, &local.job_id)
            .map_err(format_core_error)?;
        let mut job = response
            .job
            .ok_or_else(|| "RUNNER_JOB_RECOVERY_INVALID: server job missing".to_string())?;
        let mut remote = remote_runner_job(&job)?;
        let now_epoch_ms = current_epoch_ms()?;
        let mut action = recovery
            .recovery_action(&local.job_id, Some(&remote), session_id, now_epoch_ms)
            .map_err(format_core_error)?;

        if action == JobRecoveryAction::ForgetTerminal {
            recovery
                .forget_server_terminal(&local.job_id, &remote)
                .map_err(format_core_error)?;
            processed = true;
            continue;
        }
        if matches!(action, JobRecoveryAction::WaitForLeaseExpiry { .. }) {
            continue;
        }
        if action == JobRecoveryAction::RequestServerReclaim {
            let terminal_submission = recovery_terminal_submission(&local);
            let reclaimed = client
                .reclaim_runner_job(
                    credential,
                    session_id,
                    &local.job_id,
                    remote.lease_version,
                    &local.payload_fingerprint,
                    &local.idempotency_key,
                    terminal_submission.as_ref(),
                )
                .map_err(format_core_error)?;
            job = reclaimed
                .job
                .ok_or_else(|| "RUNNER_JOB_RECLAIM_INVALID: response job missing".to_string())?;
            remote = remote_runner_job(&job)?;
            if remote.status.is_terminal() {
                recovery
                    .forget_server_terminal(&local.job_id, &remote)
                    .map_err(format_core_error)?;
                processed = true;
                continue;
            }
            recovery
                .adopt_reclaimed_lease(&local.job_id, &remote, session_id, current_epoch_ms()?)
                .map_err(format_core_error)?;
            action = recovery
                .recovery_action(
                    &local.job_id,
                    Some(&remote),
                    session_id,
                    current_epoch_ms()?,
                )
                .map_err(format_core_error)?;
        } else if remote.session_id.as_deref() == Some(session_id)
            && recovery
                .job(&local.job_id)
                .is_some_and(|record| record.session_id != session_id)
        {
            recovery
                .adopt_reclaimed_lease(&local.job_id, &remote, session_id, current_epoch_ms()?)
                .map_err(format_core_error)?;
            action = recovery
                .recovery_action(
                    &local.job_id,
                    Some(&remote),
                    session_id,
                    current_epoch_ms()?,
                )
                .map_err(format_core_error)?;
        }

        match action {
            JobRecoveryAction::StartExecution | JobRecoveryAction::ResumeIdempotentExecution => {
                execute_and_finalize_runner_job(
                    client, credential, resolved, session_id, &job, recovery,
                )?;
                processed = true;
            }
            JobRecoveryAction::SubmitSucceeded(result) => {
                submit_recovered_terminal(
                    client,
                    credential,
                    session_id,
                    &local.job_id,
                    recovery,
                    true,
                    result,
                )?;
                processed = true;
            }
            JobRecoveryAction::SubmitFailed(error) => {
                submit_recovered_terminal(
                    client,
                    credential,
                    session_id,
                    &local.job_id,
                    recovery,
                    false,
                    error,
                )?;
                processed = true;
            }
            JobRecoveryAction::ManualReconciliation { reason } => {
                let record = recovery.job(&local.job_id).ok_or_else(|| {
                    "RUNNER_JOB_RECOVERY_INVALID: local record disappeared".to_string()
                })?;
                if record.session_id != session_id
                    || remote.session_id.as_deref() != Some(session_id)
                {
                    return Err(format!("RUNNER_JOB_RECOVERY_UNCERTAIN: {reason}"));
                }
                let error = json!({
                    "code": "RUNNER_JOB_RECOVERY_UNCERTAIN",
                    "message": reason,
                    "requiresHumanReconciliation": true
                });
                recovery
                    .record_failed(
                        &local.job_id,
                        session_id,
                        error.clone(),
                        current_epoch_ms()?,
                    )
                    .map_err(format_core_error)?;
                submit_recovered_terminal(
                    client,
                    credential,
                    session_id,
                    &local.job_id,
                    recovery,
                    false,
                    error,
                )?;
                processed = true;
            }
            JobRecoveryAction::ForgetTerminal
            | JobRecoveryAction::WaitForLeaseExpiry { .. }
            | JobRecoveryAction::RequestServerReclaim => {
                return Err(
                    "RUNNER_JOB_RECOVERY_INVALID: recovery action did not converge".to_string(),
                );
            }
        }
    }
    Ok(processed)
}

fn recovery_terminal_submission(job: &RecoverableRunnerJob) -> Option<Value> {
    match job.phase {
        RecoverableJobPhase::SucceededPendingAck => job
            .terminal_payload
            .clone()
            .map(|result| json!({"status": "succeeded", "result": result})),
        RecoverableJobPhase::FailedPendingAck => job
            .terminal_payload
            .clone()
            .map(|error| json!({"status": "failed", "error": error})),
        RecoverableJobPhase::Leased | RecoverableJobPhase::Running => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn submit_recovered_terminal<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    session_id: &str,
    job_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
    succeeded: bool,
    payload: Value,
) -> Result<(), String> {
    let record = recovery
        .job(job_id)
        .cloned()
        .ok_or_else(|| "RUNNER_JOB_RECOVERY_INVALID: local record missing".to_string())?;
    if succeeded {
        client
            .complete_runner_job_idempotent(
                credential,
                session_id,
                job_id,
                record.lease_version,
                &record.idempotency_key,
                payload,
            )
            .map_err(format_core_error)?;
    } else {
        client
            .fail_runner_job_idempotent(
                credential,
                session_id,
                job_id,
                record.lease_version,
                &record.idempotency_key,
                payload,
            )
            .map_err(format_core_error)?;
    }
    recovery
        .acknowledge_terminal(job_id)
        .map_err(format_core_error)
}

fn process_one_runner_control_job<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    recovery: &mut RunnerJobRecoveryJournal,
) -> Result<bool, String> {
    let lease = client
        .lease_runner_job(credential, session_id)
        .map_err(format_core_error)?;
    let Some(job) = lease.job else {
        return Ok(false);
    };
    let now_epoch_ms = current_epoch_ms()?;
    let recoverable = recoverable_runner_job(&job, resolved, session_id, now_epoch_ms)?;
    recovery
        .record_lease(recoverable)
        .map_err(format_core_error)?;
    execute_and_finalize_runner_job(client, credential, resolved, session_id, &job, recovery)?;
    Ok(true)
}

fn execute_and_finalize_runner_job<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
    recovery: &mut RunnerJobRecoveryJournal,
) -> Result<(), String> {
    let job_id = job_id(job)?;
    let lease_version = required_job_u64(job, "leaseVersion")?;
    required_job_string(job, "idempotencyKey")?;
    if job.get("status").and_then(Value::as_str) == Some("leased") {
        client
            .start_runner_job_leased(credential, session_id, &job_id, lease_version)
            .map_err(format_core_error)?;
    }
    recovery
        .mark_running(&job_id, session_id, current_epoch_ms()?)
        .map_err(format_core_error)?;
    let execution = if matches!(
        job.get("kind").and_then(Value::as_str),
        Some("shell.exec" | "command.run")
    ) {
        execute_cancellable_runner_job(
            client,
            credential,
            resolved,
            session_id,
            &job_id,
            lease_version,
            job,
            recovery,
        )
    } else {
        execute_runner_control_job_for_session(resolved, session_id, job)
    };
    match execution {
        Ok(result) => {
            recovery
                .record_succeeded(&job_id, session_id, result.clone(), current_epoch_ms()?)
                .map_err(format_core_error)?;
            let terminal_record = recovery.job(&job_id).cloned().ok_or_else(|| {
                "RUNNER_JOB_RECOVERY_INVALID: terminal record missing".to_string()
            })?;
            let _ = client.append_runner_job_events_leased(
                credential,
                session_id,
                &job_id,
                terminal_record.lease_version,
                vec![json!({
                    "eventType": "stdout",
                    "stream": "stdout",
                    "message": "job completed",
                    "payload": result.clone()
                })],
            );
            client
                .complete_runner_job_idempotent(
                    credential,
                    session_id,
                    &job_id,
                    terminal_record.lease_version,
                    &terminal_record.idempotency_key,
                    result,
                )
                .map_err(format_core_error)?;
        }
        Err(err) => {
            let error = json!({"code": "RUNNER_JOB_EXECUTION_FAILED", "message": err});
            recovery
                .record_failed(&job_id, session_id, error.clone(), current_epoch_ms()?)
                .map_err(format_core_error)?;
            let terminal_record = recovery.job(&job_id).cloned().ok_or_else(|| {
                "RUNNER_JOB_RECOVERY_INVALID: terminal record missing".to_string()
            })?;
            let _ = client.append_runner_job_events_leased(
                credential,
                session_id,
                &job_id,
                terminal_record.lease_version,
                vec![json!({
                    "eventType": "stderr",
                    "stream": "stderr",
                    "message": error["message"].as_str().unwrap_or("job failed"),
                    "payload": error.clone()
                })],
            );
            client
                .fail_runner_job_idempotent(
                    credential,
                    session_id,
                    &job_id,
                    terminal_record.lease_version,
                    &terminal_record.idempotency_key,
                    error,
                )
                .map_err(format_core_error)?;
        }
    }
    recovery
        .acknowledge_terminal(&job_id)
        .map_err(format_core_error)
}

#[allow(clippy::too_many_arguments)]
fn execute_cancellable_runner_job<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job_id: &str,
    initial_lease_version: u64,
    job: &Value,
    recovery: &mut RunnerJobRecoveryJournal,
) -> Result<Value, String> {
    let cancellation = ShellCancellationToken::default();
    let worker_cancellation = cancellation.clone();
    let worker_resolved = resolved.clone();
    let worker_session_id = session_id.to_string();
    let worker_job = job.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name(format!("loomex-job-{job_id}"))
        .spawn(move || {
            let result = execute_runner_control_job_with_cancel(
                &worker_resolved,
                &worker_session_id,
                &worker_job,
                Some(&worker_cancellation),
            );
            let _ = sender.send(result);
        })
        .map_err(|err| format!("RUNNER_JOB_THREAD_FAILED: {err}"))?;
    let mut lease_version = initial_lease_version;
    let mut next_renewal_epoch_ms = current_epoch_ms()?.saturating_add(10_000);
    loop {
        match receiver.try_recv() {
            Ok(result) => {
                let _ = worker.join();
                return result;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                let _ = worker.join();
                return Err("RUNNER_JOB_THREAD_FAILED: worker disconnected".to_string());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if client
            .list_runner_job_cancellations(credential, session_id)
            .map(|jobs| {
                jobs.iter()
                    .any(|item| job_id_from_value(item) == Some(job_id))
            })
            .unwrap_or(false)
        {
            cancellation.cancel();
        }
        let now_epoch_ms = current_epoch_ms()?;
        if now_epoch_ms >= next_renewal_epoch_ms {
            let renewed = client
                .renew_runner_job(credential, session_id, job_id, lease_version)
                .map_err(format_core_error)?
                .job
                .ok_or_else(|| "RUNNER_JOB_RENEW_INVALID: response job missing".to_string())?;
            let remote = remote_runner_job(&renewed)?;
            if remote.session_id.as_deref() != Some(session_id)
                || remote.lease_version <= lease_version
            {
                cancellation.cancel();
                return Err("RUNNER_JOB_RENEW_INVALID: renewed lease ownership changed".to_string());
            }
            let leased_until_epoch_ms = remote.leased_until_epoch_ms.ok_or_else(|| {
                "RUNNER_JOB_RENEW_INVALID: leasedUntilEpochMs missing".to_string()
            })?;
            recovery
                .renew_lease(
                    job_id,
                    session_id,
                    remote.lease_version,
                    leased_until_epoch_ms,
                    now_epoch_ms,
                )
                .map_err(format_core_error)?;
            lease_version = remote.lease_version;
            let remaining = leased_until_epoch_ms.saturating_sub(now_epoch_ms);
            next_renewal_epoch_ms = now_epoch_ms.saturating_add((remaining / 3).max(1_000));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn job_id_from_value(value: &Value) -> Option<&str> {
    value
        .get("id")
        .or_else(|| value.get("jobId"))
        .and_then(Value::as_str)
}

fn job_id(job: &Value) -> Result<String, String> {
    job.get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| "RUNNER_JOB_INVALID: job id missing".to_string())
}

#[cfg(test)]
fn execute_runner_control_job(
    resolved: &loomex_core::ResolvedCliSettings,
    job: &Value,
) -> Result<Value, String> {
    execute_runner_control_job_for_session(resolved, "local-test-session", job)
}

fn execute_runner_control_job_for_session(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
) -> Result<Value, String> {
    execute_runner_control_job_with_cancel(resolved, session_id, job, None)
}

fn execute_runner_control_job_with_cancel(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
    cancellation: Option<&ShellCancellationToken>,
) -> Result<Value, String> {
    let kind = job.get("kind").and_then(Value::as_str).unwrap_or_default();
    match kind {
        "file.list" => execute_file_list_job(resolved, session_id, job),
        "file.read_many" => execute_file_read_many_job(resolved, session_id, job),
        "file.write_many" => execute_file_write_many_job(resolved, session_id, job),
        "fs.list" | "fs.read" | "fs.write" | "fs.apply_patch" | "shell.exec" | "git.status"
        | "git.diff" | "git.log" | "http.request" => {
            execute_local_capability_job(resolved, session_id, kind, job, cancellation)
        }
        "command.run" => {
            execute_local_capability_job(resolved, session_id, "shell.exec", job, cancellation)
        }
        other => Err(format!("unsupported runner job kind {other}")),
    }
}

fn execute_local_capability_job(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    capability: &str,
    job: &Value,
    supplied_cancellation: Option<&ShellCancellationToken>,
) -> Result<Value, String> {
    let payload = job.get("payload").cloned().unwrap_or_else(|| json!({}));
    let requested_path = payload.get("path").and_then(Value::as_str).unwrap_or(".");
    authorize_runner_path(resolved, session_id, capability, requested_path)?;
    let executor = LocalCapabilityExecutor::new(runner_workspace_root(resolved)?)
        .map_err(format_core_error)?;
    if capability == "shell.exec" {
        let input: ShellExecInput = serde_json::from_value(payload)
            .map_err(|err| format!("RUNNER_JOB_PAYLOAD_INVALID: {err}"))?;
        let cancellation = supplied_cancellation.cloned().unwrap_or_default();
        if job.get("status").and_then(Value::as_str) == Some("canceling")
            || job
                .get("cancelRequested")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            cancellation.cancel();
        }
        let output = executor
            .shell_exec_with_cancel(input, &cancellation)
            .map_err(format_core_error)?;
        return Ok(json!({
            "exitCode": output.exit_code,
            "durationMs": output.duration_ms,
            "stdoutRef": output.stdout_ref,
            "stderrRef": output.stderr_ref,
            "stdout": output.artifacts.stdout,
            "stderr": output.artifacts.stderr,
            "timedOut": output.artifacts.timed_out,
            "cancelled": output.artifacts.cancelled,
            "truncated": output.truncated,
        }));
    }
    let result = executor
        .execute(CapabilityRequest {
            capability: capability.to_string(),
            input: serde_json::to_string(&payload)
                .map_err(|err| format!("RUNNER_JOB_PAYLOAD_INVALID: {err}"))?,
        })
        .map_err(format_core_error)?;
    serde_json::from_str(&result.output).map_err(|err| format!("RUNNER_JOB_RESULT_INVALID: {err}"))
}

fn runner_workspace_root(resolved: &loomex_core::ResolvedCliSettings) -> Result<PathBuf, String> {
    PathBuf::from(resolved.workspace_path.as_deref().ok_or_else(|| {
        "RUNNER_SERVICE_WORKSPACE_REQUIRED: selected profile has no workspacePath".to_string()
    })?)
    .canonicalize()
    .map_err(|err| format!("workspace path is not accessible: {err}"))
}

fn authorize_runner_path(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    capability: &str,
    relative_path: &str,
) -> Result<(), String> {
    let root = runner_workspace_root(resolved)?;
    let relative = validate_runner_relative_path(relative_path)?;
    let requested = root.join(relative);
    let requested_string = requested.to_string_lossy().to_string();
    let resolved_string = requested
        .exists()
        .then(|| requested.canonicalize())
        .transpose()
        .map_err(|err| format!("RUNNER_JOB_PATH_INVALID: {err}"))?
        .map(|path| path.to_string_lossy().to_string());
    let organization_id = resolved.organization_id.clone().ok_or_else(|| {
        "RUNNER_SERVICE_ORGANIZATION_REQUIRED: selected profile has no organizationId".to_string()
    })?;
    let project_id = resolved.project_id.clone().ok_or_else(|| {
        "RUNNER_SERVICE_PROJECT_REQUIRED: selected profile has no projectId".to_string()
    })?;
    let binding_id = resolved.binding_id.clone().ok_or_else(|| {
        "RUNNER_SERVICE_BINDING_REQUIRED: selected profile has no bindingId".to_string()
    })?;
    let runner_device_id = resolved
        .runner_id
        .clone()
        .unwrap_or_else(|| "loomex-local-runner".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("RUNNER_CLOCK_INVALID: {err}"))?
        .as_millis() as u64;
    let binding = ProjectRunnerBinding {
        id: binding_id.clone(),
        organization_id: organization_id.clone(),
        project_id: project_id.clone(),
        runner_device_id: runner_device_id.clone(),
        workspace: WorkspacePath::new(root.to_string_lossy().to_string(), None)
            .map_err(format_core_error)?,
        status: BindingStatus::Active,
        created_by: "runner-control".to_string(),
        last_seen_at_epoch_ms: Some(now),
        revoked_at_epoch_ms: None,
    };
    let session = RunnerSession {
        id: session_id.to_string(),
        organization_id: organization_id.clone(),
        project_id: project_id.clone(),
        runner_device_id,
        project_runner_binding_id: binding_id.clone(),
        status: RunnerSessionStatus::Connected,
        last_seen_at_epoch_ms: Some(now),
        lease_expires_at_epoch_ms: now.saturating_add(60_000),
        connected_at_epoch_ms: now,
        disconnected_at_epoch_ms: None,
        replaced_by_session_id: None,
        disconnect_reason: None,
    };
    let grant = RunnerCapabilityGrant {
        project_runner_binding_id: binding_id,
        capability: capability.to_string(),
        granted_by: "runner-control-leased-job".to_string(),
        created_at_epoch_ms: now,
        revoked_at_epoch_ms: None,
    };
    let context = BindingValidationContext {
        organization_id,
        project_id,
        project_permission_active: true,
    };
    loomex_core::binding::validate_session_and_grant_for_local_tool_call(
        Some(&binding),
        Some(&session),
        Some(&grant),
        &context,
        capability,
        &requested_string,
        resolved_string.as_deref(),
    )
    .map_err(format_core_error)?;
    let policy = PolicyEngine::new(vec![PolicyLayer {
        source: PolicySource::Project,
        default_decision: Some(PolicyDecision::Deny),
        rules: vec![PolicyRule::for_capability(
            capability,
            PolicyDecision::Allow,
        )],
    }]);
    let mut input = PolicyEvaluationInput::capability(capability);
    input.requested_path = Some(requested_string);
    input.resolved_path = resolved_string;
    let decision = policy
        .dry_run(&input, &binding)
        .map_err(format_core_error)?;
    enforce_policy_decision(&decision).map_err(format_core_error)
}

fn execute_file_list_job(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
) -> Result<Value, String> {
    let workspace_root = runner_workspace_root(resolved)?;
    let payload = job.get("payload").and_then(Value::as_object);
    let raw_path = payload
        .and_then(|payload| payload.get("path"))
        .and_then(Value::as_str)
        .unwrap_or(".");
    let limit = payload
        .and_then(|payload| payload.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(200) as usize;
    let include_hidden = payload
        .and_then(|payload| payload.get("includeHidden"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    authorize_runner_path(resolved, session_id, "fs.list", raw_path)?;
    let executor = LocalCapabilityExecutor::new(workspace_root).map_err(format_core_error)?;
    let output = executor
        .fs_list(FsListInput {
            path: raw_path.to_string(),
            recursive: Some(true),
            include_hidden: Some(include_hidden),
            follow_symlinks: Some(false),
            max_entries: Some(limit.max(1)),
        })
        .map_err(format_core_error)?;
    let files = output
        .entries
        .into_iter()
        .map(|entry| {
            json!({
                "path": entry.path,
                "type": entry.entry_type,
                "sizeBytes": entry.size_bytes,
                "modifiedEpochMs": entry.modified_epoch_ms,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "files": files, "truncated": output.truncated }))
}

fn execute_file_read_many_job(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
) -> Result<Value, String> {
    let workspace_root = runner_workspace_root(resolved)?;
    let payload = job.get("payload").and_then(Value::as_object);
    let files = payload
        .and_then(|payload| payload.get("files"))
        .and_then(Value::as_array)
        .ok_or_else(|| "file.read_many job requires payload.files".to_string())?;
    let max_bytes = payload
        .and_then(|payload| payload.get("maxBytesPerFile"))
        .and_then(Value::as_u64)
        .unwrap_or(200_000) as usize;
    let mut result = Vec::new();
    for item in files {
        let raw_path = item
            .as_str()
            .ok_or_else(|| "file.read_many files must contain paths".to_string())?;
        authorize_runner_path(resolved, session_id, "fs.read", raw_path)?;
        let output = LocalCapabilityExecutor::new(&workspace_root)
            .map_err(format_core_error)?
            .fs_read(FsReadInput {
                path: raw_path.to_string(),
                encoding: Some("utf-8".to_string()),
                offset: None,
                max_bytes: Some(max_bytes),
            })
            .map_err(format_core_error)?;
        result.push(json!({
            "path": output.path,
            "content": output.content,
            "encoding": output.encoding,
            "sha256": output.sha256,
            "sizeBytes": output.size_bytes,
            "truncated": output.truncated
        }));
    }
    Ok(json!({ "files": result }))
}

fn execute_file_write_many_job(
    resolved: &loomex_core::ResolvedCliSettings,
    session_id: &str,
    job: &Value,
) -> Result<Value, String> {
    let workspace_root = runner_workspace_root(resolved)?;
    let files = job
        .get("payload")
        .and_then(|payload| payload.get("files"))
        .and_then(Value::as_array)
        .ok_or_else(|| "file.write_many job requires payload.files".to_string())?;
    let mut written = Vec::new();
    for item in files {
        let path = item
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "file entry missing path".to_string())?;
        authorize_runner_path(resolved, session_id, "fs.write", path)?;
        let content = item
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if item.get("encoding").and_then(Value::as_str) == Some("base64") {
            return Err(
                "base64 file.write_many payloads are not supported by this runner".to_string(),
            );
        }
        let output = LocalCapabilityExecutor::new(&workspace_root)
            .map_err(format_core_error)?
            .fs_write(FsWriteInput {
                path: path.to_string(),
                content: content.to_string(),
                encoding: "utf-8".to_string(),
                mode: "overwrite".to_string(),
                expected_sha256: item
                    .get("expectedSha256")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                create_parent_directories: Some(true),
            })
            .map_err(format_core_error)?;
        written.push(json!({
            "path": output.path,
            "sizeBytes": output.size_bytes,
            "sha256": output.sha256,
            "created": output.created
        }));
    }
    Ok(json!({ "writtenFiles": written }))
}

fn validate_runner_relative_path(path: &str) -> Result<PathBuf, String> {
    let relative = PathBuf::from(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("file path must be relative to the runner workspace".to_string());
    }
    Ok(relative)
}

fn format_runner_service_manifest(
    manifest: &RunnerServiceManifest,
    options: &GlobalOptions,
) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerServiceUnit/v1",
            "platform": manifest.platform.as_str(),
            "installPath": manifest.install_path,
            "uninstallPath": manifest.uninstall_path,
            "manifest": manifest.content,
            "uninstallManifest": manifest.uninstall_content
        })
        .to_string());
    }
    Ok(manifest.content.clone())
}

fn write_service_file(path: &Path, content: &str) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        "RUNNER_SERVICE_WRITE_FAILED: service path has no parent directory".to_string()
    })?;
    fs::create_dir_all(parent).map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(
            "RUNNER_SERVICE_PATH_UNSAFE: service parent must be a non-symlink directory"
                .to_string(),
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(
                "RUNNER_SERVICE_PATH_UNSAFE: existing service path must be a regular non-symlink file"
                    .to_string(),
            );
        }
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "RUNNER_SERVICE_PATH_UNSAFE: service filename is invalid".to_string())?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let result = (|| -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
        }
        file.write_all(content.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
        fs::rename(&temporary, path)
            .map_err(|err| format!("RUNNER_SERVICE_WRITE_FAILED: {err}"))?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn default_service_install_path(options: &RunnerServiceOptions) -> Result<PathBuf, String> {
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            Ok(PathBuf::from(home)
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{}.plist", options.service_name)))
        }
        RunnerServicePlatform::LinuxUserSystemd => {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            Ok(PathBuf::from(home)
                .join(".config")
                .join("systemd")
                .join("user")
                .join(format!("{}.service", options.service_name)))
        }
        RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(PathBuf::from("/etc/systemd/system")
                .join(format!("{}.service", options.service_name)))
        }
    }
}

fn service_install_commands(options: &RunnerServiceOptions) -> Result<Vec<ServiceCommand>, String> {
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            let path = default_service_install_path(options)?;
            let domain = launchctl_user_domain();
            Ok(vec![
                ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "bootstrap".to_string(),
                        domain.clone(),
                        path.display().to_string(),
                    ],
                },
                ServiceCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "kickstart".to_string(),
                        "-k".to_string(),
                        format!("{}/{}", domain, options.service_name),
                    ],
                },
            ])
        }
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(vec![
                systemctl_command(options.platform, &["daemon-reload"]),
                systemctl_command(
                    options.platform,
                    &[
                        "enable",
                        "--now",
                        &format!("{}.service", options.service_name),
                    ],
                ),
            ])
        }
    }
}

fn service_deferred_install_commands(
    options: &RunnerServiceOptions,
) -> Result<Vec<ServiceCommand>, String> {
    match options.platform {
        // A LaunchAgent is registered atomically when the later start action
        // bootstraps its already-written plist.
        RunnerServicePlatform::MacOsLaunchAgent => Ok(Vec::new()),
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => Ok(
            vec![systemctl_command(options.platform, &["daemon-reload"])],
        ),
    }
}

fn service_compensation_quiesce_commands(
    options: &RunnerServiceOptions,
    active: bool,
    enabled: bool,
) -> Result<Vec<ServiceCommand>, String> {
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            if active {
                plugin_service_control_commands(options, "stop", true)
            } else {
                Ok(Vec::new())
            }
        }
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            let unit = format!("{}.service", options.service_name);
            let mut commands = Vec::new();
            if active {
                commands.push(systemctl_command(options.platform, &["stop", &unit]));
            }
            if enabled {
                commands.push(systemctl_command(options.platform, &["disable", &unit]));
            }
            Ok(commands)
        }
    }
}

fn service_compensation_enablement_commands(
    options: &RunnerServiceOptions,
    installed: bool,
    enabled: bool,
) -> Result<Vec<ServiceCommand>, String> {
    if !installed {
        return Ok(Vec::new());
    }
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => Ok(Vec::new()),
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(vec![systemctl_command(
                options.platform,
                &[
                    if enabled { "enable" } else { "disable" },
                    &format!("{}.service", options.service_name),
                ],
            )])
        }
    }
}

fn service_compensation_activity_commands(
    options: &RunnerServiceOptions,
    installed: bool,
    active: bool,
) -> Result<Vec<ServiceCommand>, String> {
    if !installed || !active {
        return Ok(Vec::new());
    }
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => {
            plugin_service_control_commands(options, "start", false)
        }
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(vec![systemctl_command(
                options.platform,
                &["start", &format!("{}.service", options.service_name)],
            )])
        }
    }
}

fn service_install_is_artifact_only(options: &RunnerServiceOptions) -> bool {
    let Some(output_path) = &options.output_path else {
        return false;
    };
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => default_service_install_path(options)
            .map(|path| path != *output_path)
            .unwrap_or(true),
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            default_service_install_path(options)
                .map(|path| path != *output_path)
                .unwrap_or(true)
        }
    }
}

fn service_uninstall_commands(
    options: &RunnerServiceOptions,
) -> Result<Vec<ServiceCommand>, String> {
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => Ok(vec![ServiceCommand {
            program: "launchctl".to_string(),
            args: vec![
                "bootout".to_string(),
                format!("{}/{}", launchctl_user_domain(), options.service_name),
            ],
        }]),
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(vec![
                systemctl_command(
                    options.platform,
                    &["stop", &format!("{}.service", options.service_name)],
                ),
                systemctl_command(
                    options.platform,
                    &["disable", &format!("{}.service", options.service_name)],
                ),
                systemctl_command(options.platform, &["daemon-reload"]),
            ])
        }
    }
}

fn service_status_commands(options: &RunnerServiceOptions) -> Result<Vec<ServiceCommand>, String> {
    match options.platform {
        RunnerServicePlatform::MacOsLaunchAgent => Ok(vec![ServiceCommand {
            program: "launchctl".to_string(),
            args: vec![
                "print".to_string(),
                format!("{}/{}", launchctl_user_domain(), options.service_name),
            ],
        }]),
        RunnerServicePlatform::LinuxUserSystemd | RunnerServicePlatform::LinuxSystemSystemd => {
            Ok(vec![
                systemctl_command(
                    options.platform,
                    &["is-active", &format!("{}.service", options.service_name)],
                ),
                systemctl_command(
                    options.platform,
                    &["is-enabled", &format!("{}.service", options.service_name)],
                ),
            ])
        }
    }
}

fn launchctl_user_domain() -> String {
    #[cfg(unix)]
    {
        format!("gui/{}", unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        "gui/0".to_string()
    }
}

fn systemctl_command(platform: RunnerServicePlatform, args: &[&str]) -> ServiceCommand {
    let mut command_args = Vec::new();
    if matches!(platform, RunnerServicePlatform::LinuxUserSystemd) {
        command_args.push("--user".to_string());
    }
    command_args.extend(args.iter().map(|value| value.to_string()));
    ServiceCommand {
        program: "systemctl".to_string(),
        args: command_args,
    }
}

fn command_plan_json(commands: &[ServiceCommand]) -> Vec<Value> {
    commands
        .iter()
        .map(|command| json!({"program": command.program, "args": command.args}))
        .collect()
}

#[allow(dead_code)]
fn build_runner_service_runtime_config<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
) -> Result<RunnerServiceRuntimeConfig, String> {
    let organization_id = resolved
        .organization_id
        .clone()
        .unwrap_or_else(|| credential.organization_id.clone());
    let project_id = resolved.project_id.clone().ok_or_else(|| {
        "RUNNER_SERVICE_PROJECT_REQUIRED: selected profile has no projectId".to_string()
    })?;
    let runner_id = resolved.runner_id.clone().ok_or_else(|| {
        "RUNNER_SERVICE_RUNNER_REQUIRED: selected profile has no runnerId".to_string()
    })?;
    let local_root_path = resolved.workspace_path.clone().ok_or_else(|| {
        "RUNNER_SERVICE_WORKSPACE_REQUIRED: selected profile has no workspacePath".to_string()
    })?;
    let request = StreamCredentialRequest {
        organization_id: organization_id.clone(),
        project_id: project_id.clone(),
        runner_id: runner_id.clone(),
        project_runner_binding_id: binding_id.to_string(),
        runner_session_id: None,
        protocol_version: PROTOCOL_VERSION.to_string(),
        runner_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let stream_credential = client
        .issue_stream_credential(
            credential,
            &request,
            &idempotency_key("service-stream-credential", binding_id),
        )
        .map_err(format_core_error)?;
    if stream_credential.token_type != "Bearer" {
        return Err(
            "RUNNER_SERVICE_STREAM_CREDENTIAL_INVALID: token_type must be Bearer".to_string(),
        );
    }
    Ok(RunnerServiceRuntimeConfig {
        profile: resolved.profile.clone(),
        organization_id,
        project_id,
        runner_id,
        binding_id: binding_id.to_string(),
        local_root_path,
        runner_device_id: format!("device_{}", machine_fingerprint_hash()),
        stream_credential,
    })
}

#[allow(dead_code)]
fn run_runner_service_reconnect_loop<C: ManagementApiClient>(
    client: &mut C,
    credential: &ManagementCredential,
    resolved: &loomex_core::ResolvedCliSettings,
    binding_id: &str,
    launcher: &mut dyn RunnerServiceRuntimeLauncher,
    max_attempts: Option<usize>,
    mut sleep: impl FnMut(Duration),
) -> Result<(), String> {
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let runtime_config =
            build_runner_service_runtime_config(client, credential, resolved, binding_id)?;
        match launcher.run_until_disconnect(runtime_config) {
            Ok(()) => return Ok(()),
            Err(err) if is_terminal_service_runtime_error(&err) => return Err(err),
            Err(err) => {
                if max_attempts.is_some_and(|max_attempts| attempts >= max_attempts) {
                    return Err(err);
                }
                eprintln!("runner service retryable runtime error: {err}");
                sleep(Duration::from_secs(5));
            }
        }
    }
}

#[allow(dead_code)]
fn is_terminal_service_runtime_error(error: &str) -> bool {
    let code = error_code_from_message(error);
    code.contains("AUTH")
        || code.contains("PERMISSION")
        || code.contains("FORBIDDEN")
        || code.contains("UNAUTHENTICATED")
        || code.contains("UNAUTHORIZED")
        || code.contains("PROTOCOL")
        || code.contains("VERSION")
        || code.contains("INVALID")
        || code.contains("EXPIRED")
        || code.contains("STREAM_CREDENTIAL")
        || code.contains("OUT_OF_ORDER")
}

#[allow(dead_code)]
fn run_service_transport_once(
    config: RunnerServiceRuntimeConfig,
) -> Result<RunnerServiceRuntimeStart, String> {
    let mut runtime = build_service_transport_runtime(config)?;
    let now_epoch_ms = current_epoch_seconds()?.saturating_mul(1_000);
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("RUNNER_SERVICE_RUNTIME_FAILED: {err}"))?;
    let step = tokio_runtime
        .block_on(runtime.connect_and_register(now_epoch_ms))
        .map_err(format_core_error)?;
    Ok(RunnerServiceRuntimeStart {
        transport: step.selection.transport.as_str().to_string(),
        event: format!("{:?}", step.event),
        fallback: step.selection.fallback,
    })
}

#[allow(dead_code)]
fn run_service_transport_until_disconnect(
    config: RunnerServiceRuntimeConfig,
) -> Result<(), String> {
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("RUNNER_SERVICE_RUNTIME_FAILED: {err}"))?;
    tokio_runtime.block_on(async move {
        let mut runtime = build_service_transport_runtime(config)?;
        let now_epoch_ms = current_epoch_seconds()?.saturating_mul(1_000);
        let step = runtime
            .connect_and_register(now_epoch_ms)
            .await
            .map_err(format_core_error)?;
        eprintln!(
            "runner service transport registered via {} ({:?})",
            step.selection.transport.as_str(),
            step.event
        );
        loop {
            let now_epoch_ms = current_epoch_seconds()?.saturating_mul(1_000);
            let event = runtime
                .receive_next(now_epoch_ms)
                .await
                .map_err(format_core_error)?;
            eprintln!("runner service event: {event:?}");
        }
    })
}

#[allow(dead_code)]
fn build_service_transport_runtime(
    config: RunnerServiceRuntimeConfig,
) -> Result<RunnerTransportRuntime, String> {
    let expires_at_epoch_ms = loomex_core::management::parse_rfc3339_utc_epoch_seconds(
        &config.stream_credential.expires_at,
    )
    .map_err(format_core_error)?
    .saturating_mul(1_000);
    let stream_credential = StreamCredential {
        stream_token: config.stream_credential.stream_token.clone(),
        audience: config.stream_credential.audience.clone(),
        expires_at_epoch_ms,
    };
    let identity = StreamIdentity {
        organization_id: config.organization_id.clone(),
        project_id: config.project_id.clone(),
        runner_device_id: config.runner_device_id.clone(),
        runner_session_id: config.stream_credential.runner_session_id.clone(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        runner_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let grpc_config = GrpcClientConfig {
        endpoint: config.stream_credential.grpc_endpoint.clone(),
        ..GrpcClientConfig::default()
    };
    let websocket_config =
        websocket_config_from_grpc_endpoint(&config.stream_credential.grpc_endpoint);
    let transport_config = TransportClientConfig {
        grpc: grpc_config,
        websocket: Some(websocket_config),
        negotiation: TransportNegotiationPolicy::GrpcPreferred,
    };
    let connector = TransportConnector::new(transport_config, stream_credential, identity.clone())
        .map_err(format_core_error)?;
    let mut supervisor = StreamSupervisor::new(StreamSupervisorConfig {
        identity,
        project_runner_binding_id: config.binding_id.clone(),
        local_root_path: config.local_root_path.clone(),
        capabilities: default_runner_capabilities(),
        default_heartbeat_interval: Duration::from_secs(20),
        default_max_output_chunk_bytes: 64 * 1024,
        transport_max_inflight_output_bytes: 1024 * 1024,
    })
    .map_err(format_core_error)?;
    supervisor.authenticate().map_err(format_core_error)?;
    supervisor.bind_project().map_err(format_core_error)?;
    Ok(RunnerTransportRuntime::new(connector, supervisor))
}

#[allow(dead_code)]
fn websocket_config_from_grpc_endpoint(endpoint: &str) -> WebSocketClientConfig {
    let websocket_endpoint = if let Some(rest) = endpoint.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        endpoint.to_string()
    };
    WebSocketClientConfig {
        endpoint: websocket_endpoint,
        proxy: WebSocketProxyConfig {
            use_environment: true,
            required: false,
            explicit_proxy_url: None,
        },
        ..WebSocketClientConfig::default()
    }
}

fn run_bind(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.first().is_some_and(|value| is_help(value)) {
        return Ok(BIND_HELP.to_string());
    }
    let config_path = cli_config_path();
    let mut config = load_cli_config_from(&config_path)?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_credential(&store, &resolved.profile)?;
    validate_runner_credential_compatibility(&credential)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let mut prompt = StdioPrompt;
    run_bind_with(
        args,
        options,
        &mut config,
        &config_path,
        &credential,
        &mut client,
        &resolved.profile,
        &mut prompt,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_bind_with<C: ManagementApiClient>(
    args: &[String],
    options: &GlobalOptions,
    config: &mut CliConfig,
    config_path: &Path,
    credential: &ManagementCredential,
    client: &mut C,
    profile: &str,
    prompt: &mut dyn Prompt,
) -> Result<String, String> {
    if args.first().is_some_and(|value| is_help(value)) {
        return Ok(BIND_HELP.to_string());
    }
    let profile_state = config.profiles.get(profile);
    match args {
        [] => {
            if options.non_interactive {
                return Err(
                    "NON_INTERACTIVE_INPUT_REQUIRED: bind requires --project and --workspace"
                        .to_string(),
                );
            }
            let request = BindRequest::prompt(profile_state, prompt)?;
            bind_workspace(
                request,
                options,
                config,
                config_path,
                credential,
                client,
                profile,
            )
        }
        [subcommand] if subcommand == "list" => {
            let project_id = profile_state
                .and_then(|state| state.project_id.clone())
                .ok_or_else(|| "PROJECT_CONTEXT_MISSING: select a project first".to_string())?;
            let bindings = client
                .list_project_runner_bindings(credential, &project_id)
                .map_err(format_core_error)?;
            format_bindings(&bindings, options)
        }
        [subcommand, binding_id] if subcommand == "revoke" => {
            let project_id = profile_state
                .and_then(|state| state.project_id.clone())
                .ok_or_else(|| "PROJECT_CONTEXT_MISSING: select a project first".to_string())?;
            client
                .revoke_project_runner_binding(
                    credential,
                    &project_id,
                    binding_id,
                    &idempotency_key("binding-revoke", binding_id),
                )
                .map_err(format_core_error)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.bindingRevoke/v1",
                    "bindingId": binding_id,
                    "revoked": true
                })
                .to_string());
            }
            Ok(format!("revoked binding: {binding_id}"))
        }
        _ => {
            let request = BindRequest::parse(args, profile_state)?;
            bind_workspace(
                request,
                options,
                config,
                config_path,
                credential,
                client,
                profile,
            )
        }
    }
}

fn bind_workspace<C: ManagementApiClient>(
    request: BindRequest,
    options: &GlobalOptions,
    config: &mut CliConfig,
    config_path: &Path,
    credential: &ManagementCredential,
    client: &mut C,
    profile: &str,
) -> Result<String, String> {
    let workspace = validate_workspace_path(&request.workspace_path)?;
    let project = client
        .get_project(credential, &request.project_id)
        .map_err(format_core_error)?;
    if project.status != "active" {
        return Err(format!(
            "PROJECT_UNAVAILABLE: project status is {}",
            project.status
        ));
    }
    let organization_id = project.organization_id.clone();
    let runner = client
        .upsert_current_runner(
            credential,
            &RunnerUpsertRequest {
                organization_id: organization_id.clone(),
                display_name: local_runner_display_name(),
                machine_fingerprint_hash: machine_fingerprint_hash(),
                os: env::consts::OS.to_string(),
                arch: env::consts::ARCH.to_string(),
                runner_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: default_runner_capabilities(),
            },
            &idempotency_key("runner-upsert", &organization_id),
        )
        .map_err(format_core_error)?;
    let binding = client
        .create_project_runner_binding(
            credential,
            &request.project_id,
            &ProjectRunnerBindingCreateRequest {
                organization_id: organization_id.clone(),
                runner_id: runner.id.clone(),
                local_root_path: workspace.display_path.clone(),
                local_root_fingerprint: Some(workspace.fingerprint.clone()),
            },
            &idempotency_key("binding-create", &workspace.display_path),
        )
        .map_err(format_core_error)?;

    config
        .set_key(
            &format!("profiles.{profile}.organizationId"),
            organization_id.clone(),
        )
        .map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{profile}.projectId"),
            request.project_id.clone(),
        )
        .map_err(format_core_error)?;
    config
        .set_key(&format!("profiles.{profile}.runnerId"), runner.id.clone())
        .map_err(format_core_error)?;
    config
        .set_key(&format!("profiles.{profile}.bindingId"), binding.id.clone())
        .map_err(format_core_error)?;
    config
        .set_key(
            &format!("profiles.{profile}.workspacePath"),
            workspace.display_path.clone(),
        )
        .map_err(format_core_error)?;
    config.save(config_path).map_err(format_core_error)?;

    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.binding/v1",
            "profile": profile,
            "projectId": request.project_id,
            "organizationId": organization_id,
            "runnerId": runner.id,
            "binding": binding,
            "workspace": {
                "path": workspace.display_path,
                "fingerprint": workspace.fingerprint
            }
        })
        .to_string());
    }
    Ok(format!(
        "bound workspace: {}\nproject: {}\nbinding: {}",
        workspace.display_path, request.project_id, binding.id
    ))
}

fn run_workflow(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(WORKFLOW_HELP.to_string());
    }
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_credential(&store, &resolved.profile)?;
    validate_runner_credential_compatibility(&credential)?;
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let mut prompt = StdioPrompt;
    run_workflow_with(
        args,
        options,
        &credential,
        &mut client,
        WorkflowInputReader::from_runtime,
        &resolved,
        &mut prompt,
    )
}

fn run_workflow_with<C: ManagementApiClient>(
    args: &[String],
    options: &GlobalOptions,
    credential: &ManagementCredential,
    client: &mut C,
    read_input: impl FnOnce(&str) -> Result<Value, String>,
    resolved: &loomex_core::ResolvedCliSettings,
    prompt: &mut dyn Prompt,
) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(WORKFLOW_HELP.to_string());
    }
    match args {
        [] => Ok(WORKFLOW_HELP.to_string()),
        [subcommand] if subcommand == "list" => parsed_stub("workflow list", &[], options),
        [subcommand, workflow_id] if subcommand == "show" => {
            parsed_stub("workflow show", std::slice::from_ref(workflow_id), options)
        }
        [subcommand, workflow_id, rest @ ..] if subcommand == "run" => {
            let request = WorkflowRunRequest::parse(workflow_id, rest, resolved, read_input)?;
            let binding_id = resolve_workflow_binding_id(
                client,
                credential,
                &request.project_id,
                request.binding_id.as_deref(),
                request.workspace_path.as_deref(),
            )?;
            let schema = client
                .get_workflow_input_schema(credential, &request.workflow_id)
                .map_err(format_core_error)?;
            let input = prepare_workflow_input(request.input, schema.as_ref(), options, prompt)?;
            let input = apply_human_input_to_workflow_input(
                input,
                request.human_input.clone(),
                request.human_input_cancelled,
                options,
                schema.as_ref(),
            )?;
            if let Some(schema) = schema.as_ref() {
                validate_workflow_input_schema(&input, schema)?;
            }
            let response = client
                .start_workflow_run(
                    credential,
                    &WorkflowRunStartRequest {
                        organization_id: request.organization_id.clone(),
                        project_id: request.project_id.clone(),
                        workflow_id: request.workflow_id.clone(),
                        inputs: input,
                        project_runner_binding_id: binding_id.clone(),
                    },
                )
                .map_err(format_core_error)?;
            let human_resolution = resolve_waiting_human_input(
                client,
                credential,
                &request.workflow_id,
                &response.id,
                &response.status,
                request.human_input.clone(),
                request.human_input_cancelled,
                options,
                prompt,
            )?;
            let followed_events = if request.follow {
                follow_run_logs(&response.id)
            } else {
                Vec::new()
            };
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.workflowRun/v1",
                    "runId": response.id,
                    "status": response.status,
                    "workflowId": request.workflow_id,
                    "projectId": request.project_id,
                    "bindingId": binding_id,
                    "uiUrl": response.ui_url,
                    "humanInput": human_resolution,
                    "follow": {
                        "enabled": request.follow,
                        "events": followed_events
                    }
                })
                .to_string());
            }
            let mut lines = vec![
                format!("run id: {}", response.id),
                format!("status: {}", response.status),
            ];
            if let Some(ui_url) = response.ui_url {
                lines.push(format!("link: {ui_url}"));
            }
            if let Some(human_resolution) = human_resolution {
                lines.push(format!("human input: {human_resolution}"));
            }
            if request.follow {
                if followed_events.is_empty() {
                    lines.push("follow: no local events yet".to_string());
                } else {
                    lines.extend(followed_events.into_iter().map(|entry| {
                        format!(
                            "{} {} {}",
                            entry.timestamp_epoch_ms, entry.event_type, entry.message
                        )
                    }));
                }
            }
            Ok(lines.join("\n"))
        }
        [subcommand, ..] => Err(format!(
            "unknown workflow subcommand: {subcommand}\n{WORKFLOW_HELP}"
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalApprovalView {
    approval_request_id: String,
    status: String,
    capability: String,
    workflow_run_id: Option<String>,
    node_id: Option<String>,
    summary: String,
    created_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalCliOptions {
    path: PathBuf,
    reason: Option<String>,
}

impl ApprovalCliOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut path = None;
        let mut reason = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--path" => {
                    index += 1;
                    path = Some(PathBuf::from(required_value(args, index, "--path")?));
                }
                "--reason" => {
                    index += 1;
                    reason = Some(required_value(args, index, "--reason")?);
                }
                value => return Err(format!("unknown approval option: {value}\n{APPROVAL_HELP}")),
            }
            index += 1;
        }
        Ok(Self {
            path: path.unwrap_or_else(default_log_path),
            reason,
        })
    }
}

fn run_approval(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(APPROVAL_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "list" => {
            let approval_options = ApprovalCliOptions::parse(rest)?;
            let approvals = local_approval_inbox(&approval_options.path)?;
            format_approval_inbox(&approvals, options)
        }
        [subcommand, approval_id, rest @ ..]
            if matches!(subcommand.as_str(), "approve" | "deny") =>
        {
            let approval_options = ApprovalCliOptions::parse(rest)?;
            let approvals = local_approval_inbox(&approval_options.path)?;
            let Some(approval) = approvals
                .iter()
                .find(|approval| approval.approval_request_id == *approval_id)
            else {
                return Err(format!("APPROVAL_NOT_FOUND: {approval_id}"));
            };
            if approval.status != "pending" {
                return Err(format!(
                    "APPROVAL_NOT_PENDING: {approval_id} is {}",
                    approval.status
                ));
            }
            let decision = if subcommand == "approve" {
                "approved"
            } else {
                "denied"
            };
            append_approval_decision_log(
                &approval_options.path,
                approval,
                decision,
                approval_options.reason.as_deref(),
            )?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.approvalDecision/v1",
                    "approvalRequestId": approval_id,
                    "decision": decision,
                    "status": "recorded"
                })
                .to_string());
            }
            Ok(format!("approval {approval_id}: {decision}"))
        }
        [subcommand, ..] => Err(format!(
            "unknown approval subcommand: {subcommand}\n{APPROVAL_HELP}"
        )),
        [] => Ok(APPROVAL_HELP.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupportBundleOptions {
    output_path: Option<PathBuf>,
    log_limit: usize,
    remote_diagnostic_consent: bool,
}

impl SupportBundleOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut output_path = None;
        let mut log_limit = DEFAULT_LOG_LIMIT;
        let mut remote_diagnostic_consent = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--output" | "--path" => {
                    let option = args[index].clone();
                    index += 1;
                    output_path = Some(PathBuf::from(required_value(args, index, &option)?));
                }
                "--limit" => {
                    index += 1;
                    log_limit = required_value(args, index, "--limit")?
                        .parse::<usize>()
                        .map_err(|_| "SUPPORT_BUNDLE_INPUT_INVALID: --limit must be numeric")?
                        .clamp(1, 1_000);
                }
                "--remote-diagnostic-consent" => {
                    remote_diagnostic_consent = true;
                }
                value => {
                    return Err(format!(
                        "unknown support bundle option: {value}\n{SUPPORT_HELP}"
                    ))
                }
            }
            index += 1;
        }
        Ok(Self {
            output_path,
            log_limit,
            remote_diagnostic_consent,
        })
    }
}

fn run_support(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || args.first().is_some_and(|value| is_help(value)) {
        return Ok(SUPPORT_HELP.to_string());
    }
    match args {
        [subcommand, rest @ ..] if subcommand == "bundle" => {
            let bundle_options = SupportBundleOptions::parse(rest)?;
            let output_path = bundle_options
                .output_path
                .unwrap_or_else(default_support_bundle_path);
            let bundle = build_support_bundle(bundle_options.log_limit)?;
            write_support_bundle(&output_path, &bundle)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.supportBundleResult/v1",
                    "outputPath": output_path,
                    "bytes": fs::metadata(&output_path).map(|metadata| metadata.len()).unwrap_or(0),
                    "remoteDiagnosticConsent": bundle_options.remote_diagnostic_consent
                })
                .to_string());
            }
            Ok(format!("support bundle: {}", output_path.display()))
        }
        [subcommand, rest @ ..] if subcommand == "diagnostic-request" => {
            let bundle_options = SupportBundleOptions::parse(rest)?;
            if !bundle_options.remote_diagnostic_consent {
                return Err(
                    "REMOTE_DIAGNOSTIC_CONSENT_REQUIRED: rerun with --remote-diagnostic-consent"
                        .to_string(),
                );
            }
            let output_path = bundle_options
                .output_path
                .unwrap_or_else(default_support_bundle_path);
            let bundle = build_support_bundle(bundle_options.log_limit)?;
            write_support_bundle(&output_path, &bundle)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.remoteDiagnosticRequest/v1",
                    "consent": true,
                    "bundlePath": output_path,
                    "uploadReady": true,
                    "bytes": fs::metadata(&output_path).map(|metadata| metadata.len()).unwrap_or(0)
                })
                .to_string());
            }
            Ok(format!(
                "remote diagnostic request prepared with consent: {}",
                output_path.display()
            ))
        }
        [subcommand, rest @ ..] if subcommand == "migrate-legacy" => {
            run_support_migrate_legacy(rest, options)
        }
        [subcommand, ..] => Err(format!(
            "unknown support subcommand: {subcommand}\n{SUPPORT_HELP}"
        )),
        [] => Ok(SUPPORT_HELP.to_string()),
    }
}

fn build_support_bundle(log_limit: usize) -> Result<Value, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(CliConfigOverrides::default(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let mut config_entries = config
        .list_entries()
        .into_iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": if is_sensitive_cli_key(&key) { "[REDACTED]".to_string() } else { redact_cli_text(&value) }
            })
        })
        .collect::<Vec<_>>();
    config_entries.sort_by_key(|entry| {
        entry
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    let log_entries = read_recent_log_entries(default_log_path(), log_limit)
        .unwrap_or_default()
        .into_iter()
        .map(redact_log_entry_for_output)
        .collect::<Vec<_>>();
    let mut fake_client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let status =
        build_runner_status_report(&config, &resolved, None, &mut fake_client, &log_entries);
    let doctor = build_doctor_checks(
        &resolved,
        None,
        Some(&"AUTH_REQUIRED: credential unavailable".to_string()),
        &mut fake_client,
        None,
        false,
        |key| env::var(key).ok(),
    );
    let recent_errors = log_entries
        .iter()
        .filter(|entry| entry.level == "error" || entry.event_type.contains("error"))
        .cloned()
        .collect::<Vec<_>>();
    let connectivity = doctor
        .iter()
        .filter(|check| matches!(check.name.as_str(), "server" | "runnerControl"))
        .map(|check| {
            json!({
                "name": check.name,
                "status": check.status,
                "message": redact_cli_text(&check.message)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": "loomex.cli.supportBundle/v1",
        "generatedAtEpochSeconds": current_epoch_seconds().unwrap_or(0),
        "profile": resolved.profile,
        "runnerVersion": env!("CARGO_PKG_VERSION"),
        "protocolVersion": PROTOCOL_VERSION,
        "os": {
            "family": env::consts::FAMILY,
            "os": env::consts::OS,
            "arch": env::consts::ARCH
        },
        "config": config_entries,
        "runnerStatus": {
            "status": status.status,
            "selectedProjectId": status.selected_project_id,
            "selectedBindingId": status.selected_binding_id,
            "workspacePath": status.workspace_path,
            "warnings": status.warnings
        },
        "bindingSummary": {
            "selectedBindingId": status.selected_binding_id,
            "activeBindingId": status.active_binding.as_ref().map(|binding| binding.id.clone()),
            "workspacePath": status.workspace_path
        },
        "policySnapshot": support_policy_snapshot(),
        "connectivityTest": connectivity,
        "doctor": doctor
            .iter()
            .map(|check| json!({"name": check.name, "status": check.status, "message": redact_cli_text(&check.message)}))
            .collect::<Vec<_>>(),
        "recentErrors": recent_errors,
        "logs": log_entries
    }))
}

fn support_policy_snapshot() -> Value {
    json!({
        "defaultDecision": "ask",
        "mvpCapabilities": loomex_core::policy::MVP_CAPABILITIES,
        "reservedCapabilities": loomex_core::policy::RESERVED_CAPABILITIES,
        "managedPolicy": "not embedded in support bundle; use loomex policy explain for local evaluation"
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct LegacyMigrationOptions {
    legacy_config_path: Option<PathBuf>,
    target_config_path: Option<PathBuf>,
    apply: bool,
    deactivate_old_daemon: bool,
}

impl LegacyMigrationOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--legacy-config" => {
                    index += 1;
                    options.legacy_config_path = Some(PathBuf::from(required_value(
                        args,
                        index,
                        "--legacy-config",
                    )?));
                }
                "--target-config" => {
                    index += 1;
                    options.target_config_path = Some(PathBuf::from(required_value(
                        args,
                        index,
                        "--target-config",
                    )?));
                }
                "--apply" => options.apply = true,
                "--deactivate-old-daemon" => options.deactivate_old_daemon = true,
                value => return Err(format!("unknown migration option: {value}\n{SUPPORT_HELP}")),
            }
            index += 1;
        }
        Ok(options)
    }
}

fn run_support_migrate_legacy(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let migration_options = LegacyMigrationOptions::parse(args)?;
    let legacy_path = migration_options
        .legacy_config_path
        .unwrap_or_else(default_legacy_config_path);
    let target_path = migration_options
        .target_config_path
        .unwrap_or_else(cli_config_path);
    let report = legacy_migration_report(
        &legacy_path,
        &target_path,
        migration_options.apply,
        migration_options.deactivate_old_daemon,
    )?;
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.legacyMigration/v1",
            "migration": report
        })
        .to_string());
    }
    Ok(format!(
        "legacy migration: {}\nlegacy config: {}\ntarget config: {}",
        report["status"].as_str().unwrap_or("unknown"),
        legacy_path.display(),
        target_path.display()
    ))
}

fn legacy_migration_report(
    legacy_path: &Path,
    target_path: &Path,
    apply: bool,
    deactivate_old_daemon: bool,
) -> Result<Value, String> {
    if !legacy_path.exists() {
        return Ok(json!({
            "status": "not_found",
            "legacyConfigPath": legacy_path,
            "targetConfigPath": target_path,
            "applied": false,
            "warnings": ["legacy loomex-runner config was not found"]
        }));
    }
    let content = fs::read_to_string(legacy_path)
        .map_err(|err| format!("LEGACY_CONFIG_READ_FAILED: {err}"))?;
    let legacy = loomex_core::RunnerConfig::parse_legacy(
        &content,
        "migration_reenroll_required".to_string(),
    )
    .map_err(|err| format!("{}: {}", err.code, err.message))?;
    let mut target = if target_path.exists() {
        load_cli_config_from(target_path)?
    } else {
        CliConfig::default()
    };
    let profile = target.selected_profile.clone();
    let conflicts = legacy_migration_conflicts(&target, &profile, &legacy);
    if !conflicts.is_empty() {
        return Err(format!(
            "LEGACY_MIGRATION_TARGET_CONFLICT: {}",
            serde_json::to_string(&conflicts).unwrap_or_else(|_| "[]".to_string())
        ));
    }
    target
        .set_key(
            &format!("profiles.{profile}.organizationId"),
            legacy.organization_id.clone(),
        )
        .map_err(format_core_error)?;
    target
        .set_key(
            &format!("profiles.{profile}.projectId"),
            legacy.project_id.clone(),
        )
        .map_err(format_core_error)?;
    target
        .set_key(
            &format!("profiles.{profile}.runnerId"),
            legacy.runner_id.clone(),
        )
        .map_err(format_core_error)?;
    target
        .set_key(
            &format!("profiles.{profile}.bindingId"),
            legacy.binding_id.clone(),
        )
        .map_err(format_core_error)?;
    target
        .set_key(
            &format!("profiles.{profile}.workspacePath"),
            legacy.local_root_path.clone(),
        )
        .map_err(format_core_error)?;
    if apply {
        target.save(target_path).map_err(format_core_error)?;
    }
    Ok(json!({
        "status": if apply { "applied" } else { "planned" },
        "legacyConfigPath": legacy_path,
        "targetConfigPath": target_path,
        "applied": apply,
        "imported": {
            "organizationId": legacy.organization_id,
            "projectId": legacy.project_id,
            "runnerId": legacy.runner_id,
            "bindingId": legacy.binding_id,
            "workspacePath": legacy.local_root_path
        },
        "credentialImported": false,
        "warnings": [
            "legacy tokens are not imported; run loomex login after migration if credentials are missing",
            "loomex runner uses gRPC/WebSocket stream semantics instead of legacy long-poll behavior",
            "verify policy and approval behavior before disabling the old runner"
        ],
        "oldDaemon": {
            "detected": legacy_daemon_detected(),
            "deactivationRequested": deactivate_old_daemon,
            "deactivationAction": if deactivate_old_daemon { "run loomex runner service uninstall for managed service installs; stop any legacy loomex-runner process before starting loomex" } else { "not_requested" }
        }
    }))
}

fn legacy_migration_conflicts(
    config: &CliConfig,
    profile: &str,
    legacy: &loomex_core::RunnerConfig,
) -> Vec<Value> {
    let Some(profile_config) = config.profiles.get(profile) else {
        return Vec::new();
    };
    [
        (
            "organizationId",
            profile_config.organization_id.as_deref(),
            legacy.organization_id.as_str(),
        ),
        (
            "projectId",
            profile_config.project_id.as_deref(),
            legacy.project_id.as_str(),
        ),
        (
            "runnerId",
            profile_config.runner_id.as_deref(),
            legacy.runner_id.as_str(),
        ),
        (
            "bindingId",
            profile_config.binding_id.as_deref(),
            legacy.binding_id.as_str(),
        ),
        (
            "workspacePath",
            profile_config.workspace_path.as_deref(),
            legacy.local_root_path.as_str(),
        ),
    ]
    .into_iter()
    .filter_map(|(key, existing, incoming)| {
        let existing = existing?.trim();
        (!existing.is_empty() && existing != incoming).then(|| {
            json!({
                "key": key,
                "existing": existing,
                "incoming": incoming
            })
        })
    })
    .collect()
}

fn default_legacy_config_path() -> PathBuf {
    env::var("HOME")
        .map(|home| loomex_core::config::legacy_config_path(Path::new(&home)))
        .unwrap_or_else(|_| env::temp_dir().join(".loomex-runner").join("config.toml"))
}

fn legacy_daemon_detected() -> bool {
    Command::new("loomex-runner")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn write_support_bundle(path: &Path, bundle: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("SUPPORT_BUNDLE_WRITE_FAILED: {err}"))?;
    }
    let text = serde_json::to_string_pretty(bundle)
        .map_err(|err| format!("SUPPORT_BUNDLE_SERIALIZE_FAILED: {err}"))?;
    if text.len() > 2 * 1024 * 1024 {
        return Err("SUPPORT_BUNDLE_TOO_LARGE: bundle exceeds 2 MiB".to_string());
    }
    fs::write(path, text).map_err(|err| format!("SUPPORT_BUNDLE_WRITE_FAILED: {err}"))
}

fn default_support_bundle_path() -> PathBuf {
    let timestamp = current_epoch_seconds().unwrap_or(0);
    env::temp_dir().join(format!("loomex-support-bundle-{timestamp}.json"))
}

fn local_approval_inbox(path: &Path) -> Result<Vec<LocalApprovalView>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let entries = read_recent_log_entries(path, 1_000)
        .map_err(|err| format!("{}: {}", err.code, err.message))?;
    let mut approvals = Vec::<LocalApprovalView>::new();
    let mut decisions = Vec::<String>::new();
    for entry in entries {
        if is_approval_decision_event(&entry.event_type) {
            if let Some(id) = approval_id_from_entry(&entry) {
                decisions.push(id);
            }
            continue;
        }
        if !is_approval_request_event(&entry.event_type) {
            continue;
        }
        let Some(approval_request_id) = approval_id_from_entry(&entry) else {
            continue;
        };
        approvals.push(LocalApprovalView {
            approval_request_id,
            status: "pending".to_string(),
            capability: string_metadata(&entry.metadata, &["capability"])
                .unwrap_or_else(|| "unknown".to_string()),
            workflow_run_id: entry.workflow_run_id.clone().or_else(|| {
                string_metadata(&entry.metadata, &["workflowRunId", "workflow_run_id"])
            }),
            node_id: string_metadata(&entry.metadata, &["nodeId", "node_id"]),
            summary: redact_cli_text(
                &string_metadata(&entry.metadata, &["summary", "actionSummary", "message"])
                    .unwrap_or_else(|| entry.message.clone()),
            ),
            created_at_epoch_ms: entry.timestamp_epoch_ms,
        });
    }
    approvals.retain(|approval| !decisions.contains(&approval.approval_request_id));
    approvals.sort_by_key(|approval| approval.created_at_epoch_ms);
    Ok(approvals)
}

fn is_approval_request_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "approval.requested" | "local_tool.approval_requested" | "approval.pending"
    )
}

fn is_approval_decision_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "approval.approved"
            | "approval.denied"
            | "approval.decision"
            | "local_tool.approval_decision"
    )
}

fn approval_id_from_entry(entry: &LogEntry) -> Option<String> {
    string_metadata(
        &entry.metadata,
        &[
            "approvalRequestId",
            "approval_request_id",
            "approvalId",
            "approval_id",
        ],
    )
    .or_else(|| (!entry.correlation_id.trim().is_empty()).then(|| entry.correlation_id.clone()))
}

fn string_metadata(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_string))
}

fn format_approval_inbox(
    approvals: &[LocalApprovalView],
    options: &GlobalOptions,
) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.approvalInbox/v1",
            "pendingCount": approvals.len(),
            "approvals": approvals
                .iter()
                .map(|approval| json!({
                    "approvalRequestId": approval.approval_request_id,
                    "status": approval.status,
                    "capability": approval.capability,
                    "workflowRunId": approval.workflow_run_id,
                    "nodeId": approval.node_id,
                    "summary": approval.summary,
                    "createdAtEpochMs": approval.created_at_epoch_ms
                }))
                .collect::<Vec<_>>()
        })
        .to_string());
    }
    if approvals.is_empty() {
        return Ok("No pending approvals".to_string());
    }
    Ok(approvals
        .iter()
        .map(|approval| {
            format!(
                "{}\t{}\t{}\t{}",
                approval.approval_request_id,
                approval.capability,
                approval.status,
                approval.summary
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn append_approval_decision_log(
    path: &Path,
    approval: &LocalApprovalView,
    decision: &str,
    reason: Option<&str>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("LOCAL_LOG_WRITE_FAILED: {err}"))?;
    }
    let entry = LogEntry::new(
        "info",
        if decision == "approved" {
            "approval.approved"
        } else {
            "approval.denied"
        },
        format!("approval {} {decision}", approval.approval_request_id),
    )
    .with_correlation_id(approval.approval_request_id.clone())
    .with_metadata(json!({
        "approvalRequestId": approval.approval_request_id,
        "decision": decision,
        "reason": reason.unwrap_or("cli_decision")
    }));
    let line = serde_json::to_string(&redact_log_entry_for_output(entry))
        .map_err(|err| format!("LOCAL_LOG_SERIALIZE_FAILED: {err}"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("LOCAL_LOG_WRITE_FAILED: {err}"))?;
    writeln!(file, "{line}").map_err(|err| format!("LOCAL_LOG_WRITE_FAILED: {err}"))
}

fn run_policy(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(POLICY_HELP.to_string());
    }
    match args {
        [subcommand] if subcommand == "view" => {
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.policyView/v1",
                    "defaultDecision": "ask",
                    "mvpCapabilities": loomex_core::policy::MVP_CAPABILITIES,
                    "reservedCapabilities": loomex_core::policy::RESERVED_CAPABILITIES
                })
                .to_string());
            }
            Ok(format!(
                "default decision: ask\nmvp capabilities: {}",
                loomex_core::policy::MVP_CAPABILITIES.join(", ")
            ))
        }
        [subcommand, rest @ ..] if matches!(subcommand.as_str(), "test" | "explain") => {
            let explanation = explain_policy(rest)?;
            if options.json {
                return Ok(json!({
                    "schemaVersion": "loomex.cli.policyExplain/v1",
                    "explanation": explanation
                })
                .to_string());
            }
            Ok(format!(
                "decision: {}\nsource: {}\nsupport: {}\nreason: {}",
                explanation["decision"].as_str().unwrap_or("unknown"),
                explanation["source"].as_str().unwrap_or("unknown"),
                explanation["capabilitySupport"]
                    .as_str()
                    .unwrap_or("unknown"),
                explanation["reason"].as_str().unwrap_or("unknown")
            ))
        }
        [subcommand, ..] => Err(format!(
            "unknown policy subcommand: {subcommand}\n{POLICY_HELP}"
        )),
        [] => Ok(POLICY_HELP.to_string()),
    }
}

fn explain_policy(args: &[String]) -> Result<Value, String> {
    let capability = option_value(args, "--capability")?;
    let workspace_path = option_value(args, "--workspace")?;
    let requested_path = option_value_optional(args, "--path");
    validate_known_options(args, &["--capability", "--workspace", "--path"])?;
    let evaluated_path = requested_path
        .as_deref()
        .map(|path| resolve_policy_explain_path(&workspace_path, path));
    let workspace =
        loomex_core::WorkspacePath::new(workspace_path.clone(), None).map_err(format_core_error)?;
    let binding = loomex_core::ProjectRunnerBinding {
        id: "local_explain_binding".to_string(),
        organization_id: "local".to_string(),
        project_id: "local".to_string(),
        runner_device_id: "local".to_string(),
        workspace,
        status: loomex_core::BindingStatus::Active,
        created_by: "cli".to_string(),
        last_seen_at_epoch_ms: None,
        revoked_at_epoch_ms: None,
    };
    let mut input = loomex_core::PolicyEvaluationInput::capability(capability.clone());
    input.requested_path = evaluated_path.clone();
    input.resolved_path = evaluated_path.clone();
    let evaluation = loomex_core::PolicyEngine::default()
        .evaluate(&input, &binding)
        .map_err(format_core_error)?;
    Ok(json!({
        "capability": capability,
        "workspacePath": workspace_path,
        "requestedPath": requested_path,
        "evaluatedPath": evaluated_path,
        "decision": format!("{:?}", evaluation.decision).to_ascii_lowercase(),
        "source": format!("{:?}", evaluation.source),
        "capabilitySupport": format!("{:?}", evaluation.capability_support),
        "reason": evaluation.reason
    }))
}

fn resolve_policy_explain_path(workspace_path: &str, requested_path: &str) -> String {
    let requested = Path::new(requested_path);
    if requested.is_absolute() {
        requested.to_string_lossy().to_string()
    } else {
        Path::new(workspace_path)
            .join(requested)
            .to_string_lossy()
            .to_string()
    }
}

fn run_trace(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if args.is_empty() || is_help(&args[0]) {
        return Ok(TRACE_HELP.to_string());
    }
    match args {
        [subcommand, run_id, rest @ ..] if subcommand == "export" => {
            validate_known_options(rest, &["--path", "--output"])?;
            let log_path = option_value_optional(rest, "--path")
                .map(PathBuf::from)
                .unwrap_or_else(default_log_path);
            let output_path = option_value_optional(rest, "--output").map(PathBuf::from);
            let entries = read_recent_log_entries(&log_path, 10_000)
                .map_err(|err| format!("{}: {}", err.code, err.message))?;
            let entries = filter_log_entries(entries, Some(run_id))
                .into_iter()
                .map(redact_log_entry_for_output)
                .collect::<Vec<_>>();
            let export = json!({
                "schemaVersion": "loomex.cli.traceExport/v1",
                "runId": run_id,
                "sourceLogPath": log_path,
                "summary": log_summary(&entries),
                "entries": entries
            });
            if let Some(output_path) = output_path {
                write_json_file(&output_path, &export, "TRACE_EXPORT_WRITE_FAILED")?;
                if options.json {
                    return Ok(json!({
                        "schemaVersion": "loomex.cli.traceExportResult/v1",
                        "runId": run_id,
                        "outputPath": output_path
                    })
                    .to_string());
                }
                return Ok(format!("trace export: {}", output_path.display()));
            }
            if options.json {
                return Ok(export.to_string());
            }
            serde_json::to_string_pretty(&export).map_err(|err| err.to_string())
        }
        [subcommand, ..] => Err(format!(
            "unknown trace subcommand: {subcommand}\n{TRACE_HELP}"
        )),
        [] => Ok(TRACE_HELP.to_string()),
    }
}

fn write_json_file(path: &Path, value: &Value, code: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{code}: {err}"))?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|err| format!("{code}: {err}"))?;
    fs::write(path, text).map_err(|err| format!("{code}: {err}"))
}

fn validate_known_options(args: &[String], known: &[&str]) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].as_str();
        if value == "." {
            index += 1;
            continue;
        }
        if !known.contains(&value) {
            return Err(format!("unknown option: {value}"));
        }
        if value == "--follow" || value == "--human-input-cancel" {
            index += 1;
            continue;
        }
        index += 1;
        if index >= args.len() {
            return Err(format!("missing value for {value}"));
        }
        index += 1;
    }
    Ok(())
}

fn parsed_stub(command: &str, args: &[String], options: &GlobalOptions) -> Result<String, String> {
    if options.non_interactive && requires_later_input(command) {
        return Err(format!(
            "NON_INTERACTIVE_INPUT_REQUIRED: {command} requires Phase 60 follow-up implementation"
        ));
    }
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.commandParsed/v1",
            "command": command,
            "args": args,
            "implemented": false
        })
        .to_string());
    }
    Ok(format!(
        "{command}: parsed; implementation pending in Phase 60 follow-up tasks"
    ))
}

fn requires_later_input(command: &str) -> bool {
    matches!(
        command,
        "login"
            | "bind"
            | "workflow run"
            | "approval approve"
            | "approval deny"
            | "project select"
            | "org select"
    )
}

fn run_runner_status(options: &GlobalOptions) -> Result<String, String> {
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_credential(&store, &resolved.profile).ok();
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let entries =
        read_recent_log_entries(default_log_path(), DEFAULT_LOG_LIMIT).unwrap_or_default();
    let report = build_runner_status_report(
        &config,
        &resolved,
        credential.as_ref(),
        &mut client,
        &entries,
    );
    format_runner_status_report(&report, options)
}

fn build_runner_status_report<C: ManagementApiClient>(
    config: &CliConfig,
    resolved: &loomex_core::ResolvedCliSettings,
    credential: Option<&ManagementCredential>,
    client: &mut C,
    log_entries: &[LogEntry],
) -> RunnerStatusReport {
    let profile = config.profiles.get(&resolved.profile);
    let mut warnings = Vec::new();
    let mut runner = None;
    let mut active_binding = None;
    if let (Some(credential), Some(organization_id)) =
        (credential, resolved.organization_id.as_deref())
    {
        match client.get_current_runner(credential, organization_id) {
            Ok(value) => runner = Some(value),
            Err(err) => warnings.push(format!("{}: {}", err.code, err.message)),
        }
    } else {
        warnings.push("AUTH_REQUIRED: login required for server runner status".to_string());
    }

    if let (Some(credential), Some(project_id)) = (credential, resolved.project_id.as_deref()) {
        match client.list_project_runner_bindings(credential, project_id) {
            Ok(bindings) => {
                active_binding =
                    select_active_binding(&bindings, profile.and_then(|p| p.binding_id.as_deref()));
            }
            Err(err) => warnings.push(format!("{}: {}", err.code, err.message)),
        }
    }

    let connected = runner
        .as_ref()
        .is_some_and(|runner| matches!(runner.status.as_str(), "connected" | "online" | "busy"));
    RunnerStatusReport {
        status: if connected {
            "connected".to_string()
        } else {
            "disconnected".to_string()
        },
        profile: resolved.profile.clone(),
        server_url: resolved.server_url.clone(),
        host_header: resolved.host_header.clone(),
        selected_project_id: resolved.project_id.clone(),
        selected_binding_id: profile.and_then(|profile| profile.binding_id.clone()),
        workspace_path: resolved.workspace_path.clone(),
        runner,
        active_binding,
        active_runs: active_run_ids_from_logs(log_entries),
        warnings,
    }
}

fn select_active_binding(
    bindings: &[ManagementProjectRunnerBinding],
    selected_binding_id: Option<&str>,
) -> Option<ManagementProjectRunnerBinding> {
    selected_binding_id
        .and_then(|id| {
            bindings
                .iter()
                .find(|binding| binding.id == id && binding.status == "active")
        })
        .or_else(|| bindings.iter().find(|binding| binding.status == "active"))
        .cloned()
}

fn active_run_ids_from_logs(entries: &[LogEntry]) -> Vec<String> {
    let mut active = Vec::<String>::new();
    for entry in entries {
        let Some(run_id) = entry.workflow_run_id.as_ref().or_else(|| {
            if entry.correlation_id.starts_with("run_") {
                Some(&entry.correlation_id)
            } else {
                None
            }
        }) else {
            continue;
        };
        if matches!(
            entry.event_type.as_str(),
            "workflow.completed" | "workflow.failed" | "workflow.canceled" | "runner.disconnected"
        ) {
            active.retain(|id| id != run_id);
        } else if !active.iter().any(|id| id == run_id) {
            active.push(run_id.clone());
        }
    }
    active
}

fn format_runner_status_report(
    report: &RunnerStatusReport,
    options: &GlobalOptions,
) -> Result<String, String> {
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerStatus/v1",
            "status": report.status,
            "profile": report.profile,
            "serverUrl": report.server_url,
            "hostHeader": report.host_header,
            "selectedProjectId": report.selected_project_id,
            "selectedBindingId": report.selected_binding_id,
            "workspacePath": report.workspace_path,
            "runner": report.runner,
            "activeBinding": report.active_binding,
            "activeRuns": report.active_runs,
            "warnings": report.warnings,
            "protocolVersion": PROTOCOL_VERSION
        })
        .to_string());
    }
    Ok([
        format!("runner status: {}", report.status),
        format!("profile: {}", report.profile),
        format!("server: {}", report.server_url),
        format!(
            "project: {}",
            report
                .selected_project_id
                .as_deref()
                .unwrap_or("not selected")
        ),
        format!(
            "binding: {}",
            report
                .active_binding
                .as_ref()
                .map(|binding| binding.id.as_str())
                .or(report.selected_binding_id.as_deref())
                .unwrap_or("none")
        ),
        format!("active runs: {}", report.active_runs.len()),
    ]
    .join("\n"))
}

fn print_runner_logs(args: &[String], global_options: &GlobalOptions) -> Result<String, String> {
    let options = LogOptions::parse(args)?;
    let entries = read_recent_log_entries(&options.path, options.limit)
        .map_err(|err| format!("{}: {}", err.code, err.message))?;
    let entries = filter_log_entries(entries, options.run_id.as_deref())
        .into_iter()
        .map(redact_log_entry_for_output)
        .collect::<Vec<_>>();
    if global_options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerLogs/v1",
            "path": options.path,
            "limit": options.limit,
            "runId": options.run_id,
            "summary": log_summary(&entries),
            "entries": entries
        })
        .to_string());
    }
    entries
        .into_iter()
        .map(|entry| {
            serde_json::to_string(&entry)
                .map_err(|err| format!("LOCAL_LOG_SERIALIZE_FAILED: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
}

fn filter_log_entries(entries: Vec<LogEntry>, run_id: Option<&str>) -> Vec<LogEntry> {
    let Some(run_id) = run_id else {
        return entries;
    };
    entries
        .into_iter()
        .filter(|entry| {
            entry.workflow_run_id.as_deref() == Some(run_id) || entry.correlation_id == run_id
        })
        .collect()
}

fn follow_run_logs(run_id: &str) -> Vec<LogEntry> {
    follow_run_logs_with_reader(
        run_id,
        DEFAULT_FOLLOW_MAX_POLLS,
        Duration::from_millis(DEFAULT_FOLLOW_POLL_INTERVAL_MS),
        || read_recent_log_entries(default_log_path(), DEFAULT_LOG_LIMIT).unwrap_or_default(),
        thread::sleep,
    )
}

fn follow_run_logs_with_reader(
    run_id: &str,
    max_polls: usize,
    poll_interval: Duration,
    mut read_entries: impl FnMut() -> Vec<LogEntry>,
    mut sleep: impl FnMut(Duration),
) -> Vec<LogEntry> {
    let mut emitted_keys = HashSet::new();
    let mut followed = Vec::new();
    for poll_index in 0..max_polls {
        let mut entries = filter_log_entries(read_entries(), Some(run_id))
            .into_iter()
            .map(redact_log_entry_for_output)
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.timestamp_epoch_ms
                .cmp(&right.timestamp_epoch_ms)
                .then_with(|| left.event_type.cmp(&right.event_type))
                .then_with(|| left.correlation_id.cmp(&right.correlation_id))
        });
        let mut terminal_seen = false;
        for entry in entries {
            terminal_seen |= is_terminal_workflow_log_entry(&entry);
            let key = follow_log_entry_key(&entry);
            if emitted_keys.insert(key) {
                followed.push(entry);
            }
        }
        if terminal_seen {
            break;
        }
        if poll_index + 1 < max_polls {
            sleep(poll_interval);
        }
    }
    followed
}

fn follow_log_entry_key(entry: &LogEntry) -> String {
    let metadata = serde_json::to_string(&entry.metadata).unwrap_or_default();
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        entry.timestamp_epoch_ms, entry.event_type, entry.correlation_id, entry.message, metadata
    )
}

fn is_terminal_workflow_log_entry(entry: &LogEntry) -> bool {
    matches!(
        entry.event_type.as_str(),
        "workflow.completed" | "workflow.failed" | "workflow.canceled" | "workflow.cancelled"
    )
}

fn log_summary(entries: &[LogEntry]) -> Value {
    let mut by_event_type = serde_json::Map::new();
    let mut stream_events = 0usize;
    for entry in entries {
        *by_event_type
            .entry(entry.event_type.clone())
            .or_insert(Value::from(0_u64)) = Value::from(
            by_event_type
                .get(&entry.event_type)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                + 1,
        );
        if entry.event_type.contains("stream") || entry.event_type.contains("grpc") {
            stream_events += 1;
        }
    }
    json!({
        "total": entries.len(),
        "byEventType": by_event_type,
        "streamEvents": stream_events
    })
}

fn redact_log_entry_for_output(mut entry: LogEntry) -> LogEntry {
    entry.message = redact_cli_text(&entry.message);
    redact_cli_json_value(&mut entry.metadata);
    entry
}

fn redact_cli_json_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_cli_text(text),
        Value::Array(items) => {
            for item in items {
                redact_cli_json_value(item);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if is_sensitive_cli_key(key) {
                    *item = Value::String("[REDACTED]".to_string());
                } else {
                    redact_cli_json_value(item);
                }
            }
        }
        _ => {}
    }
}

fn redact_cli_text(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if lower.contains("bearer ")
        || contains_sensitive_cli_assignment(&compact, "authorization")
        || contains_sensitive_cli_assignment(&compact, "token")
        || contains_sensitive_cli_assignment(&compact, "api_key")
        || contains_sensitive_cli_assignment(&compact, "api-key")
        || contains_sensitive_cli_assignment(&compact, "apikey")
        || contains_sensitive_cli_assignment(&compact, "password")
        || contains_sensitive_cli_assignment(&compact, "secret")
        || contains_sensitive_cli_assignment(&compact, "cookie")
    {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

fn contains_sensitive_cli_assignment(compact_lower: &str, key: &str) -> bool {
    compact_lower.contains(&format!("{key}="))
        || compact_lower.contains(&format!("{key}:"))
        || compact_lower.contains(&format!("\"{key}\":"))
        || compact_lower.contains(&format!("'{key}':"))
}

fn is_sensitive_cli_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    [
        "authorization",
        "api_key",
        "apikey",
        "cookie",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|part| normalized.contains(part))
}

fn run_runner_doctor(args: &[String], options: &GlobalOptions) -> Result<String, String> {
    let doctor_options = DoctorOptions::parse(args)?;
    let config = load_cli_config()?;
    let resolved = config
        .resolve(options.config_overrides(), |key| env::var(key).ok())
        .map_err(format_core_error)?;
    let store = SystemCredentialStore::new(credential_dir());
    let credential = load_credential(&store, &resolved.profile);
    let mut client =
        HttpManagementApiClient::new(&resolved.server_url, resolved.host_header.clone())
            .map_err(format_core_error)?;
    let checks = build_doctor_checks(
        &resolved,
        credential.as_ref().ok(),
        credential.as_ref().err(),
        &mut client,
        doctor_options.workspace_path.as_deref(),
        doctor_options.deep,
        |key| env::var(key).ok(),
    );
    format_doctor_checks(&checks, options)
}

fn build_doctor_checks<C: ManagementApiClient>(
    resolved: &loomex_core::ResolvedCliSettings,
    credential: Option<&ManagementCredential>,
    credential_error: Option<&String>,
    client: &mut C,
    workspace_override: Option<&str>,
    deep: bool,
    read_env: impl Fn(&str) -> Option<String>,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck::ok(
        "config",
        format!(
            "profile={} server={}",
            resolved.profile, resolved.server_url
        ),
    ));
    let Some(credential) = credential else {
        checks.push(DoctorCheck::fail(
            "auth",
            credential_error
                .cloned()
                .unwrap_or_else(|| "AUTH_REQUIRED: login required".to_string()),
        ));
        checks.push(DoctorCheck::warn(
            "server",
            "server reachability skipped because auth is unavailable",
        ));
        checks.push(DoctorCheck::warn(
            "runnerControl",
            "runner-control transport check skipped because auth is unavailable",
        ));
        checks.push(workspace_doctor_check(
            workspace_override.or(resolved.workspace_path.as_deref()),
        ));
        checks.push(command_available_check("git", &["--version"]));
        checks.push(shell_available_check());
        if deep {
            checks.extend(deep_doctor_checks(resolved, &read_env));
        }
        return checks;
    };

    checks.push(DoctorCheck::ok(
        "auth",
        "management token is present and not near expiry",
    ));
    match client.get_current_runner(
        credential,
        resolved
            .organization_id
            .as_deref()
            .unwrap_or(&credential.organization_id),
    ) {
        Ok(runner) => checks.push(DoctorCheck::ok(
            "server",
            format!("runner {} status {}", runner.id, runner.status),
        )),
        Err(err) => checks.push(DoctorCheck::fail(
            "server",
            format!("{}: {}", err.code, err.message),
        )),
    }
    checks.push(runner_control_transport_doctor_check(
        resolved, credential, client,
    ));
    checks.push(workspace_doctor_check(
        workspace_override.or(resolved.workspace_path.as_deref()),
    ));
    checks.push(command_available_check("git", &["--version"]));
    checks.push(shell_available_check());
    if deep {
        checks.extend(deep_doctor_checks(resolved, &read_env));
    }
    checks
}

fn deep_doctor_checks(
    resolved: &loomex_core::ResolvedCliSettings,
    read_env: &impl Fn(&str) -> Option<String>,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let proxy_vars = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .into_iter()
    .filter_map(|key| {
        read_env(key)
            .filter(|value| !value.trim().is_empty())
            .map(|_| key.to_string())
    })
    .collect::<Vec<_>>();
    if proxy_vars.is_empty() {
        checks.push(DoctorCheck::ok("proxy", "no proxy environment detected"));
    } else {
        checks.push(DoctorCheck::warn(
            "proxy",
            format!(
                "proxy environment detected ({}); ensure NO_PROXY includes the local runner-control endpoint",
                proxy_vars.join(",")
            ),
        ));
    }
    checks.push(DoctorCheck::ok(
        "configPath",
        format!(
            "profile={} server={}",
            resolved.profile, resolved.server_url
        ),
    ));
    checks.push(DoctorCheck::ok(
        "runnerControlMode",
        "durable runner uses runner-control long-poll sessions and leased jobs",
    ));
    checks
}

fn runner_control_transport_doctor_check<C: ManagementApiClient>(
    resolved: &loomex_core::ResolvedCliSettings,
    credential: &ManagementCredential,
    client: &mut C,
) -> DoctorCheck {
    let (Some(project_id), Some(runner_id), Some(binding_id)) = (
        resolved.project_id.as_deref(),
        resolved.runner_id.as_deref(),
        resolved.binding_id.as_deref(),
    ) else {
        return DoctorCheck::warn(
            "runnerControl",
            "runner-control check skipped until project, runner, and binding are selected",
        );
    };
    let self_status = match client.get_runner_self_status(credential) {
        Ok(response) => response,
        Err(err) => {
            return DoctorCheck::fail("runnerControl", format!("{}: {}", err.code, err.message));
        }
    };
    let response_runner = self_status
        .get("runner")
        .and_then(|runner| runner.get("id"))
        .and_then(Value::as_str);
    if response_runner != Some(runner_id) {
        return DoctorCheck::fail(
            "runnerControl",
            "RUNNER_IDENTITY_MISMATCH: authenticated runner does not match selected runnerId",
        );
    }
    let runner_status = self_status
        .get("runner")
        .and_then(|runner| runner.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if matches!(runner_status, "disabled" | "revoked") {
        return DoctorCheck::fail(
            "runnerControl",
            format!("RUNNER_DISABLED: runner status is {runner_status}"),
        );
    }
    let has_jobs_scope = self_status
        .get("tokenScopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes
                .iter()
                .any(|scope| scope.as_str() == Some("runner.jobs"))
        });
    if !has_jobs_scope {
        return DoctorCheck::fail(
            "runnerControl",
            "AUTHORIZATION_FAILED: runner token must include runner.jobs scope",
        );
    }
    DoctorCheck::ok(
        "runnerControl",
        format!(
            "runner-control long-poll transport ready for project {project_id}, binding {binding_id}"
        ),
    )
}

fn workspace_doctor_check(workspace_path: Option<&str>) -> DoctorCheck {
    let Some(workspace_path) = workspace_path else {
        return DoctorCheck::warn("workspace", "no workspace selected");
    };
    match inspect_workspace_path_without_mutation(workspace_path) {
        Ok(workspace) => DoctorCheck::ok(
            "workspace",
            format!("read/write access ok {}", workspace.display()),
        ),
        Err(err) => DoctorCheck::fail("workspace", err),
    }
}

fn inspect_workspace_path_without_mutation(path: &str) -> Result<PathBuf, String> {
    let input = PathBuf::from(path);
    let metadata =
        fs::symlink_metadata(&input).map_err(|error| format!("WORKSPACE_PATH_INVALID: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(
            "WORKSPACE_PATH_INVALID: workspace must be a non-symlink directory".to_string(),
        );
    }
    let canonical = input
        .canonicalize()
        .map_err(|error| format!("WORKSPACE_PATH_INVALID: {error}"))?;
    if canonical.parent().is_none() {
        return Err("WORKSPACE_PATH_UNSAFE: refusing to inspect filesystem root".to_string());
    }
    fs::read_dir(&canonical).map_err(|error| format!("WORKSPACE_READ_FAILED: {error}"))?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(canonical.as_os_str().as_bytes())
            .map_err(|_| "WORKSPACE_PATH_INVALID: path contains a NUL byte".to_string())?;
        if unsafe { libc::access(path.as_ptr(), libc::R_OK | libc::W_OK | libc::X_OK) } != 0 {
            return Err(format!(
                "WORKSPACE_ACCESS_FAILED: {}",
                io::Error::last_os_error()
            ));
        }
    }
    #[cfg(not(unix))]
    if fs::metadata(&canonical)
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(true)
    {
        return Err("WORKSPACE_ACCESS_FAILED: workspace is read-only".to_string());
    }
    Ok(canonical)
}

fn command_available_check(name: &str, args: &[&str]) -> DoctorCheck {
    match Command::new(name).args(args).output() {
        Ok(output) if output.status.success() => DoctorCheck::ok(name, format!("{name} available")),
        Ok(output) => DoctorCheck::fail(name, format!("{name} exited with {}", output.status)),
        Err(err) => DoctorCheck::fail(name, format!("{name} unavailable: {err}")),
    }
}

fn shell_available_check() -> DoctorCheck {
    let check = if cfg!(windows) {
        command_available_check("cmd", &["/C", "exit", "0"])
    } else {
        command_available_check("sh", &["-c", "true"])
    };
    DoctorCheck {
        name: "shell".to_string(),
        status: check.status,
        message: check.message,
    }
}

fn format_doctor_checks(checks: &[DoctorCheck], options: &GlobalOptions) -> Result<String, String> {
    let overall = if checks.iter().any(|check| check.status == "failed") {
        "failed"
    } else if checks.iter().any(|check| check.status == "warning") {
        "warning"
    } else {
        "ok"
    };
    if options.json {
        return Ok(json!({
            "schemaVersion": "loomex.cli.runnerDoctor/v1",
            "status": overall,
            "checks": checks
                .iter()
                .map(|check| json!({
                    "name": check.name,
                    "status": check.status,
                    "message": check.message
                }))
                .collect::<Vec<_>>()
        })
        .to_string());
    }
    Ok(checks
        .iter()
        .map(|check| format!("{}: {} - {}", check.name, check.status, check.message))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn load_cli_config() -> Result<CliConfig, String> {
    load_cli_config_from(&cli_config_path())
}

fn load_cli_config_from(path: &std::path::Path) -> Result<CliConfig, String> {
    CliConfig::load_or_default(path).map_err(format_core_error)
}

fn cli_config_path() -> PathBuf {
    if let Ok(path) = env::var(CONFIG_PATH_ENV) {
        return PathBuf::from(path);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    default_config_path(&PathBuf::from(home))
}

fn credential_dir() -> PathBuf {
    if let Ok(path) = env::var(CREDENTIAL_DIR_ENV) {
        return PathBuf::from(path);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".loomex").join("credentials")
}

fn default_log_path() -> PathBuf {
    if let Ok(path) = env::var(LOG_PATH_ENV) {
        return PathBuf::from(path);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".loomex").join("runner.log.jsonl")
}

fn wizard_start_output(json_mode: bool) -> String {
    if json_mode {
        return json!({
            "schemaVersion": "loomex.cli.wizard/v1",
            "status": "ready",
            "nextCommands": [
                "loomex login",
                "loomex bind --project PROJECT_ID --workspace /srv/my-app",
                "loomex workflow run WORKFLOW_ID --input @input.json"
            ]
        })
        .to_string();
    }
    [
        format!("loomex runner core protocol {PROTOCOL_VERSION}"),
        "Interactive wizard entrypoint is ready.".to_string(),
        "Next: loomex login -> loomex bind -> loomex workflow run WORKFLOW_ID --input @input.json"
            .to_string(),
    ]
    .join("\n")
}

fn is_help(value: &str) -> bool {
    value == "--help" || value == "-h"
}

fn format_core_error(err: loomex_core::CoreError) -> String {
    format!("{}: {}", err.code, err.message)
}

fn error_code_from_message(message: &str) -> &str {
    message
        .split_once(':')
        .map(|(code, _)| code)
        .unwrap_or("CLI_ERROR")
}

fn exit_code_for_error(message: &str) -> i32 {
    let code = error_code_from_message(message);
    if code.contains("AUTH") {
        10
    } else if code.contains("INPUT") || code.contains("CONFIG") || code.contains("WORKSPACE") {
        2
    } else if code.contains("HTTP") || code.contains("SERVER") || code.contains("GRPC") {
        20
    } else if code.contains("LOCAL") || code.contains("LOG") {
        30
    } else {
        1
    }
}

fn error_json_envelope(message: &str) -> String {
    json!({
        "schemaVersion": "loomex.cli.error/v1",
        "error": {
            "code": error_code_from_message(message),
            "message": message.split_once(':').map(|(_, text)| text.trim()).unwrap_or(message),
            "retryable": error_is_retryable(message),
        },
        "exitCode": exit_code_for_error(message)
    })
    .to_string()
}

fn error_is_retryable(message: &str) -> bool {
    match error_code_from_message(message) {
        // MANAGEMENT_HTTP_FAILED is produced only when sending the request fails
        // before an HTTP response is available. Explicit transient status codes are
        // the only response failures classified here. Everything else remains
        // non-retryable so authentication and configuration failures cannot loop.
        "MANAGEMENT_HTTP_FAILED" => true,
        "MANAGEMENT_HTTP_STATUS" => [408, 425, 429, 500, 502, 503, 504]
            .iter()
            .any(|status| message.contains(&format!("HTTP {status}"))),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct GlobalOptions {
    json: bool,
    non_interactive: bool,
    profile: Option<String>,
    server_url: Option<String>,
    host_header: Option<String>,
}

impl GlobalOptions {
    fn parse(args: Vec<String>) -> Result<ParsedArgs, String> {
        let mut options = Self::default();
        let mut rest = Vec::new();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--json" => options.json = true,
                "--non-interactive" => options.non_interactive = true,
                "--profile" => {
                    index += 1;
                    options.profile = Some(required_value(&args, index, "--profile")?);
                }
                "--server-url" => {
                    index += 1;
                    options.server_url = Some(required_value(&args, index, "--server-url")?);
                }
                "--host-header" => {
                    index += 1;
                    options.host_header = Some(required_value(&args, index, "--host-header")?);
                }
                value => rest.push(value.to_string()),
            }
            index += 1;
        }
        Ok(ParsedArgs {
            options,
            args: rest,
        })
    }

    fn config_overrides(&self) -> CliConfigOverrides {
        CliConfigOverrides {
            profile: self.profile.clone(),
            server_url: self.server_url.clone(),
            host_header: self.host_header.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    options: GlobalOptions,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoginRequest {
    api_key: Option<String>,
    api_secret: Option<String>,
    organization_id: Option<String>,
    device_timeout_seconds: u64,
}

impl LoginRequest {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut request = Self {
            api_key: env::var("LOOMEX_API_KEY").ok(),
            api_secret: env::var("LOOMEX_API_SECRET").ok(),
            organization_id: env::var("LOOMEX_ORGANIZATION_ID").ok(),
            device_timeout_seconds: DEFAULT_DEVICE_LOGIN_TIMEOUT_SECONDS,
        };
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--api-key" => {
                    index += 1;
                    request.api_key = Some(required_value(args, index, "--api-key")?);
                }
                "--api-secret" => {
                    index += 1;
                    request.api_secret = Some(required_value(args, index, "--api-secret")?);
                }
                "--organization" | "--organization-id" => {
                    let option = args[index].clone();
                    index += 1;
                    request.organization_id = Some(required_value(args, index, &option)?);
                }
                "--device-timeout-seconds" => {
                    index += 1;
                    request.device_timeout_seconds =
                        required_value(args, index, "--device-timeout-seconds")?
                            .parse::<u64>()
                            .map_err(|_| {
                                "LOGIN_INPUT_INVALID: --device-timeout-seconds must be an integer"
                                    .to_string()
                            })?
                            .max(1);
                }
                "--help" | "-h" => return Err(LOGIN_HELP.to_string()),
                value => return Err(format!("unknown login option: {value}")),
            }
            index += 1;
        }
        Ok(request)
    }
}

fn required_value(args: &[String], index: usize, option: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing value for {option}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogOptions {
    path: PathBuf,
    limit: usize,
    run_id: Option<String>,
}

impl LogOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut path = None;
        let mut limit = DEFAULT_LOG_LIMIT;
        let mut run_id = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--path" => {
                    index += 1;
                    path = Some(PathBuf::from(required_value(args, index, "--path")?));
                }
                "--limit" => {
                    index += 1;
                    let value = required_value(args, index, "--limit")?;
                    limit = value
                        .parse::<usize>()
                        .map_err(|_| "invalid numeric value for --limit".to_string())?
                        .clamp(1, 1_000);
                }
                "--run-id" => {
                    index += 1;
                    run_id = Some(required_value(args, index, "--run-id")?);
                }
                "--help" | "-h" => return Err(RUNNER_HELP.to_string()),
                value => {
                    return Err(format!(
                        "unknown runner logs option: {value}\n{RUNNER_HELP}"
                    ))
                }
            }
            index += 1;
        }

        Ok(Self {
            path: path.unwrap_or_else(default_log_path),
            limit,
            run_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DoctorOptions {
    workspace_path: Option<String>,
    deep: bool,
}

impl DoctorOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--workspace" => {
                    index += 1;
                    options.workspace_path = Some(required_value(args, index, "--workspace")?);
                }
                "--deep" => {
                    options.deep = true;
                }
                "--help" | "-h" => return Err(RUNNER_HELP.to_string()),
                value => {
                    return Err(format!(
                        "unknown runner doctor option: {value}\n{RUNNER_HELP}"
                    ))
                }
            }
            index += 1;
        }
        Ok(options)
    }
}

const ROOT_HELP: &str = "\
usage:
  loomex [--json] [--non-interactive] [--profile NAME] [--server-url URL] [--host-header HOST]
  loomex login
  loomex logout
  loomex completion bash|zsh|fish
  loomex config get KEY
  loomex config set KEY VALUE
  loomex config list
  loomex profile list|current|use NAME
  loomex org list|select ORG_ID
  loomex project list|select PROJECT_ID
  loomex bind .|--project PROJECT_ID --workspace PATH|list|revoke BINDING_ID
  loomex workflow list|show WORKFLOW_ID|run WORKFLOW_ID --input JSON [--follow]
  loomex runner start|stop|status|logs|doctor|service|release|ops
  loomex approval list|approve APPROVAL_ID|deny APPROVAL_ID [--path PATH]
  loomex support bundle|diagnostic-request|migrate-legacy
  loomex policy view|test|explain --capability NAME --workspace PATH
  loomex trace export RUN_ID [--path LOG_PATH] [--output PATH]";

const LOGIN_HELP: &str = "\
usage:
  loomex login
  loomex login --api-key KEY --api-secret SECRET [--organization ORG_ID]";

const CONFIG_HELP: &str = "\
usage:
  loomex config get KEY
  loomex config set KEY VALUE
  loomex config list";

const COMPLETION_HELP: &str = "\
usage:
  loomex completion bash
  loomex completion zsh
  loomex completion fish";

const PROFILE_HELP: &str = "\
usage:
  loomex profile current
  loomex profile list
  loomex profile use NAME";

const RUNNER_HELP: &str = "\
usage:
  loomex runner start
  loomex runner stop
  loomex runner status [--json]
  loomex runner logs [--path PATH] [--limit N] [--run-id RUN_ID]
  loomex runner doctor [--workspace PATH] [--deep]
  loomex runner service install|uninstall|status|unit|run
  loomex runner release sign-manifest|verify-manifest|sign-artifact|verify-artifact|sbom|installer-plan|validate-compatibility
  loomex runner ops readiness-plan|release-gate|enterprise-plan|enterprise-signoff";

const RUNNER_SERVICE_HELP: &str = "\
usage:
  loomex runner service unit --platform macos|linux-user|linux-system
  loomex runner service install [--platform macos|linux-user|linux-system] [--output PATH] [--dry-run]
  loomex runner service uninstall [--platform macos|linux-user|linux-system] [--dry-run]
  loomex runner service status [--platform macos|linux-user|linux-system]
  loomex runner service run [--config PATH] [--profile NAME] [--log-path PATH] [--once]";

const RUNNER_RELEASE_HELP: &str = "\
usage:
  loomex runner release sign-manifest --manifest PATH --signing-key-file PATH
  loomex runner release sign-manifest --manifest PATH --signing-key-env ENV_NAME
  loomex runner release sign-manifest --manifest PATH --signing-key-stdin
  loomex runner release verify-manifest --manifest PATH --public-key HEX
  loomex runner release sign-artifact --name NAME --os OS --arch ARCH --path PATH --signing-key-file PATH
  loomex runner release verify-artifact --manifest PATH --name NAME --path PATH --public-key HEX
  loomex runner release sbom --package NAME=VERSION [--package NAME=VERSION]
  loomex runner release installer-plan [--version VERSION]
  loomex runner release validate-compatibility --matrix PATH";

const RUNNER_OPS_HELP: &str = "\
usage:
  loomex runner ops readiness-plan [--expected-runners N]
  loomex runner ops release-gate --report PATH
  loomex runner ops enterprise-plan
  loomex runner ops enterprise-signoff --report PATH";

const BIND_HELP: &str = "\
usage:
  loomex bind .
  loomex bind --project PROJECT_ID --workspace PATH
  loomex bind list
  loomex bind revoke BINDING_ID";

const WORKFLOW_HELP: &str = "\
usage:
  loomex workflow list
  loomex workflow show WORKFLOW_ID
  loomex workflow run WORKFLOW_ID --workspace PATH --input JSON [--follow]";

const ORG_HELP: &str = "usage:\n  loomex org list\n  loomex org select ORG_ID";
const PROJECT_HELP: &str = "usage:\n  loomex project list\n  loomex project select PROJECT_ID";
const APPROVAL_HELP: &str = "\
usage:
  loomex approval list [--path PATH]
  loomex approval approve APPROVAL_ID [--path PATH] [--reason TEXT]
  loomex approval deny APPROVAL_ID [--path PATH] [--reason TEXT]";
const SUPPORT_HELP: &str = "\
usage:
  loomex support bundle [--output PATH] [--limit N] [--remote-diagnostic-consent]
  loomex support diagnostic-request --remote-diagnostic-consent [--output PATH] [--limit N]
  loomex support migrate-legacy [--legacy-config PATH] [--target-config PATH] [--apply] [--deactivate-old-daemon]";
const POLICY_HELP: &str = "\
usage:
  loomex policy view
  loomex policy test --capability NAME --workspace PATH
  loomex policy explain --capability NAME --workspace PATH [--path REL_PATH]";
const TRACE_HELP: &str = "usage:\n  loomex trace export RUN_ID [--path LOG_PATH] [--output PATH]";

#[cfg(test)]
mod tests {
    use super::*;

    static PLUGIN_CONTROL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_plugin_auth_flow(server_url: &str) -> PluginAuthFlow {
        PluginAuthFlow {
            login_id: String::new(),
            profile: "default".to_string(),
            server_url: server_url.to_string(),
            host_header: None,
            challenge: DeviceLoginChallenge {
                device_code: "device-secret".to_string(),
                user_code: "ABCD-EFGH-JKLM".to_string(),
                verification_uri: format!("{server_url}/api/v1/auth/device/verify"),
                expires_in_seconds: 600,
                interval_seconds: 5,
            },
            created_at_epoch_seconds: 1_700_000_000,
        }
    }

    #[test]
    fn successful_plugin_auth_persists_custom_server_for_first_use() {
        let config_path = temp_config_path("plugin-auth-custom-server");
        let credential_root = temp_credential_dir("plugin-auth-custom-server");
        let store = LocalCredentialStore::new(credential_root.clone());
        CliConfig::default().save(&config_path).unwrap();
        let flow = test_plugin_auth_flow("https://loomex.internal.example");

        let result =
            complete_plugin_auth_flow(&flow, token("user.jwt.custom-server"), &config_path, &store)
                .unwrap();
        let saved = CliConfig::load_or_default(&config_path).unwrap();
        let resolved = saved
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();

        assert_eq!(result["serverUrl"], "https://loomex.internal.example");
        assert_eq!(resolved.server_url, "https://loomex.internal.example");
        assert_eq!(
            store.load("default.user").unwrap().unwrap().access_token,
            "user.jwt.custom-server"
        );
        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir_all(credential_root);
    }

    #[test]
    fn concurrent_plugin_auth_starts_allocate_unique_create_new_files() {
        let directory = temp_credential_dir("plugin-auth-concurrent-starts");
        let workers = 32;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
        let handles = (0..workers)
            .map(|_| {
                let directory = directory.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut flow = test_plugin_auth_flow("https://loomex.example");
                    barrier.wait();
                    allocate_plugin_auth_flow_in(&directory, &mut flow).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let flows = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let ids = flows
            .iter()
            .map(|flow| flow.login_id.clone())
            .collect::<HashSet<_>>();

        assert_eq!(ids.len(), workers);
        assert!(ids.iter().all(|id| {
            id.len() == "login-".len() + 32
                && id
                    .strip_prefix("login-")
                    .unwrap()
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
        }));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), workers);

        let collision = test_plugin_auth_flow("https://loomex.example");
        let mut collision = collision;
        collision.login_id = flows[0].login_id.clone();
        assert!(!try_create_plugin_auth_flow_file(&directory, &collision).unwrap());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn plugin_control_setup_status_works_before_daemon_or_runtime_exists() {
        let _lock = PLUGIN_CONTROL_ENV_LOCK.lock().unwrap();
        let runtime_root = env::temp_dir().join(format!(
            "loomex-plugin-first-use-{}-{}",
            process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&runtime_root);
        let previous = env::var_os(loomex_core::RUNTIME_HOME_ENV);
        let previous_plugin_root = env::var_os(PLUGIN_ROOT_ENV);
        env::set_var(loomex_core::RUNTIME_HOME_ENV, &runtime_root);
        env::remove_var(PLUGIN_ROOT_ENV);

        let output = run_runner_plugin_control(
            &[
                "setup.status".to_string(),
                "--params-json".to_string(),
                "{}".to_string(),
            ],
            &GlobalOptions {
                json: true,
                non_interactive: true,
                ..Default::default()
            },
        )
        .unwrap();

        match previous {
            Some(value) => env::set_var(loomex_core::RUNTIME_HOME_ENV, value),
            None => env::remove_var(loomex_core::RUNTIME_HOME_ENV),
        }
        match previous_plugin_root {
            Some(value) => env::set_var(PLUGIN_ROOT_ENV, value),
            None => env::remove_var(PLUGIN_ROOT_ENV),
        }
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(PLUGIN_CONTROL_SCHEMA_VERSION, parsed["schemaVersion"]);
        assert_eq!("setup.status", parsed["method"]);
        assert_eq!(false, parsed["result"]["installed"]);
        assert!(parsed["result"]["service"].is_object());
        assert_eq!(
            parsed["result"]["installed"],
            parsed["result"]["durableRuntime"]["installed"]
        );
        assert_eq!(
            parsed["result"]["runtime"],
            parsed["result"]["durableRuntime"]["runtime"]
        );
        assert_eq!(
            parsed["result"]["runtimeRoot"],
            parsed["result"]["durableRuntime"]["runtimeRoot"]
        );
        assert_eq!("package.error", parsed["result"]["recommendedNextAction"]);
        assert_eq!(
            "PLUGIN_ROOT_REQUIRED",
            parsed["result"]["bundledRuntime"]["error"]["code"]
        );
        let _ = fs::remove_dir_all(runtime_root);
    }

    #[test]
    fn setup_recommendation_distinguishes_deferred_from_stopped_service() {
        assert_eq!(
            (false, "auth.status", "continue_authentication_and_binding"),
            plugin_setup_recommendation(true, true, true, true, false, Some(false), false)
        );
        assert_eq!(
            (true, "setup.plan", "service_ready_but_inactive"),
            plugin_setup_recommendation(true, true, true, true, false, Some(true), false)
        );
        assert_eq!(
            (false, "auth.status", "setup_complete"),
            plugin_setup_recommendation(true, true, true, true, true, None, false)
        );
        assert_eq!(
            (true, "setup.plan", "runtime_mismatch"),
            plugin_setup_recommendation(true, true, false, true, false, None, false)
        );
        assert_eq!(
            (true, "setup.plan", "service_not_registered"),
            plugin_setup_recommendation(true, true, true, false, false, None, false)
        );
        assert_eq!(
            (false, "package.error", "bundled_package_error"),
            plugin_setup_recommendation(true, false, false, false, false, None, false)
        );
        assert_eq!(
            (false, "unsupported", "platform_unsupported"),
            plugin_setup_recommendation(false, true, false, false, false, None, false)
        );
        assert_eq!(
            (false, "binding.create", "runner_identity_mismatch"),
            plugin_setup_recommendation(true, true, true, true, true, Some(false), true)
        );
    }

    #[test]
    fn setup_readiness_rejects_complete_profile_with_authenticated_runner_mismatch() {
        let workspace = temp_workspace_path("setup-runner-identity-mismatch");
        fs::create_dir_all(&workspace).unwrap();
        let mut config = CliConfig::default();
        for (key, value) in [
            ("organizationId", "org_123"),
            ("projectId", "prj_123"),
            ("runnerId", "runner-configured"),
            ("bindingId", "binding-configured"),
        ] {
            config
                .set_key(&format!("profiles.default.{key}"), value.to_string())
                .unwrap();
        }
        config
            .set_key(
                "profiles.default.workspacePath",
                workspace.to_string_lossy().to_string(),
            )
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = ManagementCredential::from_runner_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "runner.jwt".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        let mut client = FakeManagementClient {
            runner: Some(Runner {
                id: "runner-authenticated".to_string(),
                organization_id: "org_123".to_string(),
                status: "online".to_string(),
                runner_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: default_runner_capabilities(),
            }),
            ..Default::default()
        };

        let readiness =
            plugin_service_bootstrap_readiness_with(&resolved, Some(&credential), 0, &mut client);

        assert_eq!(readiness["ready"], false);
        assert_eq!(readiness["identity"]["checked"], true);
        assert_eq!(readiness["identity"]["matched"], false);
        assert_eq!(
            readiness["identity"]["configuredRunnerId"],
            "runner-configured"
        );
        assert_eq!(
            readiness["identity"]["authenticatedRunnerId"],
            "runner-authenticated"
        );
        assert_eq!(
            plugin_setup_recommendation(true, true, true, true, true, Some(false), true),
            (false, "binding.create", "runner_identity_mismatch")
        );
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn runtime_bundle_match_requires_version_digest_and_target() {
        let package = PluginPackageRuntime {
            plugin_version: "1.2.3".to_string(),
            runtime_version: "1.2.3".to_string(),
            channel: "stable".to_string(),
            signing_state: "unsigned-release".to_string(),
            target: "darwin-arm64".to_string(),
            sha256: "abc123".to_string(),
            source_executable: PathBuf::from("/bundle/loomex"),
            stable_executable: PathBuf::from("/runtime/loomex"),
        };
        let runtime = loomex_core::InstalledRuntime {
            schema_version: "loomex.runtime/v1".to_string(),
            version: "1.2.3".to_string(),
            artifact_name: "loomex-plugin-runtime".to_string(),
            artifact_sha256: "abc123".to_string(),
            artifact_os: "macos".to_string(),
            artifact_arch: "aarch64".to_string(),
            executable_name: "loomex".to_string(),
            installed_at_epoch_ms: 1,
        };
        assert!(plugin_runtime_matches_bundle(&package, &runtime));

        let mut wrong_digest = runtime.clone();
        wrong_digest.artifact_sha256 = "different".to_string();
        assert!(!plugin_runtime_matches_bundle(&package, &wrong_digest));

        let mut wrong_target = runtime;
        wrong_target.artifact_arch = "x86_64".to_string();
        assert!(!plugin_runtime_matches_bundle(&package, &wrong_target));
    }

    #[cfg(unix)]
    #[test]
    fn plugin_setup_transaction_lock_rejects_a_concurrent_mutation() {
        let lifecycle_root = env::temp_dir().join(format!(
            "loomex-plugin-setup-lock-{}-{}",
            process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&lifecycle_root);

        let first =
            PluginSetupTransactionLock::acquire_at_with_attempts(&lifecycle_root, 1).unwrap();
        let error =
            PluginSetupTransactionLock::acquire_at_with_attempts(&lifecycle_root, 1).unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_BUSY"));
        drop(first);
        PluginSetupTransactionLock::acquire_at_with_attempts(&lifecycle_root, 1).unwrap();

        let _ = fs::remove_dir_all(lifecycle_root);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_setup_lock_rejects_permissive_or_symlinked_preexisting_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = temp_credential_dir("unsafe-lifecycle-lock");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let error = PluginSetupTransactionLock::acquire_at_with_attempts(&root, 1).unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_LOCK_PERMISSIONS_UNSAFE"));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = root.join(".setup.lock");
        fs::write(&lock_path, b"lock").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = PluginSetupTransactionLock::acquire_at_with_attempts(&root, 1).unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_LOCK_PERMISSIONS_UNSAFE"));

        fs::remove_file(&lock_path).unwrap();
        let victim = root.join("victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, &lock_path).unwrap();
        let error = PluginSetupTransactionLock::acquire_at_with_attempts(&root, 1).unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_LOCK_OPEN_FAILED"));
        assert_eq!(b"victim", fs::read(&victim).unwrap().as_slice());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fallback_runner_status_keeps_daemon_parity_for_runtime_service_and_telemetry() {
        let status = plugin_runner_status_value(
            json!({
                "installed": true,
                "runtime": {"version": "1.2.3"},
                "service": {"installed": true, "enabled": true, "active": false},
            }),
            json!({"authenticated": true}),
            json!({"healthy": false, "status": "inactive"}),
        );

        assert_eq!(status["runtimeVersion"], "1.2.3");
        assert_eq!(status["service"]["enabled"], true);
        assert_eq!(status["health"]["healthy"], false);
        assert_eq!(status["queue"]["available"], false);
        assert_eq!(status["activeExecutions"]["available"], false);
        assert_eq!(status["updateHealth"]["status"], "unknown");
        assert_eq!(status["running"], false);
    }

    #[test]
    fn plugin_control_requires_machine_readable_noninteractive_mode() {
        let error =
            run_runner_plugin_control(&["setup.status".to_string()], &GlobalOptions::default())
                .unwrap_err();
        assert!(error.starts_with("PLUGIN_CONTROL_MODE_REQUIRED:"));
    }

    #[test]
    fn remote_logout_network_failure_is_reported_as_retryable_without_blocking_local_logout() {
        let outcome = plugin_remote_revocation_outcome(Err(
            "MANAGEMENT_HTTP_FAILED: connection refused".to_string(),
        ));
        let finalized = plugin_finalize_logout_result(
            json!({"localCredentialRemoved": true, "serverRevokeAttempted": false}),
            json!({"localLoggedOut": true}),
            outcome.clone(),
        );

        assert_eq!(outcome["revoked"], false);
        assert_eq!(outcome["retryRequired"], true);
        assert!(outcome["warning"]
            .as_str()
            .unwrap()
            .contains("connection refused"));
        assert_eq!(finalized["localCredentialRemoved"], true);
        assert_eq!(finalized["serverRevokeAttempted"], true);
        assert_eq!(finalized["serverRevokeSucceeded"], false);
        assert_eq!(finalized["lifecycle"]["localLoggedOut"], true);
    }

    #[test]
    fn plugin_logout_success_reports_remote_and_local_completion_consistently() {
        let finalized = plugin_finalize_logout_result(
            json!({"localCredentialRemoved": true, "serverRevokeAttempted": false}),
            json!({"localLoggedOut": true, "localControlInvalidated": true}),
            json!({"revoked": true}),
        );

        assert_eq!(finalized["serverRevokeAttempted"], true);
        assert_eq!(finalized["serverRevokeSucceeded"], true);
        assert_eq!(finalized["remoteTokenRevocation"]["revoked"], true);
        assert_eq!(finalized["lifecycle"]["localLoggedOut"], true);
    }

    #[test]
    fn local_control_invalidation_removes_socket_and_token_idempotently() {
        let root = env::temp_dir().join(format!("lx-invalidate-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = LocalControlPaths::for_runtime_dir(&root);
        loomex_core::prepare_local_control_paths(&paths).unwrap();
        fs::write(&paths.socket_path, b"stale socket placeholder").unwrap();

        plugin_invalidate_local_control_files_at(&paths).unwrap();
        plugin_invalidate_local_control_files_at(&paths).unwrap();

        assert!(!paths.socket_path.exists());
        assert!(!paths.token_path.exists());
        let _ = fs::remove_dir_all(root);
    }
    use std::{cell::Cell, rc::Rc};

    use loomex_core::{
        CredentialStorageOutcome, FileLogSink, HumanRequestExecution, HumanRequestResolveResponse,
        LocalCredentialStore, LogEntry, Runner, StreamCredentialResponse, WorkflowRunStartResponse,
    };

    #[derive(Default)]
    struct TestPrompt {
        answers: Vec<String>,
    }

    #[derive(Default)]
    struct TestRuntimeLauncher {
        started: Option<RunnerServiceRuntimeConfig>,
        attempts: Vec<RunnerServiceRuntimeConfig>,
        errors: Vec<String>,
    }

    impl RunnerServiceRuntimeLauncher for TestRuntimeLauncher {
        fn start_once(
            &mut self,
            config: RunnerServiceRuntimeConfig,
        ) -> Result<RunnerServiceRuntimeStart, String> {
            self.started = Some(config);
            Ok(RunnerServiceRuntimeStart {
                transport: "grpc".to_string(),
                event: "Registered".to_string(),
                fallback: false,
            })
        }

        fn run_until_disconnect(
            &mut self,
            config: RunnerServiceRuntimeConfig,
        ) -> Result<(), String> {
            self.started = Some(config.clone());
            self.attempts.push(config);
            if self.errors.is_empty() {
                Ok(())
            } else {
                Err(self.errors.remove(0))
            }
        }
    }

    #[derive(Default)]
    struct TestServiceCommandRunner {
        commands: Vec<ServiceCommand>,
    }

    impl ServiceCommandRunner for TestServiceCommandRunner {
        fn run(&mut self, command: &ServiceCommand) -> Result<ServiceCommandOutput, String> {
            self.commands.push(command.clone());
            Ok(ServiceCommandOutput {
                success: true,
                stdout: "active".to_string(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Default)]
    struct InactiveEnabledServiceCommandRunner {
        commands: Vec<ServiceCommand>,
    }

    impl ServiceCommandRunner for InactiveEnabledServiceCommandRunner {
        fn run(&mut self, command: &ServiceCommand) -> Result<ServiceCommandOutput, String> {
            self.commands.push(command.clone());
            if self.commands.len() == 1 {
                Err("service is inactive".to_string())
            } else {
                Ok(ServiceCommandOutput {
                    success: true,
                    stdout: "enabled".to_string(),
                    stderr: String::new(),
                })
            }
        }
    }

    impl TestPrompt {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .rev()
                    .map(|answer| answer.to_string())
                    .collect(),
            }
        }
    }

    impl Prompt for TestPrompt {
        fn read(&mut self, _label: &str) -> Result<String, String> {
            self.answers
                .pop()
                .ok_or_else(|| "TEST_PROMPT_EMPTY: no prompt answer configured".to_string())
        }
    }

    #[test]
    fn root_help_snapshot_contains_final_command_tree() {
        let help = run(vec!["--help".to_string()]).unwrap();

        assert!(help.contains("loomex workflow list|show WORKFLOW_ID|run WORKFLOW_ID --input JSON"));
        assert!(help.contains("loomex runner start|stop|status|logs|doctor"));
        assert!(help.contains("loomex trace export RUN_ID"));
        assert!(!help.contains("loomex run "));
        assert!(!help.contains("loomex status"));
    }

    #[test]
    fn parses_all_phase_60_task_01_commands() {
        let commands = vec![
            vec!["config", "list"],
            vec!["config", "get", "selectedProfile"],
            vec!["runner", "start"],
            vec!["runner", "stop"],
            vec!["runner", "doctor"],
            vec!["approval", "list"],
            vec!["policy", "view"],
            vec![
                "policy",
                "test",
                "--capability",
                "shell.exec",
                "--workspace",
                "/srv/app",
            ],
            vec!["trace", "export", "run_1"],
        ];

        for command in commands {
            let args = command.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(run(args).is_ok());
        }
    }

    #[test]
    fn rejects_legacy_root_aliases() {
        assert!(run(vec!["run".to_string()])
            .unwrap_err()
            .contains("unknown loomex command"));
        assert!(run(vec!["status".to_string()])
            .unwrap_err()
            .contains("unknown loomex command"));
    }

    #[test]
    fn runner_status_json_schema() {
        let output = run(vec![
            "runner".to_string(),
            "status".to_string(),
            "--json".to_string(),
            "--profile".to_string(),
            "local".to_string(),
        ])
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.runnerStatus/v1", parsed["schemaVersion"]);
        assert_eq!("disconnected", parsed["status"]);
        assert_eq!("local", parsed["profile"]);
    }

    #[test]
    fn config_commands_create_versioned_config_and_list_without_secrets() {
        let path = temp_config_path("config-commands");
        let options = GlobalOptions::default();

        run_config_with_path(
            &[
                "set".to_string(),
                "profiles.dev.serverUrl".to_string(),
                "http://127.0.0.1:28080".to_string(),
            ],
            &options,
            path.clone(),
        )
        .unwrap();
        run_config_with_path(
            &[
                "set".to_string(),
                "profiles.dev.hostHeader".to_string(),
                "loomex.localhost".to_string(),
            ],
            &options,
            path.clone(),
        )
        .unwrap();

        let value = run_config_with_path(
            &["get".to_string(), "profiles.dev.hostHeader".to_string()],
            &options,
            path.clone(),
        )
        .unwrap();
        let list = run_config_with_path(&["list".to_string()], &options, path.clone()).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!("loomex.localhost", value);
        assert!(saved.starts_with("configVersion = 2\n"));
        assert!(list.contains("profiles.dev.serverUrl=http://127.0.0.1:28080"));
        assert!(!list.to_lowercase().contains("token"));
    }

    #[test]
    fn config_list_json_schema_from_missing_file_uses_default_profile() {
        let path = temp_config_path("config-json-missing");
        let _ = std::fs::remove_file(&path);
        let options = GlobalOptions {
            json: true,
            ..Default::default()
        };

        let output = run_config_with_path(&["list".to_string()], &options, path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.configList/v1", parsed["schemaVersion"]);
        assert!(parsed["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["key"] == "selectedProfile" && entry["value"] == "default"));
    }

    #[test]
    fn config_set_rejects_host_header_for_prod_profile() {
        let path = temp_config_path("config-host-header-prod");
        let options = GlobalOptions::default();

        let err = run_config_with_path(
            &[
                "set".to_string(),
                "profiles.prod.hostHeader".to_string(),
                "loomex.localhost".to_string(),
            ],
            &options,
            path.clone(),
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&path);

        assert!(err.contains("CONFIG_HOST_HEADER_NOT_ALLOWED"));
    }

    #[test]
    fn shell_completion_generation_is_stable() {
        let output = run_completion(&["zsh".to_string()], &GlobalOptions::default()).unwrap();

        assert!(output.contains("#compdef loomex"));
        assert!(output.contains("workflow:Run workflows"));
        assert!(output.contains("support:Export diagnostics bundle"));
    }

    #[test]
    fn profile_switch_updates_selected_profile_without_auth() {
        let path = temp_config_path("profile-switch");
        let mut config = CliConfig::default();
        config
            .set_key("profiles.dev.serverUrl", "https://loomex.app".to_string())
            .unwrap();
        config.save(&path).unwrap();
        let options = GlobalOptions::default();

        let output = run_profile_with_path(
            &["use".to_string(), "dev".to_string()],
            &options,
            path.clone(),
        )
        .unwrap();
        let current =
            run_profile_with_path(&["current".to_string()], &options, path.clone()).unwrap();
        let saved = CliConfig::load_or_default(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!("selected profile: dev", output);
        assert_eq!("dev", current);
        assert_eq!("dev", saved.selected_profile);
    }

    #[test]
    fn profile_switch_rejects_unknown_profile_without_mutating_config() {
        let path = temp_config_path("profile-switch-missing");
        let config = CliConfig::default();
        config.save(&path).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let options = GlobalOptions::default();

        let err = run_profile_with_path(
            &["use".to_string(), "missing".to_string()],
            &options,
            path.clone(),
        )
        .unwrap_err();
        let after = fs::read_to_string(&path).unwrap();
        let saved = CliConfig::load_or_default(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(err.contains("PROFILE_NOT_FOUND"));
        assert_eq!(before, after);
        assert_eq!("default", saved.selected_profile);
        assert!(!saved.profiles.contains_key("missing"));
    }

    #[test]
    fn non_interactive_missing_follow_up_input_fails_without_wizard() {
        let err = run(vec!["--non-interactive".to_string(), "login".to_string()]).unwrap_err();

        assert!(err.contains("NON_INTERACTIVE_INPUT_REQUIRED"));
    }

    #[test]
    fn parses_runner_logs_options() {
        let options = LogOptions::parse(&[
            "--path".to_string(),
            "/tmp/runner.jsonl".to_string(),
            "--limit".to_string(),
            "25".to_string(),
        ])
        .unwrap();

        assert_eq!(PathBuf::from("/tmp/runner.jsonl"), options.path);
        assert_eq!(25, options.limit);
    }

    #[test]
    fn runner_logs_prints_jsonl_from_log_file() {
        let path = env::temp_dir().join(format!(
            "loomex-cli-logs-{}-{}.jsonl",
            process::id(),
            env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "loomex".to_string())
        ));
        let _ = std::fs::remove_file(&path);
        let sink = FileLogSink::new(&path, loomex_core::redaction::Redactor::new(Vec::new()));
        sink.append_result(LogEntry::new("info", "runner.connected", "connected"))
            .unwrap();

        let output = run(vec![
            "runner".to_string(),
            "logs".to_string(),
            "--path".to_string(),
            path.to_string_lossy().to_string(),
            "--limit".to_string(),
            "1".to_string(),
        ])
        .unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(output.contains("\"event_type\":\"runner.connected\""));
    }

    #[test]
    fn runner_status_connected_includes_binding_and_active_runs() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", "binding_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient {
            runner: Some(Runner {
                id: "runner_123".to_string(),
                organization_id: "org_123".to_string(),
                status: "connected".to_string(),
                runner_version: "0.1.0".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: default_runner_capabilities(),
            }),
            bindings: vec![ManagementProjectRunnerBinding {
                id: "binding_123".to_string(),
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_id: "runner_123".to_string(),
                local_root_path: "/workspace/app".to_string(),
                status: "active".to_string(),
                local_root_fingerprint: None,
            }],
            ..Default::default()
        };
        let logs =
            vec![LogEntry::new("info", "workflow.started", "started")
                .with_workflow_run_id("run_active")];

        let report =
            build_runner_status_report(&config, &resolved, Some(&credential), &mut client, &logs);
        let output = format_runner_status_report(
            &report,
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("connected", parsed["status"]);
        assert_eq!("binding_123", parsed["activeBinding"]["id"]);
        assert_eq!("run_active", parsed["activeRuns"][0]);
    }

    #[test]
    fn runner_status_disconnected_without_auth_is_deterministic() {
        let config = CliConfig::default();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let mut client = FakeManagementClient::default();

        let report = build_runner_status_report(&config, &resolved, None, &mut client, &[]);

        assert_eq!("disconnected", report.status);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("AUTH_REQUIRED")));
    }

    #[test]
    fn runner_start_stop_use_shared_core_runtime_guard_path() {
        let config_path = temp_config_path("runner-start-stop-guard");
        let binding_id = format!("binding_runner_start_stop_{}", process::id());
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.bindingId", binding_id.clone())
            .unwrap();
        config.save(&config_path).unwrap();
        let options = GlobalOptions {
            json: true,
            ..Default::default()
        };
        let expected_guard_path = runner_runtime_guard_path(&config_path, &binding_id);
        let _ = fs::remove_file(&expected_guard_path);

        let start = run_runner_start_with_config_path(&options, &config_path).unwrap();
        let duplicate = run_runner_start_with_config_path(&options, &config_path).unwrap_err();
        let stop = run_runner_stop_with_config_path(&options, &config_path).unwrap();
        let _ = fs::remove_file(&config_path);

        let parsed_start: Value = serde_json::from_str(&start).unwrap();
        let parsed_stop: Value = serde_json::from_str(&stop).unwrap();
        assert_eq!("loomex.cli.runnerStart/v1", parsed_start["schemaVersion"]);
        let actual_guard_path = PathBuf::from(parsed_start["guardPath"].as_str().unwrap());
        assert_eq!(expected_guard_path, actual_guard_path);
        assert!(duplicate.contains("RUNNER_RUNTIME_GUARD_CONFLICT"));
        assert_eq!("loomex.cli.runnerStop/v1", parsed_stop["schemaVersion"]);
        assert!(!actual_guard_path.exists());
    }

    #[test]
    fn runner_service_linux_unit_quotes_workspace_with_spaces() {
        let config_path = temp_config_path("service unit spaces").join("config.toml");
        let output = run_runner_service(
            &[
                "unit".to_string(),
                "--platform".to_string(),
                "linux-user".to_string(),
                "--binary".to_string(),
                "/opt/Loomex/bin/loomex".to_string(),
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
                "--profile".to_string(),
                "default".to_string(),
                "--log-path".to_string(),
                "/home/dev/.loomex/runner log.jsonl".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let manifest = parsed["manifest"].as_str().unwrap();

        assert_eq!("loomex.cli.runnerServiceUnit/v1", parsed["schemaVersion"]);
        assert_eq!("linux-user", parsed["platform"]);
        assert!(manifest.contains("\"/opt/Loomex/bin/loomex\" runner service run"));
        assert!(manifest.contains("--config "));
        assert!(manifest.contains("StandardOutput=journal"));
        assert!(manifest.contains("LOOMEX_RUNNER_LOG_PATH"));
    }

    #[test]
    fn runner_service_windows_is_explicitly_unsupported() {
        let error = run_runner_service(
            &[
                "unit".to_string(),
                "--platform".to_string(),
                "windows".to_string(),
                "--binary".to_string(),
                "C:\\Program Files\\Loomex\\loomex.exe".to_string(),
                "--config".to_string(),
                "C:\\Users\\Dev User\\.loomex\\config.toml".to_string(),
                "--profile".to_string(),
                "default".to_string(),
                "--log-path".to_string(),
                "C:\\Users\\Dev User\\.loomex\\runner.log".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.starts_with("RUNNER_SERVICE_PLATFORM_UNSUPPORTED:"));
    }

    #[test]
    fn runner_service_run_once_uses_shared_runtime_guard() {
        let config_path = temp_config_path("service-run-once");
        let log_path = temp_config_path("service-run-once-log");
        let credential_root = temp_credential_dir("service-run-once");
        let store = LocalCredentialStore::new(credential_root.clone());
        let binding_id = format!("binding_service_run_once_{}", process::id());
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.runnerId", "runner_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", binding_id.clone())
            .unwrap();
        config
            .set_key(
                "profiles.default.workspacePath",
                "/tmp/workspace".to_string(),
            )
            .unwrap();
        config.save(&config_path).unwrap();
        let mut service_credential = credential("default", "org_123");
        service_credential.expires_at = "2099-01-01T00:00:00Z".to_string();
        store.save(&service_credential).unwrap();
        let mut client = FakeManagementClient::default();
        let mut launcher = TestRuntimeLauncher::default();
        let guard_path = runner_runtime_guard_path(&config_path, &binding_id);
        let _ = fs::remove_file(&guard_path);

        let output = run_runner_service_run_with(
            &[
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
                "--once".to_string(),
                "--log-path".to_string(),
                log_path.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &store,
            &mut client,
            &mut launcher,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let _ = fs::remove_file(&config_path);
        let log_entries = read_recent_log_entries(&log_path, 10).unwrap();
        let tailed = LocalControlDispatcher::new(
            FakeManagementClient::default(),
            service_credential.clone(),
        )
        .with_context(None, None, None, None, Some(log_path.clone()))
        .dispatch("logs.tail", &json!({"limit": 10}))
        .unwrap();
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir_all(&credential_root);

        assert_eq!("loomex.cli.runnerServiceRun/v1", parsed["schemaVersion"]);
        assert_eq!(binding_id, parsed["bindingId"]);
        assert_eq!("runner_control_long_poll", parsed["transport"]);
        assert_eq!("idle", parsed["event"]);
        assert!(log_entries
            .iter()
            .any(|entry| entry.event_type == "runner.service.starting"));
        assert!(log_entries
            .iter()
            .any(|entry| entry.event_type == "runner.service.tick"));
        assert!(tailed["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["event_type"] == "runner.service.tick"));
        assert_eq!(
            guard_path,
            PathBuf::from(parsed["guardPath"].as_str().unwrap())
        );
        assert!(!guard_path.exists());
    }

    #[test]
    fn runner_service_run_once_writes_leased_file_job_to_workspace() {
        let config_path = temp_config_path("service-run-file-job");
        let log_path = temp_config_path("service-run-file-job-log");
        let credential_root = temp_credential_dir("service-run-file-job");
        let workspace = temp_workspace_path("service-run-file-job");
        fs::create_dir_all(&workspace).unwrap();
        let binding_id = format!("binding_service_run_file_{}", process::id());
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        config
            .set_key(
                "profiles.default.serverUrl",
                "https://loomex.app".to_string(),
            )
            .unwrap();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.runnerId", "runner_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", binding_id.clone())
            .unwrap();
        config
            .set_key(
                "profiles.default.workspacePath",
                workspace.to_string_lossy().to_string(),
            )
            .unwrap();
        config.save(&config_path).unwrap();
        let mut service_credential = credential("default", "org_123");
        service_credential.expires_at = "2099-01-01T00:00:00Z".to_string();
        store.save(&service_credential).unwrap();
        let mut client = FakeManagementClient {
            runner_jobs: vec![json!({
                "id": "job_123",
                "status": "leased",
                "sessionId": "session_123",
                "runnerId": "runner_123",
                "attemptCount": 1,
                "leaseVersion": 1,
                "leasedUntilEpochMs": 4_102_444_800_000_u64,
                "payloadDigest": "sha256:test-file-write",
                "replaySafe": false,
                "idempotencyKey": "runner-job:job_123",
                "kind": "file.write_many",
                "payload": {
                    "files": [{
                        "path": "nested/output.txt",
                        "content": "written by runner\n",
                        "encoding": "utf-8"
                    }]
                }
            })],
            ..Default::default()
        };
        let mut launcher = TestRuntimeLauncher::default();

        let output = run_runner_service_run_with(
            &[
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
                "--once".to_string(),
                "--log-path".to_string(),
                log_path.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &store,
            &mut client,
            &mut launcher,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("job.processed", parsed["event"]);
        assert_eq!(
            "written by runner\n",
            fs::read_to_string(workspace.join("nested/output.txt")).unwrap()
        );
        assert_eq!("job_123", client.completed_runner_jobs[0]["id"]);
        assert_eq!(
            "nested/output.txt",
            client.completed_runner_jobs[0]["result"]["writtenFiles"][0]["path"]
        );

        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir_all(&credential_root);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn runner_service_install_executes_systemd_enable_start_after_unit_write() {
        let home = temp_credential_dir("service-install-home");
        let output_path = home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("loomex-runner.service");
        let mut runner = TestServiceCommandRunner::default();

        let output = run_runner_service_install_with_runner_and_path(
            &[
                "--platform".to_string(),
                "linux-user".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut runner,
            Some(&output_path),
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let unit = fs::read_to_string(&output_path).unwrap();
        let _ = fs::remove_dir_all(&home);

        assert!(unit.contains("ExecStart=\"/usr/local/bin/loomex\" runner service run"));
        assert_eq!(2, runner.commands.len());
        assert_eq!("systemctl", runner.commands[0].program);
        assert_eq!(vec!["--user", "daemon-reload"], runner.commands[0].args);
        assert_eq!(
            vec!["--user", "enable", "--now", "loomex-runner.service"],
            runner.commands[1].args
        );
        assert_eq!(2, parsed["commands"].as_array().unwrap().len());
    }

    #[test]
    fn runner_service_install_output_is_artifact_only_for_non_install_path() {
        let output_path = temp_config_path("service-install-artifact-only");
        let mut runner = TestServiceCommandRunner::default();

        let output = run_runner_service_install_with_runner(
            &[
                "--platform".to_string(),
                "linux-user".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
                "--output".to_string(),
                output_path.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut runner,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let unit = fs::read_to_string(&output_path).unwrap();
        let _ = fs::remove_file(&output_path);

        assert!(unit.contains("ExecStart=\"/usr/local/bin/loomex\" runner service run"));
        assert_eq!(0, runner.commands.len());
        assert_eq!(true, parsed["artifactOnly"]);
        assert_eq!(0, parsed["commands"].as_array().unwrap().len());
    }

    #[cfg(unix)]
    #[test]
    fn service_unit_write_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = temp_credential_dir("service-unit-symlink");
        prepare_private_test_directory(&root);
        let victim = root.join("victim.txt");
        let service_path = root.join("loomex-runner.service");
        fs::write(&victim, "do not replace").unwrap();
        symlink(&victim, &service_path).unwrap();

        let error = write_service_file(&service_path, "malicious replacement").unwrap_err();

        assert!(error.starts_with("RUNNER_SERVICE_PATH_UNSAFE:"));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not replace");
        assert!(fs::symlink_metadata(&service_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn service_unit_write_atomically_replaces_regular_file() {
        let root = temp_credential_dir("service-unit-atomic-replace");
        prepare_private_test_directory(&root);
        let service_path = root.join("loomex-runner.service");
        fs::write(&service_path, "old").unwrap();

        write_service_file(&service_path, "new").unwrap();

        assert_eq!(fs::read_to_string(&service_path).unwrap(), "new");
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runner_service_install_can_write_unit_without_starting_before_bootstrap() {
        let home = temp_credential_dir("service-install-deferred");
        let output_path = home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("loomex-runner.service");
        let mut runner = TestServiceCommandRunner::default();

        let output = run_runner_service_install_with_runner_and_path(
            &[
                "--platform".to_string(),
                "linux-user".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
                "--defer-start".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut runner,
            Some(&output_path),
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert!(output_path.exists());
        assert_eq!(1, runner.commands.len());
        assert_eq!(vec!["--user", "daemon-reload"], runner.commands[0].args);
        assert_eq!(parsed["deferredStart"], true);
        assert_eq!(parsed["artifactOnly"], false);
        let service_options = RunnerServiceOptions::parse(
            &[
                "--platform".to_string(),
                "linux-user".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
            ],
            &GlobalOptions::default(),
        )
        .unwrap();
        let activation = plugin_service_control_commands(&service_options, "start", false).unwrap();
        assert_eq!(1, activation.len());
        assert_eq!(
            vec!["--user", "enable", "--now", "loomex-runner.service"],
            activation[0].args
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn runner_service_status_uses_systemctl_not_file_existence() {
        let mut runner = TestServiceCommandRunner::default();

        let output = run_runner_service_status_with_runner(
            &[
                "--platform".to_string(),
                "linux-system".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut runner,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(2, runner.commands.len());
        assert_eq!(
            vec!["is-active", "loomex-runner.service"],
            runner.commands[0].args
        );
        assert_eq!(
            vec!["is-enabled", "loomex-runner.service"],
            runner.commands[1].args
        );
        assert_eq!(true, parsed["installed"]);
        assert_eq!(true, parsed["active"]);
        assert_eq!(true, parsed["enabled"]);
    }

    #[test]
    fn runner_service_status_does_not_report_enabled_but_stopped_as_active() {
        let mut runner = InactiveEnabledServiceCommandRunner::default();

        let output = run_runner_service_status_with_runner(
            &[
                "--platform".to_string(),
                "linux-system".to_string(),
                "--binary".to_string(),
                "/usr/local/bin/loomex".to_string(),
                "--config".to_string(),
                "/tmp/loomex-config.toml".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut runner,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["installed"], true);
        assert_eq!(parsed["enabled"], true);
        assert_eq!(parsed["active"], false);
    }

    #[test]
    fn macos_start_skips_bootstrap_when_launch_agent_is_already_loaded() {
        let options = RunnerServiceOptions {
            platform: RunnerServicePlatform::MacOsLaunchAgent,
            service_name: "loomex-runner".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/loomex"),
            config_path: PathBuf::from("/tmp/loomex.toml"),
            profile: None,
            log_path: None,
            output_path: None,
            uninstall_output_path: None,
            dry_run: false,
            once: false,
            defer_start: false,
        };

        let loaded = plugin_service_control_commands(&options, "start", true).unwrap();
        let unloaded = plugin_service_control_commands(&options, "start", false).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].args[0], "kickstart");
        assert_eq!(unloaded.len(), 2);
        assert_eq!(unloaded[0].args[0], "bootstrap");
        assert_eq!(unloaded[1].args[0], "kickstart");
    }

    #[cfg(unix)]
    #[test]
    fn plugin_health_check_requires_a_real_authenticated_ipc_ping() {
        use std::os::unix::net::UnixListener;

        let root = env::temp_dir().join(format!("lx-health-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = LocalControlPaths::for_runtime_dir(&root);
        let expected_token = loomex_core::prepare_local_control_paths(&paths).unwrap();
        let listener = UnixListener::bind(&paths.socket_path).unwrap();
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request: LocalControlRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(request.auth_token, expected_token);
            assert_eq!(request.method, "ping");
            let mut stream = reader.into_inner();
            serde_json::to_writer(
                &mut stream,
                &LocalControlResponse::success(
                    request.id,
                    json!({"pong": true, "protocolVersion": LOCAL_CONTROL_PROTOCOL_VERSION}),
                ),
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        });

        let health = plugin_local_control_ping_once_at(&paths).unwrap();

        assert_eq!(health["healthy"], true);
        assert_eq!(health["protocolVersion"], LOCAL_CONTROL_PROTOCOL_VERSION);
        thread.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runner_service_reconnect_loop_stops_on_terminal_auth_error() {
        let resolved = service_resolved_settings();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient::default();
        let mut launcher = TestRuntimeLauncher {
            errors: vec!["AUTH_TOKEN_EXPIRED: stream credential expired".to_string()],
            ..Default::default()
        };

        let err = run_runner_service_reconnect_loop(
            &mut client,
            &credential,
            &resolved,
            "binding_123",
            &mut launcher,
            Some(3),
            |_| {},
        )
        .unwrap_err();

        assert!(err.contains("AUTH_TOKEN_EXPIRED"));
        assert_eq!(1, client.stream_credential_issue_count);
        assert_eq!(1, launcher.attempts.len());
    }

    #[test]
    fn runner_service_reconnect_loop_reissues_credentials_for_retryable_transport_error() {
        let resolved = service_resolved_settings();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient::default();
        let mut launcher = TestRuntimeLauncher {
            errors: vec!["GRPC_STREAM_CLOSED: disconnected".to_string()],
            ..Default::default()
        };

        run_runner_service_reconnect_loop(
            &mut client,
            &credential,
            &resolved,
            "binding_123",
            &mut launcher,
            Some(2),
            |_| {},
        )
        .unwrap();

        assert_eq!(2, client.stream_credential_issue_count);
        assert_eq!(2, launcher.attempts.len());
    }

    #[test]
    fn runner_control_reconnect_backoff_resets_after_control_operation_succeeds() {
        let mut backoff = RunnerControlReconnectBackoff::new();

        let accumulated_delays =
            [1, 2, 4, 8, 16, 30, 30].map(|_| backoff.next_retry_delay().as_secs());
        assert_eq!([1, 2, 4, 8, 16, 30, 30], accumulated_delays);

        backoff.control_operation_succeeded();

        assert_eq!(Duration::from_secs(1), backoff.next_retry_delay());
        assert_eq!(Duration::from_secs(2), backoff.next_retry_delay());
    }

    #[test]
    fn runner_control_flapping_sessions_keep_backing_off_until_control_succeeds() {
        let mut backoff = RunnerControlReconnectBackoff::new();

        // Each session creation succeeds, but recovery or the first lease poll
        // fails. Creation alone must not reset the accumulated delay.
        assert_eq!(Duration::from_secs(1), backoff.next_retry_delay());
        assert_eq!(Duration::from_secs(2), backoff.next_retry_delay());
        assert_eq!(Duration::from_secs(4), backoff.next_retry_delay());

        // Recovery plus the first successful control operation proves that the
        // session is healthy. A later transient disconnect starts again at 1s.
        backoff.control_operation_succeeded();
        assert_eq!(Duration::from_secs(1), backoff.next_retry_delay());
    }

    #[test]
    fn runner_control_session_health_requires_a_successful_lease_poll() {
        let resolved = service_resolved_settings();
        let credential = credential("default", "org_123");
        let transport_error =
            || loomex_core::CoreError::new("RUNNER_CONTROL_HTTP_FAILED", "temporary failure");
        let mut client = FakeManagementClient {
            runner_job_lease_errors: vec![
                Some(transport_error()),
                Some(transport_error()),
                Some(transport_error()),
                None,
                Some(transport_error()),
            ],
            ..Default::default()
        };
        let recovery_path = env::temp_dir().join(format!(
            "loomex-reconnect-recovery-{}-{}.json",
            process::id(),
            current_epoch_ms().unwrap()
        ));
        let log_path = recovery_path.with_extension("log");
        let mut recovery = RunnerJobRecoveryJournal::open(&recovery_path).unwrap();
        let mut backoff = RunnerControlReconnectBackoff::new();

        for expected_delay in [1, 2, 4] {
            let mut session_healthy = false;
            let error = run_runner_control_session(
                &mut client,
                &credential,
                &resolved,
                "binding_123",
                &mut recovery,
                &log_path,
                &mut || session_healthy = true,
            )
            .unwrap_err();
            assert!(error.contains("RUNNER_CONTROL_HTTP_FAILED"));
            assert!(!session_healthy, "session creation alone is not healthy");
            assert_eq!(
                Duration::from_secs(expected_delay),
                backoff.next_retry_delay()
            );
        }

        let mut session_healthy = false;
        let error = run_runner_control_session(
            &mut client,
            &credential,
            &resolved,
            "binding_123",
            &mut recovery,
            &log_path,
            &mut || session_healthy = true,
        )
        .unwrap_err();
        assert!(error.contains("RUNNER_CONTROL_HTTP_FAILED"));
        assert!(session_healthy, "the first lease poll succeeded");
        backoff.control_operation_succeeded();
        assert_eq!(Duration::from_secs(1), backoff.next_retry_delay());

        let _ = fs::remove_file(recovery_path);
        let _ = fs::remove_file(log_path);
    }

    #[test]
    fn runner_stop_does_not_remove_live_guard_owned_by_app() {
        let config_path = temp_config_path("runner-stop-foreign-guard");
        let binding_id = format!("binding_runner_stop_foreign_{}", process::id());
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.bindingId", binding_id.clone())
            .unwrap();
        config.save(&config_path).unwrap();
        let options = GlobalOptions {
            json: true,
            ..Default::default()
        };
        let guard_path = runner_runtime_guard_path(&config_path, &binding_id);
        let _ = fs::remove_file(&guard_path);
        let app_guard =
            acquire_runner_runtime_guard(&config_path, &binding_id, "loomex-tauri").unwrap();
        let guard_path = app_guard.path().to_path_buf();

        let err = run_runner_stop_with_config_path(&options, &config_path).unwrap_err();
        let still_present = loomex_core::read_runner_runtime_guard(&guard_path)
            .unwrap()
            .unwrap();
        app_guard.release().unwrap();
        let _ = fs::remove_file(&config_path);

        assert!(err.contains("RUNNER_RUNTIME_GUARD_NOT_OWNER"));
        assert_eq!("loomex-tauri", still_present.surface);
        assert!(!guard_path.exists());
    }

    #[test]
    fn runner_logs_filter_by_run_id_and_redact_secrets() {
        let path = env::temp_dir().join(format!(
            "loomex-cli-logs-filter-{}-{}.jsonl",
            process::id(),
            env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "loomex".to_string())
        ));
        let _ = std::fs::remove_file(&path);
        let sink = FileLogSink::new(&path, loomex_core::redaction::Redactor::new(Vec::new()));
        sink.append_result(
            LogEntry::new("info", "stream.output", "token=secret")
                .with_workflow_run_id("run_keep")
                .with_metadata(json!({"authorization": "Bearer secret", "safe": "ok"})),
        )
        .unwrap();
        sink.append_result(
            LogEntry::new("info", "stream.output", "visible").with_workflow_run_id("run_skip"),
        )
        .unwrap();

        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "logs".to_string(),
            "--path".to_string(),
            path.to_string_lossy().to_string(),
            "--run-id".to_string(),
            "run_keep".to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!("loomex.cli.runnerLogs/v1", parsed["schemaVersion"]);
        assert_eq!(1, parsed["summary"]["total"]);
        assert_eq!("run_keep", parsed["entries"][0]["workflow_run_id"]);
        assert_eq!("[REDACTED]", parsed["entries"][0]["message"]);
        assert_eq!(
            "[REDACTED]",
            parsed["entries"][0]["metadata"]["authorization"]
        );
        assert!(!output.contains("Bearer secret"));
    }

    #[test]
    fn workflow_follow_polls_filters_orders_redacts_and_stops_on_terminal() {
        fn entry(run_id: &str, timestamp: u64, event_type: &str, message: &str) -> LogEntry {
            let mut entry = LogEntry::new("info", event_type, message).with_workflow_run_id(run_id);
            entry.timestamp_epoch_ms = timestamp;
            entry
        }

        let batches = [
            vec![
                entry("run_skip", 1, "workflow.started", "wrong run"),
                entry(
                    "run_keep",
                    20,
                    "stream.output",
                    "Authorization = Bearer secret",
                ),
                entry("run_keep", 10, "workflow.started", "started"),
            ],
            vec![
                entry(
                    "run_keep",
                    20,
                    "stream.output",
                    "Authorization = Bearer secret",
                ),
                entry("run_keep", 30, "workflow.completed", "completed"),
                entry("run_other", 25, "workflow.completed", "other completed"),
            ],
            vec![entry("run_keep", 40, "stream.output", "after terminal")],
        ];
        let mut calls = 0usize;
        let followed = follow_run_logs_with_reader(
            "run_keep",
            5,
            Duration::from_millis(1),
            || {
                let index = calls.min(batches.len() - 1);
                calls += 1;
                batches[index].clone()
            },
            |_| {},
        );

        assert_eq!(2, calls);
        assert_eq!(3, followed.len());
        assert_eq!("workflow.started", followed[0].event_type);
        assert_eq!("stream.output", followed[1].event_type);
        assert_eq!("[REDACTED]", followed[1].message);
        assert_eq!("workflow.completed", followed[2].event_type);
        assert!(followed
            .iter()
            .all(|entry| entry.workflow_run_id.as_deref() == Some("run_keep")));
    }

    #[test]
    fn approval_inbox_lists_and_records_local_decision() {
        let path = temp_config_path("approval-inbox-log");
        let _ = fs::remove_file(&path);
        let sink = FileLogSink::new(&path, loomex_core::redaction::Redactor::new(Vec::new()));
        sink.append_result(
            LogEntry::new("info", "approval.requested", "approval needed")
                .with_correlation_id("approval_1")
                .with_workflow_run_id("run_123")
                .with_metadata(json!({
                    "approvalRequestId": "approval_1",
                    "capability": "shell.exec",
                    "nodeId": "node_1",
                    "summary": "run shell command"
                })),
        )
        .unwrap();

        let listed = run_approval(
            &[
                "list".to_string(),
                "--path".to_string(),
                path.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let decided = run_approval(
            &[
                "approve".to_string(),
                "approval_1".to_string(),
                "--path".to_string(),
                path.to_string_lossy().to_string(),
            ],
            &GlobalOptions::default(),
        )
        .unwrap();
        let after = run_approval(
            &[
                "list".to_string(),
                "--path".to_string(),
                path.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let _ = fs::remove_file(&path);
        let listed: Value = serde_json::from_str(&listed).unwrap();
        let after: Value = serde_json::from_str(&after).unwrap();

        assert_eq!("loomex.cli.approvalInbox/v1", listed["schemaVersion"]);
        assert_eq!(1, listed["pendingCount"]);
        assert_eq!("shell.exec", listed["approvals"][0]["capability"]);
        assert!(decided.contains("approved"));
        assert_eq!(0, after["pendingCount"]);
    }

    #[test]
    fn support_bundle_redacts_logs_and_config() {
        let log_path = temp_config_path("support-bundle-log");
        let bundle_path = temp_config_path("support-bundle-output");
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_file(&bundle_path);
        let sink = FileLogSink::new(&log_path, loomex_core::redaction::Redactor::new(Vec::new()));
        sink.append_result(
            LogEntry::new("info", "runner.diagnostic", "token=secret")
                .with_metadata(json!({"authorization": "Bearer secret", "safe": "ok"})),
        )
        .unwrap();
        sink.append_result(LogEntry::new(
            "info",
            "runner.diagnostic",
            r#"{"token": "json-secret"}"#,
        ))
        .unwrap();
        sink.append_result(LogEntry::new(
            "info",
            "runner.diagnostic",
            "Authorization = Bearer auth-secret",
        ))
        .unwrap();
        sink.append_result(LogEntry::new(
            "info",
            "runner.diagnostic",
            "api-key: key-secret",
        ))
        .unwrap();
        sink.append_result(LogEntry::new(
            "info",
            "runner.diagnostic",
            "cookie: session=cookie-secret",
        ))
        .unwrap();
        let previous_log_path = env::var(LOG_PATH_ENV).ok();
        env::set_var(LOG_PATH_ENV, &log_path);

        let bundle = build_support_bundle(10).unwrap();
        write_support_bundle(&bundle_path, &bundle).unwrap();
        let encoded = fs::read_to_string(&bundle_path).unwrap();
        if let Some(previous) = previous_log_path {
            env::set_var(LOG_PATH_ENV, previous);
        } else {
            env::remove_var(LOG_PATH_ENV);
        }
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_file(&bundle_path);

        assert!(encoded.contains("loomex.cli.supportBundle/v1"));
        assert!(!encoded.contains("Bearer secret"));
        assert!(!encoded.contains("token=secret"));
        assert!(!encoded.contains("json-secret"));
        assert!(!encoded.contains("auth-secret"));
        assert!(!encoded.contains("key-secret"));
        assert!(!encoded.contains("cookie-secret"));
        assert!(encoded.contains("[REDACTED]"));
    }

    #[test]
    fn support_bundle_contains_required_debug_sections_without_sensitive_files() {
        let bundle = build_support_bundle(5).unwrap();

        assert_eq!("loomex.cli.supportBundle/v1", bundle["schemaVersion"]);
        assert!(bundle.get("runnerVersion").is_some());
        assert!(bundle.get("os").is_some());
        assert!(bundle.get("connectivityTest").is_some());
        assert!(bundle.get("policySnapshot").is_some());
        assert!(bundle.get("bindingSummary").is_some());
        assert!(bundle.get("recentErrors").is_some());
        assert!(bundle.get("config").is_some());
        assert!(bundle.get("logs").is_some());
        assert!(bundle.get("fileContents").is_none());
        assert!(bundle.get("credentials").is_none());
    }

    #[test]
    fn remote_diagnostic_requires_explicit_consent() {
        let denied = run_support(
            &["diagnostic-request".to_string()],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(denied.contains("REMOTE_DIAGNOSTIC_CONSENT_REQUIRED"));

        let output_path = temp_config_path("remote-diagnostic-bundle");
        let output = run_support(
            &[
                "diagnostic-request".to_string(),
                "--remote-diagnostic-consent".to_string(),
                "--output".to_string(),
                output_path.display().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let _ = fs::remove_file(&output_path);

        assert_eq!(
            "loomex.cli.remoteDiagnosticRequest/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(json!(true), parsed["consent"]);
        assert_eq!(json!(true), parsed["uploadReady"]);
    }

    #[test]
    fn migration_detects_and_imports_safe_legacy_config() {
        let legacy_path = temp_config_path("legacy-runner-config");
        let target_path = temp_config_path("legacy-target-config");
        let _ = fs::remove_file(&legacy_path);
        let _ = fs::remove_file(&target_path);
        fs::write(
            &legacy_path,
            [
                "organization_id = \"org_123\"\n",
                "project_id = \"prj_123\"\n",
                "runner_id = \"runner_123\"\n",
                "binding_id = \"binding_123\"\n",
                "local_root_path = \"/tmp/workspace\"\n",
            ]
            .join(""),
        )
        .unwrap();

        let output = run_support(
            &[
                "migrate-legacy".to_string(),
                "--legacy-config".to_string(),
                legacy_path.display().to_string(),
                "--target-config".to_string(),
                target_path.display().to_string(),
                "--apply".to_string(),
                "--deactivate-old-daemon".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let migrated = CliConfig::load_or_default(&target_path).unwrap();
        let _ = fs::remove_file(&legacy_path);
        let _ = fs::remove_file(&target_path);

        assert_eq!("loomex.cli.legacyMigration/v1", parsed["schemaVersion"]);
        assert_eq!("applied", parsed["migration"]["status"]);
        assert_eq!(json!(false), parsed["migration"]["credentialImported"]);
        assert_eq!(
            Some("binding_123"),
            migrated.profiles["default"].binding_id.as_deref()
        );
        assert_eq!(
            Some("/tmp/workspace"),
            migrated.profiles["default"].workspace_path.as_deref()
        );
        assert_eq!(
            json!(true),
            parsed["migration"]["oldDaemon"]["deactivationRequested"]
        );
    }

    #[test]
    fn migration_handles_corrupt_legacy_config() {
        let legacy_path = temp_config_path("legacy-corrupt-config");
        let _ = fs::remove_file(&legacy_path);
        fs::write(&legacy_path, "organization_id = org_123\n").unwrap();

        let error = run_support(
            &[
                "migrate-legacy".to_string(),
                "--legacy-config".to_string(),
                legacy_path.display().to_string(),
            ],
            &GlobalOptions::default(),
        )
        .unwrap_err();
        let _ = fs::remove_file(&legacy_path);

        assert!(error.contains("CONFIG_PARSE_FAILED"));
    }

    #[test]
    fn migration_refuses_to_overwrite_conflicting_target_profile() {
        let legacy_path = temp_config_path("legacy-conflict-config");
        let target_path = temp_config_path("legacy-conflict-target");
        let _ = fs::remove_file(&legacy_path);
        let _ = fs::remove_file(&target_path);
        fs::write(
            &legacy_path,
            [
                "organization_id = \"org_legacy\"\n",
                "project_id = \"prj_legacy\"\n",
                "runner_id = \"runner_legacy\"\n",
                "binding_id = \"binding_legacy\"\n",
                "local_root_path = \"/tmp/legacy\"\n",
            ]
            .join(""),
        )
        .unwrap();
        let mut target = CliConfig::default();
        target
            .set_key("profiles.default.projectId", "prj_existing".to_string())
            .unwrap();
        target
            .set_key("profiles.default.bindingId", "binding_existing".to_string())
            .unwrap();
        target
            .set_key(
                "profiles.default.workspacePath",
                "/tmp/existing".to_string(),
            )
            .unwrap();
        target.save(&target_path).unwrap();
        let before = fs::read_to_string(&target_path).unwrap();

        let error = run_support(
            &[
                "migrate-legacy".to_string(),
                "--legacy-config".to_string(),
                legacy_path.display().to_string(),
                "--target-config".to_string(),
                target_path.display().to_string(),
                "--apply".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        let after = fs::read_to_string(&target_path).unwrap();
        let _ = fs::remove_file(&legacy_path);
        let _ = fs::remove_file(&target_path);

        assert!(error.contains("LEGACY_MIGRATION_TARGET_CONFLICT"));
        assert!(error.contains("projectId"));
        assert!(error.contains("bindingId"));
        assert!(error.contains("workspacePath"));
        assert_eq!(before, after);
    }

    #[test]
    fn trace_export_filters_run_and_redacts_secrets() {
        let log_path = temp_config_path("trace-export-log");
        let output_path = temp_config_path("trace-export-output");
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_file(&output_path);
        let sink = FileLogSink::new(&log_path, loomex_core::redaction::Redactor::new(Vec::new()));
        sink.append_result(
            LogEntry::new("info", "workflow.started", "Authorization = Bearer secret")
                .with_workflow_run_id("run_keep")
                .with_metadata(json!({"token": "secret"})),
        )
        .unwrap();
        sink.append_result(
            LogEntry::new("info", "workflow.started", "visible").with_workflow_run_id("run_skip"),
        )
        .unwrap();

        let output = run_trace(
            &[
                "export".to_string(),
                "run_keep".to_string(),
                "--path".to_string(),
                log_path.display().to_string(),
                "--output".to_string(),
                output_path.display().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let exported = fs::read_to_string(&output_path).unwrap();
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_file(&output_path);

        assert_eq!("loomex.cli.traceExportResult/v1", parsed["schemaVersion"]);
        assert!(exported.contains("run_keep"));
        assert!(!exported.contains("run_skip"));
        assert!(!exported.contains("Bearer secret"));
        assert!(!exported.contains("\"secret\""));
        assert!(exported.contains("[REDACTED]"));
    }

    #[test]
    fn policy_explain_matches_evaluator_output() {
        let workspace = env::temp_dir();
        let output = run_policy(
            &[
                "explain".to_string(),
                "--capability".to_string(),
                "git.status".to_string(),
                "--workspace".to_string(),
                workspace.display().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.policyExplain/v1", parsed["schemaVersion"]);
        assert_eq!("git.status", parsed["explanation"]["capability"]);
        assert!(parsed["explanation"]["decision"].is_string());
        assert!(parsed["explanation"]["reason"].is_string());
    }

    #[test]
    fn policy_explain_resolves_relative_path_against_workspace() {
        let workspace = temp_workspace_path("policy-explain-relative");
        let src_dir = workspace.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("file.txt"), "ok").unwrap();

        let output = run_policy(
            &[
                "explain".to_string(),
                "--capability".to_string(),
                "fs.read".to_string(),
                "--workspace".to_string(),
                workspace.display().to_string(),
                "--path".to_string(),
                "src/file.txt".to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.policyExplain/v1", parsed["schemaVersion"]);
        assert_eq!("fs.read", parsed["explanation"]["capability"]);
        assert_eq!("src/file.txt", parsed["explanation"]["requestedPath"]);
        assert_eq!(
            workspace.join("src/file.txt").display().to_string(),
            parsed["explanation"]["evaluatedPath"]
        );
        assert!(parsed["explanation"]["decision"].is_string());

        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn deep_doctor_reports_proxy_issue() {
        let config = CliConfig::default();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let mut client = FakeManagementClient::default();
        let checks = build_doctor_checks(
            &resolved,
            None,
            Some(&"AUTH_REQUIRED: missing".to_string()),
            &mut client,
            None,
            true,
            |key| (key == "HTTPS_PROXY").then(|| "http://proxy.local:8080".to_string()),
        );

        assert!(checks
            .iter()
            .any(|check| check.name == "proxy" && check.status == "warning"));
        assert!(checks
            .iter()
            .any(|check| check.name == "runnerControlMode" && check.status == "ok"));
    }

    #[test]
    fn doctor_success_json_schema() {
        let checks = vec![
            DoctorCheck::ok("config", "ok"),
            DoctorCheck::ok("auth", "ok"),
            DoctorCheck::ok("server", "ok"),
            DoctorCheck::ok("runnerControl", "ok"),
            DoctorCheck::ok("workspace", "ok"),
            DoctorCheck::ok("git", "ok"),
            DoctorCheck::ok("shell", "ok"),
        ];

        let output = format_doctor_checks(
            &checks,
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.runnerDoctor/v1", parsed["schemaVersion"]);
        assert_eq!("ok", parsed["status"]);
    }

    #[test]
    fn doctor_auth_failure_skips_server_and_runner_control() {
        let config = CliConfig::default();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let mut client = FakeManagementClient::default();

        let checks = build_doctor_checks(
            &resolved,
            None,
            Some(&"AUTH_TOKEN_EXPIRED: expired".to_string()),
            &mut client,
            None,
            false,
            |_| None,
        );

        assert!(checks
            .iter()
            .any(|check| check.name == "auth" && check.status == "failed"));
        assert!(checks
            .iter()
            .any(|check| check.name == "runnerControl" && check.status == "warning"));
    }

    #[test]
    fn doctor_json_auth_failure_maps_to_nonzero_exit_without_losing_schema() {
        let checks = vec![
            DoctorCheck::ok("config", "ok"),
            DoctorCheck::fail("auth", "AUTH_TOKEN_EXPIRED: expired"),
            DoctorCheck::warn("server", "skipped"),
            DoctorCheck::warn("runnerControl", "skipped"),
        ];
        let output = format_doctor_checks(
            &checks,
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let args = vec![
            "--json".to_string(),
            "runner".to_string(),
            "doctor".to_string(),
        ];

        assert_eq!("loomex.cli.runnerDoctor/v1", parsed["schemaVersion"]);
        assert_eq!("failed", parsed["status"]);
        assert_eq!(10, exit_code_for_successful_output(&args, &output));
    }

    #[test]
    fn doctor_runner_control_scope_error_returns_failed_check_without_legacy_stream_call() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.runnerId", "runner_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", "binding_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient {
            runner_self_error: Some(loomex_core::CoreError::new(
                "AUTHORIZATION_FAILED",
                "Runner token must include runner.read scope",
            )),
            ..Default::default()
        };

        let check = runner_control_transport_doctor_check(&resolved, &credential, &mut client);

        assert_eq!("runnerControl", check.name);
        assert_eq!("failed", check.status);
        assert!(check.message.contains("AUTHORIZATION_FAILED"));
        assert!(check.message.contains("runner.read scope"));
        assert_eq!(0, client.stream_credential_issue_count);
    }

    #[test]
    fn doctor_runner_control_transport_requires_jobs_scope() {
        let mut config = CliConfig::default();
        for (key, value) in [
            ("organizationId", "org_123"),
            ("projectId", "prj_123"),
            ("runnerId", "runner_123"),
            ("bindingId", "binding_123"),
        ] {
            config
                .set_key(&format!("profiles.default.{key}"), value.to_string())
                .unwrap();
        }
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient {
            runner_self_status: Some(json!({
                "runner": {"id": "runner_123", "status": "online"},
                "tokenScopes": ["runner.read"],
            })),
            ..Default::default()
        };

        let check = runner_control_transport_doctor_check(&resolved, &credential, &mut client);

        assert_eq!("failed", check.status);
        assert!(check.message.contains("runner.jobs scope"));
        assert_eq!(0, client.stream_credential_issue_count);
    }

    #[test]
    fn bootstrap_doctor_rejects_configured_runner_identity_mismatch() {
        let mut config = CliConfig::default();
        for (key, value) in [
            ("organizationId", "org_123"),
            ("projectId", "prj_123"),
            ("runnerId", "runner-configured"),
            ("bindingId", "binding_123"),
        ] {
            config
                .set_key(&format!("profiles.default.{key}"), value.to_string())
                .unwrap();
        }
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient {
            runner_self_status: Some(json!({
                "runner": {"id": "runner-authenticated", "status": "online"},
                "tokenScopes": ["runner.read", "runner.jobs"],
            })),
            ..Default::default()
        };

        let check = runner_control_transport_doctor_check(&resolved, &credential, &mut client);

        assert_eq!(check.status, "failed");
        assert!(check.message.contains("RUNNER_IDENTITY_MISMATCH"));
    }

    #[test]
    fn doctor_json_runner_control_failure_maps_to_nonzero_exit_without_losing_schema() {
        let checks = vec![
            DoctorCheck::ok("config", "ok"),
            DoctorCheck::ok("auth", "ok"),
            DoctorCheck::ok("server", "ok"),
            DoctorCheck::fail(
                "runnerControl",
                "RUNNER_CONTROL_UNAVAILABLE: backend unavailable",
            ),
        ];
        let output = format_doctor_checks(
            &checks,
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let args = vec![
            "--json".to_string(),
            "runner".to_string(),
            "doctor".to_string(),
        ];

        assert_eq!("loomex.cli.runnerDoctor/v1", parsed["schemaVersion"]);
        assert_eq!("failed", parsed["status"]);
        assert_eq!(20, exit_code_for_successful_output(&args, &output));
    }

    #[test]
    fn doctor_json_shell_failure_uses_stable_shell_name_and_exit_30() {
        let checks = vec![
            DoctorCheck::ok("config", "ok"),
            DoctorCheck::ok("auth", "ok"),
            DoctorCheck::ok("server", "ok"),
            DoctorCheck::ok("runnerControl", "ok"),
            DoctorCheck::fail("shell", "sh unavailable: not found"),
        ];
        let output = format_doctor_checks(
            &checks,
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let args = vec![
            "--json".to_string(),
            "runner".to_string(),
            "doctor".to_string(),
        ];

        assert_eq!("loomex.cli.runnerDoctor/v1", parsed["schemaVersion"]);
        assert_eq!("failed", parsed["status"]);
        assert_eq!("shell", parsed["checks"][4]["name"]);
        assert_eq!(30, exit_code_for_successful_output(&args, &output));
    }

    #[test]
    fn shell_doctor_check_uses_contract_name_not_platform_binary() {
        let check = shell_available_check();

        assert_eq!("shell", check.name);
    }

    #[test]
    fn doctor_workspace_permission_denied_is_failed_check() {
        let path = temp_config_path("doctor-workspace-file");
        fs::write(&path, "not a directory").unwrap();

        let check = workspace_doctor_check(Some(&path.to_string_lossy()));
        let _ = fs::remove_file(&path);

        assert_eq!("workspace", check.name);
        assert_eq!("failed", check.status);
    }

    #[test]
    fn exit_code_mapping_and_json_error_schema_are_stable() {
        let error = "AUTH_TOKEN_EXPIRED: token expired";
        let envelope: Value = serde_json::from_str(&error_json_envelope(error)).unwrap();

        assert_eq!(10, exit_code_for_error(error));
        assert_eq!("loomex.cli.error/v1", envelope["schemaVersion"]);
        assert_eq!("AUTH_TOKEN_EXPIRED", envelope["error"]["code"]);
        assert_eq!(false, envelope["error"]["retryable"]);
        assert_eq!(10, envelope["exitCode"]);
    }

    #[test]
    fn json_error_schema_marks_only_reliable_management_failures_retryable() {
        for error in [
            "MANAGEMENT_HTTP_FAILED: connection refused",
            "MANAGEMENT_HTTP_STATUS: management API returned HTTP 429",
            "MANAGEMENT_HTTP_STATUS: management API returned HTTP 503",
        ] {
            let envelope: Value = serde_json::from_str(&error_json_envelope(error)).unwrap();
            assert_eq!(true, envelope["error"]["retryable"], "{error}");
        }

        for error in [
            "MANAGEMENT_HTTP_STATUS: management API returned HTTP 400",
            "MANAGEMENT_AUTH_FAILED: token expired",
            "AUTH_DEVICE_FLOW_EXPIRED: start authentication again",
        ] {
            let envelope: Value = serde_json::from_str(&error_json_envelope(error)).unwrap();
            assert_eq!(false, envelope["error"]["retryable"], "{error}");
        }
    }

    #[test]
    fn api_key_login_stores_credential_and_profile_org_without_printing_token() {
        let config_path = temp_config_path("api-key-login");
        let credential_root = temp_credential_dir("api-key-login");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            api_key_token: Some(token("management_secret")),
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: Some("wfpk_123".to_string()),
                api_secret: Some("wfsk_123".to_string()),
                organization_id: Some("org_123".to_string()),
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap();
        let saved = store.load("default").unwrap().unwrap();
        let saved_config = CliConfig::load_or_default(&config_path).unwrap();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert_eq!("management_secret", saved.access_token);
        assert_eq!(
            Some("org_123".to_string()),
            saved_config.profiles["default"].organization_id
        );
        assert!(!output.contains("management_secret"));
        assert!(output.contains("warning:"));
    }

    #[test]
    fn api_key_login_without_org_persists_runner_control_org() {
        let config_path = temp_config_path("api-key-login-no-org");
        let credential_root = temp_credential_dir("api-key-login-no-org");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            api_key_token: Some(token("management_secret")),
            api_key_exchange_organization_id: Some("org_123".to_string()),
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: Some("wfpk_123".to_string()),
                api_secret: Some("wfsk_123".to_string()),
                organization_id: None,
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap();
        let saved = store.load("default").unwrap().unwrap();
        let saved_config = CliConfig::load_or_default(&config_path).unwrap();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert_eq!("org_123", saved.organization_id);
        assert_eq!(
            Some("org_123".to_string()),
            saved_config.profiles["default"].organization_id
        );
        assert!(output.contains("organization: org_123"));
    }

    #[test]
    fn api_key_login_invalid_returns_structured_error() {
        let config_path = temp_config_path("api-key-invalid");
        let credential_root = temp_credential_dir("api-key-invalid");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            api_key_error: Some(loomex_core::CoreError::new(
                "MANAGEMENT_AUTH_FAILED",
                "invalid API key",
            )),
            ..Default::default()
        };

        let err = run_login_with(
            LoginRequest {
                api_key: Some("wfpk_bad".to_string()),
                api_secret: Some("wfsk_bad".to_string()),
                organization_id: Some("org_123".to_string()),
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(err.contains("MANAGEMENT_AUTH_FAILED"));
    }

    #[test]
    fn device_login_timeout_is_deterministic() {
        let config_path = temp_config_path("device-timeout");
        let credential_root = temp_credential_dir("device-timeout");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            device_challenge: Some(DeviceLoginChallenge {
                device_code: "dev_code".to_string(),
                user_code: "USER-CODE".to_string(),
                verification_uri: "https://loomex.app/device".to_string(),
                expires_in_seconds: 10,
                interval_seconds: 1,
            }),
            ..Default::default()
        };

        let err = run_login_with(
            LoginRequest {
                api_key: None,
                api_secret: None,
                organization_id: Some("org_123".to_string()),
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(err.contains("LOGIN_DEVICE_TIMEOUT"));
    }

    #[test]
    fn device_login_success_auto_selects_single_organization() {
        let config_path = temp_config_path("device-success");
        let credential_root = temp_credential_dir("device-success");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            device_challenge: Some(DeviceLoginChallenge {
                device_code: "dev_code".to_string(),
                user_code: "USER-CODE".to_string(),
                verification_uri: "https://loomex.app/device".to_string(),
                expires_in_seconds: 10,
                interval_seconds: 1,
            }),
            device_token: Some(token("device_management_secret")),
            organizations: vec![Organization {
                id: "org_123".to_string(),
                name: "Only Org".to_string(),
            }],
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: None,
                api_secret: None,
                organization_id: None,
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap();
        let saved = store.load("default.user").unwrap().unwrap();
        let saved_config = CliConfig::load_or_default(&config_path).unwrap();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert_eq!("device_management_secret", saved.access_token);
        assert!(store.load("default").unwrap().is_none());
        assert_eq!(
            Some("org_123".to_string()),
            saved_config.profiles["default"].organization_id
        );
        assert!(!output.contains("device_management_secret"));
    }

    #[test]
    fn runner_credential_schema_marker_requires_legacy_reauthentication() {
        let legacy = credential("default", "org_123");
        let current = ManagementCredential::from_runner_token_response(
            "default",
            "org_123",
            token("opaque-runner-token"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();

        assert!(runner_credential_upgrade_reason(&legacy).is_some());
        assert!(runner_credential_upgrade_reason(&current).is_none());
        assert!(validate_runner_credential_compatibility(&legacy)
            .unwrap_err()
            .contains("RUNNER_CREDENTIAL_UPGRADE_REQUIRED"));
        let (ready, reason) = runner_credential_local_readiness(Some(&legacy), 0);
        assert!(!ready);
        assert_eq!(Some(RUNNER_REAUTH_GUIDANCE), reason);
    }

    #[test]
    fn selected_project_bootstraps_separate_runner_credential() {
        let config_path = temp_config_path("project-runner-bootstrap");
        let credential_root = temp_credential_dir("project-runner-bootstrap");
        let store = LocalCredentialStore::new(credential_root.clone());
        let user_credential = ManagementCredential::from_user_token_response(
            "default.user",
            "org_123",
            token("signed-user-token"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&user_credential).unwrap();
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let mut client = FakeManagementClient::default();

        bootstrap_cli_runner_for_project(
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
            "default",
            "org_123",
            "prj_123",
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();

        let runner = store.load("default").unwrap().unwrap();
        assert_eq!(CredentialKind::RunnerControlV1, runner.kind);
        assert_eq!("lmxrt_runner_secret", runner.access_token);
        assert_eq!(1, client.bootstrap_call_count);
        assert_eq!(
            Some("runner_123".to_string()),
            config.profiles["default"].runner_id
        );
        assert!(config.profiles["default"].binding_id.is_none());
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let readiness =
            plugin_service_bootstrap_readiness_with(&resolved, Some(&runner), 0, &mut client);
        assert_eq!(readiness["ready"], false);
        assert!(readiness["missingContext"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "bindingId"));
        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir_all(credential_root);
    }

    #[test]
    fn device_login_challenge_is_presented_before_polling_token() {
        let config_path = temp_config_path("device-challenge-presented");
        let credential_root = temp_credential_dir("device-challenge-presented");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let challenge_presented = Rc::new(Cell::new(false));
        let mut client = FakeManagementClient {
            device_challenge: Some(DeviceLoginChallenge {
                device_code: "dev_code".to_string(),
                user_code: "USER-CODE".to_string(),
                verification_uri: "https://loomex.app/device".to_string(),
                expires_in_seconds: 10,
                interval_seconds: 1,
            }),
            device_token: Some(token("device_management_secret")),
            organizations: vec![Organization {
                id: "org_123".to_string(),
                name: "Only Org".to_string(),
            }],
            poll_requires_presented: Some(Rc::clone(&challenge_presented)),
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: None,
                api_secret: None,
                organization_id: None,
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |challenge| {
                assert_eq!("USER-CODE", challenge.user_code);
                assert_eq!("https://loomex.app/device", challenge.verification_uri);
                challenge_presented.set(true);
            },
        )
        .unwrap();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(output.contains("device login verified"));
        assert!(challenge_presented.get());
    }

    #[test]
    fn device_login_with_multiple_orgs_requires_explicit_selection() {
        let config_path = temp_config_path("device-multi-org");
        let credential_root = temp_credential_dir("device-multi-org");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            device_challenge: Some(DeviceLoginChallenge {
                device_code: "dev_code".to_string(),
                user_code: "USER-CODE".to_string(),
                verification_uri: "https://loomex.app/device".to_string(),
                expires_in_seconds: 10,
                interval_seconds: 1,
            }),
            device_token: Some(token("device_management_secret")),
            organizations: vec![
                Organization {
                    id: "org_1".to_string(),
                    name: "One".to_string(),
                },
                Organization {
                    id: "org_2".to_string(),
                    name: "Two".to_string(),
                },
            ],
            ..Default::default()
        };

        let err = run_login_with(
            LoginRequest {
                api_key: None,
                api_secret: None,
                organization_id: None,
                device_timeout_seconds: 1,
            },
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::LocalFileFallback,
            |_| {},
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(err.contains("ORG_SELECTION_REQUIRED"));
    }

    #[test]
    fn json_login_reports_actual_storage_backend() {
        let config_path = temp_config_path("api-key-login-keychain-json");
        let credential_root = temp_credential_dir("api-key-login-keychain-json");
        let store = LocalCredentialStore::new(credential_root.clone());
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            api_key_token: Some(token("management_secret")),
            ..Default::default()
        };
        let options = GlobalOptions {
            json: true,
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: Some("wfpk_123".to_string()),
                api_secret: Some("wfsk_123".to_string()),
                organization_id: Some("org_123".to_string()),
                device_timeout_seconds: 1,
            },
            &options,
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::MacOsKeychain,
            |_| {},
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir_all(&credential_root);

        assert_eq!("macos_keychain", parsed["storageBackend"]);
    }

    #[test]
    fn json_login_reports_actual_fallback_when_keychain_save_falls_back() {
        let config_path = temp_config_path("api-key-login-keychain-fallback-json");
        let store = FallingBackCredentialStore;
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            api_key_token: Some(token("management_secret")),
            ..Default::default()
        };
        let options = GlobalOptions {
            json: true,
            ..Default::default()
        };

        let output = run_login_with(
            LoginRequest {
                api_key: Some("wfpk_123".to_string()),
                api_secret: Some("wfsk_123".to_string()),
                organization_id: Some("org_123".to_string()),
                device_timeout_seconds: 1,
            },
            &options,
            &mut config,
            &config_path,
            &store,
            &mut client,
            "default",
            CredentialStorageBackend::MacOsKeychain,
            |_| {},
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let _ = std::fs::remove_file(&config_path);

        assert_eq!("local_file_fallback", parsed["storageBackend"]);
        assert!(parsed["storageWarning"]
            .as_str()
            .unwrap()
            .contains("fallback"));
    }

    #[test]
    fn org_list_and_select_persist_profile_context() {
        let config_path = temp_config_path("org-select");
        let mut config = CliConfig::default();
        let credential = credential("default", "org_1");
        let mut client = FakeManagementClient {
            organizations: vec![
                Organization {
                    id: "org_1".to_string(),
                    name: "First".to_string(),
                },
                Organization {
                    id: "org_2".to_string(),
                    name: "Second".to_string(),
                },
            ],
            ..Default::default()
        };

        let list = run_org_with(
            &["list".to_string()],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
        )
        .unwrap();
        let selected = run_org_with(
            &["select".to_string(), "org_2".to_string()],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
        )
        .unwrap();
        let saved = CliConfig::load_or_default(&config_path).unwrap();
        let _ = std::fs::remove_file(&config_path);

        assert!(list.contains("org_1\tFirst"));
        assert!(selected.contains("Second"));
        assert_eq!(
            Some("org_2".to_string()),
            saved.profiles["default"].organization_id
        );
        assert_eq!(None, saved.profiles["default"].project_id);
    }

    #[test]
    fn project_select_validates_org_and_persists_default_project() {
        let config_path = temp_config_path("project-select");
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        let credential = credential("default", "org_123");
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            ..Default::default()
        };

        let output = run_project_with(
            &["select".to_string(), "prj_123".to_string()],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            "org_123",
        )
        .unwrap();
        let saved = CliConfig::load_or_default(&config_path).unwrap();
        let _ = std::fs::remove_file(&config_path);

        assert!(output.contains("Demo"));
        assert_eq!(
            Some("prj_123".to_string()),
            saved.profiles["default"].project_id
        );
    }

    #[test]
    fn project_list_empty_org_returns_clear_error() {
        let config_path = temp_config_path("project-empty");
        let mut config = CliConfig::default();
        let credential = credential("default", "org_empty");
        let mut client = FakeManagementClient::default();

        let err = run_project_with(
            &["list".to_string()],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            "org_empty",
        )
        .unwrap_err();
        let _ = std::fs::remove_file(&config_path);

        assert!(err.contains("PROJECT_ACCESS_EMPTY"));
    }

    #[test]
    fn logout_token_removal_deletes_local_credential() {
        let credential_root = temp_credential_dir("logout");
        let store = LocalCredentialStore::new(credential_root.clone());
        store.save(&credential("default", "org_123")).unwrap();

        store.delete("default").unwrap();
        let loaded = store.load("default").unwrap();
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(loaded.is_none());
    }

    #[test]
    fn expired_loaded_credential_fails_before_management_call() {
        let credential_root = temp_credential_dir("expired-token");
        let store = LocalCredentialStore::new(credential_root.clone());
        let expired = ManagementCredential::from_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "management_secret".to_string(),
                refresh_token: Some("refresh_secret".to_string()),
                token_type: "Bearer".to_string(),
                expires_at: "1970-01-01T00:00:01Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&expired).unwrap();

        let err = load_credential(&store, "default").unwrap_err();
        let _ = std::fs::remove_dir_all(&credential_root);

        assert!(err.contains("AUTH_TOKEN_EXPIRED"));
    }

    #[test]
    fn bind_creates_binding_and_persists_runner_context() {
        let config_path = temp_config_path("bind-success");
        let workspace = temp_workspace_path("bind-success");
        fs::create_dir_all(&workspace).unwrap();
        let mut config = CliConfig::default();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            ..Default::default()
        };

        let output = run_bind_with(
            &[
                "--project".to_string(),
                "prj_123".to_string(),
                "--workspace".to_string(),
                workspace.to_string_lossy().to_string(),
            ],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap();
        let saved = CliConfig::load_or_default(&config_path).unwrap();
        let canonical_workspace = workspace
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&workspace);

        assert!(output.contains("\"schemaVersion\":\"loomex.cli.binding/v1\""));
        assert_eq!(
            Some("org_123".to_string()),
            saved.profiles["default"].organization_id
        );
        assert_eq!(
            Some("prj_123".to_string()),
            saved.profiles["default"].project_id
        );
        assert_eq!(
            Some("runner_123".to_string()),
            saved.profiles["default"].runner_id
        );
        assert_eq!(
            Some("binding_123".to_string()),
            saved.profiles["default"].binding_id
        );
        assert_eq!(
            Some(canonical_workspace.clone()),
            saved.profiles["default"].workspace_path
        );
        assert_eq!(
            Some(canonical_workspace),
            client
                .last_binding_request
                .as_ref()
                .map(|request| request.local_root_path.clone())
        );
    }

    #[test]
    fn plugin_binding_bootstraps_runner_token_before_runner_control_call() {
        let config_path = temp_config_path("plugin-binding-bootstrap");
        let credential_root = temp_credential_dir("plugin-binding-bootstrap");
        let workspace = temp_workspace_path("plugin-binding-bootstrap");
        fs::create_dir_all(&workspace).unwrap();
        let store = LocalCredentialStore::new(credential_root.clone());
        let user_credential = ManagementCredential::from_user_token_response(
            "default.user",
            "org_123",
            AuthTokenResponse {
                access_token: "user.jwt".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&user_credential).unwrap();
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            ..Default::default()
        };

        let result = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();
        let repeated = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();
        let saved_runner_credential = store.load("default").unwrap().unwrap();
        let saved_config = CliConfig::load_or_default(&config_path).unwrap();

        assert_eq!(client.bootstrap_call_count, 1);
        assert_eq!(client.upsert_call_count, 0);
        assert_eq!(client.binding_create_count, 1);
        assert_eq!(
            client.last_bootstrap_access_token.as_deref(),
            Some("user.jwt")
        );
        assert_eq!(
            client.last_binding_access_token.as_deref(),
            Some("lmxrt_runner_secret")
        );
        assert_eq!(saved_runner_credential.access_token, "lmxrt_runner_secret");
        assert_eq!(
            store.load("default.user").unwrap().unwrap().access_token,
            "user.jwt"
        );
        assert_eq!(result["binding"]["id"], "binding_123");
        assert_eq!(result["bootstrapped"], true);
        assert_eq!(result["reused"], false);
        assert_eq!(repeated["bootstrapped"], false);
        assert_eq!(repeated["reused"], true);
        assert_eq!(
            saved_config.profiles["default"].binding_id.as_deref(),
            Some("binding_123")
        );
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&credential_root);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn plugin_binding_reconciles_decode_failure_after_server_created_binding_once() {
        let config_path = temp_config_path("plugin-binding-reconcile");
        let credential_root = temp_credential_dir("plugin-binding-reconcile");
        let workspace = temp_workspace_path("plugin-binding-reconcile");
        fs::create_dir_all(&workspace).unwrap();
        let store = LocalCredentialStore::new(credential_root.clone());
        let user_credential = ManagementCredential::from_user_token_response(
            "default.user",
            "org_123",
            token("user.jwt"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&user_credential).unwrap();
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            binding_create_error_after_insert: Some(loomex_core::CoreError::new(
                "MANAGEMENT_RESPONSE_INVALID",
                "response body could not be decoded",
            )),
            ..Default::default()
        };

        let result = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();

        assert_eq!(client.binding_create_count, 1);
        assert_eq!(client.bindings.len(), 1);
        assert_eq!(result["binding"]["id"], "binding_123");
        assert_eq!(result["reconciled"], true);
        assert_eq!(
            config.profiles["default"].binding_id.as_deref(),
            Some("binding_123")
        );
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&credential_root);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn plugin_binding_uses_authenticated_runner_and_does_not_reuse_foreign_binding() {
        let config_path = temp_config_path("plugin-binding-authenticated-runner");
        let credential_root = temp_credential_dir("plugin-binding-authenticated-runner");
        let workspace = temp_workspace_path("plugin-binding-authenticated-runner");
        fs::create_dir_all(&workspace).unwrap();
        let canonical_workspace = workspace.canonicalize().unwrap().display().to_string();
        let store = LocalCredentialStore::new(credential_root.clone());
        let user_credential = ManagementCredential::from_user_token_response(
            "default.user",
            "org_123",
            token("user.jwt"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        let runner_credential = ManagementCredential::from_runner_token_response(
            "default",
            "org_123",
            AuthTokenResponse {
                access_token: "runner.jwt".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
            },
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&user_credential).unwrap();
        store.save(&runner_credential).unwrap();
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.runnerId", "runner-stale".to_string())
            .unwrap();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            runner: Some(Runner {
                id: "runner_123".to_string(),
                organization_id: "org_123".to_string(),
                status: "online".to_string(),
                runner_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: default_runner_capabilities(),
            }),
            bindings: vec![ManagementProjectRunnerBinding {
                id: "binding-foreign".to_string(),
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_id: "runner-stale".to_string(),
                local_root_path: canonical_workspace,
                status: "active".to_string(),
                local_root_fingerprint: None,
            }],
            ..Default::default()
        };

        let result = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();

        assert_eq!(client.binding_create_count, 1);
        assert_eq!(result["reused"], false);
        assert_eq!(result["runnerId"], "runner_123");
        assert_eq!(
            client.last_binding_request.as_ref().unwrap().runner_id,
            "runner_123"
        );
        assert_eq!(
            config.profiles["default"].runner_id.as_deref(),
            Some("runner_123")
        );
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&credential_root);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn plugin_binding_revoke_and_recreate_uses_a_fresh_lifecycle_idempotency_key() {
        let config_path = temp_config_path("plugin-binding-recreate");
        let credential_root = temp_credential_dir("plugin-binding-recreate");
        let workspace = temp_workspace_path("plugin-binding-recreate");
        fs::create_dir_all(&workspace).unwrap();
        let store = LocalCredentialStore::new(credential_root.clone());
        let user_credential = ManagementCredential::from_user_token_response(
            "default.user",
            "org_123",
            token("user.jwt"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap();
        store.save(&user_credential).unwrap();
        let mut config = CliConfig::default();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            ..Default::default()
        };

        let first = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();
        client.bindings[0].status = "revoked".to_string();
        let second = create_plugin_binding_with(
            "prj_123",
            &workspace.to_string_lossy(),
            "default",
            &mut config,
            &config_path,
            &store,
            &user_credential,
            &mut client,
        )
        .unwrap();

        assert_eq!(client.binding_create_count, 2);
        assert_eq!(client.binding_create_keys.len(), 2);
        assert_ne!(client.binding_create_keys[0], client.binding_create_keys[1]);
        assert_eq!(first["binding"]["id"], "binding_123");
        assert_eq!(second["binding"]["id"], "binding_2");
        assert_eq!(second["reused"], false);
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&credential_root);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn project_and_organization_switch_clear_stale_runner_scope() {
        let mut project_switch = CliConfig::default();
        for (key, value) in [
            ("organizationId", "org_123"),
            ("projectId", "prj_old"),
            ("runnerId", "runner_old"),
            ("bindingId", "binding_old"),
            ("workspacePath", "/tmp/old"),
        ] {
            project_switch
                .set_key(&format!("profiles.default.{key}"), value.to_string())
                .unwrap();
        }

        clear_plugin_runner_scope(&mut project_switch, "default", false).unwrap();

        let profile = &project_switch.profiles["default"];
        assert_eq!(profile.organization_id.as_deref(), Some("org_123"));
        assert_eq!(profile.project_id.as_deref(), Some("prj_old"));
        assert!(profile.runner_id.is_none());
        assert!(profile.binding_id.is_none());
        assert!(profile.workspace_path.is_none());

        let mut organization_switch = project_switch;
        clear_plugin_runner_scope(&mut organization_switch, "default", true).unwrap();
        let profile = &organization_switch.profiles["default"];
        assert_eq!(profile.organization_id.as_deref(), Some("org_123"));
        assert!(profile.project_id.is_none());
        assert!(profile.runner_id.is_none());
        assert!(profile.binding_id.is_none());
        assert!(profile.workspace_path.is_none());
    }

    #[test]
    fn bind_without_args_prompts_for_project_and_workspace() {
        let config_path = temp_config_path("bind-wizard");
        let workspace = temp_workspace_path("bind-wizard");
        fs::create_dir_all(&workspace).unwrap();
        let mut config = CliConfig::default();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::new(&["prj_123", &workspace.to_string_lossy()]);
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "active".to_string(),
            }),
            ..Default::default()
        };

        let output = run_bind_with(
            &[],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap();
        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&workspace);

        assert!(output.contains("bound workspace:"));
        assert!(client.last_binding_request.is_some());
    }

    #[test]
    fn bind_rejects_archived_project_before_binding_creation() {
        let config_path = temp_config_path("bind-archived");
        let workspace = temp_workspace_path("bind-archived");
        fs::create_dir_all(&workspace).unwrap();
        let mut config = CliConfig::default();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            project: Some(Project {
                id: "prj_123".to_string(),
                organization_id: "org_123".to_string(),
                name: "Demo".to_string(),
                status: "archived".to_string(),
            }),
            ..Default::default()
        };

        let err = run_bind_with(
            &[
                "--project".to_string(),
                "prj_123".to_string(),
                "--workspace".to_string(),
                workspace.to_string_lossy().to_string(),
            ],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap_err();
        let _ = fs::remove_dir_all(&workspace);

        assert!(err.contains("PROJECT_UNAVAILABLE"));
        assert!(client.last_binding_request.is_none());
    }

    #[test]
    fn bind_requires_workspace_path() {
        let config_path = temp_config_path("bind-missing-workspace");
        let mut config = CliConfig::default();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient::default();

        let err = run_bind_with(
            &["--project".to_string(), "prj_123".to_string()],
            &GlobalOptions::default(),
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap_err();

        assert!(err.contains("WORKSPACE_PATH_REQUIRED"));
        assert!(client.last_binding_request.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bind_rejects_symlink_workspace_root() {
        use std::os::unix::fs::symlink;

        let target = temp_workspace_path("bind-symlink-target");
        let link = temp_workspace_path("bind-symlink-link");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();

        let err = validate_workspace_path(&link.to_string_lossy()).unwrap_err();
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&target);

        assert!(err.contains("WORKSPACE_SYMLINK_NOT_ALLOWED"));
    }

    #[test]
    fn bind_list_and_revoke_use_selected_project_context() {
        let config_path = temp_config_path("bind-list");
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            bindings: vec![ManagementProjectRunnerBinding {
                id: "binding_123".to_string(),
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_id: "runner_123".to_string(),
                local_root_path: "/srv/app".to_string(),
                status: "active".to_string(),
                local_root_fingerprint: None,
            }],
            ..Default::default()
        };

        let list_output = run_bind_with(
            &["list".to_string()],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap();
        let revoke_output = run_bind_with(
            &["revoke".to_string(), "binding_123".to_string()],
            &GlobalOptions {
                json: true,
                ..Default::default()
            },
            &mut config,
            &config_path,
            &credential,
            &mut client,
            "default",
            &mut prompt,
        )
        .unwrap();

        assert!(list_output.contains("\"schemaVersion\":\"loomex.cli.bindingList/v1\""));
        assert!(list_output.contains("binding_123"));
        assert!(revoke_output.contains("\"revoked\":true"));
    }

    #[test]
    fn workflow_run_sends_json_input_binding_and_human_input() {
        let workspace = temp_workspace_path("workflow-run");
        fs::create_dir_all(&workspace).unwrap();
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", "binding_123".to_string())
            .unwrap();
        config
            .set_key(
                "profiles.default.workspacePath",
                workspace.to_string_lossy().to_string(),
            )
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let validated_workspace = validate_workspace_path(&workspace.to_string_lossy()).unwrap();
        let mut client = FakeManagementClient {
            bindings: vec![ManagementProjectRunnerBinding {
                id: "binding_123".to_string(),
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_id: "runner_123".to_string(),
                local_root_path: validated_workspace.display_path.clone(),
                status: "active".to_string(),
                local_root_fingerprint: Some(validated_workspace.fingerprint.clone()),
            }],
            ..Default::default()
        };

        let output = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{\"task\":\"ship\"}".to_string(),
                "--human-input".to_string(),
                "{\"approved\":true}".to_string(),
            ],
            &GlobalOptions {
                json: true,
                non_interactive: true,
                ..Default::default()
            },
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap();
        let request = client.last_workflow_request.unwrap();
        let _ = fs::remove_dir_all(&workspace);

        assert!(output.contains("\"schemaVersion\":\"loomex.cli.workflowRun/v1\""));
        assert_eq!("wf_123", request.workflow_id);
        assert_eq!(
            Some("binding_123".to_string()),
            request.project_runner_binding_id
        );
        assert_eq!(json!("ship"), request.inputs["task"]);
        assert_eq!(json!(true), request.inputs["humanInput"]["approved"]);
    }

    #[test]
    fn workflow_run_without_input_prompts_from_schema() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::new(&["ship it"]);
        let mut client = FakeManagementClient {
            workflow_input_schema: Some(json!({
                "type": "object",
                "required": ["task"],
                "properties": {"task": {"type": "string"}}
            })),
            ..Default::default()
        };

        run_workflow_with(
            &["run".to_string(), "wf_123".to_string()],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap();
        let request = client.last_workflow_request.unwrap();

        assert_eq!(json!("ship it"), request.inputs["task"]);
    }

    #[test]
    fn workflow_run_workspace_must_match_selected_binding() {
        let workspace = temp_workspace_path("workflow-binding-mismatch");
        fs::create_dir_all(&workspace).unwrap();
        let validated_workspace = validate_workspace_path(&workspace.to_string_lossy()).unwrap();
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.bindingId", "binding_other".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            bindings: vec![ManagementProjectRunnerBinding {
                id: "binding_workspace".to_string(),
                organization_id: "org_123".to_string(),
                project_id: "prj_123".to_string(),
                runner_id: "runner_123".to_string(),
                local_root_path: validated_workspace.display_path,
                status: "active".to_string(),
                local_root_fingerprint: Some(validated_workspace.fingerprint),
            }],
            ..Default::default()
        };

        let err = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--workspace".to_string(),
                workspace.to_string_lossy().to_string(),
                "--input".to_string(),
                "{}".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap_err();
        let _ = fs::remove_dir_all(&workspace);

        assert!(err.contains("PROJECT_RUNNER_BINDING_MISMATCH"));
        assert!(client.last_workflow_request.is_none());
    }

    #[test]
    fn workflow_run_non_interactive_waiting_human_input_fails() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            workflow_run: Some(WorkflowRunStartResponse {
                id: "run_123".to_string(),
                status: "waiting".to_string(),
                ui_url: None,
            }),
            human_requests: vec![HumanRequestSummary {
                id: "human_123".to_string(),
                status: "pending".to_string(),
                title: "Approve".to_string(),
                execution: Some(HumanRequestExecution {
                    id: "run_123".to_string(),
                }),
                description: "".to_string(),
                blocking: true,
                extra: Default::default(),
            }],
            ..Default::default()
        };

        let err = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{}".to_string(),
            ],
            &GlobalOptions {
                non_interactive: true,
                ..Default::default()
            },
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap_err();

        assert!(err.contains("NON_INTERACTIVE_HUMAN_INPUT_PENDING"));
        assert!(client.last_human_resolution.is_none());
    }

    #[test]
    fn workflow_run_can_cancel_waiting_human_input() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            workflow_run: Some(WorkflowRunStartResponse {
                id: "run_123".to_string(),
                status: "waiting".to_string(),
                ui_url: None,
            }),
            human_requests: vec![HumanRequestSummary {
                id: "human_123".to_string(),
                status: "pending".to_string(),
                title: "Approve".to_string(),
                execution: Some(HumanRequestExecution {
                    id: "run_123".to_string(),
                }),
                description: "".to_string(),
                blocking: true,
                extra: Default::default(),
            }],
            ..Default::default()
        };

        run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{}".to_string(),
                "--human-input-cancel".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap();

        assert_eq!(
            Some(json!({"answer": {"cancelled": true}})),
            client.last_human_resolution
        );
    }

    #[test]
    fn workflow_run_resolves_human_request_for_started_execution_only() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            workflow_run: Some(WorkflowRunStartResponse {
                id: "run_new".to_string(),
                status: "waiting".to_string(),
                ui_url: None,
            }),
            human_requests: vec![
                HumanRequestSummary {
                    id: "human_old".to_string(),
                    status: "pending".to_string(),
                    title: "Old".to_string(),
                    execution: Some(HumanRequestExecution {
                        id: "run_old".to_string(),
                    }),
                    description: "".to_string(),
                    blocking: true,
                    extra: Default::default(),
                },
                HumanRequestSummary {
                    id: "human_new".to_string(),
                    status: "pending".to_string(),
                    title: "New".to_string(),
                    execution: Some(HumanRequestExecution {
                        id: "run_new".to_string(),
                    }),
                    description: "".to_string(),
                    blocking: true,
                    extra: Default::default(),
                },
            ],
            ..Default::default()
        };

        run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{}".to_string(),
                "--human-input".to_string(),
                "{\"approved\":true}".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap();

        assert_eq!(Some("human_new".to_string()), client.last_human_request_id);
        assert_eq!(
            Some(json!({"answer": {"approved": true}})),
            client.last_human_resolution
        );
    }

    #[test]
    fn workflow_run_rejects_missing_required_schema_input() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            workflow_input_schema: Some(json!({
                "type": "object",
                "required": ["task"],
                "properties": {
                    "task": {"type": "string"}
                }
            })),
            ..Default::default()
        };

        let err = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{}".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap_err();

        assert!(err.contains("WORKFLOW_INPUT_REQUIRED_FIELD_MISSING"));
        assert!(client.last_workflow_request.is_none());
    }

    #[test]
    fn workflow_run_rejects_schema_type_mismatch() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient {
            workflow_input_schema: Some(json!({
                "type": "object",
                "required": ["task"],
                "properties": {
                    "task": {"type": "string"}
                },
                "additionalProperties": false
            })),
            ..Default::default()
        };

        let err = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "{\"task\":42}".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap_err();

        assert!(err.contains("WORKFLOW_INPUT_SCHEMA_VALIDATION_FAILED"));
        assert!(client.last_workflow_request.is_none());
    }

    #[test]
    fn workflow_run_accepts_human_input_primitive_and_array_shapes() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();

        let primitive = WorkflowRunRequest::parse(
            "wf_123",
            &[
                "--input".to_string(),
                "{}".to_string(),
                "--human-input".to_string(),
                "\"approved\"".to_string(),
            ],
            &resolved,
            parse_json_value,
        )
        .unwrap();
        let array = WorkflowRunRequest::parse(
            "wf_123",
            &[
                "--input".to_string(),
                "{}".to_string(),
                "--human-input".to_string(),
                "[\"a\",\"b\"]".to_string(),
            ],
            &resolved,
            parse_json_value,
        )
        .unwrap();

        assert_eq!(Some(json!("approved")), primitive.human_input);
        assert_eq!(Some(json!(["a", "b"])), array.human_input);
    }

    #[test]
    fn workflow_run_rejects_non_object_input_before_dispatch() {
        let mut config = CliConfig::default();
        config
            .set_key("profiles.default.organizationId", "org_123".to_string())
            .unwrap();
        config
            .set_key("profiles.default.projectId", "prj_123".to_string())
            .unwrap();
        let resolved = config
            .resolve(CliConfigOverrides::default(), |_| None)
            .unwrap();
        let credential = credential("default", "org_123");
        let mut prompt = TestPrompt::default();
        let mut client = FakeManagementClient::default();

        let err = run_workflow_with(
            &[
                "run".to_string(),
                "wf_123".to_string(),
                "--input".to_string(),
                "[\"not-object\"]".to_string(),
            ],
            &GlobalOptions::default(),
            &credential,
            &mut client,
            parse_json_value,
            &resolved,
            &mut prompt,
        )
        .unwrap_err();

        assert!(err.contains("WORKFLOW_INPUT_INVALID"));
        assert!(client.last_workflow_request.is_none());
    }

    #[test]
    fn workflow_input_reader_supports_file_references() {
        let input_path = temp_config_path("workflow-input");
        fs::write(&input_path, "{\"task\":\"ship\"}").unwrap();

        let value = WorkflowInputReader::from_runtime(&format!("@{}", input_path.display()))
            .expect("file input should parse");
        let _ = fs::remove_file(&input_path);

        assert_eq!(json!("ship"), value["task"]);
    }

    #[test]
    fn runner_release_cli_signs_and_verifies_manifest_and_artifact() {
        let signing_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = loomex_core::verifying_key_hex_from_signing_key(signing_key).unwrap();
        let artifact_path = temp_config_path("release-artifact.bin");
        let signing_key_path = temp_config_path("release-signing-key.txt");
        let manifest_path = temp_config_path("release-manifest.json");
        fs::write(&artifact_path, b"loomex release binary").unwrap();
        fs::write(&signing_key_path, format!("{signing_key}\n")).unwrap();

        let sign_artifact = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "sign-artifact".to_string(),
            "--name".to_string(),
            "loomex-cli-macos-aarch64".to_string(),
            "--os".to_string(),
            "macos".to_string(),
            "--arch".to_string(),
            "aarch64".to_string(),
            "--path".to_string(),
            artifact_path.display().to_string(),
            "--signing-key-file".to_string(),
            signing_key_path.display().to_string(),
        ])
        .unwrap();
        let sign_artifact_json: Value = serde_json::from_str(&sign_artifact).unwrap();
        let artifact = sign_artifact_json["artifact"].clone();
        let manifest = json!({
            "schema_version": loomex_core::RELEASE_MANIFEST_SCHEMA_VERSION,
            "product": "loomex-runner",
            "version": "1.2.3",
            "channel": "stable",
            "rollout_percent": 100,
            "previous_versions": ["1.2.2"],
            "artifacts": [artifact],
            "sbom": [{"name": "loomex-cli", "version": "0.1.0"}],
            "provenance": {
                "builder_id": "github-actions:loomex-runner",
                "source_repository": "https://github.com/loomex-app/runner",
                "source_revision": "abcdef123456",
                "build_started_at": "2026-06-29T00:00:00Z",
                "build_finished_at": "2026-06-29T00:01:00Z",
                "workflow_run_id": "run_123"
            },
            "created_at": "2026-06-29T00:02:00Z"
        });
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let sign_manifest = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "sign-manifest".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--signing-key-file".to_string(),
            signing_key_path.display().to_string(),
        ])
        .unwrap();
        let signed_manifest_json: Value = serde_json::from_str(&sign_manifest).unwrap();
        assert_eq!(
            "loomex.cli.releaseSignManifest/v1",
            signed_manifest_json["schemaVersion"]
        );
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&signed_manifest_json["manifest"]).unwrap(),
        )
        .unwrap();

        let verify_manifest = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "verify-manifest".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--public-key".to_string(),
            public_key.clone(),
        ])
        .unwrap();
        let verify_manifest_json: Value = serde_json::from_str(&verify_manifest).unwrap();
        assert_eq!(json!(true), verify_manifest_json["verified"]);

        let verify_artifact = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "verify-artifact".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--name".to_string(),
            "loomex-cli-macos-aarch64".to_string(),
            "--path".to_string(),
            artifact_path.display().to_string(),
            "--public-key".to_string(),
            public_key,
        ])
        .unwrap();
        let verify_artifact_json: Value = serde_json::from_str(&verify_artifact).unwrap();
        assert_eq!(json!(true), verify_artifact_json["verified"]);

        let _ = fs::remove_file(artifact_path);
        let _ = fs::remove_file(signing_key_path);
        let _ = fs::remove_file(manifest_path);
    }

    #[test]
    fn runner_release_rejects_signing_key_in_argv() {
        let manifest_path = temp_config_path("release-unsafe-key-manifest.json");

        let error = run(vec![
            "runner".to_string(),
            "release".to_string(),
            "sign-manifest".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--signing-key".to_string(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("RELEASE_SIGNING_KEY_ARG_UNSAFE"));
    }

    #[test]
    fn runner_release_verify_artifact_requires_signed_manifest() {
        let signing_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = loomex_core::verifying_key_hex_from_signing_key(signing_key).unwrap();
        let artifact_path = temp_config_path("release-artifact-unsigned.bin");
        let manifest_path = temp_config_path("release-manifest-unsigned.json");
        fs::write(&artifact_path, b"loomex release binary").unwrap();
        let artifact = loomex_core::sign_release_artifact(
            "loomex-cli-linux-x86_64",
            "linux",
            "x86_64",
            b"loomex release binary",
            signing_key,
        )
        .unwrap();
        let manifest = json!({
            "schema_version": loomex_core::RELEASE_MANIFEST_SCHEMA_VERSION,
            "product": "loomex-runner",
            "version": "1.2.3",
            "channel": "stable",
            "rollout_percent": 100,
            "previous_versions": ["1.2.2"],
            "artifacts": [artifact],
            "sbom": [{"name": "loomex-cli", "version": "0.1.0"}],
            "provenance": {
                "builder_id": "github-actions:loomex-runner",
                "source_repository": "https://github.com/loomex-app/runner",
                "source_revision": "abcdef123456",
                "build_started_at": "2026-06-29T00:00:00Z",
                "build_finished_at": "2026-06-29T00:01:00Z",
                "workflow_run_id": "run_123"
            },
            "created_at": "2026-06-29T00:02:00Z"
        });
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let error = run(vec![
            "runner".to_string(),
            "release".to_string(),
            "verify-artifact".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--name".to_string(),
            "loomex-cli-linux-x86_64".to_string(),
            "--path".to_string(),
            artifact_path.display().to_string(),
            "--public-key".to_string(),
            public_key,
        ])
        .unwrap_err();

        assert!(error.contains("RELEASE_MANIFEST_SIGNATURE_MISSING"));
        let _ = fs::remove_file(artifact_path);
        let _ = fs::remove_file(manifest_path);
    }

    #[test]
    fn runner_release_verify_artifact_rejects_tampered_manifest() {
        let signing_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = loomex_core::verifying_key_hex_from_signing_key(signing_key).unwrap();
        let artifact_path = temp_config_path("release-artifact-tampered.bin");
        let manifest_path = temp_config_path("release-manifest-tampered.json");
        fs::write(&artifact_path, b"loomex release binary").unwrap();
        let artifact = loomex_core::sign_release_artifact(
            "loomex-cli-linux-x86_64",
            "linux",
            "x86_64",
            b"loomex release binary",
            signing_key,
        )
        .unwrap();
        let manifest = loomex_core::sign_release_manifest(
            loomex_core::ReleaseManifest {
                schema_version: loomex_core::RELEASE_MANIFEST_SCHEMA_VERSION.to_string(),
                product: "loomex-runner".to_string(),
                version: "1.2.3".to_string(),
                channel: loomex_core::ReleaseChannel::Stable,
                rollout_percent: 100,
                rollback_to_version: None,
                previous_versions: vec!["1.2.2".to_string()],
                artifacts: vec![artifact],
                sbom: vec![loomex_core::SbomPackage {
                    name: "loomex-cli".to_string(),
                    version: "0.1.0".to_string(),
                    license: None,
                }],
                provenance: loomex_core::BuildProvenance {
                    builder_id: "github-actions:loomex-runner".to_string(),
                    source_repository: "https://github.com/loomex-app/runner".to_string(),
                    source_revision: "abcdef123456".to_string(),
                    build_started_at: "2026-06-29T00:00:00Z".to_string(),
                    build_finished_at: "2026-06-29T00:01:00Z".to_string(),
                    workflow_run_id: "run_123".to_string(),
                },
                created_at: "2026-06-29T00:02:00Z".to_string(),
                signature: None,
            },
            signing_key,
        )
        .unwrap();
        let mut tampered = serde_json::to_value(manifest).unwrap();
        tampered["version"] = json!("9.9.9");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&tampered).unwrap(),
        )
        .unwrap();

        let error = run(vec![
            "runner".to_string(),
            "release".to_string(),
            "verify-artifact".to_string(),
            "--manifest".to_string(),
            manifest_path.display().to_string(),
            "--name".to_string(),
            "loomex-cli-linux-x86_64".to_string(),
            "--path".to_string(),
            artifact_path.display().to_string(),
            "--public-key".to_string(),
            public_key,
        ])
        .unwrap_err();

        assert!(error.contains("RELEASE_MANIFEST_SIGNATURE_INVALID"));
        let _ = fs::remove_file(artifact_path);
        let _ = fs::remove_file(manifest_path);
    }

    #[test]
    fn runner_release_sbom_generates_sorted_json() {
        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "sbom".to_string(),
            "--package".to_string(),
            "loomex-tauri=0.1.0".to_string(),
            "--package".to_string(),
            "loomex-core=0.1.0".to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!("loomex.cli.releaseSbom/v1", parsed["schemaVersion"]);
        assert_eq!("loomex-core", parsed["packages"][0]["name"]);
        assert_eq!("loomex-tauri", parsed["packages"][1]["name"]);
    }

    #[test]
    fn runner_release_installer_plan_lists_official_channels_and_installers() {
        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "installer-plan".to_string(),
            "--version".to_string(),
            "1.2.3".to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        let plan = &parsed["plan"];
        let channels = plan["channels"].as_array().unwrap();
        let installers = plan["installers"].as_array().unwrap();

        assert_eq!(
            "loomex.cli.releaseInstallerPlan/v1",
            parsed["schemaVersion"]
        );
        assert!(channels
            .iter()
            .any(|channel| channel["channel"] == "stable"));
        assert!(channels.iter().any(|channel| channel["channel"] == "beta"));
        assert!(channels
            .iter()
            .any(|channel| channel["channel"] == "nightly_internal"));
        assert!(channels.iter().any(|channel| {
            channel["channel"] == "enterprise_pinned" && channel["autoUpdateAllowed"] == false
        }));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "homebrew_tap"));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "mac_dmg"));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "mac_pkg"));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "linux_deb"));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "linux_rpm"));
        assert!(installers
            .iter()
            .any(|installer| installer["kind"] == "windows_msi"));
        assert!(installers
            .iter()
            .all(|installer| installer["preservesUserData"] == true));
        assert_eq!("loomex-runner", plan["legacyDeprecation"]["legacyBinary"]);
        assert_eq!("loomex", plan["legacyDeprecation"]["replacementBinary"]);
    }

    #[test]
    fn runner_release_validate_compatibility_matrix() {
        let matrix_path = temp_config_path("release-compatibility-matrix.json");
        let matrix = loomex_core::official_compatibility_matrix("1.2.3");
        fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap()).unwrap();

        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "release".to_string(),
            "validate-compatibility".to_string(),
            "--matrix".to_string(),
            matrix_path.display().to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            "loomex.cli.releaseCompatibilityValidation/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(json!(true), parsed["valid"]);
        assert_eq!(json!(1), parsed["entries"]);
        let _ = fs::remove_file(matrix_path);
    }

    #[test]
    fn runner_release_validate_compatibility_rejects_duplicate_versions() {
        let matrix_path = temp_config_path("release-compatibility-duplicate.json");
        let mut matrix = loomex_core::official_compatibility_matrix("1.2.3");
        matrix.entries.push(matrix.entries[0].clone());
        fs::write(&matrix_path, serde_json::to_string_pretty(&matrix).unwrap()).unwrap();

        let error = run(vec![
            "runner".to_string(),
            "release".to_string(),
            "validate-compatibility".to_string(),
            "--matrix".to_string(),
            matrix_path.display().to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("RELEASE_COMPATIBILITY_DUPLICATE_VERSION"));
        let _ = fs::remove_file(matrix_path);
    }

    #[test]
    fn runner_release_validate_compatibility_rejects_invalid_targeting_fields() {
        for (field, value, expected_error) in [
            (
                "channel",
                json!("dev"),
                "RELEASE_COMPATIBILITY_CHANNEL_INVALID",
            ),
            (
                "platform",
                json!("beos"),
                "RELEASE_COMPATIBILITY_PLATFORM_INVALID",
            ),
            ("arch", json!("mips"), "RELEASE_COMPATIBILITY_ARCH_INVALID"),
        ] {
            let matrix_path = temp_config_path(&format!("release-compatibility-invalid-{field}"));
            let matrix = loomex_core::official_compatibility_matrix("1.2.3");
            let mut matrix_json = serde_json::to_value(matrix).unwrap();
            matrix_json["entries"][0][field] = value;
            fs::write(
                &matrix_path,
                serde_json::to_string_pretty(&matrix_json).unwrap(),
            )
            .unwrap();

            let error = run(vec![
                "--json".to_string(),
                "runner".to_string(),
                "release".to_string(),
                "validate-compatibility".to_string(),
                "--matrix".to_string(),
                matrix_path.display().to_string(),
            ])
            .unwrap_err();

            assert!(error.contains(expected_error));
            let _ = fs::remove_file(matrix_path);
        }
    }

    #[test]
    fn runner_ops_readiness_plan_outputs_required_operational_contract() {
        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "ops".to_string(),
            "readiness-plan".to_string(),
            "--expected-runners".to_string(),
            "12000".to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            "loomex.cli.operationalReadinessPlan/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(
            "loomex.runner.operationalReadinessPlan/v1",
            parsed["plan"]["schemaVersion"]
        );
        assert!(parsed["plan"]["slos"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slo| {
                slo["id"] == "runner_stream_connect_success" && slo["targetPercent"] == json!(99.5)
            }));
        assert!(parsed["plan"]["slos"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slo| {
                slo["id"] == "workflow_local_dispatch_latency_p95" && slo["maxP95Ms"] == json!(2000)
            }));
        assert!(parsed["plan"]["requiredMetrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|metric| metric == "transport_fallback_total"));
        assert_eq!(
            json!(12000),
            parsed["plan"]["capacityPlan"]["expectedRunnerConnections"]
        );
    }

    #[test]
    fn runner_ops_release_gate_blocks_on_error_budget_burn() {
        let report_path = temp_config_path("operational-readiness-report.json");
        let mut report = complete_operational_readiness_report();
        report
            .error_budget_burn
            .iter_mut()
            .find(|burn| burn.slo_id == "trace_upload_success")
            .unwrap()
            .burn_percent_7d = 75.0;
        fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        let args = vec![
            "--json".to_string(),
            "runner".to_string(),
            "ops".to_string(),
            "release-gate".to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
        ];
        let output = run(args.clone()).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            "loomex.cli.operationalReleaseGate/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(json!(false), parsed["decision"]["allowed"]);
        assert_eq!(40, exit_code_for_successful_output(&args, &output));
        assert!(parsed["decision"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("error budget burn")));
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn runner_ops_release_gate_text_blocked_exits_non_zero() {
        let report_path = temp_config_path("operational-readiness-report-text.json");
        let mut report = complete_operational_readiness_report();
        report
            .slo_results
            .iter_mut()
            .find(|result| result.slo_id == "runner_stream_connect_success")
            .unwrap()
            .passed = false;
        fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        let args = vec![
            "runner".to_string(),
            "ops".to_string(),
            "release-gate".to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
        ];
        let output = run(args.clone()).unwrap();

        assert!(output.starts_with("operational release gate blocked:"));
        assert_eq!(40, exit_code_for_successful_output(&args, &output));
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn runner_ops_release_gate_rejects_incomplete_report() {
        let report_path = temp_config_path("operational-readiness-report-incomplete.json");
        let report = loomex_core::OperationalReadinessReport {
            schema_version: "loomex.runner.operationalReadinessReport/v1".to_string(),
            slo_results: vec![],
            error_budget_burn: vec![],
            open_critical_or_high_security_findings: 0,
            update_chain_tamper_test_passed: true,
            workspace_escape_tests_passed: true,
            secret_leakage_scan_passed: true,
            policy_bypass_tests_passed: true,
        };
        fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        let error = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "ops".to_string(),
            "release-gate".to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("OPERATIONAL_READINESS_REPORT_SLO_MISSING"));
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn runner_ops_enterprise_plan_outputs_required_scope() {
        let output = run(vec![
            "--json".to_string(),
            "runner".to_string(),
            "ops".to_string(),
            "enterprise-plan".to_string(),
        ])
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            "loomex.cli.enterpriseAcceptancePlan/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(
            "loomex.runner.enterpriseAcceptancePlan/v1",
            parsed["plan"]["schemaVersion"]
        );
        assert!(parsed["plan"]["checklist"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "playwright_local_http_db"));
        assert!(parsed["plan"]["securityReviewScope"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope["id"] == "update_chain"));
        assert!(parsed["plan"]["compliancePackage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "legal_hold_behavior"));
    }

    #[test]
    fn runner_ops_enterprise_signoff_blocks_for_high_finding() {
        let report_path = temp_config_path("enterprise-acceptance-report.json");
        let mut report = complete_enterprise_acceptance_report();
        report
            .security_findings
            .push(loomex_core::EnterpriseSecurityFinding {
                id: "finding-high".to_string(),
                severity: loomex_core::SecurityFindingSeverity::High,
                status: loomex_core::SecurityFindingStatus::Open,
                owner: None,
                mitigation: None,
                target_date: None,
            });
        fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        let json_args = vec![
            "--json".to_string(),
            "runner".to_string(),
            "ops".to_string(),
            "enterprise-signoff".to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
        ];
        let json_output = run(json_args.clone()).unwrap();
        let parsed: Value = serde_json::from_str(&json_output).unwrap();

        assert_eq!(
            "loomex.cli.enterpriseAcceptanceSignoff/v1",
            parsed["schemaVersion"]
        );
        assert_eq!(json!(false), parsed["decision"]["allowed"]);
        assert_eq!(
            41,
            exit_code_for_successful_output(&json_args, &json_output)
        );

        let text_args = vec![
            "runner".to_string(),
            "ops".to_string(),
            "enterprise-signoff".to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
        ];
        let text_output = run(text_args.clone()).unwrap();
        assert!(text_output.starts_with("enterprise acceptance sign-off blocked:"));
        assert_eq!(
            41,
            exit_code_for_successful_output(&text_args, &text_output)
        );
        let _ = fs::remove_file(report_path);
    }

    fn complete_operational_readiness_report() -> loomex_core::OperationalReadinessReport {
        let slo_results = loomex_core::official_slos()
            .into_iter()
            .map(|slo| loomex_core::SloResult {
                slo_id: slo.id,
                passed: true,
                observed_percent: Some(100.0),
                observed_p95_ms: Some(1),
                error_budget_burn_percent: 0.0,
            })
            .collect::<Vec<_>>();
        let error_budget_burn = slo_results
            .iter()
            .map(|result| loomex_core::ErrorBudgetBurn {
                slo_id: result.slo_id.clone(),
                burn_percent_7d: 0.0,
            })
            .collect::<Vec<_>>();

        loomex_core::OperationalReadinessReport {
            schema_version: "loomex.runner.operationalReadinessReport/v1".to_string(),
            slo_results,
            error_budget_burn,
            open_critical_or_high_security_findings: 0,
            update_chain_tamper_test_passed: true,
            workspace_escape_tests_passed: true,
            secret_leakage_scan_passed: true,
            policy_bypass_tests_passed: true,
        }
    }

    fn complete_enterprise_acceptance_report() -> loomex_core::EnterpriseAcceptanceReport {
        loomex_core::EnterpriseAcceptanceReport {
            schema_version: "loomex.runner.enterpriseAcceptanceReport/v1".to_string(),
            scenario_results: loomex_core::official_acceptance_checks()
                .into_iter()
                .map(|check| loomex_core::EnterpriseScenarioResult {
                    id: check.id,
                    passed: true,
                    evidence: check.evidence_required,
                })
                .collect(),
            security_review_results: loomex_core::official_security_review_scope()
                .into_iter()
                .map(|scope| loomex_core::SecurityReviewResult {
                    id: scope.id,
                    passed: true,
                    evidence: scope.required_tests,
                })
                .collect(),
            security_findings: vec![],
            compliance_reviews: loomex_core::official_compliance_package()
                .into_iter()
                .map(|item| loomex_core::ComplianceReviewResult {
                    id: item.id,
                    reviewed: true,
                    evidence: item.required_evidence,
                })
                .collect(),
            load_chaos_result: loomex_core::LoadChaosAcceptanceResult {
                passed: true,
                max_concurrent_runners: 10_000,
                reconnect_recovery_p95_ms: 20_000,
                transport_fallback_verified: true,
            },
            supported_runner_versions: vec![loomex_core::SupportedRunnerVersionResult {
                version: "1.0.0".to_string(),
                passed: true,
            }],
        }
    }

    fn token(access_token: &str) -> AuthTokenResponse {
        AuthTokenResponse {
            access_token: access_token.to_string(),
            refresh_token: Some("refresh_secret".to_string()),
            token_type: "Bearer".to_string(),
            expires_at: "2026-06-29T00:00:00Z".to_string(),
        }
    }

    fn credential(profile: &str, organization_id: &str) -> ManagementCredential {
        ManagementCredential::from_token_response(
            profile,
            organization_id,
            token("management_secret"),
            CredentialStorageBackend::LocalFileFallback,
        )
        .unwrap()
    }

    fn service_resolved_settings() -> loomex_core::ResolvedCliSettings {
        loomex_core::ResolvedCliSettings {
            profile: "default".to_string(),
            server_url: "https://loomex.app".to_string(),
            host_header: None,
            organization_id: Some("org_123".to_string()),
            project_id: Some("prj_123".to_string()),
            runner_id: Some("runner_123".to_string()),
            binding_id: Some("binding_123".to_string()),
            workspace_path: Some("/tmp/workspace".to_string()),
        }
    }

    #[derive(Clone, Default)]
    struct FakeManagementClient {
        device_challenge: Option<DeviceLoginChallenge>,
        device_token: Option<AuthTokenResponse>,
        poll_requires_presented: Option<Rc<Cell<bool>>>,
        api_key_token: Option<AuthTokenResponse>,
        api_key_exchange_organization_id: Option<String>,
        api_key_error: Option<loomex_core::CoreError>,
        organizations: Vec<Organization>,
        projects: Vec<Project>,
        project: Option<Project>,
        runner: Option<Runner>,
        current_runner_error: Option<loomex_core::CoreError>,
        runner_self_status: Option<Value>,
        runner_self_error: Option<loomex_core::CoreError>,
        binding: Option<ManagementProjectRunnerBinding>,
        bindings: Vec<ManagementProjectRunnerBinding>,
        stream_credential: Option<StreamCredentialResponse>,
        stream_credential_error: Option<loomex_core::CoreError>,
        stream_credential_issue_count: usize,
        workflow_run: Option<WorkflowRunStartResponse>,
        workflow_input_schema: Option<Value>,
        human_requests: Vec<HumanRequestSummary>,
        last_binding_request: Option<ProjectRunnerBindingCreateRequest>,
        last_bootstrap_access_token: Option<String>,
        last_binding_access_token: Option<String>,
        bootstrap_call_count: usize,
        upsert_call_count: usize,
        binding_create_count: usize,
        binding_create_keys: Vec<String>,
        binding_create_replays: std::collections::HashMap<String, ManagementProjectRunnerBinding>,
        binding_create_error_after_insert: Option<loomex_core::CoreError>,
        last_workflow_request: Option<WorkflowRunStartRequest>,
        last_human_request_id: Option<String>,
        last_human_resolution: Option<Value>,
        runner_session_response: Option<loomex_core::RunnerSessionResponse>,
        runner_jobs: Vec<Value>,
        runner_job_lease_errors: Vec<Option<loomex_core::CoreError>>,
        completed_runner_jobs: Vec<Value>,
        failed_runner_jobs: Vec<Value>,
    }

    struct FallingBackCredentialStore;

    impl CredentialStore for FallingBackCredentialStore {
        fn save(
            &self,
            _credential: &ManagementCredential,
        ) -> loomex_core::CoreResult<CredentialStorageOutcome> {
            Ok(CredentialStorageOutcome {
                backend: CredentialStorageBackend::LocalFileFallback,
                warning: Some(
                    "secure OS credential storage unavailable; token stored in restricted local fallback"
                        .to_string(),
                ),
            })
        }

        fn load(&self, _profile: &str) -> loomex_core::CoreResult<Option<ManagementCredential>> {
            Ok(None)
        }

        fn delete(&self, _profile: &str) -> loomex_core::CoreResult<()> {
            Ok(())
        }
    }

    impl ManagementApiClient for FakeManagementClient {
        fn start_device_login(&mut self) -> loomex_core::CoreResult<DeviceLoginChallenge> {
            self.device_challenge.clone().ok_or_else(|| {
                loomex_core::CoreError::new("DEVICE_LOGIN_UNAVAILABLE", "no challenge")
            })
        }

        fn poll_device_token(
            &mut self,
            _device_code: &str,
        ) -> loomex_core::CoreResult<Option<AuthTokenResponse>> {
            if let Some(required) = &self.poll_requires_presented {
                assert!(
                    required.get(),
                    "device challenge must be presented before poll"
                );
            }
            Ok(self.device_token.take())
        }

        fn exchange_api_key(
            &mut self,
            _api_key: &str,
            _api_secret: &str,
            _organization_id: &str,
        ) -> loomex_core::CoreResult<loomex_core::ApiKeyExchangeResult> {
            if let Some(err) = self.api_key_error.clone() {
                return Err(err);
            }
            self.api_key_token
                .clone()
                .map(|token| {
                    let mut exchange = loomex_core::ApiKeyExchangeResult::from_token(token);
                    exchange.organization_id = self.api_key_exchange_organization_id.clone();
                    exchange
                })
                .ok_or_else(|| loomex_core::CoreError::new("MANAGEMENT_AUTH_FAILED", "invalid"))
        }

        fn login_workspace(
            &mut self,
            _email: &str,
            _password: &str,
        ) -> loomex_core::CoreResult<loomex_core::WorkspaceLoginResult> {
            Err(loomex_core::CoreError::new("TEST_UNIMPLEMENTED", "unused"))
        }

        fn bootstrap_runner_with_workspace_token(
            &mut self,
            workspace_token: &str,
            organization_id: &str,
            project_id: Option<&str>,
            _workspace_root: Option<&str>,
        ) -> loomex_core::CoreResult<loomex_core::ApiKeyExchangeResult> {
            self.bootstrap_call_count += 1;
            self.last_bootstrap_access_token = Some(workspace_token.to_string());
            Ok(loomex_core::ApiKeyExchangeResult {
                token: AuthTokenResponse {
                    access_token: "lmxrt_runner_secret".to_string(),
                    refresh_token: None,
                    token_type: "Bearer".to_string(),
                    expires_at: "9999-12-31T23:59:59Z".to_string(),
                },
                organization_id: Some(organization_id.to_string()),
                project_id: project_id.map(str::to_string),
                runner_id: Some("runner_123".to_string()),
                binding_id: None,
            })
        }

        fn list_organizations(
            &mut self,
            _credential: &ManagementCredential,
        ) -> loomex_core::CoreResult<Vec<Organization>> {
            Ok(self.organizations.clone())
        }

        fn list_projects(
            &mut self,
            _credential: &ManagementCredential,
            _organization_id: &str,
        ) -> loomex_core::CoreResult<Vec<Project>> {
            Ok(self.projects.clone())
        }

        fn get_project(
            &mut self,
            _credential: &ManagementCredential,
            project_id: &str,
        ) -> loomex_core::CoreResult<Project> {
            self.project
                .clone()
                .filter(|project| project.id == project_id)
                .ok_or_else(|| loomex_core::CoreError::new("PROJECT_NOT_FOUND", project_id))
        }

        fn get_current_runner(
            &mut self,
            _credential: &ManagementCredential,
            organization_id: &str,
        ) -> loomex_core::CoreResult<Runner> {
            if let Some(err) = self.current_runner_error.clone() {
                return Err(err);
            }
            Ok(self.runner.clone().unwrap_or_else(|| Runner {
                id: "runner_123".to_string(),
                organization_id: organization_id.to_string(),
                status: "connected".to_string(),
                runner_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: default_runner_capabilities(),
            }))
        }

        fn get_runner_self_status(
            &mut self,
            _credential: &ManagementCredential,
        ) -> loomex_core::CoreResult<Value> {
            if let Some(error) = self.runner_self_error.clone() {
                return Err(error);
            }
            Ok(self.runner_self_status.clone().unwrap_or_else(|| {
                let runner = self.runner.clone().unwrap_or_else(|| Runner {
                    id: "runner_123".to_string(),
                    organization_id: "org_123".to_string(),
                    status: "online".to_string(),
                    runner_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    capabilities: default_runner_capabilities(),
                });
                json!({
                    "runner": {
                        "id": runner.id,
                        "organizationId": runner.organization_id,
                        "status": runner.status,
                    },
                    "tokenScopes": ["runner.read", "runner.jobs"],
                })
            }))
        }

        fn upsert_current_runner(
            &mut self,
            _credential: &ManagementCredential,
            request: &RunnerUpsertRequest,
            _idempotency_key: &str,
        ) -> loomex_core::CoreResult<Runner> {
            self.upsert_call_count += 1;
            Ok(self.runner.clone().unwrap_or_else(|| Runner {
                id: "runner_123".to_string(),
                organization_id: request.organization_id.clone(),
                status: "connected".to_string(),
                runner_version: request.runner_version.clone(),
                protocol_version: request.protocol_version.clone(),
                capabilities: request.capabilities.clone(),
            }))
        }

        fn create_project_runner_binding(
            &mut self,
            credential: &ManagementCredential,
            project_id: &str,
            request: &ProjectRunnerBindingCreateRequest,
            idempotency_key: &str,
        ) -> loomex_core::CoreResult<ManagementProjectRunnerBinding> {
            self.binding_create_count += 1;
            self.binding_create_keys.push(idempotency_key.to_string());
            self.last_binding_access_token = Some(credential.access_token.clone());
            self.last_binding_request = Some(request.clone());
            if let Some(binding) = self.binding_create_replays.get(idempotency_key) {
                return Ok(binding.clone());
            }
            let binding = self
                .binding
                .clone()
                .unwrap_or_else(|| ManagementProjectRunnerBinding {
                    id: if self.binding_create_count == 1 {
                        "binding_123".to_string()
                    } else {
                        format!("binding_{}", self.binding_create_count)
                    },
                    organization_id: request.organization_id.clone(),
                    project_id: project_id.to_string(),
                    runner_id: request.runner_id.clone(),
                    local_root_path: request.local_root_path.clone(),
                    status: "active".to_string(),
                    local_root_fingerprint: request.local_root_fingerprint.clone(),
                });
            self.binding_create_replays
                .insert(idempotency_key.to_string(), binding.clone());
            if !self.bindings.iter().any(|item| item.id == binding.id) {
                self.bindings.push(binding.clone());
            }
            if let Some(error) = self.binding_create_error_after_insert.take() {
                return Err(error);
            }
            Ok(binding)
        }

        fn list_project_runner_bindings(
            &mut self,
            _credential: &ManagementCredential,
            project_id: &str,
        ) -> loomex_core::CoreResult<Vec<ManagementProjectRunnerBinding>> {
            Ok(self
                .bindings
                .iter()
                .filter(|binding| binding.project_id == project_id)
                .cloned()
                .collect())
        }

        fn revoke_project_runner_binding(
            &mut self,
            _credential: &ManagementCredential,
            _project_id: &str,
            _binding_id: &str,
            _idempotency_key: &str,
        ) -> loomex_core::CoreResult<()> {
            Ok(())
        }

        fn start_workflow_run(
            &mut self,
            _credential: &ManagementCredential,
            request: &WorkflowRunStartRequest,
        ) -> loomex_core::CoreResult<WorkflowRunStartResponse> {
            self.last_workflow_request = Some(request.clone());
            Ok(self
                .workflow_run
                .clone()
                .unwrap_or_else(|| WorkflowRunStartResponse {
                    id: "run_123".to_string(),
                    status: "queued".to_string(),
                    ui_url: Some("https://loomex.app/workspace/runs/run_123".to_string()),
                }))
        }

        fn list_runner_workflows(
            &mut self,
            _credential: &ManagementCredential,
        ) -> loomex_core::CoreResult<Vec<loomex_core::RunnerWorkflowSummary>> {
            Ok(Vec::new())
        }

        fn start_runner_workflow_execution(
            &mut self,
            _credential: &ManagementCredential,
            _workflow_id: &str,
            _inputs: Value,
            _session_id: Option<&str>,
            _version: Option<&str>,
        ) -> loomex_core::CoreResult<loomex_core::RunnerWorkflowExecutionResponse> {
            Err(loomex_core::CoreError::new("TEST_UNIMPLEMENTED", "unused"))
        }

        fn list_runner_workflow_executions(
            &mut self,
            _credential: &ManagementCredential,
            _workflow_id: &str,
            _limit: usize,
        ) -> loomex_core::CoreResult<loomex_core::RunnerWorkflowExecutionListResponse> {
            Ok(loomex_core::RunnerWorkflowExecutionListResponse {
                executions: Vec::new(),
                next_cursor: None,
            })
        }

        fn get_runner_workflow_input_schema(
            &mut self,
            _credential: &ManagementCredential,
            _workflow_id: &str,
            _version: Option<&str>,
        ) -> loomex_core::CoreResult<loomex_core::RunnerWorkflowInputSchemaResponse> {
            Ok(loomex_core::RunnerWorkflowInputSchemaResponse {
                workflow: None,
                input_schema: None,
                active_version: None,
                selected_version: None,
                versions: Vec::new(),
                first_human_input: None,
                nodes: Vec::new(),
                capabilities: serde_json::Map::new(),
                extra: serde_json::Map::new(),
            })
        }

        fn get_runner_workflow_execution(
            &mut self,
            _credential: &ManagementCredential,
            _execution_id: &str,
        ) -> loomex_core::CoreResult<loomex_core::RunnerWorkflowExecutionResponse> {
            Err(loomex_core::CoreError::new("TEST_UNIMPLEMENTED", "unused"))
        }

        fn get_workflow_input_schema(
            &mut self,
            _credential: &ManagementCredential,
            _workflow_id: &str,
        ) -> loomex_core::CoreResult<Option<Value>> {
            Ok(self.workflow_input_schema.clone())
        }

        fn list_human_requests(
            &mut self,
            _credential: &ManagementCredential,
            _workflow_id: &str,
            execution_id: Option<&str>,
        ) -> loomex_core::CoreResult<Vec<HumanRequestSummary>> {
            Ok(self
                .human_requests
                .iter()
                .filter(|request| {
                    execution_id.is_none_or(|execution_id| {
                        request
                            .execution
                            .as_ref()
                            .is_some_and(|execution| execution.id == execution_id)
                    })
                })
                .cloned()
                .collect())
        }

        fn resolve_human_request(
            &mut self,
            _credential: &ManagementCredential,
            request_id: &str,
            payload: &Value,
        ) -> loomex_core::CoreResult<HumanRequestResolveResponse> {
            self.last_human_request_id = Some(request_id.to_string());
            self.last_human_resolution = Some(payload.clone());
            Ok(HumanRequestResolveResponse {
                request_id: request_id.to_string(),
                request_status: "resolved".to_string(),
                execution_id: Some("run_123".to_string()),
                execution_status: Some("queued".to_string()),
            })
        }

        fn create_runner_session(
            &mut self,
            _credential: &ManagementCredential,
            workspace_root: &str,
            manifest: Value,
            transport: &str,
        ) -> loomex_core::CoreResult<loomex_core::RunnerSessionResponse> {
            Ok(self.runner_session_response.clone().unwrap_or_else(|| {
                loomex_core::RunnerSessionResponse {
                    runner: json!({"id": "runner_123", "status": "online"}),
                    session: json!({
                        "id": "session_123",
                        "transport": transport,
                        "manifest": manifest,
                        "workspaceRoot": workspace_root
                    }),
                }
            }))
        }

        fn heartbeat_runner_session(
            &mut self,
            _credential: &ManagementCredential,
            session_id: &str,
            manifest: Value,
        ) -> loomex_core::CoreResult<loomex_core::RunnerSessionResponse> {
            Ok(loomex_core::RunnerSessionResponse {
                runner: json!({"id": "runner_123", "status": "online"}),
                session: json!({"id": session_id, "manifest": manifest}),
            })
        }

        fn lease_runner_job(
            &mut self,
            _credential: &ManagementCredential,
            _session_id: &str,
        ) -> loomex_core::CoreResult<loomex_core::RunnerJobResponse> {
            if !self.runner_job_lease_errors.is_empty() {
                if let Some(error) = self.runner_job_lease_errors.remove(0) {
                    return Err(error);
                }
            }
            Ok(loomex_core::RunnerJobResponse {
                job: if self.runner_jobs.is_empty() {
                    None
                } else {
                    Some(self.runner_jobs.remove(0))
                },
            })
        }

        fn start_runner_job(
            &mut self,
            _credential: &ManagementCredential,
            _session_id: &str,
            job_id: &str,
        ) -> loomex_core::CoreResult<loomex_core::RunnerJobResponse> {
            Ok(loomex_core::RunnerJobResponse {
                job: Some(json!({"id": job_id, "status": "running"})),
            })
        }

        fn append_runner_job_events(
            &mut self,
            _credential: &ManagementCredential,
            _session_id: &str,
            _job_id: &str,
            events: Vec<Value>,
        ) -> loomex_core::CoreResult<loomex_core::RunnerJobEventCreateResponse> {
            Ok(loomex_core::RunnerJobEventCreateResponse { events })
        }

        fn complete_runner_job(
            &mut self,
            _credential: &ManagementCredential,
            _session_id: &str,
            job_id: &str,
            result: Value,
        ) -> loomex_core::CoreResult<loomex_core::RunnerJobResponse> {
            let job = json!({"id": job_id, "status": "succeeded", "result": result});
            self.completed_runner_jobs.push(job.clone());
            Ok(loomex_core::RunnerJobResponse { job: Some(job) })
        }

        fn fail_runner_job(
            &mut self,
            _credential: &ManagementCredential,
            _session_id: &str,
            job_id: &str,
            error: Value,
        ) -> loomex_core::CoreResult<loomex_core::RunnerJobResponse> {
            let job = json!({"id": job_id, "status": "failed", "error": error});
            self.failed_runner_jobs.push(job.clone());
            Ok(loomex_core::RunnerJobResponse { job: Some(job) })
        }

        fn issue_stream_credential(
            &mut self,
            _credential: &ManagementCredential,
            _request: &StreamCredentialRequest,
            _idempotency_key: &str,
        ) -> loomex_core::CoreResult<StreamCredentialResponse> {
            self.stream_credential_issue_count += 1;
            if let Some(err) = self.stream_credential_error.clone() {
                return Err(err);
            }
            Ok(self
                .stream_credential
                .clone()
                .unwrap_or_else(|| StreamCredentialResponse {
                    stream_token: "stream_secret".to_string(),
                    token_type: "Bearer".to_string(),
                    audience: "runner_stream".to_string(),
                    runner_session_id: "session_123".to_string(),
                    expires_at: "2026-06-29T00:05:00Z".to_string(),
                    grpc_endpoint: "https://loomex.app/runner-stream".to_string(),
                }))
        }
    }

    #[test]
    fn runner_control_file_list_and_read_many_jobs_inspect_workspace() {
        let workspace = temp_workspace_path("runner-file-jobs");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(workspace.join("old/src")).unwrap();
        fs::write(workspace.join("old/README.md"), "hello\n").unwrap();
        fs::write(workspace.join("old/src/AuthService.php"), "<?php\n").unwrap();
        let mut resolved = service_resolved_settings();
        resolved.workspace_path = Some(workspace.display().to_string());

        let list = execute_runner_control_job(
            &resolved,
            &json!({
                "kind": "file.list",
                "payload": {"path": ".", "limit": 20}
            }),
        )
        .unwrap();
        let listed = list["files"].as_array().unwrap();
        assert!(listed.iter().any(|item| item["path"] == "old/README.md"));
        assert!(listed
            .iter()
            .any(|item| item["path"] == "old/src/AuthService.php"));

        let read = execute_runner_control_job(
            &resolved,
            &json!({
                "kind": "file.read_many",
                "payload": {"files": ["old/README.md"], "maxBytesPerFile": 4}
            }),
        )
        .unwrap();
        assert_eq!(read["files"][0]["path"], "old/README.md");
        assert_eq!(read["files"][0]["content"], "hell");
        assert_eq!(read["files"][0]["truncated"], true);
        let _ = fs::remove_dir_all(workspace);
    }

    #[cfg(unix)]
    #[test]
    fn runner_control_shell_job_honors_timeout_and_cancel() {
        let workspace = temp_workspace_path("runner-shell-job");
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).unwrap();
        let mut resolved = service_resolved_settings();
        resolved.workspace_path = Some(workspace.display().to_string());

        let timed_out = execute_runner_control_job_for_session(
            &resolved,
            "session-shell-timeout",
            &json!({
                "kind": "shell.exec",
                "payload": {
                    "command": ["sh", "-c", "sleep 2"],
                    "timeout_seconds": 1,
                    "max_output_bytes": 1024
                }
            }),
        )
        .unwrap();
        assert_eq!(timed_out["timedOut"], true);

        let cancelled = execute_runner_control_job_for_session(
            &resolved,
            "session-shell-cancel",
            &json!({
                "kind": "shell.exec",
                "cancelRequested": true,
                "payload": {
                    "command": ["sh", "-c", "sleep 2"],
                    "timeout_seconds": 10,
                    "max_output_bytes": 1024
                }
            }),
        )
        .unwrap();
        assert_eq!(cancelled["cancelled"], true);
        let _ = fs::remove_dir_all(workspace);
    }

    #[cfg(unix)]
    #[test]
    fn runner_control_active_dispatch_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let workspace = temp_workspace_path("runner-symlink-workspace");
        let outside = temp_workspace_path("runner-symlink-outside");
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "outside").unwrap();
        symlink(&outside, workspace.join("escape")).unwrap();
        let mut resolved = service_resolved_settings();
        resolved.workspace_path = Some(workspace.display().to_string());

        let error = execute_runner_control_job_for_session(
            &resolved,
            "session-symlink",
            &json!({
                "kind": "fs.read",
                "payload": {"path": "escape/secret.txt", "max_bytes": 100}
            }),
        )
        .unwrap_err();
        assert!(
            error.contains("WORKSPACE_SYMLINK_ESCAPE")
                || error.contains("POLICY_DENIED_OUTSIDE_WORKSPACE"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_dir_all(workspace);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn plugin_setup_snapshot_captures_both_runtime_pointers() {
        let root = temp_credential_dir("setup-pointer-snapshot");
        let _ = fs::remove_dir_all(&root);
        let installer = RuntimeInstaller::new(&root);
        install_bundled_test_runtime(&installer, "0.9.0", b"runtime-0.9");
        install_bundled_test_runtime(&installer, "1.0.0", b"runtime-1.0");

        let (active, previous) = plugin_capture_runtime_pointer_state(&installer).unwrap();

        assert_eq!(Some("1.0.0".to_string()), active);
        assert_eq!(Some("0.9.0".to_string()), previous);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_mutations_fail_closed_while_setup_recovery_is_pending() {
        let root = temp_credential_dir("setup-pending-lifecycle");
        let _ = fs::remove_dir_all(&root);
        prepare_private_test_directory(&root);
        let store = SetupTransactionStore::new(&root);
        let snapshot = SetupTransactionSnapshot {
            runtime_root: root.join("runtime-a"),
            active_runtime_version: Some("1.0.0".to_string()),
            previous_runtime_version: Some("0.9.0".to_string()),
            config: FileSnapshot::capture(root.join("config.toml")).unwrap(),
            service_file: FileSnapshot::capture(root.join("loomex.service")).unwrap(),
            service_installed: false,
            service_enabled: false,
            service_active: false,
        };
        let mut journal = store
            .begin(SetupTransactionOperation::Apply, snapshot)
            .unwrap();

        let error = plugin_reject_unfinished_setup_transaction_at(&store).unwrap_err();
        assert!(error.starts_with("PLUGIN_SETUP_RECOVERY_REQUIRED:"));
        assert!(store.load().unwrap().is_some());
        for method in [
            "auth.start",
            "auth.wait",
            "auth.logout",
            "org.select",
            "project.select",
            "binding.create",
            "binding.revoke",
            "runner.control",
        ] {
            assert!(plugin_control_is_lifecycle_mutation(method), "{method}");
        }
        store
            .update_phase(&mut journal, SetupTransactionPhase::Compensated)
            .unwrap();
        plugin_reject_unfinished_setup_transaction_at(&store).unwrap();
        assert!(store.load().unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn direct_cli_lifecycle_mutations_share_the_setup_transaction_fence() {
        let mutations = [
            vec!["login"],
            vec!["logout"],
            vec!["config", "set", "selectedProfile", "stage"],
            vec!["profile", "use", "stage"],
            vec!["profile", "switch", "stage"],
            vec!["org", "select", "org_1"],
            vec!["project", "select", "project_1"],
            vec!["bind"],
            vec!["bind", "."],
            vec!["bind", "revoke", "binding_1"],
            vec!["runner", "start"],
            vec!["runner", "stop"],
            vec!["runner", "service", "install"],
            vec!["runner", "service", "uninstall"],
        ];
        for args in mutations {
            let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(direct_cli_is_lifecycle_mutation(&args), "{args:?}");
        }

        let read_only_or_runtime = [
            vec!["config", "list"],
            vec!["profile", "current"],
            vec!["org", "list"],
            vec!["project", "list"],
            vec!["bind", "list"],
            vec!["runner", "status"],
            vec!["runner", "service", "status"],
            vec!["runner", "service", "unit"],
            vec!["runner", "service", "run"],
            vec!["runner", "plugin-control", "setup.apply"],
        ];
        for args in read_only_or_runtime {
            let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(!direct_cli_is_lifecycle_mutation(&args), "{args:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn two_runtime_homes_share_one_lifecycle_lock_and_journal_identity() {
        let home = temp_credential_dir("stable-lifecycle-home");
        let runtime_a = home.join("runtime-a");
        let runtime_b = home.join("runtime-b");
        let lifecycle_root_a = plugin_lifecycle_root_for_home(&home);
        let lifecycle_root_b = plugin_lifecycle_root_for_home(&home);
        assert_eq!(lifecycle_root_a, lifecycle_root_b);
        assert_ne!(runtime_a, runtime_b);

        let first =
            PluginSetupTransactionLock::acquire_at_with_attempts(&lifecycle_root_a, 1).unwrap();
        let error =
            PluginSetupTransactionLock::acquire_at_with_attempts(&lifecycle_root_b, 1).unwrap_err();
        assert!(error.contains("PLUGIN_SETUP_BUSY"));

        let store_a = SetupTransactionStore::new(&lifecycle_root_a);
        let snapshot = SetupTransactionSnapshot {
            runtime_root: runtime_a.clone(),
            active_runtime_version: None,
            previous_runtime_version: None,
            config: FileSnapshot::capture(home.join(".loomex/config.toml")).unwrap(),
            service_file: FileSnapshot::capture(home.join("service/loomex.service")).unwrap(),
            service_installed: false,
            service_enabled: false,
            service_active: false,
        };
        store_a
            .begin(SetupTransactionOperation::Apply, snapshot)
            .unwrap();
        let store_b = SetupTransactionStore::new(&lifecycle_root_b);
        let loaded = store_b.load().unwrap().unwrap();
        assert_eq!(runtime_a, loaded.snapshot.runtime_root);
        assert_ne!(runtime_b, loaded.snapshot.runtime_root);

        store_b.clear().unwrap();
        drop(first);
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn systemd_compensation_orders_quiesce_restore_reload_enable_and_start() {
        let options = RunnerServiceOptions {
            platform: RunnerServicePlatform::LinuxUserSystemd,
            service_name: "loomex-runner".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/loomex"),
            config_path: PathBuf::from("/tmp/loomex.toml"),
            profile: None,
            log_path: None,
            output_path: None,
            uninstall_output_path: None,
            dry_run: false,
            once: false,
            defer_start: false,
        };

        let quiesce = service_compensation_quiesce_commands(&options, true, true).unwrap();
        let reload = systemctl_command(options.platform, &["daemon-reload"]);
        let enable = service_compensation_enablement_commands(&options, true, true).unwrap();
        let start = service_compensation_activity_commands(&options, true, true).unwrap();

        assert_eq!(
            vec!["--user", "stop", "loomex-runner.service"],
            quiesce[0].args
        );
        assert_eq!(
            vec!["--user", "disable", "loomex-runner.service"],
            quiesce[1].args
        );
        // FileSnapshot::restore occurs between quiesce and this reload.
        assert_eq!(vec!["--user", "daemon-reload"], reload.args);
        assert_eq!(
            vec!["--user", "enable", "loomex-runner.service"],
            enable[0].args
        );
        assert_eq!(
            vec!["--user", "start", "loomex-runner.service"],
            start[0].args
        );
        assert!(
            service_compensation_enablement_commands(&options, false, false)
                .unwrap()
                .is_empty()
        );
        assert!(
            service_compensation_activity_commands(&options, true, false)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn compensation_stop_and_disable_failures_preserve_the_pending_journal() {
        struct FailingRunner {
            fail_at: usize,
            calls: usize,
        }

        impl ServiceCommandRunner for FailingRunner {
            fn run(&mut self, command: &ServiceCommand) -> Result<ServiceCommandOutput, String> {
                let call = self.calls;
                self.calls += 1;
                if call == self.fail_at {
                    return Err(format!("injected failure: {}", command.args.join(" ")));
                }
                Ok(ServiceCommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }

        let root = temp_credential_dir("compensation-command-failure");
        prepare_private_test_directory(&root);
        let store = SetupTransactionStore::new(&root);
        let snapshot = SetupTransactionSnapshot {
            runtime_root: root.join("runtime"),
            active_runtime_version: None,
            previous_runtime_version: None,
            config: FileSnapshot::capture(root.join("config.toml")).unwrap(),
            service_file: FileSnapshot::capture(root.join("loomex.service")).unwrap(),
            service_installed: false,
            service_enabled: false,
            service_active: false,
        };
        store
            .begin(SetupTransactionOperation::Apply, snapshot)
            .unwrap();
        let options = RunnerServiceOptions {
            platform: RunnerServicePlatform::LinuxUserSystemd,
            service_name: "loomex-runner".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/loomex"),
            config_path: PathBuf::from("/tmp/loomex.toml"),
            profile: None,
            log_path: None,
            output_path: None,
            uninstall_output_path: None,
            dry_run: false,
            once: false,
            defer_start: false,
        };
        let commands = service_compensation_quiesce_commands(&options, true, true).unwrap();

        for fail_at in [0, 1] {
            let error = plugin_quiesce_service_for_compensation_with_runner(
                &commands,
                &mut FailingRunner { fail_at, calls: 0 },
            )
            .unwrap_err();
            assert!(error.contains("injected failure"));
            assert!(store.load().unwrap().is_some());
        }

        store.clear().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_service_probe_classifies_expected_negatives_and_manager_errors() {
        assert_eq!(
            Ok(false),
            classify_strict_probe_output(
                false,
                Some(113),
                "",
                "could not find service",
                StrictProbeKind::LaunchctlLoaded,
            )
        );
        assert!(classify_strict_probe_output(
            false,
            Some(1),
            "",
            "operation not permitted",
            StrictProbeKind::LaunchctlLoaded,
        )
        .unwrap_err()
        .contains("operation not permitted"));
        assert_eq!(
            Ok(false),
            classify_strict_probe_output(
                false,
                Some(3),
                "inactive",
                "",
                StrictProbeKind::SystemdActive,
            )
        );
        assert_eq!(
            Ok(false),
            classify_strict_probe_output(
                true,
                Some(0),
                "static",
                "",
                StrictProbeKind::SystemdEnabled,
            )
        );
        assert_eq!(
            Ok(true),
            classify_strict_probe_output(
                true,
                Some(0),
                "enabled",
                "",
                StrictProbeKind::SystemdEnabled,
            )
        );
        assert!(classify_strict_probe_output(
            false,
            Some(1),
            "",
            "failed to connect to bus",
            StrictProbeKind::SystemdEnabled,
        )
        .unwrap_err()
        .contains("failed to connect to bus"));
    }

    #[test]
    fn strict_systemd_initial_and_launchctl_final_probe_failures_preserve_journal() {
        struct SequenceProbe {
            results: std::collections::VecDeque<Result<StrictServiceState, String>>,
        }

        impl TransactionServiceStatusProbe for SequenceProbe {
            fn probe(
                &mut self,
                _options: &RunnerServiceOptions,
            ) -> Result<StrictServiceState, String> {
                self.results.pop_front().expect("probe sequence exhausted")
            }
        }

        fn pending_journal(root: &Path) -> (SetupTransactionStore, SetupTransactionJournal) {
            prepare_private_test_directory(root);
            let store = SetupTransactionStore::new(root);
            let snapshot = SetupTransactionSnapshot {
                runtime_root: root.join("runtime"),
                active_runtime_version: None,
                previous_runtime_version: None,
                config: FileSnapshot::capture(root.join("config.toml")).unwrap(),
                service_file: FileSnapshot::capture(root.join("loomex.service")).unwrap(),
                service_installed: false,
                service_enabled: false,
                service_active: false,
            };
            let journal = store
                .begin(SetupTransactionOperation::Apply, snapshot)
                .unwrap();
            (store, journal)
        }

        let initial_root = temp_credential_dir("strict-systemd-initial-probe");
        let (initial_store, initial_journal) = pending_journal(&initial_root);
        let mut initial_probe = SequenceProbe {
            results: [Err(
                "PLUGIN_SETUP_SERVICE_PROBE_FAILED: systemd manager unavailable".to_string(),
            )]
            .into(),
        };
        let error = plugin_compensate_setup_transaction_with(
            &initial_journal,
            &GlobalOptions::default(),
            &mut initial_probe,
            &mut TestServiceCommandRunner::default(),
        )
        .unwrap_err();
        assert!(error.contains("systemd manager unavailable"));
        assert!(initial_store.load().unwrap().is_some());

        let final_root = temp_credential_dir("strict-launchctl-final-probe");
        let (final_store, final_journal) = pending_journal(&final_root);
        let mut final_probe = SequenceProbe {
            results: [
                Ok(StrictServiceState {
                    installed: false,
                    enabled: false,
                    active: false,
                }),
                Err("PLUGIN_SETUP_SERVICE_PROBE_FAILED: launchctl probe denied".to_string()),
            ]
            .into(),
        };
        let error = plugin_compensate_setup_transaction_with(
            &final_journal,
            &GlobalOptions::default(),
            &mut final_probe,
            &mut TestServiceCommandRunner::default(),
        )
        .unwrap_err();
        assert!(error.contains("launchctl probe denied"));
        assert!(final_store.load().unwrap().is_some());

        initial_store.clear().unwrap();
        final_store.clear().unwrap();
        fs::remove_dir_all(initial_root).unwrap();
        fs::remove_dir_all(final_root).unwrap();
    }

    #[test]
    fn strict_pre_snapshot_systemd_and_launchctl_failures_create_no_journal_or_mutation() {
        struct FailingSnapshotProbe {
            expected_platform: RunnerServicePlatform,
            calls: usize,
        }

        impl TransactionServiceStatusProbe for FailingSnapshotProbe {
            fn probe(
                &mut self,
                options: &RunnerServiceOptions,
            ) -> Result<StrictServiceState, String> {
                assert_eq!(self.expected_platform, options.platform);
                self.calls += 1;
                Err(format!(
                    "PLUGIN_SETUP_SERVICE_PROBE_FAILED: injected {} pre-snapshot failure",
                    options.platform.as_str()
                ))
            }
        }

        for platform in [
            RunnerServicePlatform::LinuxUserSystemd,
            RunnerServicePlatform::MacOsLaunchAgent,
        ] {
            let root = temp_credential_dir(&format!("pre-snapshot-{}", platform.as_str()));
            let lifecycle_root = root.join("lifecycle");
            prepare_private_test_directory(&lifecycle_root);
            let runtime_root = root.join("runtime");
            let installer = RuntimeInstaller::new(&runtime_root);
            let store = SetupTransactionStore::new(&lifecycle_root);
            let observer = SetupTransactionStore::new(&lifecycle_root);
            let service_options = RunnerServiceOptions {
                platform,
                service_name: "loomex-runner".to_string(),
                binary_path: PathBuf::from("/usr/local/bin/loomex"),
                config_path: root.join("config.toml"),
                profile: None,
                log_path: None,
                output_path: None,
                uninstall_output_path: None,
                dry_run: false,
                once: false,
                defer_start: false,
            };
            let mut probe = FailingSnapshotProbe {
                expected_platform: platform,
                calls: 0,
            };

            let error = plugin_begin_setup_transaction_with_probe(
                SetupTransactionOperation::Apply,
                &installer,
                &service_options,
                store,
                &mut probe,
            )
            .unwrap_err();

            assert!(error.contains("pre-snapshot failure"));
            assert_eq!(1, probe.calls);
            assert!(observer.load().unwrap().is_none());
            assert!(!runtime_root.exists());
            assert!(!root.join("config.toml").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn install_bundled_test_runtime(installer: &RuntimeInstaller, version: &str, bytes: &[u8]) {
        let digest = sha256_hex(bytes);
        installer
            .install_bundled(BundledRuntimeInstall {
                version,
                artifact_name: "loomex-plugin-runtime",
                artifact_sha256: &digest,
                artifact_os: env::consts::OS,
                artifact_arch: env::consts::ARCH,
                artifact_bytes: bytes,
                executable_name: plugin_runtime_executable_name(),
            })
            .unwrap();
    }

    #[test]
    fn plugin_setup_plan_id_binds_every_reviewed_field() {
        let base = json!({
            "channel": "stable",
            "installService": true,
            "serviceAction": "restart_healthcheck",
            "previousVersion": "1.2.2",
            "runtimePath": "/runtime/current/bin/loomex",
        });
        let mut changed = base.clone();
        changed["serviceAction"] = json!("stop_and_defer");
        assert_ne!(
            plugin_setup_plan_id(&base).unwrap(),
            plugin_setup_plan_id(&changed).unwrap()
        );
    }

    #[test]
    fn plugin_setup_install_service_false_preserves_any_existing_service() {
        assert_eq!(
            plugin_setup_service_disposition(false, false),
            PluginSetupServiceDisposition::Preserve
        );
        assert_eq!(
            plugin_setup_service_disposition(false, true),
            PluginSetupServiceDisposition::Preserve
        );
        assert_eq!(
            plugin_setup_service_disposition(true, true),
            PluginSetupServiceDisposition::ActivateExisting
        );
        assert_eq!(
            plugin_setup_service_disposition(true, false),
            PluginSetupServiceDisposition::Install
        );
    }

    #[test]
    fn plugin_runtime_self_test_rejects_unverified_bytes_before_execution() {
        let error =
            plugin_self_test_runtime_bytes(b"not an executable", &"0".repeat(64)).unwrap_err();
        assert!(error.contains("PLUGIN_RUNTIME_CHECKSUM_MISMATCH"));
    }

    #[test]
    fn unsigned_validation_package_requires_explicit_validation_gate() {
        let error =
            validate_plugin_distribution("validation", "unsigned-validation", false).unwrap_err();
        assert!(error.contains("PLUGIN_PACKAGE_UNSIGNED_VALIDATION_ONLY"));
        validate_plugin_distribution("validation", "unsigned-validation", true).unwrap();
        validate_plugin_distribution("release", "unsigned-release", false).unwrap();
        assert!(validate_plugin_distribution("release", "unsigned-validation", true).is_err());
        assert!(validate_plugin_distribution("validation", "unsigned-release", true).is_err());
    }

    fn temp_config_path(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "loomex-cli-{label}-{}-{}.toml",
            process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    fn temp_credential_dir(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "loomex-cli-credentials-{label}-{}-{}",
            process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    fn temp_workspace_path(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "loomex-cli-workspace-{label}-{}-{}",
            process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    fn prepare_private_test_directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
