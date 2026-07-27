use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use loomex_protocol::{
    AgentErrorCode, AgentExecutorCapability, AgentModelCapability, AgentOutput, AgentOutputFormat,
    AgentProcessDispatchV2, AgentProvider, AgentRuntimeErrorEnvelopeV2, AgentTaskRequestV2,
    AuthenticationState, ExecutorKind, InstallationState, ModelAvailability, ModelFallbackPolicy,
    ModelSelectionMode, ModelTarget, RuntimeReadiness,
};
use serde_json::Value;

use super::{
    classify_process_failure, output::parse_agent_event, parse_agent_output, runtime_error,
    validate_json_schema, validate_schema_contract, AdapterFeatures, AgentAdapter, AgyAdapter,
    CancellationToken, ClaudeAdapter, CodexAdapter, ExecutionInvocation, InvocationMode,
    ProbeCache, ProcessLimits, ProcessObserver, ProcessRunner, RuntimeErrorContext,
};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub executables: BTreeMap<ExecutorKind, PathBuf>,
    pub execution_limits: ProcessLimits,
    pub probe_limits: ProcessLimits,
    pub probe_ttl: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            executables: BTreeMap::new(),
            execution_limits: ProcessLimits::default(),
            probe_limits: ProcessLimits {
                // Production probes remain tightly bounded. Unit tests get a
                // larger scheduling window so unrelated parallel journal
                // stress tests cannot turn fast fake CLIs into false timeouts.
                timeout: Duration::from_secs(if cfg!(test) { 60 } else { 10 }),
                max_stdout_bytes: 512 * 1024,
                max_stderr_bytes: 64 * 1024,
                ..ProcessLimits::default()
            },
            probe_ttl: Duration::from_secs(60),
        }
    }
}

pub struct AdapterRegistry {
    adapters: BTreeMap<ExecutorKind, Arc<dyn AgentAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        let mut registry = Self {
            adapters: BTreeMap::new(),
        };
        registry.register(CodexAdapter);
        registry.register(ClaudeAdapter);
        registry.register(AgyAdapter);
        registry
    }
}

impl AdapterRegistry {
    pub fn register(&mut self, adapter: impl AgentAdapter + 'static) {
        self.adapters.insert(adapter.executor(), Arc::new(adapter));
    }

    pub fn get(&self, executor: ExecutorKind) -> Option<Arc<dyn AgentAdapter>> {
        self.adapters.get(&executor).cloned()
    }

    /// Resolves only canonical v2 names. In particular, `gemini` and
    /// `gemini_cli` are deliberately rejected instead of being aliases to agy.
    pub fn resolve_alias(&self, value: &str) -> Option<ExecutorKind> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open_ai" | "codex_cli" | "codex" => Some(ExecutorKind::CodexCli),
            "anthropic" | "claude_cli" | "claude" => Some(ExecutorKind::ClaudeCli),
            "google" | "agy_cli" | "agy" => Some(ExecutorKind::AgyCli),
            _ => None,
        }
    }

    pub fn adapters(&self) -> impl Iterator<Item = Arc<dyn AgentAdapter>> + '_ {
        self.adapters.values().cloned()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeExecutionResult {
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    pub model: Option<ModelTarget>,
    pub output: AgentOutput,
    pub provider_session_id: Option<String>,
    /// Zero is the primary selection; one and above identify the ordered
    /// fallback position actually executed.
    pub selection_index: u32,
    pub repair_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDiscovery {
    pub request_id: String,
    pub provider_session_id: String,
    pub selection_index: u32,
    pub executor: ExecutorKind,
    pub provider: AgentProvider,
    pub model_key: Option<String>,
    pub provider_model_id: Option<String>,
}

pub trait AgentRuntimeObserver: Send + Sync {
    /// Called synchronously as soon as a provider session identifier is parsed
    /// from stdout. Implementations should durably checkpoint this typed event
    /// before returning. Raw process output is never exposed to this boundary.
    fn on_session_initialized(
        &self,
        session: SessionDiscovery,
    ) -> Result<(), AgentRuntimeErrorEnvelopeV2>;
}

#[derive(Debug, Default)]
struct NoopAgentRuntimeObserver;

impl AgentRuntimeObserver for NoopAgentRuntimeObserver {
    fn on_session_initialized(
        &self,
        _session: SessionDiscovery,
    ) -> Result<(), AgentRuntimeErrorEnvelopeV2> {
        Ok(())
    }
}

pub struct LocalAgentRuntime {
    registry: AdapterRegistry,
    process_runner: ProcessRunner,
    probe_cache: Mutex<ProbeCache>,
}

impl Default for LocalAgentRuntime {
    fn default() -> Self {
        Self::new(AdapterRegistry::default(), ProcessRunner::default())
    }
}

impl LocalAgentRuntime {
    pub fn new(registry: AdapterRegistry, process_runner: ProcessRunner) -> Self {
        Self {
            registry,
            process_runner,
            probe_cache: Mutex::new(ProbeCache::default()),
        }
    }

    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    pub fn invalidate_probe(&self, executor: ExecutorKind) {
        if let Ok(mut cache) = self.probe_cache.lock() {
            cache.invalidate(executor);
        }
    }

    pub fn probe_all(
        &self,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
    ) -> Vec<AgentExecutorCapability> {
        self.registry
            .adapters()
            .map(|adapter| {
                self.probe_adapter(adapter.as_ref(), config, workspace, cancellation, false)
            })
            .collect()
    }

    /// Bypasses the TTL cache for an explicit user/status refresh. Periodic
    /// heartbeat callers should continue using [`Self::probe_all`].
    pub fn probe_all_force(
        &self,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
    ) -> Vec<AgentExecutorCapability> {
        self.registry
            .adapters()
            .map(|adapter| {
                self.probe_adapter(adapter.as_ref(), config, workspace, cancellation, true)
            })
            .collect()
    }

    pub fn probe_executor(
        &self,
        executor: ExecutorKind,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
        force: bool,
    ) -> AgentExecutorCapability {
        match self.registry.get(executor) {
            Some(adapter) => {
                self.probe_adapter(adapter.as_ref(), config, workspace, cancellation, force)
            }
            None => unavailable_capability(
                executor,
                runtime_error(
                    AgentErrorCode::RuntimeUnavailable,
                    "No allowlisted adapter is registered for the selected executor.",
                    RuntimeErrorContext {
                        executor: Some(executor),
                        ..Default::default()
                    },
                ),
            ),
        }
    }

    pub fn execute(
        &self,
        dispatch: &AgentProcessDispatchV2,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
    ) -> Result<RuntimeExecutionResult, AgentRuntimeErrorEnvelopeV2> {
        self.execute_observed(
            dispatch,
            config,
            workspace,
            cancellation,
            Arc::new(NoopAgentRuntimeObserver),
        )
    }

    pub fn execute_observed(
        &self,
        dispatch: &AgentProcessDispatchV2,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
        observer: Arc<dyn AgentRuntimeObserver>,
    ) -> Result<RuntimeExecutionResult, AgentRuntimeErrorEnvelopeV2> {
        dispatch.validate().map_err(|_| {
            runtime_error(
                AgentErrorCode::InvalidRequest,
                "The agent process dispatch v2 contract is invalid.",
                RuntimeErrorContext::default(),
            )
        })?;
        self.execute_task_observed(&dispatch.task, config, workspace, cancellation, observer)
    }

    fn execute_task_observed(
        &self,
        request: &AgentTaskRequestV2,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
        observer: Arc<dyn AgentRuntimeObserver>,
    ) -> Result<RuntimeExecutionResult, AgentRuntimeErrorEnvelopeV2> {
        request.validate().map_err(|_| {
            runtime_error(
                AgentErrorCode::InvalidRequest,
                "The plugin agent task v2 contract is invalid.",
                RuntimeErrorContext::default(),
            )
        })?;
        if request
            .output_schema
            .as_ref()
            .is_some_and(|schema| validate_schema_contract(schema).is_err())
        {
            return Err(runtime_error(
                AgentErrorCode::UnsupportedCapability,
                "The requested output schema uses unsupported or unsafe assertions.",
                RuntimeErrorContext::default(),
            ));
        }
        if !workspace.is_absolute() {
            return Err(runtime_error(
                AgentErrorCode::InvalidRequest,
                "The bound workspace path is not absolute.",
                RuntimeErrorContext::default(),
            ));
        }

        let candidates = execution_candidates(request);
        let mut last_fallback_error = None;
        for (candidate_position, candidate) in candidates.into_iter().enumerate() {
            match self.execute_candidate(CandidateExecution {
                request,
                selection_index: candidate.selection_index,
                candidate,
                config,
                workspace,
                cancellation,
                observer: observer.clone(),
            }) {
                Ok(result) => return Ok(result),
                Err(failure)
                    if request.continuation.is_none()
                        && !failure.process_spawned
                        && can_try_ordered_fallback(failure.error.code)
                        && candidate_position + 1 < candidate_count(request) =>
                {
                    last_fallback_error = Some(failure.error);
                }
                Err(failure) => return Err(failure.error),
            }
        }
        Err(last_fallback_error.unwrap_or_else(|| {
            runtime_error(
                AgentErrorCode::RuntimeUnavailable,
                "No valid local agent selection could be executed.",
                RuntimeErrorContext::default(),
            )
        }))
    }

    fn execute_candidate(
        &self,
        execution: CandidateExecution<'_>,
    ) -> Result<RuntimeExecutionResult, CandidateFailure> {
        let CandidateExecution {
            request,
            candidate,
            selection_index,
            config,
            workspace,
            cancellation,
            observer,
        } = execution;
        let adapter = self.registry.get(candidate.executor).ok_or_else(|| {
            runtime_error(
                AgentErrorCode::RuntimeUnavailable,
                "The selected executor does not have an allowlisted adapter.",
                candidate.context(),
            )
        })?;

        // Every requested execution is an explicit retry boundary. Force a
        // fresh readiness/auth probe so a just-installed or just-authenticated
        // executor is not blocked by the heartbeat TTL cache.
        let capability =
            self.probe_adapter(adapter.as_ref(), config, workspace, cancellation, true);
        ensure_ready(&capability, &candidate)?;
        let detected_features =
            adapter.features_for_version(capability.executor_version.as_deref());
        verify_requirements(adapter.as_ref(), detected_features, request, &candidate)?;

        let resolved_target = candidate.target.clone().or_else(|| {
            request
                .continuation
                .is_none()
                .then(|| default_model_target(&capability))
                .flatten()
        });
        if let Some(target) = &resolved_target {
            ensure_model_available(&capability, target, &candidate)?;
        }
        let resolved_error_context = candidate.resolved_context(resolved_target.as_ref());

        let executable = config
            .executables
            .get(&candidate.executor)
            .ok_or_else(|| not_installed(&candidate))?;
        let mode = request
            .continuation
            .as_ref()
            .map(|continuation| InvocationMode::ResumeExact {
                provider_session_id: continuation.provider_session_id.clone(),
            })
            .unwrap_or(InvocationMode::Start);
        let provider_model_id = resolved_target
            .as_ref()
            .map(|target| target.provider_model_id.clone())
            .filter(|model| !model.is_empty());

        let execution_prompt = invocation_prompt(request);
        let invocation = ExecutionInvocation {
            executable,
            workspace,
            prompt: &execution_prompt,
            provider_model_id: provider_model_id.as_deref(),
            reasoning_effort: request.requirements.reasoning_effort,
            output_schema: request.output_schema.as_ref(),
            mode,
        };
        let command = adapter.build_execution(&invocation).map_err(|_| {
            runtime_error(
                AgentErrorCode::UnsupportedCapability,
                "The selected local agent cannot execute the requested session mode.",
                resolved_error_context.clone(),
            )
        })?;
        let spawned_result = (|| {
            let session_observer = Arc::new(SessionLineObserver::new(
                observer,
                cancellation.clone(),
                request.request_id.clone(),
                candidate.clone(),
                resolved_target.clone(),
            ));
            let process_observer = detected_features
                .session_resume
                .then(|| session_observer.clone() as Arc<dyn ProcessObserver>);
            let output = self
                .process_runner
                .run_observed(
                    &command,
                    &config.execution_limits,
                    cancellation,
                    process_observer,
                )
                .map_err(|_| {
                    runtime_error(
                        AgentErrorCode::RuntimeUnavailable,
                        "The selected local agent process could not be started.",
                        resolved_error_context.clone(),
                    )
                })?;
            if let Some(error) = session_observer.take_error() {
                return Err(error);
            }
            if !output.status.success() || output.timed_out || output.cancelled {
                let mut error = classify_process_failure(&output, resolved_error_context.clone());
                // Generic failures after a process was started may follow local
                // file mutations. They must not silently spawn a fallback.
                if matches!(
                    error.code,
                    AgentErrorCode::ExecutionFailed
                        | AgentErrorCode::RateLimited
                        | AgentErrorCode::NetworkError
                ) {
                    error = indeterminate_after_spawn(
                        detected_features,
                        resolved_error_context.clone(),
                    );
                } else if error.code == AgentErrorCode::Timeout {
                    error = indeterminate_timeout_after_spawn(
                        detected_features,
                        resolved_error_context.clone(),
                    );
                }
                return Err(error);
            }
            if output.stdout_truncated {
                return Err(runtime_error(
                    AgentErrorCode::OutputInvalid,
                    "The local agent output exceeded the bounded capture limit.",
                    resolved_error_context.clone(),
                ));
            }
            if let Some(error) = structured_execution_error(&output, resolved_error_context.clone())
            {
                return Err(post_spawn_provider_error(
                    error,
                    detected_features,
                    resolved_error_context.clone(),
                ));
            }

            let mut parsed = parse_agent_output(&output.stdout).map_err(|_| {
                runtime_error(
                    AgentErrorCode::OutputInvalid,
                    "The local agent returned malformed or empty output.",
                    resolved_error_context.clone(),
                )
            })?;
            if adapter.requires_machine_readable_output() && !parsed.machine_readable {
                return Err(runtime_error(
                    AgentErrorCode::OutputInvalid,
                    "The local agent did not return its required machine-readable output.",
                    resolved_error_context.clone(),
                ));
            }
            if parsed
                .structured
                .as_ref()
                .is_some_and(|value| !value.is_object())
            {
                return Err(runtime_error(
                    AgentErrorCode::OutputInvalid,
                    "Structured agent output must be a JSON object.",
                    resolved_error_context.clone(),
                ));
            }
            let mut repair_used = false;

            if let Some(schema) = request.output_schema.as_ref() {
                let structured = parsed
                    .structured
                    .clone()
                    .or_else(|| serde_json::from_str::<Value>(&parsed.text).ok());
                let violations = structured
                    .as_ref()
                    .map(|value| validate_json_schema(value, schema))
                    .unwrap_or_else(|| {
                        Err(vec![super::SchemaViolation {
                            path: "$".to_string(),
                            message: "output is not JSON".to_string(),
                        }])
                    });
                if let Err(violations) = violations {
                    if !detected_features.session_resume {
                        return Err(runtime_error(
                        AgentErrorCode::OutputInvalid,
                        "Structured output was invalid and this local agent cannot repair it in the same session.",
                        resolved_error_context.clone(),
                    ));
                    }
                    let session_id = parsed.provider_session_id.clone().ok_or_else(|| {
                    runtime_error(
                        AgentErrorCode::OutputInvalid,
                        "Structured output was invalid and no exact session was available for repair.",
                        resolved_error_context.clone(),
                    )
                })?;
                    let repair_prompt = repair_prompt(schema, &violations);
                    let repair_invocation = ExecutionInvocation {
                        executable,
                        workspace,
                        prompt: &repair_prompt,
                        provider_model_id: provider_model_id.as_deref(),
                        reasoning_effort: request.requirements.reasoning_effort,
                        output_schema: request.output_schema.as_ref(),
                        mode: InvocationMode::ResumeExact {
                            provider_session_id: session_id.clone(),
                        },
                    };
                    let repair_command = adapter.build_execution(&repair_invocation).map_err(|_| {
                    runtime_error(
                        AgentErrorCode::UnsupportedCapability,
                        "The local agent cannot resume the exact session required for output repair.",
                        resolved_error_context.clone(),
                    )
                })?;
                    let repair_output = self
                        .process_runner
                        .run(&repair_command, &config.execution_limits, cancellation)
                        .map_err(|_| {
                            indeterminate_after_spawn(
                                detected_features,
                                resolved_error_context.clone(),
                            )
                        })?;
                    if !repair_output.status.success()
                        || repair_output.timed_out
                        || repair_output.cancelled
                    {
                        let error = classify_process_failure(
                            &repair_output,
                            resolved_error_context.clone(),
                        );
                        if error.code == AgentErrorCode::Cancelled {
                            return Err(error);
                        }
                        return Err(if error.code == AgentErrorCode::Timeout {
                            indeterminate_timeout_after_spawn(
                                detected_features,
                                resolved_error_context.clone(),
                            )
                        } else {
                            indeterminate_after_spawn(
                                detected_features,
                                resolved_error_context.clone(),
                            )
                        });
                    }
                    if repair_output.stdout_truncated {
                        return Err(runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The output repair turn exceeded the bounded capture limit.",
                            resolved_error_context.clone(),
                        ));
                    }
                    if structured_execution_error(&repair_output, resolved_error_context.clone())
                        .is_some()
                    {
                        return Err(indeterminate_after_spawn(
                            detected_features,
                            resolved_error_context.clone(),
                        ));
                    }
                    parsed = parse_agent_output(&repair_output.stdout).map_err(|_| {
                        runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The one allowed output repair turn returned malformed output.",
                            resolved_error_context.clone(),
                        )
                    })?;
                    if adapter.requires_machine_readable_output() && !parsed.machine_readable {
                        return Err(runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The output repair turn was not machine-readable.",
                            resolved_error_context.clone(),
                        ));
                    }
                    if parsed
                        .structured
                        .as_ref()
                        .is_some_and(|value| !value.is_object())
                    {
                        return Err(runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The output repair turn returned non-object JSON.",
                            resolved_error_context.clone(),
                        ));
                    }
                    if parsed.provider_session_id.is_none() {
                        parsed.provider_session_id = Some(session_id);
                    }
                    let repaired = parsed
                        .structured
                        .clone()
                        .or_else(|| serde_json::from_str::<Value>(&parsed.text).ok())
                        .ok_or_else(|| {
                            runtime_error(
                                AgentErrorCode::OutputInvalid,
                                "The one allowed output repair turn did not return JSON.",
                                resolved_error_context.clone(),
                            )
                        })?;
                    validate_json_schema(&repaired, schema).map_err(|_| {
                        runtime_error(
                            AgentErrorCode::OutputInvalid,
                            "The one allowed output repair turn still violated the output schema.",
                            resolved_error_context.clone(),
                        )
                    })?;
                    parsed.structured = Some(repaired);
                    repair_used = true;
                } else {
                    parsed.structured = structured;
                }
            } else if request.requirements.structured_output && parsed.structured.is_none() {
                parsed.structured = serde_json::from_str::<Value>(&parsed.text).ok();
                if parsed.structured.is_none() {
                    return Err(runtime_error(
                        AgentErrorCode::OutputInvalid,
                        "The task required structured output but the local agent returned text.",
                        resolved_error_context.clone(),
                    ));
                }
            }

            let agent_output = if let Some(structured) = parsed.structured {
                AgentOutput {
                    format: AgentOutputFormat::Json,
                    content: parsed.text,
                    structured: Some(structured),
                }
            } else {
                AgentOutput {
                    format: AgentOutputFormat::Text,
                    content: parsed.text,
                    structured: None,
                }
            };

            Ok(RuntimeExecutionResult {
                executor: candidate.executor,
                provider: candidate.executor.provider(),
                model: resolved_target,
                output: agent_output,
                provider_session_id: detected_features
                    .session_resume
                    .then_some(parsed.provider_session_id)
                    .flatten(),
                selection_index,
                repair_used,
            })
        })();
        spawned_result.map_err(CandidateFailure::after_spawn)
    }

    #[cfg(test)]
    pub(crate) fn execute_task_for_test(
        &self,
        request: &AgentTaskRequestV2,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
    ) -> Result<RuntimeExecutionResult, AgentRuntimeErrorEnvelopeV2> {
        self.execute_task_observed(
            request,
            config,
            workspace,
            cancellation,
            Arc::new(NoopAgentRuntimeObserver),
        )
    }

    #[cfg(test)]
    pub(crate) fn execute_task_observed_for_test(
        &self,
        request: &AgentTaskRequestV2,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
        observer: Arc<dyn AgentRuntimeObserver>,
    ) -> Result<RuntimeExecutionResult, AgentRuntimeErrorEnvelopeV2> {
        self.execute_task_observed(request, config, workspace, cancellation, observer)
    }

    fn probe_adapter(
        &self,
        adapter: &dyn AgentAdapter,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
        force: bool,
    ) -> AgentExecutorCapability {
        let Some(executable) = config.executables.get(&adapter.executor()) else {
            return not_installed_capability(adapter);
        };
        if !force {
            if let Ok(cache) = self.probe_cache.lock() {
                if let Some(capability) =
                    cache.get(adapter.executor(), executable, config.probe_ttl)
                {
                    return capability;
                }
            }
        }
        let capability = self.run_probe(adapter, executable, config, workspace, cancellation);
        if let Ok(mut cache) = self.probe_cache.lock() {
            cache.insert(adapter.executor(), executable.clone(), capability.clone());
        }
        capability
    }

    fn run_probe(
        &self,
        adapter: &dyn AgentAdapter,
        executable: &Path,
        config: &RuntimeConfig,
        workspace: &Path,
        cancellation: &CancellationToken,
    ) -> AgentExecutorCapability {
        if !executable.is_absolute() || !executable.is_file() {
            return not_installed_capability(adapter);
        }

        let commands = adapter.probe_commands(executable, workspace);
        let version =
            match self
                .process_runner
                .run(&commands.version, &config.probe_limits, cancellation)
            {
                Ok(output) if output.status.success() && !output.cancelled && !output.timed_out => {
                    sanitize_executor_version(&output.stdout)
                }
                Ok(output) => {
                    return unavailable_capability(
                        adapter.executor(),
                        classify_process_failure(
                            &output,
                            RuntimeErrorContext {
                                executor: Some(adapter.executor()),
                                ..Default::default()
                            },
                        ),
                    )
                }
                Err(_) => return not_installed_capability(adapter),
            };
        let detected_features = adapter.features_for_version(version.as_deref());
        if !detected_features.model_selection
            || (adapter.requires_machine_readable_output() && !detected_features.structured_output)
        {
            return unsupported_cli_capability(adapter, version, detected_features);
        }

        let mut authentication = AuthenticationState::Unknown;
        let mut readiness = RuntimeReadiness::Ready;
        let mut last_error = None;
        if let Some(auth_command) = commands.authentication {
            match self
                .process_runner
                .run(&auth_command, &config.probe_limits, cancellation)
            {
                Ok(output) => {
                    let combined = format!("{}\n{}", output.stdout, output.stderr);
                    match adapter.authentication_succeeded(&combined) {
                        Some(true) if output.status.success() => {
                            authentication = AuthenticationState::Authenticated
                        }
                        Some(false) => {
                            authentication = AuthenticationState::NotAuthenticated;
                            readiness = RuntimeReadiness::NotAuthenticated;
                            last_error = Some(runtime_error(
                                AgentErrorCode::ProviderNotAuthenticated,
                                "The local agent is not authenticated.",
                                RuntimeErrorContext {
                                    executor: Some(adapter.executor()),
                                    ..Default::default()
                                },
                            ));
                        }
                        _ if !output.status.success() => {
                            let error = classify_process_failure(
                                &output,
                                RuntimeErrorContext {
                                    executor: Some(adapter.executor()),
                                    ..Default::default()
                                },
                            );
                            match error.code {
                                AgentErrorCode::ProviderNotAuthenticated => {
                                    authentication = AuthenticationState::NotAuthenticated;
                                    readiness = RuntimeReadiness::NotAuthenticated;
                                }
                                AgentErrorCode::ProviderNotEligible => {
                                    readiness = RuntimeReadiness::Unavailable;
                                }
                                _ => readiness = RuntimeReadiness::Degraded,
                            }
                            last_error = Some(error);
                        }
                        _ => {
                            authentication = AuthenticationState::Unknown;
                            readiness = RuntimeReadiness::Unknown;
                        }
                    }
                }
                Err(_) => {
                    readiness = RuntimeReadiness::Degraded;
                    last_error = Some(runtime_error(
                        AgentErrorCode::RuntimeUnavailable,
                        "The local agent authentication probe could not be executed.",
                        RuntimeErrorContext {
                            executor: Some(adapter.executor()),
                            ..Default::default()
                        },
                    ));
                }
            }
        }

        let mut models = Vec::new();
        if let Some(models_command) = commands.models {
            match self
                .process_runner
                .run(&models_command, &config.probe_limits, cancellation)
            {
                Ok(output) if output.status.success() => {
                    if let Some(error) = successful_probe_error(
                        &output,
                        RuntimeErrorContext {
                            executor: Some(adapter.executor()),
                            ..Default::default()
                        },
                    ) {
                        apply_probe_error_state(&error, &mut authentication, &mut readiness);
                        last_error = Some(error);
                    } else {
                        if authentication == AuthenticationState::Unknown {
                            authentication = adapter
                                .authentication_succeeded(&output.stdout)
                                .map(|authenticated| {
                                    if authenticated {
                                        AuthenticationState::Authenticated
                                    } else {
                                        AuthenticationState::NotAuthenticated
                                    }
                                })
                                .unwrap_or(AuthenticationState::Unknown);
                        }
                        let discovered_models = adapter
                            .parse_models(&output.stdout)
                            .into_iter()
                            .map(|(model_key, provider_model_id)| AgentModelCapability {
                                provider: adapter.provider(),
                                model_key,
                                provider_model_id,
                                availability: ModelAvailability::Available,
                                is_default: false,
                                supported_reasoning_efforts: Vec::new(),
                                unavailable_reason: None,
                            })
                            .collect::<Vec<_>>();
                        if discovered_models.is_empty() {
                            readiness = RuntimeReadiness::Degraded;
                            last_error = Some(runtime_error(
                                AgentErrorCode::RuntimeUnavailable,
                                "The local agent model probe returned no valid model capabilities.",
                                RuntimeErrorContext {
                                    executor: Some(adapter.executor()),
                                    ..Default::default()
                                },
                            ));
                        } else {
                            models = discovered_models;
                        }
                    }
                }
                Ok(output) => {
                    let error = classify_process_failure(
                        &output,
                        RuntimeErrorContext {
                            executor: Some(adapter.executor()),
                            ..Default::default()
                        },
                    );
                    apply_probe_error_state(&error, &mut authentication, &mut readiness);
                    last_error = Some(error);
                }
                Err(_) => {
                    readiness = RuntimeReadiness::Degraded;
                    last_error = Some(runtime_error(
                        AgentErrorCode::RuntimeUnavailable,
                        "The local agent model probe could not be executed.",
                        RuntimeErrorContext {
                            executor: Some(adapter.executor()),
                            ..Default::default()
                        },
                    ));
                }
            }
        }

        AgentExecutorCapability {
            executor: adapter.executor(),
            provider: adapter.provider(),
            readiness,
            installation: InstallationState::Installed,
            authentication,
            executor_version: version,
            model_discovery: detected_features.model_discovery,
            models,
            features: detected_features.into(),
            last_error,
        }
    }
}

fn successful_probe_error(
    output: &super::ProcessOutput,
    context: RuntimeErrorContext,
) -> Option<AgentRuntimeErrorEnvelopeV2> {
    let classified = classify_process_failure(output, context.clone());
    if matches!(
        classified.code,
        AgentErrorCode::ProviderNotAuthenticated
            | AgentErrorCode::ProviderNotEligible
            | AgentErrorCode::RateLimited
            | AgentErrorCode::NetworkError
    ) {
        return Some(classified);
    }
    structured_execution_error(output, context)
}

fn structured_execution_error(
    output: &super::ProcessOutput,
    context: RuntimeErrorContext,
) -> Option<AgentRuntimeErrorEnvelopeV2> {
    structured_error_stream(&output.stdout, context.clone())
        .or_else(|| structured_error_stream(&output.stderr, context))
}

fn structured_error_stream(
    stream: &str,
    context: RuntimeErrorContext,
) -> Option<AgentRuntimeErrorEnvelopeV2> {
    if let Ok(value) = serde_json::from_str::<Value>(stream) {
        return structured_error_value(&value, context);
    }
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find_map(|value| structured_error_value(&value, context.clone()))
}

fn structured_error_value(
    value: &Value,
    context: RuntimeErrorContext,
) -> Option<AgentRuntimeErrorEnvelopeV2> {
    let single_error_field = value.as_object().is_some_and(|object| {
        object.len() == 1
            && object
                .get("error")
                .and_then(Value::as_object)
                .is_some_and(|error| {
                    error.contains_key("code")
                        || error.contains_key("status")
                        || error.contains_key("type")
                })
    });
    let is_error_envelope = single_error_field
        || value
            .get("success")
            .and_then(Value::as_bool)
            .is_some_and(|success| !success)
        || value
            .get("ok")
            .and_then(Value::as_bool)
            .is_some_and(|ok| !ok)
        || value
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || value
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("error"));
    if !is_error_envelope {
        return None;
    }

    let error_code = value
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| value.get("code"));
    let trusted_text = value
        .get("error")
        .or_else(|| value.get("message"))
        .or_else(|| value.get("result"))
        .map(Value::to_string)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let code = match error_code {
        Some(Value::Number(code)) if code.as_u64() == Some(401) => {
            AgentErrorCode::ProviderNotAuthenticated
        }
        Some(Value::Number(code)) if code.as_u64() == Some(403) => {
            AgentErrorCode::ProviderNotEligible
        }
        Some(Value::Number(code)) if code.as_u64() == Some(429) => AgentErrorCode::RateLimited,
        Some(Value::String(code))
            if code.eq_ignore_ascii_case("unauthorized")
                || code.eq_ignore_ascii_case("authentication_error") =>
        {
            AgentErrorCode::ProviderNotAuthenticated
        }
        Some(Value::String(code))
            if code.eq_ignore_ascii_case("forbidden")
                || code.eq_ignore_ascii_case("permission_denied")
                || code.eq_ignore_ascii_case("not_eligible") =>
        {
            AgentErrorCode::ProviderNotEligible
        }
        Some(Value::String(code))
            if code.eq_ignore_ascii_case("rate_limited")
                || code.eq_ignore_ascii_case("rate_limit_error") =>
        {
            AgentErrorCode::RateLimited
        }
        Some(Value::String(code))
            if code.eq_ignore_ascii_case("model_not_found")
                || code.eq_ignore_ascii_case("unknown_model")
                || code.eq_ignore_ascii_case("invalid_model")
                || code.eq_ignore_ascii_case("unsupported_model") =>
        {
            AgentErrorCode::ModelNotAvailable
        }
        Some(Value::String(code))
            if code.eq_ignore_ascii_case("session_not_found")
                || code.eq_ignore_ascii_case("conversation_not_found")
                || code.eq_ignore_ascii_case("thread_not_found") =>
        {
            AgentErrorCode::SessionNotFound
        }
        _ if trusted_text.contains("not authenticated")
            || trusted_text.contains("unauthorized")
            || trusted_text.contains("login required") =>
        {
            AgentErrorCode::ProviderNotAuthenticated
        }
        _ if trusted_text.contains("403")
            || trusted_text.contains("forbidden")
            || trusted_text.contains("not eligible")
            || trusted_text.contains("permission_denied") =>
        {
            AgentErrorCode::ProviderNotEligible
        }
        _ if trusted_text.contains("429") || trusted_text.contains("rate limit") => {
            AgentErrorCode::RateLimited
        }
        _ if trusted_text.contains("model not found")
            || trusted_text.contains("unknown model")
            || trusted_text.contains("invalid model")
            || trusted_text.contains("unsupported model")
            || trusted_text.contains("model unavailable")
            || trusted_text.contains("model is not available") =>
        {
            AgentErrorCode::ModelNotAvailable
        }
        _ if trusted_text.contains("session not found")
            || trusted_text.contains("conversation not found")
            || trusted_text.contains("thread not found")
            || trusted_text.contains("unknown session") =>
        {
            AgentErrorCode::SessionNotFound
        }
        _ if trusted_text.contains("network error")
            || trusted_text.contains("connection refused")
            || trusted_text.contains("service unavailable") =>
        {
            AgentErrorCode::NetworkError
        }
        _ => AgentErrorCode::RuntimeUnavailable,
    };
    Some(runtime_error(
        code,
        match code {
            AgentErrorCode::ProviderNotAuthenticated => {
                "The local agent returned an authentication error envelope."
            }
            AgentErrorCode::ProviderNotEligible => {
                "The local agent account is not eligible for this provider operation."
            }
            AgentErrorCode::RateLimited => {
                "The local agent returned a provider rate-limit error envelope."
            }
            AgentErrorCode::ModelNotAvailable => {
                "The selected model is not available to this local agent."
            }
            AgentErrorCode::SessionNotFound => "The exact provider session is no longer available.",
            _ => "The local agent returned a provider error envelope.",
        },
        context,
    ))
}

fn apply_probe_error_state(
    error: &AgentRuntimeErrorEnvelopeV2,
    authentication: &mut AuthenticationState,
    readiness: &mut RuntimeReadiness,
) {
    match error.code {
        AgentErrorCode::ProviderNotAuthenticated => {
            *authentication = AuthenticationState::NotAuthenticated;
            *readiness = RuntimeReadiness::NotAuthenticated;
        }
        AgentErrorCode::ProviderNotEligible => *readiness = RuntimeReadiness::Unavailable,
        _ => *readiness = RuntimeReadiness::Degraded,
    }
}

fn indeterminate_after_spawn(
    features: AdapterFeatures,
    context: RuntimeErrorContext,
) -> AgentRuntimeErrorEnvelopeV2 {
    let mut error = runtime_error(
        AgentErrorCode::ExecutionIndeterminate,
        "The local agent stopped after starting; its side effects are unknown, so inspect the workspace before retrying.",
        context,
    );
    if !features.session_resume {
        error.retry = loomex_protocol::AgentRetryDisposition::Never;
        error.remediation = vec![loomex_protocol::AgentRemediationAction::ContactSupport];
    }
    error
}

fn indeterminate_timeout_after_spawn(
    features: AdapterFeatures,
    context: RuntimeErrorContext,
) -> AgentRuntimeErrorEnvelopeV2 {
    let mut error = indeterminate_after_spawn(features, context);
    error
        .context
        .safe_details
        .insert("processLoss".to_string(), "timeout".to_string());
    error
}

fn post_spawn_provider_error(
    error: AgentRuntimeErrorEnvelopeV2,
    features: AdapterFeatures,
    context: RuntimeErrorContext,
) -> AgentRuntimeErrorEnvelopeV2 {
    if matches!(
        error.code,
        AgentErrorCode::RateLimited
            | AgentErrorCode::NetworkError
            | AgentErrorCode::RuntimeUnavailable
    ) {
        indeterminate_after_spawn(features, context)
    } else {
        error
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) selection_index: u32,
    pub(crate) executor: ExecutorKind,
    pub(crate) target: Option<ModelTarget>,
}

struct CandidateExecution<'a> {
    request: &'a AgentTaskRequestV2,
    candidate: Candidate,
    selection_index: u32,
    config: &'a RuntimeConfig,
    workspace: &'a Path,
    cancellation: &'a CancellationToken,
    observer: Arc<dyn AgentRuntimeObserver>,
}

struct CandidateFailure {
    error: AgentRuntimeErrorEnvelopeV2,
    process_spawned: bool,
}

impl CandidateFailure {
    fn after_spawn(error: AgentRuntimeErrorEnvelopeV2) -> Self {
        Self {
            error,
            process_spawned: true,
        }
    }
}

impl From<AgentRuntimeErrorEnvelopeV2> for CandidateFailure {
    fn from(error: AgentRuntimeErrorEnvelopeV2) -> Self {
        Self {
            error,
            process_spawned: false,
        }
    }
}

struct SessionLineObserver {
    observer: Arc<dyn AgentRuntimeObserver>,
    cancellation: CancellationToken,
    request_id: String,
    candidate: Candidate,
    resolved_target: Option<ModelTarget>,
    seen_session: Mutex<Option<String>>,
    error: Mutex<Option<AgentRuntimeErrorEnvelopeV2>>,
}

impl SessionLineObserver {
    fn new(
        observer: Arc<dyn AgentRuntimeObserver>,
        cancellation: CancellationToken,
        request_id: String,
        candidate: Candidate,
        resolved_target: Option<ModelTarget>,
    ) -> Self {
        Self {
            observer,
            cancellation,
            request_id,
            candidate,
            resolved_target,
            seen_session: Mutex::new(None),
            error: Mutex::new(None),
        }
    }

    fn take_error(&self) -> Option<AgentRuntimeErrorEnvelopeV2> {
        self.error.lock().ok()?.take()
    }
}

impl ProcessObserver for SessionLineObserver {
    fn on_stdout_line(&self, line: &str) {
        let Some(provider_session_id) =
            parse_agent_event(line).and_then(|event| event.provider_session_id)
        else {
            return;
        };
        let Ok(mut seen) = self.seen_session.lock() else {
            self.cancellation.cancel();
            return;
        };
        if seen.as_ref() == Some(&provider_session_id) {
            return;
        }
        *seen = Some(provider_session_id.clone());
        drop(seen);

        let target = self
            .resolved_target
            .as_ref()
            .or(self.candidate.target.as_ref());
        let discovery = SessionDiscovery {
            request_id: self.request_id.clone(),
            provider_session_id,
            selection_index: self.candidate.selection_index,
            executor: self.candidate.executor,
            provider: self.candidate.executor.provider(),
            model_key: target.map(|target| target.model_key.clone()),
            provider_model_id: target.map(|target| target.provider_model_id.clone()),
        };
        if let Err(error) = self.observer.on_session_initialized(discovery) {
            if let Ok(mut slot) = self.error.lock() {
                *slot = Some(error);
            }
            self.cancellation.cancel();
        }
    }
}

impl Candidate {
    fn context(&self) -> RuntimeErrorContext {
        RuntimeErrorContext {
            executor: Some(self.executor),
            target: self.target.clone(),
            ..Default::default()
        }
    }

    fn resolved_context(&self, resolved_target: Option<&ModelTarget>) -> RuntimeErrorContext {
        RuntimeErrorContext {
            resolved_target: resolved_target.cloned(),
            ..self.context()
        }
    }
}

fn execution_candidates(request: &AgentTaskRequestV2) -> Vec<Candidate> {
    if let Some(continuation) = &request.continuation {
        return vec![Candidate {
            selection_index: continuation.selection_index,
            executor: continuation.executor,
            target: continuation
                .resolved_model()
                .map(|(model_key, provider_model_id)| ModelTarget {
                    executor: continuation.executor,
                    provider: continuation.provider,
                    model_key: model_key.to_string(),
                    provider_model_id: provider_model_id.to_string(),
                }),
        }];
    }
    let primary = match &request.selection.primary {
        ModelSelectionMode::Exact { target } => Candidate {
            selection_index: 0,
            executor: target.executor,
            target: Some(target.clone()),
        },
        ModelSelectionMode::Auto { executor, .. } => Candidate {
            selection_index: 0,
            executor: *executor,
            target: None,
        },
    };
    let mut candidates = vec![primary];
    if let ModelFallbackPolicy::Ordered { targets } = &request.selection.fallback {
        candidates.extend(
            targets
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, target)| Candidate {
                    selection_index: (index + 1) as u32,
                    executor: target.executor,
                    target: Some(target),
                }),
        );
    }
    candidates
}

fn invocation_prompt(request: &AgentTaskRequestV2) -> Cow<'_, str> {
    if request.continuation.is_none() {
        return Cow::Borrowed(&request.prompt);
    }
    if request.output_schema.is_some() {
        Cow::Borrowed(
            "Continue this exact provider session from its current state. Do not repeat any task \
             step or side effect already completed. If the interruption happened during \
             structured-output repair, finish only that pending repair and return corrected JSON \
             matching the required schema. Otherwise complete only unfinished work and return the \
             required structured result.",
        )
    } else {
        Cow::Borrowed(
            "Continue this exact provider session from its current state. Do not repeat any task \
             step or side effect already completed. Inspect the session history and complete only \
             unfinished work.",
        )
    }
}

fn candidate_count(request: &AgentTaskRequestV2) -> usize {
    if request.continuation.is_some() {
        1
    } else {
        1 + match &request.selection.fallback {
            ModelFallbackPolicy::None => 0,
            ModelFallbackPolicy::Ordered { targets } => targets.len(),
        }
    }
}

fn verify_requirements(
    adapter: &dyn AgentAdapter,
    features: AdapterFeatures,
    request: &AgentTaskRequestV2,
    candidate: &Candidate,
) -> Result<(), AgentRuntimeErrorEnvelopeV2> {
    let exact_model_requested = candidate.target.is_some()
        || request
            .continuation
            .as_ref()
            .is_some_and(|continuation| continuation.provider_model_id.is_some());
    let unsupported = (exact_model_requested && !features.model_selection)
        || (request.requirements.structured_output && !features.structured_output)
        || ((request.requirements.session_resume || request.continuation.is_some())
            && !features.session_resume)
        || (request.requirements.cancellation && !features.cancellation)
        || request.requirements.reasoning_effort.is_some_and(|effort| {
            !features.reasoning_effort || !adapter.supports_reasoning_effort(effort)
        });
    if unsupported {
        Err(runtime_error(
            AgentErrorCode::UnsupportedCapability,
            "The selected local agent does not satisfy the task requirements.",
            candidate.context(),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_ready(
    capability: &AgentExecutorCapability,
    candidate: &Candidate,
) -> Result<(), AgentRuntimeErrorEnvelopeV2> {
    match capability.readiness {
        RuntimeReadiness::NotInstalled => Err(not_installed(candidate)),
        RuntimeReadiness::NotAuthenticated => Err(runtime_error(
            AgentErrorCode::ProviderNotAuthenticated,
            "The selected local agent is not authenticated.",
            candidate.context(),
        )),
        RuntimeReadiness::Unavailable => Err(capability.last_error.clone().unwrap_or_else(|| {
            runtime_error(
                AgentErrorCode::RuntimeUnavailable,
                "The selected local agent is unavailable.",
                candidate.context(),
            )
        })),
        RuntimeReadiness::Degraded | RuntimeReadiness::Unknown => {
            Err(capability.last_error.clone().unwrap_or_else(|| {
                runtime_error(
                    AgentErrorCode::RuntimeUnavailable,
                    "The selected local agent readiness could not be verified.",
                    candidate.context(),
                )
            }))
        }
        RuntimeReadiness::Ready => match capability.authentication {
            AuthenticationState::Authenticated | AuthenticationState::NotRequired => Ok(()),
            AuthenticationState::NotAuthenticated => Err(runtime_error(
                AgentErrorCode::ProviderNotAuthenticated,
                "The selected local agent is not authenticated.",
                candidate.context(),
            )),
            AuthenticationState::Unknown => {
                Err(capability.last_error.clone().unwrap_or_else(|| {
                    runtime_error(
                        AgentErrorCode::RuntimeUnavailable,
                        "The selected local agent authentication state could not be verified.",
                        candidate.context(),
                    )
                }))
            }
        },
    }
}

fn ensure_model_available(
    capability: &AgentExecutorCapability,
    target: &ModelTarget,
    candidate: &Candidate,
) -> Result<(), AgentRuntimeErrorEnvelopeV2> {
    if capability.models.is_empty() {
        return Ok(());
    }
    match capability.models.iter().find(|model| {
        model.model_key == target.model_key && model.provider_model_id == target.provider_model_id
    }) {
        Some(model) if model.availability == ModelAvailability::Available => Ok(()),
        Some(_) => Err(runtime_error(
            AgentErrorCode::ModelNotAvailable,
            "The selected model is known but unavailable to this local agent account.",
            candidate.context(),
        )),
        None => Err(runtime_error(
            AgentErrorCode::ModelUnknown,
            "The selected model is not reported by this local agent.",
            candidate.context(),
        )),
    }
}

fn default_model_target(capability: &AgentExecutorCapability) -> Option<ModelTarget> {
    capability
        .models
        .iter()
        .find(|model| model.is_default && model.availability == ModelAvailability::Available)
        .map(|model| ModelTarget {
            executor: capability.executor,
            provider: capability.provider,
            model_key: model.model_key.clone(),
            provider_model_id: model.provider_model_id.clone(),
        })
}

fn executable_name(executor: ExecutorKind) -> &'static str {
    match executor {
        ExecutorKind::CodexCli => "codex",
        ExecutorKind::ClaudeCli => "claude",
        ExecutorKind::AgyCli => "agy",
    }
}

fn not_installed(candidate: &Candidate) -> AgentRuntimeErrorEnvelopeV2 {
    let command = executable_name(candidate.executor);
    runtime_error(
        AgentErrorCode::ProviderNotInstalled,
        &format!(
            "The selected local agent executable `{command}` is not configured. Install it, then run `loomex setup agents refresh --confirm` in a local interactive terminal."
        ),
        candidate.context(),
    )
}

fn not_installed_capability(adapter: &dyn AgentAdapter) -> AgentExecutorCapability {
    let command = adapter.executable_name();
    let features = AdapterFeatures {
        model_selection: false,
        structured_output: false,
        session_resume: false,
        cancellation: false,
        reasoning_effort: false,
        model_discovery: adapter.features().model_discovery,
    };
    AgentExecutorCapability {
        executor: adapter.executor(),
        provider: adapter.provider(),
        readiness: RuntimeReadiness::NotInstalled,
        installation: InstallationState::NotInstalled,
        authentication: AuthenticationState::Unknown,
        executor_version: None,
        model_discovery: features.model_discovery,
        models: Vec::new(),
        features: features.into(),
        last_error: Some(runtime_error(
            AgentErrorCode::ProviderNotInstalled,
            &format!(
                "The local agent executable `{command}` is not configured. Install it, then run `loomex setup agents refresh --confirm` in a local interactive terminal."
            ),
            RuntimeErrorContext {
                executor: Some(adapter.executor()),
                ..Default::default()
            },
        )),
    }
}

fn unsupported_cli_capability(
    adapter: &dyn AgentAdapter,
    version: Option<String>,
    features: AdapterFeatures,
) -> AgentExecutorCapability {
    let command = adapter.executable_name();
    let mut error = runtime_error(
        AgentErrorCode::UnsupportedCapability,
        &format!(
            "The installed local agent `{command}` does not have a verified non-interactive model and machine-readable execution interface. Update the local agent, then refresh executable discovery."
        ),
        RuntimeErrorContext {
            executor: Some(adapter.executor()),
            ..Default::default()
        },
    );
    error.retry = loomex_protocol::AgentRetryDisposition::UserActionRequired;
    error.remediation = vec![
        loomex_protocol::AgentRemediationAction::UpgradeExecutor,
        loomex_protocol::AgentRemediationAction::RefreshExecutorDiscovery,
    ];
    error.context.safe_details.insert(
        "reasonCode".to_string(),
        "executor_version_unverified".to_string(),
    );
    AgentExecutorCapability {
        executor: adapter.executor(),
        provider: adapter.provider(),
        readiness: RuntimeReadiness::Unavailable,
        installation: InstallationState::Installed,
        authentication: AuthenticationState::Unknown,
        executor_version: version,
        model_discovery: features.model_discovery,
        models: Vec::new(),
        features: features.into(),
        last_error: Some(error),
    }
}

fn unavailable_capability(
    executor: ExecutorKind,
    error: AgentRuntimeErrorEnvelopeV2,
) -> AgentExecutorCapability {
    let features = AdapterFeatures {
        model_selection: false,
        structured_output: false,
        session_resume: false,
        cancellation: false,
        reasoning_effort: false,
        model_discovery: loomex_protocol::ModelDiscoveryKind::Unknown,
    };
    AgentExecutorCapability {
        executor,
        provider: executor.provider(),
        readiness: RuntimeReadiness::Unavailable,
        installation: InstallationState::Unknown,
        authentication: AuthenticationState::Unknown,
        executor_version: None,
        model_discovery: features.model_discovery,
        models: Vec::new(),
        features: features.into(),
        last_error: Some(error),
    }
}

fn sanitize_executor_version(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .map(|token| {
            token.trim_matches(|character: char| {
                matches!(character, '(' | ')' | '[' | ']' | ',' | ';')
            })
        })
        .find_map(numeric_semver_core)
}

fn numeric_semver_core(token: &str) -> Option<String> {
    if token.len() > 128 {
        return None;
    }
    let token = token.strip_prefix('v').unwrap_or(token);
    if !token.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let core = &token[..token
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(token.len())];
    let mut components = core.split('.');
    let major = components.next()?;
    let minor = components.next()?;
    let patch = components.next()?;
    if components.next().is_some()
        || [major, minor, patch]
            .iter()
            .any(|component| component.is_empty() || component.len() > 10)
    {
        return None;
    }
    Some(format!("{major}.{minor}.{patch}"))
}

fn can_try_ordered_fallback(code: AgentErrorCode) -> bool {
    matches!(
        code,
        AgentErrorCode::ProviderNotInstalled
            | AgentErrorCode::ProviderNotAuthenticated
            | AgentErrorCode::ProviderNotEligible
            | AgentErrorCode::RuntimeUnavailable
            | AgentErrorCode::ModelUnknown
            | AgentErrorCode::ModelNotAvailable
            | AgentErrorCode::UnsupportedCapability
            | AgentErrorCode::RateLimited
            | AgentErrorCode::NetworkError
            | AgentErrorCode::Timeout
    )
}

fn repair_prompt(schema: &Value, violations: &[super::SchemaViolation]) -> String {
    let issue_list = violations
        .iter()
        .take(16)
        .map(|violation| format!("- {}: {}", violation.path, violation.message))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Your previous final response did not satisfy the required JSON Schema.\n\
         Return one corrected JSON value only, with no markdown or explanation.\n\
         This is the only repair attempt.\n\
         Validation issues:\n{issue_list}\n\
         JSON Schema:\n{}",
        serde_json::to_string(schema).unwrap_or_else(|_| "{}".to_string())
    )
}
