use std::collections::BTreeMap;

use crate::{CoreError, CoreResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BindingStatus {
    Active,
    Revoked,
    Stale,
    PathChanged,
    RunnerDisabled,
    ProjectArchived,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerSessionStatus {
    Connecting,
    Connected,
    Draining,
    Disconnected,
    Stale,
    Replaced,
    Revoked,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RunnerSessionReplacementPolicy {
    ReplaceExisting,
    RejectIfActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePath {
    pub local_workspace_root: String,
    pub normalized_workspace_root: String,
    pub local_root_fingerprint: Option<String>,
}

impl WorkspacePath {
    pub fn new(
        local_workspace_root: impl Into<String>,
        local_root_fingerprint: Option<String>,
    ) -> CoreResult<Self> {
        let local_workspace_root = local_workspace_root.into();
        let normalized_workspace_root = normalize_workspace_path(&local_workspace_root)?;
        Ok(Self {
            local_workspace_root,
            normalized_workspace_root,
            local_root_fingerprint,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBinding {
    pub organization_id: String,
    pub project_id: String,
    pub binding_id: String,
    pub runner_device_id: String,
    pub local_root_path: String,
}

impl ProjectBinding {
    pub fn normalized_root(&self) -> CoreResult<String> {
        normalize_workspace_path(&self.local_root_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRunnerBinding {
    pub id: String,
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub workspace: WorkspacePath,
    pub status: BindingStatus,
    pub created_by: String,
    pub last_seen_at_epoch_ms: Option<u64>,
    pub revoked_at_epoch_ms: Option<u64>,
}

impl ProjectRunnerBinding {
    pub fn revoke(&mut self, revoked_at_epoch_ms: u64) {
        self.status = BindingStatus::Revoked;
        self.revoked_at_epoch_ms = Some(revoked_at_epoch_ms);
    }

    pub fn assert_active(&self) -> CoreResult<()> {
        match self.status {
            BindingStatus::Active => Ok(()),
            BindingStatus::Revoked => Err(CoreError::new(
                "PROJECT_BINDING_REVOKED",
                "project runner binding has been revoked",
            )),
            BindingStatus::Stale => Err(CoreError::new(
                "PROJECT_BINDING_STALE",
                "project runner binding is stale",
            )),
            BindingStatus::PathChanged => Err(CoreError::new(
                "PROJECT_BINDING_PATH_CHANGED",
                "workspace path changed and must be reverified",
            )),
            BindingStatus::RunnerDisabled => Err(CoreError::new(
                "PROJECT_BINDING_RUNNER_DISABLED",
                "runner device is disabled",
            )),
            BindingStatus::ProjectArchived => Err(CoreError::new(
                "PROJECT_BINDING_PROJECT_ARCHIVED",
                "project is archived",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSession {
    pub id: String,
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub project_runner_binding_id: String,
    pub status: RunnerSessionStatus,
    pub last_seen_at_epoch_ms: Option<u64>,
    pub lease_expires_at_epoch_ms: u64,
    pub connected_at_epoch_ms: u64,
    pub disconnected_at_epoch_ms: Option<u64>,
    pub replaced_by_session_id: Option<String>,
    pub disconnect_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRunnerSessionInput {
    pub session_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub project_runner_binding_id: String,
    pub now_epoch_ms: u64,
    pub lease_duration_ms: u64,
    pub replacement_policy: RunnerSessionReplacementPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSessionAuditEvent {
    pub session_id: String,
    pub project_runner_binding_id: String,
    pub reason: String,
    pub occurred_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSessionActivation {
    pub session: RunnerSession,
    pub replaced_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerCapabilityGrant {
    pub project_runner_binding_id: String,
    pub capability: String,
    pub granted_by: String,
    pub created_at_epoch_ms: u64,
    pub revoked_at_epoch_ms: Option<u64>,
}

impl RunnerCapabilityGrant {
    pub fn is_active(&self) -> bool {
        self.revoked_at_epoch_ms.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBindingInput {
    pub organization_id: String,
    pub project_id: String,
    pub runner_device_id: String,
    pub local_workspace_root: String,
    pub local_root_fingerprint: Option<String>,
    pub created_by: String,
    pub now_epoch_ms: u64,
    pub allow_same_path_different_project: bool,
    pub project_archived: bool,
    pub runner_disabled: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BindingRegistry {
    bindings: BTreeMap<String, ProjectRunnerBinding>,
    next_id: u64,
}

impl BindingRegistry {
    pub fn create_or_reuse_binding(
        &mut self,
        input: CreateBindingInput,
    ) -> CoreResult<ProjectRunnerBinding> {
        validate_create_input(&input)?;
        if input.project_archived {
            return Err(CoreError::new(
                "PROJECT_BINDING_PROJECT_ARCHIVED",
                "archived project cannot create an active runner binding",
            ));
        }
        if input.runner_disabled {
            return Err(CoreError::new(
                "PROJECT_BINDING_RUNNER_DISABLED",
                "disabled runner cannot create an active runner binding",
            ));
        }
        let workspace = WorkspacePath::new(
            input.local_workspace_root.clone(),
            input.local_root_fingerprint.clone(),
        )?;

        for binding in self.bindings.values() {
            if binding.organization_id == input.organization_id
                && binding.project_id == input.project_id
                && binding.runner_device_id == input.runner_device_id
                && binding.workspace.normalized_workspace_root
                    == workspace.normalized_workspace_root
                && binding.status == BindingStatus::Active
            {
                return Ok(binding.clone());
            }
        }

        if !input.allow_same_path_different_project {
            for binding in self.bindings.values() {
                if binding.organization_id == input.organization_id
                    && binding.project_id != input.project_id
                    && binding.runner_device_id == input.runner_device_id
                    && binding.workspace.normalized_workspace_root
                        == workspace.normalized_workspace_root
                    && binding.status == BindingStatus::Active
                {
                    return Err(CoreError::new(
                        "PROJECT_BINDING_PATH_CONFLICT",
                        "workspace path is already bound to another project",
                    ));
                }
            }
        }

        self.next_id += 1;
        let binding = ProjectRunnerBinding {
            id: format!("bind_{:06}", self.next_id),
            organization_id: input.organization_id,
            project_id: input.project_id,
            runner_device_id: input.runner_device_id,
            workspace,
            status: BindingStatus::Active,
            created_by: input.created_by,
            last_seen_at_epoch_ms: Some(input.now_epoch_ms),
            revoked_at_epoch_ms: None,
        };
        self.bindings.insert(binding.id.clone(), binding.clone());
        Ok(binding)
    }

    pub fn revoke_binding(&mut self, binding_id: &str, revoked_at_epoch_ms: u64) -> CoreResult<()> {
        let binding = self.bindings.get_mut(binding_id).ok_or_else(|| {
            CoreError::new(
                "PROJECT_BINDING_NOT_FOUND",
                "project runner binding was not found",
            )
        })?;
        binding.revoke(revoked_at_epoch_ms);
        Ok(())
    }

    pub fn get(&self, binding_id: &str) -> Option<&ProjectRunnerBinding> {
        self.bindings.get(binding_id)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RunnerSessionRegistry {
    sessions: BTreeMap<String, RunnerSession>,
    active_session_by_binding: BTreeMap<String, String>,
    audit_events: Vec<RunnerSessionAuditEvent>,
}

impl RunnerSessionRegistry {
    pub fn connect_session_for_binding(
        &mut self,
        binding: &ProjectRunnerBinding,
        input: CreateRunnerSessionInput,
    ) -> CoreResult<RunnerSessionActivation> {
        validate_session_input(&input)?;
        binding.assert_active()?;
        validate_session_matches_binding(&input, binding)?;

        let mut replaced_session_id = None;
        if let Some(active_session_id) = self.active_session_by_binding.get(&binding.id).cloned() {
            if let Some(existing) = self.sessions.get_mut(&active_session_id) {
                let existing_is_active = matches!(
                    existing.status,
                    RunnerSessionStatus::Connecting
                        | RunnerSessionStatus::Connected
                        | RunnerSessionStatus::Draining
                );
                if existing_is_active
                    && existing.lease_expires_at_epoch_ms > input.now_epoch_ms
                    && input.replacement_policy == RunnerSessionReplacementPolicy::RejectIfActive
                {
                    return Err(CoreError::new(
                        "RUNNER_SESSION_ACTIVE_CONFLICT",
                        "an active runner session already controls this binding",
                    ));
                }

                existing.status = RunnerSessionStatus::Replaced;
                existing.disconnected_at_epoch_ms = Some(input.now_epoch_ms);
                existing.replaced_by_session_id = Some(input.session_id.clone());
                existing.disconnect_reason = Some("replaced_by_new_session".to_string());
                replaced_session_id = Some(existing.id.clone());
                self.audit_events.push(RunnerSessionAuditEvent {
                    session_id: existing.id.clone(),
                    project_runner_binding_id: existing.project_runner_binding_id.clone(),
                    reason: "replaced_by_new_session".to_string(),
                    occurred_at_epoch_ms: input.now_epoch_ms,
                });
            }
        }

        let session = RunnerSession {
            id: input.session_id,
            organization_id: input.organization_id,
            project_id: input.project_id,
            runner_device_id: input.runner_device_id,
            project_runner_binding_id: input.project_runner_binding_id,
            status: RunnerSessionStatus::Connected,
            last_seen_at_epoch_ms: Some(input.now_epoch_ms),
            lease_expires_at_epoch_ms: input.now_epoch_ms + input.lease_duration_ms,
            connected_at_epoch_ms: input.now_epoch_ms,
            disconnected_at_epoch_ms: None,
            replaced_by_session_id: None,
            disconnect_reason: None,
        };
        self.active_session_by_binding
            .insert(binding.id.clone(), session.id.clone());
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(RunnerSessionActivation {
            session,
            replaced_session_id,
        })
    }

    pub fn heartbeat(
        &mut self,
        session_id: &str,
        now_epoch_ms: u64,
        lease_duration_ms: u64,
    ) -> CoreResult<RunnerSession> {
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            CoreError::new("RUNNER_SESSION_NOT_FOUND", "runner session was not found")
        })?;
        if now_epoch_ms > session.lease_expires_at_epoch_ms {
            mark_session_terminal(
                session,
                RunnerSessionStatus::Stale,
                now_epoch_ms,
                "lease_expired",
            );
            self.active_session_by_binding
                .remove(&session.project_runner_binding_id);
            return Err(CoreError::new(
                "RUNNER_SESSION_STALE",
                "runner session missed its heartbeat lease",
            ));
        }
        if session.status != RunnerSessionStatus::Connected {
            return Err(session_status_error(session.status));
        }
        session.last_seen_at_epoch_ms = Some(now_epoch_ms);
        session.lease_expires_at_epoch_ms = now_epoch_ms + lease_duration_ms;
        Ok(session.clone())
    }

    pub fn cleanup_stale_sessions(&mut self, now_epoch_ms: u64) -> Vec<String> {
        let mut stale_session_ids = Vec::new();
        for session in self.sessions.values_mut() {
            if session.status == RunnerSessionStatus::Connected
                && now_epoch_ms > session.lease_expires_at_epoch_ms
            {
                mark_session_terminal(
                    session,
                    RunnerSessionStatus::Stale,
                    now_epoch_ms,
                    "lease_expired",
                );
                stale_session_ids.push(session.id.clone());
            }
        }
        for session_id in &stale_session_ids {
            if let Some(session) = self.sessions.get(session_id) {
                self.active_session_by_binding
                    .remove(&session.project_runner_binding_id);
            }
        }
        stale_session_ids
    }

    pub fn force_disconnect(
        &mut self,
        session_id: &str,
        now_epoch_ms: u64,
        reason: impl Into<String>,
    ) -> CoreResult<RunnerSession> {
        let reason = reason.into();
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            CoreError::new("RUNNER_SESSION_NOT_FOUND", "runner session was not found")
        })?;
        mark_session_terminal(
            session,
            RunnerSessionStatus::Disconnected,
            now_epoch_ms,
            &reason,
        );
        self.active_session_by_binding
            .remove(&session.project_runner_binding_id);
        self.audit_events.push(RunnerSessionAuditEvent {
            session_id: session.id.clone(),
            project_runner_binding_id: session.project_runner_binding_id.clone(),
            reason,
            occurred_at_epoch_ms: now_epoch_ms,
        });
        Ok(session.clone())
    }

    pub fn mark_reconnecting(&mut self, session_id: &str) -> CoreResult<RunnerSession> {
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            CoreError::new("RUNNER_SESSION_NOT_FOUND", "runner session was not found")
        })?;
        if session.status != RunnerSessionStatus::Connected {
            return Err(session_status_error(session.status));
        }
        session.status = RunnerSessionStatus::Connecting;
        Ok(session.clone())
    }

    pub fn active_session_for_binding(&self, binding_id: &str) -> Option<&RunnerSession> {
        self.active_session_by_binding
            .get(binding_id)
            .and_then(|session_id| self.sessions.get(session_id))
    }

    pub fn validate_run_can_start(&self, binding: &ProjectRunnerBinding) -> CoreResult<()> {
        let session = self
            .active_session_for_binding(&binding.id)
            .ok_or_else(|| {
                CoreError::new(
                    "RUNNER_SESSION_REQUIRED",
                    "run requires an active runner session",
                )
            })?;
        validate_runner_session_for_dispatch(Some(session), binding)
    }

    pub fn audit_events(&self) -> &[RunnerSessionAuditEvent] {
        &self.audit_events
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingValidationContext {
    pub organization_id: String,
    pub project_id: String,
    pub project_permission_active: bool,
}

pub fn validate_binding_for_workflow_run(
    binding: &ProjectRunnerBinding,
    context: &BindingValidationContext,
) -> CoreResult<()> {
    validate_binding_scope(binding, context)?;
    binding.assert_active()
}

pub fn validate_binding_for_local_tool_call(
    binding: Option<&ProjectRunnerBinding>,
    context: &BindingValidationContext,
    requested_path: &str,
    resolved_path: Option<&str>,
) -> CoreResult<()> {
    let binding = binding.ok_or_else(|| {
        CoreError::new(
            "PROJECT_BINDING_REQUIRED",
            "local tool call requires an active project runner binding",
        )
    })?;
    validate_binding_for_workflow_run(binding, context)?;
    validate_workspace_path_inside_binding(binding, requested_path, resolved_path)
}

pub fn validate_session_and_grant_for_local_tool_call(
    binding: Option<&ProjectRunnerBinding>,
    session: Option<&RunnerSession>,
    grant: Option<&RunnerCapabilityGrant>,
    context: &BindingValidationContext,
    capability: &str,
    requested_path: &str,
    resolved_path: Option<&str>,
) -> CoreResult<()> {
    let binding = binding.ok_or_else(|| {
        CoreError::new(
            "PROJECT_BINDING_REQUIRED",
            "local tool call requires an active project runner binding",
        )
    })?;
    validate_binding_for_workflow_run(binding, context)?;
    validate_runner_session_for_dispatch(session, binding)?;
    validate_runner_capability_grant(grant, binding, capability)?;
    validate_workspace_path_inside_binding(binding, requested_path, resolved_path)
}

pub fn validate_runner_session_for_dispatch(
    session: Option<&RunnerSession>,
    binding: &ProjectRunnerBinding,
) -> CoreResult<()> {
    let session = session.ok_or_else(|| {
        CoreError::new(
            "RUNNER_SESSION_REQUIRED",
            "local tool call requires an active runner session",
        )
    })?;
    match session.status {
        RunnerSessionStatus::Connected => {}
        RunnerSessionStatus::Connecting => {
            return Err(CoreError::new(
                "RUNNER_SESSION_CONNECTING",
                "reconnecting runner session cannot receive local tool calls",
            ));
        }
        RunnerSessionStatus::Draining => {
            return Err(CoreError::new(
                "RUNNER_SESSION_DRAINING",
                "draining runner session cannot receive new local tool calls",
            ));
        }
        RunnerSessionStatus::Disconnected => {
            return Err(CoreError::new(
                "RUNNER_SESSION_DISCONNECTED",
                "disconnected runner session cannot receive local tool calls",
            ));
        }
        RunnerSessionStatus::Stale => {
            return Err(CoreError::new(
                "RUNNER_SESSION_STALE",
                "stale runner session cannot receive local tool calls",
            ));
        }
        RunnerSessionStatus::Replaced => {
            return Err(CoreError::new(
                "RUNNER_SESSION_REPLACED",
                "replaced runner session cannot receive local tool calls",
            ));
        }
        RunnerSessionStatus::Revoked => {
            return Err(CoreError::new(
                "RUNNER_SESSION_REVOKED",
                "revoked runner session cannot receive local tool calls",
            ));
        }
    }
    if session.organization_id != binding.organization_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_ORG_MISMATCH",
            "runner session organization does not match binding",
        ));
    }
    if session.project_id != binding.project_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_PROJECT_MISMATCH",
            "runner session project does not match binding",
        ));
    }
    if session.runner_device_id != binding.runner_device_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_DEVICE_MISMATCH",
            "runner session device does not match binding",
        ));
    }
    if session.project_runner_binding_id != binding.id {
        return Err(CoreError::new(
            "RUNNER_SESSION_BINDING_MISMATCH",
            "runner session binding does not match binding",
        ));
    }
    Ok(())
}

pub fn validate_runner_capability_grant(
    grant: Option<&RunnerCapabilityGrant>,
    binding: &ProjectRunnerBinding,
    capability: &str,
) -> CoreResult<()> {
    let grant = grant.ok_or_else(|| {
        CoreError::new(
            "RUNNER_CAPABILITY_GRANT_REQUIRED",
            "local tool call requires a capability grant for the binding",
        )
    })?;
    if grant.project_runner_binding_id != binding.id {
        return Err(CoreError::new(
            "RUNNER_CAPABILITY_GRANT_BINDING_MISMATCH",
            "capability grant does not match project runner binding",
        ));
    }
    if grant.capability != capability {
        return Err(CoreError::new(
            "RUNNER_CAPABILITY_GRANT_MISMATCH",
            "capability grant does not match requested capability",
        ));
    }
    if !grant.is_active() {
        return Err(CoreError::new(
            "RUNNER_CAPABILITY_GRANT_REVOKED",
            "capability grant has been revoked",
        ));
    }
    Ok(())
}

pub fn validate_workspace_path_inside_binding(
    binding: &ProjectRunnerBinding,
    requested_path: &str,
    resolved_path: Option<&str>,
) -> CoreResult<()> {
    let requested = normalize_workspace_path(requested_path)?;
    if !path_is_inside_root(&binding.workspace.normalized_workspace_root, &requested) {
        return Err(CoreError::new(
            "WORKSPACE_PATH_OUTSIDE_BINDING",
            "requested path is outside the project runner binding root",
        ));
    }

    if let Some(resolved_path) = resolved_path {
        let resolved = normalize_workspace_path(resolved_path)?;
        if !path_is_inside_root(&binding.workspace.normalized_workspace_root, &resolved) {
            return Err(CoreError::new(
                "WORKSPACE_SYMLINK_ESCAPE",
                "resolved path escapes the project runner binding root",
            ));
        }
    }

    Ok(())
}

pub fn normalize_workspace_path(input: &str) -> CoreResult<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::new(
            "EMPTY_WORKSPACE_PATH",
            "workspace path is required",
        ));
    }

    let replaced = trimmed.replace('\\', "/");
    let absolute = replaced.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in replaced.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(CoreError::new(
                        "WORKSPACE_PATH_TRAVERSAL",
                        "workspace path cannot escape above root",
                    ));
                }
            }
            _ => parts.push(part),
        }
    }

    let normalized = parts.join("/");
    if normalized.is_empty() {
        return Ok(if absolute {
            "/".to_string()
        } else {
            ".".to_string()
        });
    }
    if absolute {
        Ok(format!("/{normalized}"))
    } else {
        Ok(normalized)
    }
}

fn validate_binding_scope(
    binding: &ProjectRunnerBinding,
    context: &BindingValidationContext,
) -> CoreResult<()> {
    if binding.organization_id != context.organization_id {
        return Err(CoreError::new(
            "PROJECT_BINDING_ORG_MISMATCH",
            "binding organization does not match request",
        ));
    }
    if binding.project_id != context.project_id {
        return Err(CoreError::new(
            "PROJECT_BINDING_PROJECT_MISMATCH",
            "binding project does not match request",
        ));
    }
    if !context.project_permission_active {
        return Err(CoreError::new(
            "PROJECT_PERMISSION_REVOKED",
            "caller no longer has project permission",
        ));
    }
    Ok(())
}

fn validate_session_input(input: &CreateRunnerSessionInput) -> CoreResult<()> {
    for (field, value) in [
        ("session_id", &input.session_id),
        ("organization_id", &input.organization_id),
        ("project_id", &input.project_id),
        ("runner_device_id", &input.runner_device_id),
        (
            "project_runner_binding_id",
            &input.project_runner_binding_id,
        ),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("RUNNER_SESSION_MISSING_FIELD", field));
        }
    }
    if input.lease_duration_ms == 0 {
        return Err(CoreError::new(
            "RUNNER_SESSION_LEASE_INVALID",
            "runner session lease duration must be positive",
        ));
    }
    Ok(())
}

fn validate_session_matches_binding(
    input: &CreateRunnerSessionInput,
    binding: &ProjectRunnerBinding,
) -> CoreResult<()> {
    if input.organization_id != binding.organization_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_ORG_MISMATCH",
            "runner session organization does not match binding",
        ));
    }
    if input.project_id != binding.project_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_PROJECT_MISMATCH",
            "runner session project does not match binding",
        ));
    }
    if input.runner_device_id != binding.runner_device_id {
        return Err(CoreError::new(
            "RUNNER_SESSION_DEVICE_MISMATCH",
            "runner session device does not match binding",
        ));
    }
    if input.project_runner_binding_id != binding.id {
        return Err(CoreError::new(
            "RUNNER_SESSION_BINDING_MISMATCH",
            "runner session binding does not match binding",
        ));
    }
    Ok(())
}

fn mark_session_terminal(
    session: &mut RunnerSession,
    status: RunnerSessionStatus,
    now_epoch_ms: u64,
    reason: &str,
) {
    session.status = status;
    session.disconnected_at_epoch_ms = Some(now_epoch_ms);
    session.disconnect_reason = Some(reason.to_string());
}

fn session_status_error(status: RunnerSessionStatus) -> CoreError {
    match status {
        RunnerSessionStatus::Connected => CoreError::new(
            "RUNNER_SESSION_INVALID_STATE",
            "connected session was rejected unexpectedly",
        ),
        RunnerSessionStatus::Connecting => CoreError::new(
            "RUNNER_SESSION_CONNECTING",
            "runner session is reconnecting",
        ),
        RunnerSessionStatus::Draining => {
            CoreError::new("RUNNER_SESSION_DRAINING", "runner session is draining")
        }
        RunnerSessionStatus::Disconnected => CoreError::new(
            "RUNNER_SESSION_DISCONNECTED",
            "runner session is disconnected",
        ),
        RunnerSessionStatus::Stale => {
            CoreError::new("RUNNER_SESSION_STALE", "runner session is stale")
        }
        RunnerSessionStatus::Replaced => {
            CoreError::new("RUNNER_SESSION_REPLACED", "runner session is replaced")
        }
        RunnerSessionStatus::Revoked => {
            CoreError::new("RUNNER_SESSION_REVOKED", "runner session is revoked")
        }
    }
}

fn path_is_inside_root(root: &str, candidate: &str) -> bool {
    if candidate == root {
        return true;
    }
    match candidate.strip_prefix(root) {
        Some(suffix) => suffix.starts_with('/'),
        None => false,
    }
}

fn validate_create_input(input: &CreateBindingInput) -> CoreResult<()> {
    for (field, value) in [
        ("organization_id", &input.organization_id),
        ("project_id", &input.project_id),
        ("runner_device_id", &input.runner_device_id),
        ("local_workspace_root", &input.local_workspace_root),
        ("created_by", &input.created_by),
    ] {
        if value.trim().is_empty() {
            return Err(CoreError::new("PROJECT_BINDING_MISSING_FIELD", field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_input(project_id: &str, path: &str) -> CreateBindingInput {
        CreateBindingInput {
            organization_id: "org_123".to_string(),
            project_id: project_id.to_string(),
            runner_device_id: "device_123".to_string(),
            local_workspace_root: path.to_string(),
            local_root_fingerprint: Some("fp_123".to_string()),
            created_by: "user_123".to_string(),
            now_epoch_ms: 1_000,
            allow_same_path_different_project: false,
            project_archived: false,
            runner_disabled: false,
        }
    }

    fn validation_context(project_id: &str) -> BindingValidationContext {
        BindingValidationContext {
            organization_id: "org_123".to_string(),
            project_id: project_id.to_string(),
            project_permission_active: true,
        }
    }

    fn active_session(binding: &ProjectRunnerBinding) -> RunnerSession {
        RunnerSession {
            id: "session_123".to_string(),
            organization_id: binding.organization_id.clone(),
            project_id: binding.project_id.clone(),
            runner_device_id: binding.runner_device_id.clone(),
            project_runner_binding_id: binding.id.clone(),
            status: RunnerSessionStatus::Connected,
            last_seen_at_epoch_ms: Some(1_000),
            lease_expires_at_epoch_ms: 31_000,
            connected_at_epoch_ms: 1_000,
            disconnected_at_epoch_ms: None,
            replaced_by_session_id: None,
            disconnect_reason: None,
        }
    }

    fn session_input(binding: &ProjectRunnerBinding, session_id: &str) -> CreateRunnerSessionInput {
        CreateRunnerSessionInput {
            session_id: session_id.to_string(),
            organization_id: binding.organization_id.clone(),
            project_id: binding.project_id.clone(),
            runner_device_id: binding.runner_device_id.clone(),
            project_runner_binding_id: binding.id.clone(),
            now_epoch_ms: 1_000,
            lease_duration_ms: 30_000,
            replacement_policy: RunnerSessionReplacementPolicy::ReplaceExisting,
        }
    }

    fn active_grant(binding: &ProjectRunnerBinding, capability: &str) -> RunnerCapabilityGrant {
        RunnerCapabilityGrant {
            project_runner_binding_id: binding.id.clone(),
            capability: capability.to_string(),
            granted_by: "policy_123".to_string(),
            created_at_epoch_ms: 1_000,
            revoked_at_epoch_ms: None,
        }
    }

    #[test]
    fn create_binding_success() {
        let mut registry = BindingRegistry::default();

        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();

        assert_eq!("org_123", binding.organization_id);
        assert_eq!("prj_123", binding.project_id);
        assert_eq!("device_123", binding.runner_device_id);
        assert_eq!(
            "/Users/example/app",
            binding.workspace.normalized_workspace_root
        );
        assert_eq!(BindingStatus::Active, binding.status);
    }

    #[test]
    fn duplicate_binding_same_project_path_reuses_existing() {
        let mut registry = BindingRegistry::default();
        let first = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let second = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/./app"))
            .unwrap();

        assert_eq!(first.id, second.id);
    }

    #[test]
    fn same_path_for_different_project_requires_confirmation() {
        let mut registry = BindingRegistry::default();
        registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();

        let err = registry
            .create_or_reuse_binding(create_input("prj_other", "/Users/example/app"))
            .unwrap_err();

        assert_eq!("PROJECT_BINDING_PATH_CONFLICT", err.code);
    }

    #[test]
    fn archived_project_blocks_binding_creation() {
        let mut registry = BindingRegistry::default();
        let mut input = create_input("prj_123", "/Users/example/app");
        input.project_archived = true;

        let err = registry.create_or_reuse_binding(input).unwrap_err();

        assert_eq!("PROJECT_BINDING_PROJECT_ARCHIVED", err.code);
    }

    #[test]
    fn disabled_runner_blocks_binding_creation() {
        let mut registry = BindingRegistry::default();
        let mut input = create_input("prj_123", "/Users/example/app");
        input.runner_disabled = true;

        let err = registry.create_or_reuse_binding(input).unwrap_err();

        assert_eq!("PROJECT_BINDING_RUNNER_DISABLED", err.code);
    }

    #[test]
    fn revoke_binding_blocks_future_runs() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        registry.revoke_binding(&binding.id, 2_000).unwrap();

        let err = validate_binding_for_workflow_run(
            registry.get(&binding.id).unwrap(),
            &validation_context("prj_123"),
        )
        .unwrap_err();

        assert_eq!("PROJECT_BINDING_REVOKED", err.code);
    }

    #[test]
    fn local_tool_call_with_missing_binding_fails() {
        let err = validate_binding_for_local_tool_call(
            None,
            &validation_context("prj_123"),
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("PROJECT_BINDING_REQUIRED", err.code);
    }

    #[test]
    fn path_normalization_handles_dots_and_duplicate_separators() {
        let path = normalize_workspace_path("/Users/example//app/./src/../src").unwrap();

        assert_eq!("/Users/example/app/src", path);
    }

    #[test]
    fn symlink_escape_is_rejected_after_runner_resolution() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();

        let err = validate_binding_for_local_tool_call(
            Some(&binding),
            &validation_context("prj_123"),
            "/Users/example/app/link/file.txt",
            Some("/Users/example/secret/file.txt"),
        )
        .unwrap_err();

        assert_eq!("WORKSPACE_SYMLINK_ESCAPE", err.code);
    }

    #[test]
    fn organization_mismatch_is_rejected() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let context = BindingValidationContext {
            organization_id: "org_other".to_string(),
            project_id: "prj_123".to_string(),
            project_permission_active: true,
        };

        let err = validate_binding_for_workflow_run(&binding, &context).unwrap_err();

        assert_eq!("PROJECT_BINDING_ORG_MISMATCH", err.code);
    }

    #[test]
    fn project_permission_revoked_is_rejected() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let context = BindingValidationContext {
            organization_id: "org_123".to_string(),
            project_id: "prj_123".to_string(),
            project_permission_active: false,
        };

        let err = validate_binding_for_workflow_run(&binding, &context).unwrap_err();

        assert_eq!("PROJECT_PERMISSION_REVOKED", err.code);
    }

    #[test]
    fn local_tool_call_outside_binding_root_is_rejected() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();

        let err = validate_binding_for_local_tool_call(
            Some(&binding),
            &validation_context("prj_123"),
            "/Users/example/other/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("WORKSPACE_PATH_OUTSIDE_BINDING", err.code);
    }

    #[test]
    fn stale_session_cannot_receive_tool_call() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut session = active_session(&binding);
        session.status = RunnerSessionStatus::Stale;
        let grant = active_grant(&binding, "shell.exec");

        let err = validate_session_and_grant_for_local_tool_call(
            Some(&binding),
            Some(&session),
            Some(&grant),
            &validation_context("prj_123"),
            "shell.exec",
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("RUNNER_SESSION_STALE", err.code);
    }

    #[test]
    fn grant_missing_blocks_local_tool_call() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let session = active_session(&binding);

        let err = validate_session_and_grant_for_local_tool_call(
            Some(&binding),
            Some(&session),
            None,
            &validation_context("prj_123"),
            "shell.exec",
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("RUNNER_CAPABILITY_GRANT_REQUIRED", err.code);
    }

    #[test]
    fn grant_capability_mismatch_blocks_local_tool_call() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let session = active_session(&binding);
        let grant = active_grant(&binding, "fs.read");

        let err = validate_session_and_grant_for_local_tool_call(
            Some(&binding),
            Some(&session),
            Some(&grant),
            &validation_context("prj_123"),
            "shell.exec",
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("RUNNER_CAPABILITY_GRANT_MISMATCH", err.code);
    }

    #[test]
    fn revoked_grant_blocks_local_tool_call() {
        let mut registry = BindingRegistry::default();
        let binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let session = active_session(&binding);
        let mut grant = active_grant(&binding, "shell.exec");
        grant.revoked_at_epoch_ms = Some(2_000);

        let err = validate_session_and_grant_for_local_tool_call(
            Some(&binding),
            Some(&session),
            Some(&grant),
            &validation_context("prj_123"),
            "shell.exec",
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("RUNNER_CAPABILITY_GRANT_REVOKED", err.code);
    }

    #[test]
    fn runner_disabled_binding_blocks_local_dispatch() {
        let mut registry = BindingRegistry::default();
        let mut binding = registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        binding.status = BindingStatus::RunnerDisabled;
        let session = active_session(&binding);
        let grant = active_grant(&binding, "shell.exec");

        let err = validate_session_and_grant_for_local_tool_call(
            Some(&binding),
            Some(&session),
            Some(&grant),
            &validation_context("prj_123"),
            "shell.exec",
            "/Users/example/app/file.txt",
            None,
        )
        .unwrap_err();

        assert_eq!("PROJECT_BINDING_RUNNER_DISABLED", err.code);
    }

    #[test]
    fn first_runner_session_active() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();

        let activation = sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        assert_eq!(RunnerSessionStatus::Connected, activation.session.status);
        assert_eq!(
            "session_1",
            sessions.active_session_for_binding(&binding.id).unwrap().id
        );
    }

    #[test]
    fn second_runner_same_binding_replaces_first() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        let activation = sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_2"))
            .unwrap();

        assert_eq!(
            Some("session_1".to_string()),
            activation.replaced_session_id
        );
        assert_eq!(
            "session_2",
            sessions.active_session_for_binding(&binding.id).unwrap().id
        );
        assert_eq!("replaced_by_new_session", sessions.audit_events()[0].reason);
    }

    #[test]
    fn stale_session_cleanup_removes_active_session() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        let stale = sessions.cleanup_stale_sessions(31_001);

        assert_eq!(vec!["session_1".to_string()], stale);
        assert!(sessions.active_session_for_binding(&binding.id).is_none());
    }

    #[test]
    fn heartbeat_missed_marks_session_stale() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        let err = sessions.heartbeat("session_1", 31_001, 30_000).unwrap_err();

        assert_eq!("RUNNER_SESSION_STALE", err.code);
        assert!(sessions.active_session_for_binding(&binding.id).is_none());
    }

    #[test]
    fn heartbeat_extends_active_session_lease() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        let session = sessions.heartbeat("session_1", 10_000, 30_000).unwrap();

        assert_eq!(Some(10_000), session.last_seen_at_epoch_ms);
        assert_eq!(40_000, session.lease_expires_at_epoch_ms);
    }

    #[test]
    fn force_disconnect_removes_active_session_and_audits_reason() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();

        let session = sessions
            .force_disconnect("session_1", 2_000, "server_force_disconnect")
            .unwrap();

        assert_eq!(RunnerSessionStatus::Disconnected, session.status);
        assert!(sessions.active_session_for_binding(&binding.id).is_none());
        assert_eq!("server_force_disconnect", sessions.audit_events()[0].reason);
    }

    #[test]
    fn run_started_while_session_reconnecting_is_rejected() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        sessions
            .connect_session_for_binding(&binding, session_input(&binding, "session_1"))
            .unwrap();
        sessions.mark_reconnecting("session_1").unwrap();

        let err = sessions.validate_run_can_start(&binding).unwrap_err();

        assert_eq!("RUNNER_SESSION_CONNECTING", err.code);
    }

    #[test]
    fn session_for_wrong_binding_rejected() {
        let mut binding_registry = BindingRegistry::default();
        let binding = binding_registry
            .create_or_reuse_binding(create_input("prj_123", "/Users/example/app"))
            .unwrap();
        let mut sessions = RunnerSessionRegistry::default();
        let mut input = session_input(&binding, "session_1");
        input.project_runner_binding_id = "bind_other".to_string();

        let err = sessions
            .connect_session_for_binding(&binding, input)
            .unwrap_err();

        assert_eq!("RUNNER_SESSION_BINDING_MISMATCH", err.code);
    }
}
