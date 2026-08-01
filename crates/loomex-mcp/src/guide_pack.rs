use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Component, Path, PathBuf},
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const GUIDE_SCHEMA_VERSION: &str = "loomex.workflow-guides/v1";
const GUIDE_AUDIT_SCHEMA_VERSION: &str = "loomex.plugin-guide-audit/v1";
const MAX_SELECTED_GUIDES: usize = 12;
const MAX_GUIDE_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone)]
struct GuideEntry {
    id: String,
    path: String,
    sha256: String,
    node_types: HashSet<String>,
    audience: HashSet<String>,
    kind: String,
}

#[derive(Debug, Clone)]
struct VerifiedGuide {
    entry: GuideEntry,
    content: String,
}

pub fn enrich_agent_tasks(envelope: &mut Value) {
    let Some(root) = env::var_os("LOOMEX_PLUGIN_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let Some(data) = envelope.get_mut("data") else {
        return;
    };
    if let Some(task) = data.get_mut("agentTask") {
        if is_workflow_builder_task(task) {
            enrich_task(task, &root);
        }
    }
    if let Some(request) = data.get_mut("humanRequest") {
        if let Some(task) = request.get_mut("agentTask") {
            if is_workflow_builder_task(task) {
                enrich_task(task, &root);
            }
        }
    }
    if let Some(requests) = data.get_mut("humanRequests").and_then(Value::as_array_mut) {
        for request in requests {
            if let Some(task) = request.get_mut("agentTask") {
                if is_workflow_builder_task(task) {
                    enrich_task(task, &root);
                }
            }
        }
    }
}

fn is_workflow_builder_task(task: &Value) -> bool {
    task.get("workflowBuilder").is_some_and(Value::is_object)
        || task.pointer("/promptContext/workflowNodeCatalog").is_some()
        || task
            .pointer("/node/key")
            .and_then(Value::as_str)
            .is_some_and(|key| matches!(key, "clarifier" | "designer" | "reviewer"))
}

fn enrich_task(task: &mut Value, plugin_root: &Path) {
    let guides_root = plugin_root.join("skills/create-workflow/guides");
    let (reference_context, audit) = match load_selected_guides(task, &guides_root) {
        Ok(value) => value,
        Err(reason) => {
            log_guide_event("guide_pack_unavailable", json!({"reason": reason}));
            (
                Vec::new(),
                json!({
                    "schemaVersion": GUIDE_AUDIT_SCHEMA_VERSION,
                    "status": "unavailable",
                    "selected": [],
                    "reason": reason,
                }),
            )
        }
    };
    let Some(object) = task.as_object_mut() else {
        return;
    };
    object.insert(
        "referenceContext".to_string(),
        Value::Array(reference_context),
    );
    object.insert("guideAudit".to_string(), audit);
}

fn load_selected_guides(task: &Value, guides_root: &Path) -> Result<(Vec<Value>, Value), String> {
    let index_path = guides_root.join("index.json");
    let index_bytes = fs::read(&index_path).map_err(|error| format!("read index: {error}"))?;
    let index: Value =
        serde_json::from_slice(&index_bytes).map_err(|error| format!("parse index: {error}"))?;
    if index.get("schemaVersion").and_then(Value::as_str) != Some(GUIDE_SCHEMA_VERSION) {
        return Err("unsupported guide index schema".to_string());
    }
    let pack_version = index
        .get("packVersion")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let raw_guides = index
        .get("guides")
        .and_then(Value::as_array)
        .ok_or_else(|| "guide index guides must be an array".to_string())?;

    let mut verified = HashMap::new();
    let mut invalid = Vec::new();
    for raw in raw_guides {
        match parse_entry(raw).and_then(|entry| verify_guide(entry, guides_root)) {
            Ok(guide) => {
                verified.insert(guide.entry.id.clone(), guide);
            }
            Err(error) => invalid.push(error),
        }
    }
    if !invalid.is_empty() {
        log_guide_event("guide_pack_invalid_entries", json!({"entries": invalid}));
    }

    let selected_ids = select_guide_ids(task, &verified);
    let mut reference_context = Vec::new();
    let mut selected = Vec::new();
    for id in selected_ids.into_iter().take(MAX_SELECTED_GUIDES) {
        let Some(guide) = verified.get(&id) else {
            continue;
        };
        reference_context.push(json!({
            "id": guide.entry.id,
            "path": guide.entry.path,
            "sha256": guide.entry.sha256,
            "content": guide.content,
            "readOnly": true,
        }));
        selected.push(json!({
            "id": guide.entry.id,
            "path": guide.entry.path,
            "sha256": guide.entry.sha256,
        }));
    }
    let catalog_sha256 = task
        .pointer("/promptContext/workflowNodeCatalog")
        .map(canonical_sha256)
        .or_else(|| task.get("catalog").map(canonical_sha256));
    let audit = json!({
        "schemaVersion": GUIDE_AUDIT_SCHEMA_VERSION,
        "status": "loaded",
        "packVersion": pack_version,
        "selected": selected,
        "invalidCount": invalid.len(),
        "catalogSha256": catalog_sha256,
    });
    log_guide_event(
        "guide_pack_loaded",
        json!({
            "packVersion": pack_version,
            "selected": audit.get("selected"),
            "invalidCount": invalid.len()
        }),
    );
    Ok((reference_context, audit))
}

fn parse_entry(raw: &Value) -> Result<GuideEntry, String> {
    let id = raw
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "guide entry id is missing".to_string())?
        .to_string();
    let path = raw
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{id}: guide path is missing"))?
        .to_string();
    let sha256 = raw
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{id}: guide sha256 is invalid"))?
        .to_lowercase();
    Ok(GuideEntry {
        id,
        path,
        sha256,
        node_types: string_set(raw.get("nodeTypes")),
        audience: string_set(raw.get("audience")),
        kind: raw
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("reference")
            .to_string(),
    })
}

fn verify_guide(entry: GuideEntry, guides_root: &Path) -> Result<VerifiedGuide, String> {
    let relative = Path::new(&entry.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("{}: unsafe path", entry.id));
    }
    let path = guides_root.join(relative);
    let canonical_root = guides_root
        .canonicalize()
        .map_err(|error| format!("{}: guide root: {error}", entry.id))?;
    let canonical_path = path
        .canonicalize()
        .map_err(|error| format!("{}: file missing: {error}", entry.id))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(format!("{}: path escapes guide root", entry.id));
    }
    let bytes =
        fs::read(&canonical_path).map_err(|error| format!("{}: read: {error}", entry.id))?;
    if bytes.len() > MAX_GUIDE_BYTES {
        return Err(format!("{}: file exceeds size limit", entry.id));
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != entry.sha256 {
        return Err(format!("{}: hash mismatch", entry.id));
    }
    let content =
        String::from_utf8(bytes).map_err(|error| format!("{}: not UTF-8: {error}", entry.id))?;
    Ok(VerifiedGuide { entry, content })
}

fn select_guide_ids(task: &Value, verified: &HashMap<String, VerifiedGuide>) -> Vec<String> {
    let role = task
        .pointer("/node/key")
        .and_then(Value::as_str)
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "designer".to_string());
    let searchable = serde_json::to_string(task)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut node_types = candidate_node_types(task);
    if node_types.is_empty() {
        if searchable.contains("human")
            || searchable.contains("question")
            || searchable.contains("input")
        {
            node_types.insert("human".to_string());
        }
        if searchable.contains("person") || searchable.contains("memory") {
            node_types.insert("person".to_string());
        }
        if searchable.contains("review")
            || searchable.contains("developer")
            || searchable.contains("agent")
        {
            node_types.insert("ai_agent".to_string());
        }
        if searchable.contains("condition")
            || searchable.contains("branch")
            || searchable.contains("review")
        {
            node_types.insert("condition".to_string());
        }
        if searchable.contains("switch") {
            node_types.insert("switch".to_string());
        }
        if searchable.contains("tool") || searchable.contains("mcp") {
            node_types.insert("tool".to_string());
        }
        if searchable.contains("sub-workflow") || searchable.contains("sub_workflow") {
            node_types.insert("sub_workflow".to_string());
        }
    }
    node_types.extend(["start".to_string(), "end".to_string()]);

    let mut ids = Vec::new();
    for guide in verified.values() {
        if !guide.entry.audience.is_empty()
            && !guide.entry.audience.contains(&role)
            && !guide.entry.audience.contains("all")
        {
            continue;
        }
        let is_contract = guide.entry.kind == "contract";
        let node_match =
            guide.entry.node_types.is_empty() || !guide.entry.node_types.is_disjoint(&node_types);
        let pattern_match = pattern_matches(&guide.entry.id, &role, &searchable, &node_types);
        let selected = is_contract
            || (guide.entry.kind == "node" && node_match)
            || (guide.entry.kind == "pattern" && pattern_match);
        if selected {
            ids.push(guide.entry.id.clone());
        }
    }
    ids.sort_by_key(|id| (priority(id), id.clone()));
    ids
}

fn candidate_node_types(task: &Value) -> HashSet<String> {
    let mut types = HashSet::new();
    let candidates = [
        task.pointer("/input/nodeInput/draft/workflow/nodes"),
        task.pointer("/input/nodeInput/workflow/nodes"),
        task.pointer("/promptContext/nodeInput/draft/workflow/nodes"),
    ];
    for nodes in candidates.into_iter().flatten().filter_map(Value::as_array) {
        for node in nodes {
            if let Some(node_type) = node.get("type").and_then(Value::as_str) {
                types.insert(node_type.to_string());
            }
        }
    }
    types
}

fn pattern_matches(id: &str, role: &str, searchable: &str, node_types: &HashSet<String>) -> bool {
    match id {
        "pattern.clarifier-loop" => {
            role == "clarifier" || searchable.contains("clarif") || searchable.contains("question")
        }
        "pattern.human-radio-after-agent" => {
            node_types.contains("human")
                && (searchable.contains("radio") || searchable.contains("question"))
        }
        "pattern.human-checkbox-after-agent" => {
            node_types.contains("human") && searchable.contains("checkbox")
        }
        "pattern.developer-reviewer-loop" => {
            searchable.contains("review") || searchable.contains("developer")
        }
        "pattern.condition-after-review" => {
            node_types.contains("condition") || searchable.contains("review")
        }
        "pattern.person-memory" => node_types.contains("person") || searchable.contains("memory"),
        _ => false,
    }
}

fn priority(id: &str) -> u8 {
    if id == "workflow-contract" {
        0
    } else if id == "catalog-summary" {
        1
    } else if id.starts_with("node.") {
        2
    } else {
        3
    }
}

fn string_set(value: Option<&Value>) -> HashSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn canonical_sha256(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn log_guide_event(event: &str, metadata: Value) {
    eprintln!(
        "loomex-guide-pack: {}",
        json!({"event": event, "metadata": metadata})
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_pack(root: &Path) {
        let guides = root.join("skills/create-workflow/guides");
        fs::create_dir_all(guides.join("node-guides")).unwrap();
        fs::write(guides.join("workflow-contract.md"), "contract").unwrap();
        fs::write(guides.join("node-guides/human.md"), "human").unwrap();
        let contract_hash = format!("{:x}", Sha256::digest(b"contract"));
        let human_hash = format!("{:x}", Sha256::digest(b"human"));
        fs::write(
            guides.join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": GUIDE_SCHEMA_VERSION,
                "packVersion": "1",
                "guides": [
                    {"id":"workflow-contract","path":"workflow-contract.md","sha256":contract_hash,"kind":"contract","audience":["clarifier","designer","reviewer"]},
                    {"id":"node.human","path":"node-guides/human.md","sha256":human_hash,"kind":"node","nodeTypes":["human"],"audience":["designer","reviewer"]}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn verifies_hashes_and_selects_only_relevant_guides() {
        let temp = tempdir().unwrap();
        write_pack(temp.path());
        let task = json!({
            "node":{"key":"designer","type":"ai_agent"},
            "promptContext":{"workflowNodeCatalog":[]},
            "input":{"nodeInput":{"draft":{"workflow":{"nodes":[{"type":"human"}]}}}}
        });
        let (context, audit) =
            load_selected_guides(&task, &temp.path().join("skills/create-workflow/guides"))
                .unwrap();
        assert_eq!(context.len(), 2);
        assert_eq!(audit["status"], "loaded");
        assert_eq!(audit["selected"][1]["id"], "node.human");
    }

    #[test]
    fn rejects_tampered_guide_without_importing_it() {
        let temp = tempdir().unwrap();
        write_pack(temp.path());
        fs::write(
            temp.path()
                .join("skills/create-workflow/guides/node-guides/human.md"),
            "tampered",
        )
        .unwrap();
        let task = json!({"node":{"key":"designer"}});
        let (context, audit) =
            load_selected_guides(&task, &temp.path().join("skills/create-workflow/guides"))
                .unwrap();
        assert_eq!(context.len(), 1);
        assert_eq!(audit["invalidCount"], 1);
        assert_eq!(audit["selected"][0]["id"], "workflow-contract");
    }

    #[test]
    fn guide_enrichment_keeps_the_server_prompt_byte_for_byte() {
        let temp = tempdir().unwrap();
        write_pack(temp.path());
        let mut task = json!({
            "node":{"key":"designer"},
            "prompt":"exact server prompt\nwith unicode: سلام",
            "promptContract":{"sha256":"server-hash"},
            "promptContext":{"workflowNodeCatalog":[]}
        });
        let original = task["prompt"].clone();
        enrich_task(&mut task, temp.path());
        assert_eq!(task["prompt"], original);
        assert!(task.get("referenceContext").is_some());
        assert!(task.get("guideAudit").is_some());
    }

    #[test]
    fn checked_in_guide_pack_has_no_hash_drift() {
        let plugin_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugin/loomex");
        let task = json!({
            "node":{"key":"designer"},
            "prompt":"Build a workflow with a human radio, developer reviewer, condition, and person memory.",
            "promptContext":{"workflowNodeCatalog":[]}
        });
        let (_context, audit) =
            load_selected_guides(&task, &plugin_root.join("skills/create-workflow/guides"))
                .unwrap();
        assert_eq!(audit["status"], "loaded");
        assert_eq!(audit["invalidCount"], 0);
    }
}
