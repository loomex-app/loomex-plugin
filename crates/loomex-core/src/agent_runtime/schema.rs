use serde_json::Value;

const MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_SCHEMA_NODES: usize = 10_000;
const MAX_SCHEMA_REF_EXPANSIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaContractError {
    TooLarge,
    TooDeep,
    TooManyNodes,
    TooManyReferenceExpansions,
    UnsupportedKeyword { path: String, keyword: String },
    UnsupportedReference { path: String },
    UnresolvableReference { path: String },
    CyclicReference { path: String },
    InvalidSchemaNode { path: String },
}

/// Fail-closed preflight for the exact JSON Schema subset implemented below.
/// Annotation keywords are accepted, while unsupported assertions are rejected
/// before an agent process is spawned.
pub fn validate_schema_contract(schema: &Value) -> Result<(), SchemaContractError> {
    if serde_json::to_vec(schema)
        .map_err(|_| SchemaContractError::InvalidSchemaNode {
            path: "$".to_string(),
        })?
        .len()
        > MAX_SCHEMA_BYTES
    {
        return Err(SchemaContractError::TooLarge);
    }
    let mut state = SchemaContractState {
        nodes: 0,
        reference_expansions: 0,
        reference_stack: Vec::new(),
    };
    preflight_schema(schema, schema, "$", 0, &mut state)
}

/// Validates the JSON Schema subset used by Loomex structured workflow
/// outputs. Unknown annotation keywords are ignored, while malformed supported
/// keywords fail closed.
pub fn validate_json_schema(value: &Value, schema: &Value) -> Result<(), Vec<SchemaViolation>> {
    let mut violations = Vec::new();
    validate_at(value, schema, schema, "$", &mut violations);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn validate_at(
    value: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    if let Some(boolean) = schema.as_bool() {
        if !boolean {
            violation(violations, path, "schema rejects every value");
        }
        return;
    }
    let Some(object) = schema.as_object() else {
        violation(violations, path, "schema must be an object or boolean");
        return;
    };

    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        match resolve_local_ref(root, reference) {
            Some(resolved) => validate_at(value, resolved, root, path, violations),
            None => violation(violations, path, "unresolvable local schema reference"),
        }
    }

    if let Some(expected) = object.get("type") {
        let matches = match expected {
            Value::String(expected) => type_matches(value, expected),
            Value::Array(types) => types
                .iter()
                .filter_map(Value::as_str)
                .any(|expected| type_matches(value, expected)),
            _ => false,
        };
        if !matches {
            violation(violations, path, "value has the wrong JSON type");
            return;
        }
    }

    if let Some(expected) = object.get("const") {
        if value != expected {
            violation(violations, path, "value does not match const");
        }
    }
    if let Some(allowed) = object.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            violation(violations, path, "value is not in enum");
        }
    }

    validate_combinators(value, schema, root, path, violations);

    if let Some(instance) = value.as_object() {
        validate_object(instance, schema, root, path, violations);
    }
    if let Some(instance) = value.as_array() {
        validate_array(instance, schema, root, path, violations);
    }
    if let Some(instance) = value.as_str() {
        validate_string(instance, schema, path, violations);
    }
    if let Some(instance) = value.as_f64() {
        validate_number(instance, schema, path, violations);
    }
}

struct SchemaContractState {
    nodes: usize,
    reference_expansions: usize,
    reference_stack: Vec<String>,
}

fn preflight_schema(
    schema: &Value,
    root: &Value,
    path: &str,
    depth: usize,
    state: &mut SchemaContractState,
) -> Result<(), SchemaContractError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaContractError::TooDeep);
    }
    state.nodes += 1;
    if state.nodes > MAX_SCHEMA_NODES {
        return Err(SchemaContractError::TooManyNodes);
    }
    if schema.is_boolean() {
        return Ok(());
    }
    let object = schema
        .as_object()
        .ok_or_else(|| SchemaContractError::InvalidSchemaNode {
            path: path.to_string(),
        })?;

    for keyword in object.keys() {
        if !is_supported_keyword(keyword) && !is_annotation_keyword(keyword) {
            return Err(SchemaContractError::UnsupportedKeyword {
                path: path.to_string(),
                keyword: keyword.clone(),
            });
        }
    }

    if let Some(reference) = object.get("$ref") {
        let reference =
            reference
                .as_str()
                .ok_or_else(|| SchemaContractError::InvalidSchemaNode {
                    path: format!("{path}.$ref"),
                })?;
        if !reference.starts_with('#') {
            return Err(SchemaContractError::UnsupportedReference {
                path: format!("{path}.$ref"),
            });
        }
        if state
            .reference_stack
            .iter()
            .any(|active| active == reference)
        {
            return Err(SchemaContractError::CyclicReference {
                path: format!("{path}.$ref"),
            });
        }
        state.reference_expansions += 1;
        if state.reference_expansions > MAX_SCHEMA_REF_EXPANSIONS {
            return Err(SchemaContractError::TooManyReferenceExpansions);
        }
        let resolved = resolve_local_ref(root, reference).ok_or_else(|| {
            SchemaContractError::UnresolvableReference {
                path: format!("{path}.$ref"),
            }
        })?;
        state.reference_stack.push(reference.to_string());
        let result = preflight_schema(resolved, root, reference, depth + 1, state);
        state.reference_stack.pop();
        result?;
    }

    for keyword in ["properties", "$defs", "definitions"] {
        if let Some(children) = object.get(keyword) {
            let children =
                children
                    .as_object()
                    .ok_or_else(|| SchemaContractError::InvalidSchemaNode {
                        path: format!("{path}.{keyword}"),
                    })?;
            for (name, child) in children {
                preflight_schema(
                    child,
                    root,
                    &format!("{path}.{keyword}.{name}"),
                    depth + 1,
                    state,
                )?;
            }
        }
    }
    for keyword in ["additionalProperties", "items", "not"] {
        if let Some(child) = object.get(keyword) {
            preflight_schema(child, root, &format!("{path}.{keyword}"), depth + 1, state)?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(children) = object.get(keyword) {
            let children =
                children
                    .as_array()
                    .ok_or_else(|| SchemaContractError::InvalidSchemaNode {
                        path: format!("{path}.{keyword}"),
                    })?;
            for (index, child) in children.iter().enumerate() {
                preflight_schema(
                    child,
                    root,
                    &format!("{path}.{keyword}[{index}]"),
                    depth + 1,
                    state,
                )?;
            }
        }
    }
    Ok(())
}

fn is_supported_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "$ref"
            | "$defs"
            | "definitions"
            | "type"
            | "const"
            | "enum"
            | "allOf"
            | "anyOf"
            | "oneOf"
            | "not"
            | "required"
            | "properties"
            | "additionalProperties"
            | "minProperties"
            | "maxProperties"
            | "items"
            | "minItems"
            | "maxItems"
            | "uniqueItems"
            | "minLength"
            | "maxLength"
            | "minimum"
            | "maximum"
            | "exclusiveMinimum"
            | "exclusiveMaximum"
    )
}

fn is_annotation_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "$schema"
            | "$id"
            | "$anchor"
            | "title"
            | "description"
            | "default"
            | "examples"
            | "deprecated"
            | "readOnly"
            | "writeOnly"
    ) || keyword.starts_with("x-")
}

fn validate_combinators(
    value: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    for keyword in ["allOf"] {
        if let Some(schemas) = schema.get(keyword).and_then(Value::as_array) {
            for child in schemas {
                validate_at(value, child, root, path, violations);
            }
        }
    }
    if let Some(schemas) = schema.get("anyOf").and_then(Value::as_array) {
        if !schemas
            .iter()
            .any(|child| schema_matches(value, child, root, path))
        {
            violation(violations, path, "value does not match anyOf");
        }
    }
    if let Some(schemas) = schema.get("oneOf").and_then(Value::as_array) {
        if schemas
            .iter()
            .filter(|child| schema_matches(value, child, root, path))
            .count()
            != 1
        {
            violation(
                violations,
                path,
                "value does not match exactly one oneOf branch",
            );
        }
    }
    if let Some(child) = schema.get("not") {
        if schema_matches(value, child, root, path) {
            violation(violations, path, "value matches forbidden not schema");
        }
    }
}

fn validate_object(
    instance: &serde_json::Map<String, Value>,
    schema: &Value,
    root: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !instance.contains_key(key) {
                violation(violations, &join(path, key), "required property is missing");
            }
        }
    }
    if let Some(min) = schema.get("minProperties").and_then(Value::as_u64) {
        if instance.len() < min as usize {
            violation(violations, path, "object has too few properties");
        }
    }
    if let Some(max) = schema.get("maxProperties").and_then(Value::as_u64) {
        if instance.len() > max as usize {
            violation(violations, path, "object has too many properties");
        }
    }

    let properties = schema.get("properties").and_then(Value::as_object);
    for (key, value) in instance {
        if let Some(property_schema) = properties.and_then(|properties| properties.get(key)) {
            validate_at(value, property_schema, root, &join(path, key), violations);
            continue;
        }
        if let Some(additional) = schema.get("additionalProperties") {
            match additional {
                Value::Bool(false) => violation(
                    violations,
                    &join(path, key),
                    "additional property is not allowed",
                ),
                Value::Object(_) | Value::Bool(true) => {
                    validate_at(value, additional, root, &join(path, key), violations)
                }
                _ => violation(
                    violations,
                    &join(path, key),
                    "additionalProperties must be a schema or boolean",
                ),
            }
        }
    }
}

fn validate_array(
    instance: &[Value],
    schema: &Value,
    root: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if instance.len() < min as usize {
            violation(violations, path, "array has too few items");
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if instance.len() > max as usize {
            violation(violations, path, "array has too many items");
        }
    }
    if schema
        .get("uniqueItems")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        for (index, item) in instance.iter().enumerate() {
            if instance[..index].contains(item) {
                violation(
                    violations,
                    &format!("{path}[{index}]"),
                    "array item is not unique",
                );
            }
        }
    }
    if let Some(items) = schema.get("items") {
        for (index, item) in instance.iter().enumerate() {
            validate_at(item, items, root, &format!("{path}[{index}]"), violations);
        }
    }
}

fn validate_string(
    instance: &str,
    schema: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    let length = instance.chars().count();
    if schema
        .get("minLength")
        .and_then(Value::as_u64)
        .is_some_and(|min| length < min as usize)
    {
        violation(violations, path, "string is shorter than minLength");
    }
    if schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .is_some_and(|max| length > max as usize)
    {
        violation(violations, path, "string is longer than maxLength");
    }
}

fn validate_number(
    instance: f64,
    schema: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    if schema
        .get("minimum")
        .and_then(Value::as_f64)
        .is_some_and(|minimum| instance < minimum)
    {
        violation(violations, path, "number is below minimum");
    }
    if schema
        .get("maximum")
        .and_then(Value::as_f64)
        .is_some_and(|maximum| instance > maximum)
    {
        violation(violations, path, "number is above maximum");
    }
    if schema
        .get("exclusiveMinimum")
        .and_then(Value::as_f64)
        .is_some_and(|minimum| instance <= minimum)
    {
        violation(violations, path, "number is not above exclusiveMinimum");
    }
    if schema
        .get("exclusiveMaximum")
        .and_then(Value::as_f64)
        .is_some_and(|maximum| instance >= maximum)
    {
        violation(violations, path, "number is not below exclusiveMaximum");
    }
}

fn schema_matches(value: &Value, schema: &Value, root: &Value, path: &str) -> bool {
    let mut violations = Vec::new();
    validate_at(value, schema, root, path, &mut violations);
    violations.is_empty()
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn join(path: &str, key: &str) -> String {
    format!("{path}.{}", key.replace('.', "\\."))
}

fn violation(violations: &mut Vec<SchemaViolation>, path: &str, message: &str) {
    if violations.len() < 64 {
        violations.push(SchemaViolation {
            path: path.to_string(),
            message: message.to_string(),
        });
    }
}
