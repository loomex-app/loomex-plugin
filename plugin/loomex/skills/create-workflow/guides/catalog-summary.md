# Catalog grounding

## Purpose

Help the three builder agents reason about the live catalog without replacing
it.

## When to use

Clarifier uses this to ask implementation questions. Designer uses the live
catalog to choose nodes. Reviewer uses it to detect invented types and config.

## Configuration fields

The real catalog supplies `type`, `capabilities`, `defaults`, `validation`,
`inputSchema`, `outputSchema`, and supported config sections. Never copy a
field from this summary when the live catalog says otherwise.

The catalog is the node-type authority, but the generated workflow must still
materialize the selected node's effective schemas and mappings. In particular,
the default Human Input catalog entry is single/text; when the design needs
radio or checkbox questions, explicitly set `config.inputType` and
`config.collectionMode` to the catalog-supported values and emit the matching
canonical schemas in the draft.

## Valid enum values

There is no independent enum list in this guide. Read enum values from the
Backend catalog included in the provider context.

## Defaults

The Backend catalog owns defaults. A missing guide or summary never authorizes
an invented default.

## Input contract

For Clarifier, ask only about user-visible behavior: desired outcome, inputs,
audience, content, interaction, choices, approvals, and failure behavior.
Questions must be in the user's language, plain and answerable without knowing
Loomex. Never ask the user to choose node types, node ids, mappings, schemas,
field names, transitions, model names, session policies, tool policies, JSON,
or configuration parameters. The catalog is internal context for Clarifier and
the implementation authority for Designer and Reviewer.

For a batch radio/checkbox Human Input, the effective output schema must expose
`answers` as an array. A downstream mapping is valid only in this exact form:
`{"source":"node_output","nodeId":"<human-key>","field":"answers"}`.
The source Human node must declare that field in its `outputSchema`.

For a condition, every condition object in both branches must include a stable
non-empty `id`, for example `review_valid_true` and `review_valid_false`, as
well as `left`, `operator`, and `right`.

## Output contract

Return only the role-specific schema requested by the workflow node. Do not
return catalog prose as workflow JSON.

## Data mapping examples

Inspect `inputSchema.required` and create one mapping per required field. Check
that `node_output` fields exist in the source node's `outputSchema`.

## Session policy examples

The catalog and workflow contract decide whether `new_each_run` or
`resume_per_node` is valid. A review loop normally needs the latter.

## Tool access examples

Only use catalog-supported tool policies. A guide cannot grant a capability.

## Valid minimal example

Choose `human` only when the live catalog exposes `human` and its canonical
input type supports the requested interaction.

## Valid advanced example

Combine `ai_agent`, `human`, `condition`, and `person` only when every node and
mapping is present in the live catalog and validator.

## Common mistakes

- Treating a guide example as an API contract.
- Assuming a familiar provider or node type is installed.
- Omitting mapping fields because a prompt mentions the data.
- Treating the default single/text Human schema as if it were a batch schema.
- Selecting a source node for `answers` without selecting its `answers` output field.
- Creating branch conditions without condition ids.

## Anti-patterns

Never fabricate node types, schema properties, enums, defaults, or provider
capabilities from this document.

## Backend validation notes

The live `workflowNodeCatalog` and `loomex_workflow_validate` response outrank
all guide content. Invalid candidates must be repaired, not rationalized.
