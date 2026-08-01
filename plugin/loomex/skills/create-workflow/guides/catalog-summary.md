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

## Valid enum values

There is no independent enum list in this guide. Read enum values from the
Backend catalog included in the provider context.

## Defaults

The Backend catalog owns defaults. A missing guide or summary never authorizes
an invented default.

## Input contract

Ask questions only about decisions that affect catalog-valid node types,
schemas, mappings, Human Input behavior, sessions, tools, or branches.

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

## Anti-patterns

Never fabricate node types, schema properties, enums, defaults, or provider
capabilities from this document.

## Backend validation notes

The live `workflowNodeCatalog` and `loomex_workflow_validate` response outrank
all guide content. Invalid candidates must be repaired, not rationalized.

