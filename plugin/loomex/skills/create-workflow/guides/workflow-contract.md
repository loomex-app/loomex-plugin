# Loomex workflow contract

## Purpose

Define the canonical wire format used by the Loomex workflow builder.

## When to use

Always. This guide explains semantics; the live Backend node catalog and
validator remain authoritative.

## Configuration fields

Every node is a flat object with `key`, `type`, `name`, `position`, `config`,
`inputs`, `inputSchema`, and `outputSchema` as supported by its catalog entry.
The graph contains `nodes` and `transitions`. Use exactly one `start` and one
`end` node.

## Valid enum values

Use only enum values returned by the live Backend catalog. Human Input values
are `text`, `radio`, `checkbox`, and `boolean`; AI session policies are
`new_each_run` and `resume_per_node`.

## Defaults

Do not invent defaults. Copy catalog defaults or omit optional fields so the
Backend can normalize them.

## Input contract

`start.inputSchema` is the workflow input contract. Every required input on a
non-start node needs an `inputs` mapping. A `node_output` mapping references an
upstream node and an output field; a `workflow_input` mapping references a
start input field; static values use `{ "source": "static", "value": ... }`.

## Output contract

Each node declares the fields it emits in `outputSchema`. The `end` node maps
the public workflow result from upstream node outputs.

## Data mapping examples

```json
{
  "inputs": {
    "taskText": {"source": "workflow_input", "value": "task"},
    "review": {"source": "node_output", "nodeId": "reviewer", "field": "feedback"}
  }
}
```

## Session policy examples

Use `new_each_run` for independent work. Use `resume_per_node` when a loop
returns to the same AI or Person node with correction or review feedback.

## Tool access examples

Use `read_only` unless the node genuinely needs tools. `approval_required` and
`full_access` must be supported by the catalog and policy.

## Valid minimal example

`start -> ai_agent -> end`, with a complete input mapping into the agent and a
complete mapping from the agent into `end`.

## Valid advanced example

`start -> clarifier -> human radio -> designer -> reviewer -> condition`; the
false branch returns to the same designer/reviewer session policy and the true
branch reaches `end`.

## Common mistakes

- Leaving `inputs` empty while `inputSchema.required` is non-empty.
- Referencing a node id or field that does not exist.
- Using UI/React Flow objects instead of flat canonical nodes.
- Adding a second start or end node.

## Anti-patterns

Do not add provider-specific node types, arbitrary config keys, or invented
Human Input output fields. Do not rely on prose in a prompt to carry data that
should be mapped structurally.

## Backend validation notes

The Backend catalog and canonical validator are the final authority. A guide
is explanatory reference context only. If this guide and the catalog differ,
follow the catalog and the validation response.

