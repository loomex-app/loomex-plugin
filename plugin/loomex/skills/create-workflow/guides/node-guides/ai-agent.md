# AI Agent node

## Purpose

Perform local agent work through the Plugin/Runner-selected provider route.

## When to use

Use for reasoning, clarification, design, implementation, review, or other
model work that belongs in a workflow.

## Configuration fields

Use catalog-supported `model`, `effort`, `temperature`, `sessionPolicy`,
`toolAccessPolicy`, `prompt`, or `prompts`. The live catalog defines exact
requirements and limits.

## Valid enum values

`sessionPolicy` is `new_each_run` or `resume_per_node`. Tool policy is
`read_only`, `approval_required`, or `full_access` when exposed by the catalog.

## Defaults

Use catalog defaults. Do not infer a model or effort from the parent Codex
session.

## Input contract

Declare all required task, feedback, correction, and review fields in
`inputSchema` and map them explicitly in `inputs`.

## Output contract

Declare a structured `outputSchema`; the Runner validates the returned object.

## Data mapping examples

Developer inputs can map `taskText`, `reviewerFeedback`, and `humanCorrection`
from upstream outputs, with static empty feedback only when the contract allows
it.

## Session policy examples

Use `new_each_run` for a first independent attempt. Use `resume_per_node` for a
false reviewer branch so the same agent session receives feedback.

## Tool access examples

Use `read_only` for clarification/review; use a catalog-approved write policy
only when implementation needs local tools.

## Valid minimal example

An agent with a prompt, output schema, required input mappings, and a transition
to `end`.

## Valid advanced example

Developer -> reviewer -> condition, with the false branch returning to the
developer using `resume_per_node`.

## Common mistakes

Changing the server prompt, omitting required mappings, or returning prose
instead of the declared JSON object.

## Anti-patterns

Do not execute the model on the server, construct React Flow JSON, or invent a
provider-specific config field.

## Backend validation notes

Backend validation is authoritative; Plugin reference context never overrides
the catalog, schemas, or validation result.

