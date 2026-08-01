# Sub-workflow node

## Purpose

Compose an existing active workflow as a child execution.

## When to use

Use only when reuse is clearer than keeping one graph local.

## Configuration fields

Use catalog-supported workflow reference and version fields.

## Valid enum values

Use only active version selectors supported by the catalog.

## Defaults

Never default to a draft or unknown workflow.

## Input contract

Map child workflow inputs to the child workflow's published input schema.

## Output contract

Declare and map the child result fields consumed by the parent.

## Data mapping examples

Map `node_output` from the child result into a parent agent input.

## Session policy examples

Child execution owns its own agent sessions; parent loops must not assume child
provider session continuity.

## Tool access examples

Child tools remain subject to the child workflow and Runner policies.

## Valid minimal example

A sub-workflow references an existing active workflow and maps its inputs.

## Valid advanced example

A validated reusable review workflow is called by a larger orchestration graph.

## Common mistakes

Referencing the current workflow, a draft version, or missing required inputs.

## Anti-patterns

Do not use sub-workflow to evade graph validation or create recursive execution.

## Backend validation notes

Backend validates existence, active version rules, and recursive references.

