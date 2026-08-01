# End node

## Purpose

Terminate the workflow and expose its public result.

## When to use

Use exactly once as the reachable terminal node unless the live catalog
explicitly supports another terminal shape.

## Configuration fields

Use structural defaults and the catalog-defined output schema.

## Valid enum values

No independent config enum.

## Defaults

Use catalog defaults; do not invent a public envelope.

## Input contract

Map every public result field from an upstream node output or an allowed static
value.

## Output contract

The end output is the workflow's final result and must match its declared
schema.

## Data mapping examples

`{ "source": "node_output", "nodeId": "reviewer", "field": "workflow" }`.

## Session policy examples

Not applicable.

## Tool access examples

Not applicable.

## Valid minimal example

An end node receiving a `result` field from the immediately preceding node.

## Valid advanced example

A reviewer-approved workflow maps name, workflow, rationale, and warnings into
the final result.

## Common mistakes

Leaving the end unreachable or mapping fields that are absent upstream.

## Anti-patterns

Do not make end execute an agent or contain a provider command.

## Backend validation notes

Backend validation checks graph reachability, schema, and output mappings.

