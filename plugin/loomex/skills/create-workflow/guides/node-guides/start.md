# Start node

## Purpose

Declare the workflow's external input contract.

## When to use

Use exactly once as the graph entry point.

## Configuration fields

Use the catalog-defined `name`, `inputSchema`, and `outputSchema`. Do not add
`start.inputs`; the schema properties define workflow inputs.

## Valid enum values

No independent config enum. Use the live catalog.

## Defaults

Use the built-in structural defaults.

## Input contract

Start receives the user/workflow invocation input. Its schema properties are
the only valid targets for `workflow_input` mappings.

## Output contract

Start exposes its declared input fields to downstream `node_output` mappings.

## Data mapping examples

`{ "source": "node_output", "nodeId": "start", "field": "task" }` is valid
only when `start.inputSchema.properties.task` exists.

## Session policy examples

Not applicable.

## Tool access examples

Not applicable.

## Valid minimal example

One `start` node with an object input schema and a transition to the next node.

## Valid advanced example

Start declares `task`, `answers`, and optional execution metadata used by
separate downstream mappings.

## Common mistakes

Adding `start.inputs`, using more than one start, or referencing undeclared
workflow input fields.

## Anti-patterns

Do not put provider prompts or Human Input configuration on start.

## Backend validation notes

The Backend graph validator owns start uniqueness, reachability, and schema
validity.

