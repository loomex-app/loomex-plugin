# Tool node

## Purpose

Invoke a catalog-approved local tool through the Runner policy boundary.

## When to use

Use for explicit tool capabilities that are needed by the workflow.

## Configuration fields

Use only catalog-supported tool, method, authentication, request, and policy
fields.

## Valid enum values

Read tool names and policy enums from the live catalog.

## Defaults

No implicit network, shell, or filesystem capability.

## Input contract

Map every request parameter structurally and keep credentials in approved secret
references.

## Output contract

Declare the tool result fields consumed by downstream mappings.

## Data mapping examples

Map a tool result field into an AI or Person input using `node_output`.

## Session policy examples

Not applicable unless the catalog exposes a session-aware tool contract.

## Tool access examples

A tool's own policy and approval requirements are authoritative.

## Valid minimal example

A catalog-listed tool with complete inputs and a declared output schema.

## Valid advanced example

Tool -> Person, where the Person consumes only the explicitly mapped tool result.

## Common mistakes

Inventing a tool name, embedding secrets, or assuming the server executes the
tool.

## Anti-patterns

Do not bypass Runner approvals or add arbitrary provider command arguments.

## Backend validation notes

Backend tool and HTTP request validators outrank all guide examples.

