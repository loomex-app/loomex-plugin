# Pattern: Person with memory MCP

## Purpose

Use a reusable Person while keeping memory operations explicit and local to the
Person's allowed MCP tools.

## When to use

Use when the workflow needs durable context across interactions.

## Configuration fields

Use catalog-supported Person identity, model, session, tool policy, prompt, and
memory MCP capability configuration.

## Valid enum values

Use only catalog values and the available memory MCP tool contract.

## Defaults

Do not assume memory access; read, write, and search must be explicitly
available to the Person.

## Input contract

Map task fields into the Person. Memory search criteria are tool inputs, not
hidden workflow inputs.

## Output contract

Return the Person's declared structured result and record memory writes through
the memory MCP audit path.

## Data mapping examples

Person reads relevant memory, performs work, then writes a concise durable fact
with an explicit memory MCP call.

## Session policy examples

Use `resume_per_node` when a correction returns to the same Person.

## Tool access examples

Allowed operations are memory read, write, and search as exposed by the active
MCP policy.

## Valid minimal example

Person -> end with a mapped task and read-only memory search.

## Valid advanced example

Person searches memory, uses the result, writes a validated update, and returns
to a reviewer loop using the same session.

## Common mistakes

Treating memory as arbitrary JSON in the workflow or omitting the Person
identity.

## Anti-patterns

Do not bypass memory MCP with server-side AI execution or unapproved storage.

## Backend validation notes

Person, memory permissions, and catalog validation outrank this guide.

