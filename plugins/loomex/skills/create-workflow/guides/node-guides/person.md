# Person node

## Purpose

Run a configured Loomex Person locally as an agent with its identity and
memory tools.

## When to use

Use when the workflow needs a reusable person identity, not merely a one-off
AI-agent prompt.

## Configuration fields

Use catalog-supported `personId`, `model`, `effort`, `temperature`,
`sessionPolicy`, `toolAccessPolicy`, `prompt`, and `prompts`.

## Valid enum values

Use the same session and tool policy enums exposed by the catalog. Do not add
provider or memory enums locally.

## Defaults

Use the Person and catalog defaults. A Person's identity must resolve to an
active organization-owned Person.

## Input contract

Map task and feedback fields explicitly. Memory context is accessed through the
Person's memory MCP tools, not by smuggling unrelated workflow state into the
prompt.

## Output contract

Declare the structured result expected from the Person node.

## Data mapping examples

Map `taskText` from `start` or a prior node and map reviewer feedback when a
Person participates in a repair loop.

## Session policy examples

Use `resume_per_node` when the same Person must continue a review loop.

## Tool access examples

The Person may use memory MCP tools for memory read, write, and search when
those tools are available under the catalog/policy.

## Valid minimal example

An active Person with one mapped task field and a structured output.

## Valid advanced example

A Person reads relevant memory, performs work, writes a durable memory update,
and returns a structured result through the same local agent session.

## Common mistakes

Treating Person as a free-form provider node, omitting `personId`, or inventing
memory fields in the workflow schema.

## Anti-patterns

Do not execute Person logic on the server or bypass memory MCP with hidden
filesystem/network access.

## Backend validation notes

Catalog, Person status, permissions, and Backend validation outrank this guide.

