# Switch node

## Purpose

Route execution across multiple catalog-defined branches.

## When to use

Use only when more than two explicit branches materially simplify the workflow.

## Configuration fields

Use the catalog's `evaluationMode` and complete branch definitions.

## Valid enum values

Read evaluation modes and branch schema from the live catalog.

## Defaults

Do not invent a default branch or implicit fallthrough.

## Input contract

Map the value being evaluated and define each branch's comparison explicitly.

## Output contract

Switch selects a transition; it does not mutate node output data.

## Data mapping examples

Route a structured `status` from a reviewer or Person output into named branches.

## Session policy examples

Not applicable.

## Tool access examples

Not applicable.

## Valid minimal example

A catalog-valid switch with two explicit branches and complete transitions.

## Valid advanced example

Route `approved`, `needs_changes`, and `blocked` to separate review paths.

## Common mistakes

Leaving branch data unknown or adding branches that have no transition.

## Anti-patterns

Do not use switch to hide an invalid condition or to bypass validation.

## Backend validation notes

Backend catalog and graph validation decide whether the switch shape is valid.

