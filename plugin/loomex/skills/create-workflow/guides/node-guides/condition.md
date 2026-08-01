# Condition node

## Purpose

Route execution using structured values from workflow input or node outputs.

## When to use

Use for a bounded true/false branch such as reviewer approval.

## Configuration fields

Use catalog-defined `trueBranch`, `falseBranch`, logical operators, and
mapping-based conditions.

## Valid enum values

Use only operators and branch fields in the live catalog.

## Defaults

No invented truthiness or implicit branch default.

## Input contract

Every condition operand must reference a valid workflow input, node output, or
catalog-approved static value.

## Output contract

The condition selects a transition branch; it does not fabricate business data.

## Data mapping examples

Compare `reviewer.valid` to `true` for the success branch and `false` for the
repair branch.

## Session policy examples

Not applicable. The target agent nodes own session continuity.

## Tool access examples

Not applicable.

## Valid minimal example

A condition with complete true and false branches and transitions for both.

## Valid advanced example

Reviewer -> condition; false returns to a `resume_per_node` developer and true
maps the reviewer result to end.

## Common mistakes

Using prompt text as a condition, leaving one branch incomplete, or referencing
an unknown node field.

## Anti-patterns

Do not use arbitrary JavaScript, provider expressions, or hidden side effects.

## Backend validation notes

Backend validates branch shape, mapping references, and reachable transitions.

