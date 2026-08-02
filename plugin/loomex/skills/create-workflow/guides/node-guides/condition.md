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

Each condition object in both `trueBranch.conditions` and
`falseBranch.conditions` must include a stable, non-empty `id`. The id is part
of the persisted workflow contract; it is not optional UI metadata.

## Output contract

The condition selects a transition branch; it does not fabricate business data.

## Data mapping examples

Compare `reviewer.valid` to `true` for the success branch and `false` for the
repair branch, with explicit ids:

```json
{
  "trueBranch": {"conditions": [{
    "id": "review_valid_true",
    "left": {"source": "node_output", "nodeId": "reviewer", "field": "valid"},
    "operator": "==",
    "right": {"source": "static", "value": true}
  }]},
  "falseBranch": {"conditions": [{
    "id": "review_valid_false",
    "left": {"source": "node_output", "nodeId": "reviewer", "field": "valid"},
    "operator": "==",
    "right": {"source": "static", "value": false}
  }]}
}
```

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

Using prompt text as a condition, omitting a branch or its condition id, or
referencing an unknown node field.

## Anti-patterns

Do not use arbitrary JavaScript, provider expressions, or hidden side effects.

## Backend validation notes

Backend validates branch shape, mapping references, and reachable transitions.
