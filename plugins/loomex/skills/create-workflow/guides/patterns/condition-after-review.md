# Pattern: Reviewer false/true branches

## Purpose

Route a review result deterministically.

## When to use

Use after a Reviewer or Person emits a structured validity field.

## Configuration fields

Use a catalog-valid condition with complete true and false branch definitions.

## Valid enum values

Use only catalog condition operators and branch values.

## Defaults

No implicit false or truthy coercion.

## Input contract

Reference the exact reviewer output field in the condition mapping.

Both branch condition objects require stable ids. The id must be present even
when the branch has only one condition.

## Output contract

True reaches the approved path; false reaches the bounded repair path.

## Data mapping examples

Compare `reviewer.valid` to boolean `true` and `false` in separate branches:

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

The repair target uses `resume_per_node` when it is the same Developer/Person.

## Tool access examples

Not applicable.

## Valid minimal example

Reviewer -> condition -> end or developer.

## Valid advanced example

Add a Human correction node on the false path before returning to Developer.

## Common mistakes

Checking a prose warning instead of a boolean field, omitting condition ids, or
leaving the false branch without a transition.

## Anti-patterns

Do not hide a failed Backend validation behind a true branch.

## Backend validation notes

Backend graph and condition validators are authoritative.
