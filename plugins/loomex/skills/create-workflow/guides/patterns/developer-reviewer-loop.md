# Pattern: Developer -> Reviewer -> Condition

## Purpose

Implement work, review it, and boundedly repair the same developer session.

## When to use

Use for code generation, document generation, and other work requiring review.

## Configuration fields

Developer and Reviewer are AI/Person nodes with structured schemas. Reviewer
returns a boolean validity decision and actionable feedback.

## Valid enum values

Use `resume_per_node` on the returning Developer path and catalog-valid branch
configuration.

## Defaults

Reviewer validation must call the official Loomex MCP validator when a workflow
candidate is being reviewed.

## Input contract

Map task, developer output, reviewer feedback, and human correction explicitly.

## Output contract

Condition routes `valid=true` to success and `valid=false` to repair.

## Data mapping examples

```json
"reviewerFeedback": {"source":"node_output","nodeId":"reviewer","field":"warnings"}
```

## Session policy examples

Developer and Reviewer can each resume their own prior session when the graph
returns to that node; never spawn a replacement for a resume directive.

## Tool access examples

Reviewer is normally read-only and may use `loomex_workflow_validate`.

## Valid minimal example

Developer -> Reviewer -> Condition -> End or Developer.

## Valid advanced example

Human correction joins reviewer feedback and returns to Developer, then the same
Reviewer session evaluates the repaired result.

## Common mistakes

Using `new_each_run` on a repair edge, omitting feedback mappings, or allowing
unbounded retries.

## Anti-patterns

Do not let subjective reviewer preference override Backend validation.

## Backend validation notes

The Backend owns the validation result and bounded repair state.

