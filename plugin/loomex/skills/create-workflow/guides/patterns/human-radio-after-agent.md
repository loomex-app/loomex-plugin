# Pattern: Agent -> Human Radio -> Developer

## Purpose

Collect exactly five implementation decisions from a user before development.

## When to use

Use when an agent can generate concrete multiple-choice questions from a task.

## Configuration fields

Agent output must contain question objects. Human node uses `inputType: radio`,
batch mode, `allowOther`, and `otherLabel` according to the catalog.

## Valid enum values

Radio is a valid Human Input type; each question has exactly four options.

## Defaults

Backend derives the canonical Human Input schemas.

## Input contract

Map agent `questions` into Human Input `questions`; map the original task and
canonical human result into Developer inputs.

## Output contract

Radio returns canonical `value` and `label` data, with batch answers where the
Backend schema requires them.

## Data mapping examples

```json
"questions": {"source":"node_output","nodeId":"question_generator","field":"questions"}
```

## Session policy examples

Developer starts with `new_each_run` unless it participates in a repair loop.

## Tool access examples

Question generation is normally read-only; Developer policy follows its local
implementation needs.

## Valid minimal example

Start -> question agent -> radio human -> developer -> end, with all mappings.

## Valid advanced example

Five questions are generated from the task, answers are mapped alongside the
task, and the developer produces a structured implementation result.

## Common mistakes

Missing the `questions` mapping or passing only the selected label to Developer.

## Anti-patterns

Do not model radio as text or invent option selection fields.

## Backend validation notes

Backend Human Input normalization and required mapping validation decide whether
this pattern is executable.

