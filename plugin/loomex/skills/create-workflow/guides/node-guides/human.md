# Human Input node

## Purpose

Pause execution and collect a canonical user response.

## When to use

Use for information, clarification, approval-like decisions represented by the
active Human Input contract, or explicit user correction.

## Configuration fields

Valid `inputType` values are exactly `text`, `radio`, `checkbox`, and
`boolean`. Radio and checkbox are batch question forms. Configure
`allowOther` and `otherLabel` only according to the active contract.

## Valid enum values

`text`, `radio`, `checkbox`, and `boolean` only. Do not use provider or UI
selection enums.

## Defaults

Backend derives canonical `inputSchema` and `outputSchema` from the Human Input
config and mappings. Do not hand-author competing schemas.

## Input contract

Dynamic radio/checkbox forms map `questions`. Text/boolean forms use the
canonical question/value contract defined by the Backend.

## Output contract

Radio output uses `value` and `label`. Checkbox output uses `values` and
`labels`. Batch forms may also expose canonical `answers[]` according to the
Backend-generated schema. Typed Human Input must not invent other output keys.

## Data mapping examples

`questions` maps from an upstream agent's structured questions output. A text
correction form maps its question from static config or an upstream field.

## Session policy examples

Not applicable; Human Input resumes the same workflow execution.

## Tool access examples

Not applicable.

## Valid minimal example

A radio node with exactly four options per question and a mapping for dynamic
`questions` when questions are supplied by an agent.

## Valid advanced example

Agent -> Human Radio -> Developer, where the developer maps canonical answers
and the original task separately.

## Common mistakes

Using fewer or more than four options, missing the questions mapping, or
expecting a radio response as free-form text.

## Anti-patterns

Do not invent `optionId`, `selected`, `approval`, or `answer` output fields.
Do not add a hand-written schema that conflicts with Backend normalization.

## Backend validation notes

Backend Human Input normalization and validation are authoritative.

