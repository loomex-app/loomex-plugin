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

The live catalog default is single/text. Backend normalization remains the
authority, but the AI-generated draft is validated before normalization and
must include the effective canonical `inputSchema` and `outputSchema`.
Do not omit them and do not invent a competing schema.

## Input contract

Dynamic radio/checkbox forms map `questions`. Text/boolean forms use the
canonical question/value contract defined by the Backend.

## Output contract

Text and boolean use canonical `value`. A single radio response may expose
`value` and `label`; a single checkbox response may expose `values` and
`labels`. A dynamic radio/checkbox node with `collectionMode: "batch"` must
declare `answers` as an array in its `outputSchema`, because downstream nodes
map the complete response through that field. The effective batch schema must
also identify the canonical schema version, input type, and collection mode.
Typed Human Input must not invent `selected`, `answer`, `approval`, or other
output keys.

## Data mapping examples

`questions` maps from an upstream agent's structured questions output. A text
correction form maps its question from static config or an upstream field. For
batch responses, consumers must map the exact output field:

```json
"answers": {
  "source": "node_output",
  "nodeId": "clarification_input",
  "field": "answers"
}
```

This mapping is invalid unless `clarification_input.outputSchema.properties`
contains `answers`.

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

Using fewer or more than four options, missing the questions mapping, omitting
the effective batch output schema, mapping `answers` from a source that does
not declare it, or expecting a radio response as free-form text.

## Anti-patterns

Do not invent `optionId`, `selected`, `approval`, or `answer` output fields.
Do not add a hand-written schema that conflicts with Backend normalization.

## Backend validation notes

Backend Human Input normalization and validation are authoritative.
