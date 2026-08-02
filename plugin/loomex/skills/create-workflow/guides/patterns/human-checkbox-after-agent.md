# Pattern: Agent -> Human Checkbox

## Purpose

Collect multiple user selections from an agent-generated question set.

## When to use

Use when more than one option may be selected for each question.

## Configuration fields

Use `inputType: checkbox`, batch mode, exactly four options per question, and
contract-valid `allowOther`/`otherLabel`.

## Valid enum values

Checkbox is a valid Human Input type.

## Defaults

The live Human catalog defaults to single/text. For this pattern explicitly
use batch checkbox configuration and include the effective canonical schemas;
do not rely on normalization to add a missing output field.

## Input contract

Map upstream `questions` into the Human node and map the Human node's canonical
batch `answers` output into the consumer node.

## Output contract

Checkbox uses `values` and `labels`, with canonical batch answers as exposed by
the Backend schema.

## Data mapping examples

Map `node_output.questions` into the Human node's `questions` input and map
`node_output.<human-key>.answers` into the consumer's `answers` input.

## Session policy examples

The workflow execution resumes after the Human response; agent session policy is
independent.

## Tool access examples

Not applicable to the Human node.

## Valid minimal example

Agent -> checkbox Human -> downstream node, with a complete questions mapping.

## Valid advanced example

Checkbox selections control a switch that chooses several independent review
paths.

## Common mistakes

Using a single-value output, omitting the `answers` field from the Human
outputSchema, mapping from an undeclared source field, or using fewer/more than
four options.

## Anti-patterns

Do not substitute radio semantics or invent UI selection keys.

## Backend validation notes

Backend canonical Human Input schemas and mapping validation are authoritative.
