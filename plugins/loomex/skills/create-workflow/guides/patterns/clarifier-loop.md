# Pattern: Clarifier loop

## Purpose

Turn an ambiguous request into an implementation-ready specification.

## When to use

Use before Designer when the user's desired outcome, audience, inputs,
interaction, approval, or failure behavior is unclear. Technical implementation
details are internal decisions for Loomex and the Designer.

## Configuration fields

Clarifier returns `clear`, complete `clarifiedPrompt`, and exactly five radio
questions when clarification is needed.

## Valid enum values

Each clarification question uses `inputType: radio` and exactly four options.

## Defaults

If answers are absent or insufficient and a user-facing decision is unclear,
ask exactly five simple questions in the user's language; never design the
workflow in Clarifier. If the user-facing behavior is clear, infer sensible
technical defaults and set `clear=true`.

## Input contract

Map the original user request and previous canonical answers into Clarifier.

## Output contract

When clear, questions is empty and clarifiedPrompt is complete. Otherwise clear
is false and questions contains exactly five useful radio questions.

## Data mapping examples

Clarifier -> condition; false -> Human Radio -> Clarifier; true -> Designer.

## Session policy examples

Clarifier may use `resume_per_node` across question rounds.

## Tool access examples

Clarifier is normally read-only and uses catalog/reference context.

## Valid minimal example

Request -> Clarifier -> condition -> Designer or Human Radio.

## Valid advanced example

Several clarification rounds continue until user-facing behavior is resolved,
with a bounded retry policy. The catalog may be used internally to understand
what is possible, but it must not be exposed as a questionnaire.

## Common mistakes

Asking the user to choose a node type, node id, mapping, schema, field name,
transition, model, session policy, tool policy, JSON shape, or configuration
parameter.

## Anti-patterns

Do not return a workflow JSON from Clarifier, ask generic confirmation, or use
technical vocabulary when a plain-language question is possible.

## Backend validation notes

Backend schema validation and the seeded workflow's bounded loop are final.
