# Pattern: Clarifier loop

## Purpose

Turn an ambiguous request into an implementation-ready specification.

## When to use

Use before Designer when node choice, Human Input shape, mappings, session
continuity, tools, or branch behavior is unclear.

## Configuration fields

Clarifier returns `clear`, complete `clarifiedPrompt`, and exactly five radio
questions when clarification is needed.

## Valid enum values

Each clarification question uses `inputType: radio` and exactly four options.

## Defaults

If answers are absent or insufficient, ask five concrete implementation
questions; never design the workflow in Clarifier.

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

Several clarification rounds continue until decisions affecting the canonical
graph are resolved, with a bounded retry policy.

## Common mistakes

Declaring a high-level request clear without deciding concrete node contracts.

## Anti-patterns

Do not return a workflow JSON from Clarifier or ask generic confirmation.

## Backend validation notes

Backend schema validation and the seeded workflow's bounded loop are final.

