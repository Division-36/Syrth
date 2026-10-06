# User Preferences — SYRTH

Only preferences **explicitly stated** by the user are recorded here. Nothing
is inferred. Current explicit instructions always outrank this file.

## Language

`[FACT]` The user writes in Egyptian Arabic and expects replies in Egyptian
Arabic.

`[FACT]` Technical identifiers, file paths, commands and code stay in English
regardless of the conversation language.

## Engineering expectations

`[FACT]` Stated explicitly:

- **No fake results.** Fabricated numbers, unverified claims, or demo
  implementations presented as production code are unacceptable.
- **"Just make it work."** When something is broken, the expectation is a working
  fix, not an explanation of why it is hard.
- **Rejected tolerance for half-built systems.** The user described the current
  state as "the engine is stupid and still experimental… nothing works" and
  pressed for it to be fixed.
- **Willingness to rebuild.** The user proposed "a full rebuild from zero on the
  same idea", so large-scope restructuring is on the table if evidence supports
  it.

## Interaction preferences

`[FACT]` The user reacts strongly to incomplete or broken results and expects the
agent to keep working until the task is genuinely finished rather than stopping to
explain obstacles.

`[FACT]` The user values a direct answer to the question asked. They asked what
the benchmark results were and did not want a defence of the work.

## Interaction preferences for asking

`[FACT]` The user has repeatedly pushed back on plans and asked for execution
("fix all of this", "we must rebuild"). Prefer demonstrating a result over
proposing a plan.

`[FACT]` The user asked directly to set up a persistent context system to prevent
this kind of re-exploration and context loss.

## Not recorded / not applicable

- No formatting or style preferences were stated.
- No confirmation cadence was stated.
- No personal information was provided beyond what git history already contains.
- No preferences about review, authorship or attribution.