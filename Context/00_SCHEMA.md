# Context System Schema

This file defines the context system itself. Read it before adding to or
restructuring `Context/`.

## Purpose

`Context/` is the persistent operational memory of the project for AI agents. It
exists to avoid repeated repository exploration, preserve decisions, prevent
context loss, and let agents load only what a task needs.

It is **not** documentation, **not** a README, and **not** a place for guesses.

## Knowledge classification

Every non-obvious claim in `Context/` must carry one of these tags.

| Tag | Meaning |
|---|---|
| `[FACT]` | Directly verified from repository evidence or a command that was run |
| `[INFERENCE]` | Conclusion derived from multiple verified facts |
| `[ASSUMPTION]` | Plausible but unverified |
| `[UNKNOWN]` | Could not be determined |
| `[STALE]` | Was valid, may no longer reflect the repository |
| `[CONFLICT]` | Two or more sources disagree |

Promoting a tag requires evidence. `ASSUMPTION → FACT` without a verifying
command is contamination and is the primary failure mode this system guards
against.

## Authority order

When sources disagree, the higher entry wins:

```
current source code
  > current tests
  > current configuration
  > current executable behaviour
  > current documentation
  > Context/
  > git history
  > AI inference
```

Context is never authority over code. It is a cache of verified knowledge that
can be stale.

## Conflict handling

1. Identify both sources.
2. Classify the conflict:
   - **Objective factual** (e.g. Context says Python 3.10, `pyproject.toml` says
     `>=3.12`): resolve automatically, update Context, note it in the changelog.
   - **Interpretive** (e.g. code looks mid-migration): stop and ask if the
     distinction changes the task outcome.
   - **Architectural** (a design decision): stop and ask. Never silently pick
     one side.
3. Never erase meaningful history. Supersede with a new record.

## Directory purposes

| Directory | Contains | Must not contain |
|---|---|---|
| `SYSTEM/` | Stable agent operating rules, safety limits, workflow | Temporary project state |
| `PROJECT/` | Mission, architecture, technical detail, file map | Mutable status, secrets |
| `OPERATIONS/` | Commands, environment, testing strategy | Architecture prose |
| `STATE/` | Mutable current truth: state, issues, decisions | Long-form history |
| `USER/` | Explicitly stated user preferences | Invented preferences, private data |
| `HISTORY/` | Append-only changelog and archives | Current-state assertions |

## Update rules

- Update only what a change actually invalidates. Do not rewrite unrelated files.
- Every `[VERIFIED]` command label must correspond to a command that was run.
- After meaningful work, decide whether the repository, knowledge, state,
  decisions, issues, architecture, or user preferences changed. If none did,
  do not touch `Context/`.
- Never rewrite a superseded decision. Add a new decision referencing the old ID.

## Anti-contamination rules

Before recording any claim ask:

1. What is the evidence?
2. Is it current?
3. Observed or inferred?
4. Does another source disagree?
5. Is it important enough to persist?

If the answer to 1 or 3 is unclear, tag it `[ASSUMPTION]` or `[UNKNOWN]`
explicitly rather than writing it as prose that reads like fact.

## Freshness

`00_INDEX.md` carries `Last Verified` and `Repository Commit`. When the working
tree gains a commit that invalidates context, re-verify the affected modules and
update both fields. Mark superseded modules `[STALE]` rather than deleting them.