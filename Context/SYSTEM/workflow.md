# Agent Workflow — SYRTH

## Standard loop

```
BOOT → LOAD → VERIFY → PLAN → EXECUTE → VALIDATE → SYNCHRONIZE → RECORD
```

### BOOT
- Does `Context/00_INDEX.md` exist?
- Read it. Note `Repository Commit` and whether the working tree is dirty.
- If the tree is dirty, `Context` describes the working tree, not a commit.

### LOAD
- Use `00_INDEX.md` task routing to select modules.
- Load the minimum needed. Expand only when a dependency, contradiction, or
  unverifiable critical fact appears.

### VERIFY
- Re-verify anything the task depends on: current test count, current behaviour
  of a function you intend to change, existence of a file you will reference.
- `[STALE]` context is not evidence. A `[FACT]` is only evidence until the
  repository contradicts it.

### PLAN
- Scale the plan to risk. A one-line fix needs no plan section.
- For anything touching detection or measurement, state explicitly how you will
  know whether it worked. Detection work without a stated success criterion is
  how the previous cycle went wrong.

### EXECUTE
- Stay inside the authorised scope. Report unrelated findings; do not silently
  fix them.
- Read a file fully before editing it.

### VALIDATE
- Run the real commands. Record real output.
- `[NOT VERIFIED]` is an acceptable, required result when a command cannot run.

### SYNCHRONIZE
Update only what changed:

| Change | Context update |
|---|---|
| New/renamed/deleted file | `PROJECT/file_map.md` |
| Architecture or interface | `PROJECT/architecture.md`, `STATE/decisions.md` |
| Fixed or found bug | `STATE/known_issues.md` |
| New verified command | `OPERATIONS/commands.md` |
| Development status, blockers | `STATE/current_state.md` |
| Dependency / env change | `OPERATIONS/environment.md` |
| Test strategy or gap | `OPERATIONS/testing.md` |
| Durable user preference | `USER/preferences.md` |

### RECORD
Append meaningful entries to `HISTORY/changelog.md`. Do not log formatting-only
or debugging noise. Archive superseded material to `HISTORY/archive/` rather than
deleting it.

## Risk-scaled variation

| Risk | Variation |
|---|---|
| Low | LOAD may be skipped for trivial, self-contained edits |
| Medium | Full VERIFY of touched modules; explicit success criterion |
| High | Add PLAN + confirmation before EXECUTE; require written validation plan |

## Anti-pattern observed in this project

Recording as a standing warning because it actually happened:

> Fixing first and measuring afterwards produced three successive wrong benchmark
> numbers (9.4% → 8.1% → stable), because each fix revealed a defect in the
> *measurement*, not the system. Establish that a measurement path is sound
> before quoting anything it produces.