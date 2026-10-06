# Agent Operating Rules — SYRTH

## Repository-specific constraints

1. **`syrth/` is the only v3 product code.** Root-level `*.py` files
   (`benchmark.py`, `collect.py`, `harvester.py`, `train_model.py`, …) plus
   `experiments/` and `legacy/` are v1 audit material. They are **not maintained**
   and are not evidence of current behaviour.
2. **`syrth_scan.py` is a deprecation shim**, not the scanner. It forwards to
   `syrth.scan`. Do not add features to it.
3. **The security registry (`syrth/registry.py`) is the single source of truth**
   for sinks, sources, sanitisers and CWEs. Never add a sink in a parser module.
4. **`syrth/parser/guards.py` holds guard recognition.** Guard logic elsewhere is
   a bug, not an extension point.
5. **No PyTorch.** The default install must stay at two runtime dependencies
   (tree-sitter, tree-sitter-python). Anything heavier belongs in an extra.
6. **No committed generated data.** `data/`, `*.joblib`, `syrth_codebert/`,
   `*.safetensors`, `syrth_engine.{h,so}` are gitignored. Do not force-add them.

## Validation requirements

Before reporting work complete, run and report the actual result of:

```
python -m pytest tests -q -o addopts=
python -m ruff check syrth tests benchmarks
```

Never state a command passed unless it was run in this session. If a command
cannot be run, say `[NOT VERIFIED]` and give the reason.

## Evidence discipline

This project has a documented history of **measuring before fixing**, which
produced three consecutive wrong benchmark numbers. Therefore:

- A number is not a result until the measurement path that produced it has been
  checked for defects.
- When a metric changes after a fix, establish whether the *measurement* moved
  or the *system* moved. Do not assume the system moved.
- Any new benchmark harness must be validated against a known-answer case before
  its output is quoted.

## Reporting honesty

- Quote confidence intervals alongside point estimates.
- State corpus size and composition with every accuracy figure.
- When a label is an assumption (e.g. "the patched revision is safe"), say so.
- Do not report a metric the tool does not claim to support as a failure without
  saying it was out of scope.

## Code conventions

- Follow existing style: `from __future__ import annotations`, full type
  annotations, dataclasses for records, module-level constant tables for
  security data.
- Docstrings explain *why*, especially for non-obvious safety decisions. The
  codebase already does this well; match it.
- Line length 100; ruff enforces `E,F,W,I,B,UP` with `E501` ignored.
- Tests use pytest classes grouping a behaviour area. New behaviour needs a test
  that fails when the behaviour is absent.

## Autonomy

Low-risk actions (reading, searching, running tests, correcting objectively stale
context) proceed without asking. Medium-risk changes (implementation logic,
tests, config, public API) proceed when the user's request clearly authorises
them and the intended behaviour is clear. High-risk actions (destructive
operations, architecture changes, changing project direction, deleting data)
require explicit confirmation.