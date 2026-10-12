# SYRTH

**Static analysis for Python that reports the nearest vulnerability class to your
code, with the evidence and a likelihood — and verifies its own patches.**

Syrth parses Python and reports every point where your code touches a dangerous
operation: which vulnerability class is nearest, how likely it is, and why. It is a
**risk surface mapper, not a verdict machine.** It does not decide whether code is
safe.

```console
$ syrth --path src/
========================================================================
SYRTH - Scan Your Risk Trace History
target : (repository)
model  : rule
scanned: 412 file(s), 3180 function(s), 37 trace(s)
cross-function flows resolved: 6
========================================================================

[CRITICAL] CWE-94 (EXEC) confidence 0.89
  src/handlers/admin.py:31 in rebuild_cache()
  sink: subprocess.run -> EXEC_COMMAND via pos:0
  origin: REQUEST
  >> L28     call     request.GET.get
     L30     arg      request.GET.get('path')
     L31     sink     subprocess.run
------------------------------------------------------------------------
[LOW] CWE-79 (XSS) confidence 0.40
  src/views/comment.py:12 in render_comment()
  sink: HttpResponse -> XSS_RESPONSE_BODY via none
  origin: none (sanitiser assertion)
  reaches a XSS sink but no external origin was confirmed
------------------------------------------------------------------------
```

Two different kinds of statement. The first is a confirmed flow: untrusted input
reaches a command execution sink. The second is a sink contact with no confirmed
flow — the nearest vulnerability class to that function, reported at low
likelihood rather than omitted. **Everything is reported.** Silence is not an
answer.

## What it answers, and what it does not

> **What is the nearest vulnerability class to this code, and how likely is it?**

It does not answer *is this code vulnerable?* It is not a classifier and produces no
accuracy score. A finding is never deleted to improve a number: `--threshold` marks
a finding so a consumer can filter it, and the only things that suppress output are
an explicit suppression file and an inline ignore — decisions you make. The full
contract is in [docs/risk-model.md](docs/risk-model.md), which is the document to
read before quoting any figure from this project.

## Install and run

```bash
pip install -e .                 # two dependencies: tree-sitter only
pip install -e ".[dev,benchmark]"

syrth --file app.py
syrth --path src/ --json
syrth --file app.py --fix        # propose and verify patches
```

Python 3.10+. No PyTorch, no model server, no network.

## Documentation

| I want to | Read |
|---|---|
| know what the tool actually claims | [docs/risk-model.md](docs/risk-model.md) |
| see the measurements | [docs/benchmark.md](docs/benchmark.md) |
| know what it cannot do | [docs/limitations.md](docs/limitations.md) |
| understand the pipeline | [docs/architecture.md](docs/architecture.md) |
| find every open problem | [Context/STATE/known_issues.md](Context/STATE/known_issues.md) |

## Measured behaviour

On the built corpus (350 records, 175 vulnerable/patched pairs, 24 repositories),
against an **independent AST scan** that shares no code with the analyser:

| Measurement | Result |
|---|---|
| category coverage | **95.7%** (111/116) |
| rank agreement | **100%** (22/22) |
| rename invariance | **100%** (350/350) |
| patch kill rate | **89.0%** (89/100) |
| determinism | **100%** (350/350) |

Against the same corpus, the same ground truth, and six instruments. **Sink
coverage** is the stronger axis: it asks only whether each tool looked at the same
dangerous call the AST scan proves is present, so it scores tools that publish no
CWE metadata.

| Tool | Class coverage | Sink coverage | Fix noticed | Still flagged | Time |
|---|---|---|---|---|---|
| **SYRTH 1.0.0** | **111/116** (95.7%) | **199/217** (91.7%) | 8/74 | 66/74 | 3.5s |
| Bandit 1.9.4 | 23/116 (19.8%) | 11/217 (5.1%) | 8/60 | 52/60 | 19.6s |
| Semgrep 1.180.0 `p/security-audit` | 17/116 (14.7%) | 14/217 (6.5%) | 11/25 | 14/25 | 99.0s |
| Semgrep `p/owasp-top-ten` | 0/116 (0.0%) | 0/217 (0.0%) | 1/3 | 2/3 | 24.0s |
| Semgrep `p/python` | 0/116 (0.0%) | 0/217 (0.0%) | 1/3 | 2/3 | 19.5s |
| Ruff 0.16.10 `--select S` | 0/116 (0.0%) | 73/217 (33.6%) | 0/0 | 0/0 | 0.2s |

Four caveats stated plainly, because the table is easy to misread:

- **A `0/116` usually means "does not model this class", not "found nothing".**
  Bandit ships no open-redirect rule and Semgrep's two extra configs carry no rules
  for the seven classes here. Where both tools do have a rule, Bandit wins one:
  **14/15** against SYRTH's **15/15** on CWE-502.
- **Ruff's `0/116` is a metadata gap.** It names 111 findings and none carries a
  CWE, so the class axis cannot score it. It is in the table because dropping it
  would flatter everyone else — and on the axis it *can* be scored on, it reaches
  33.6%, second only to SYRTH.
- **Read the mitigation columns with their denominators.** Semgrep's `11/25` is
  over the 25 pairs it can detect; SYRTH's `8/74` is over 74. Bare percentages
  would credit the narrower field of view.
- **Every tool misses most of the fixes it can see.** SYRTH still flags 66 of the
  74 patches it detects. This is the honest headline and it is not flattering.

This is not a precision or recall measurement. The corpus has no reliable negative
class, and each pair's patched side still contains its sink call by design. The
full per-class matrix and the methodology are in
[docs/benchmark.md](docs/benchmark.md#competitor-comparison).

## Repository layout

```
syrth/        the analyser: parser, taint, registry, guards, reporting
benchmarks/   the measurement surface and the corpus comparison harness
tools/        the corpus builder
tests/        631 tests
docs/         the contract, the measurements, and their limits
legacy/       why the retired v1 pipeline was deleted, and how to check the audit
experiments/  scratch space; the v1 scripts that were here are gone
paper/        WITHDRAWN.md -- which v1 results were withdrawn, and why
Context/      project state, decisions, and open issues
RLTESTS/      smoke-test fixtures: deliberately vulnerable modules
```

`syrth_scan.py` is a compatibility shim that forwards to the current CLI and prints
a notice that the old PyTorch inference path is retired.

## Licence

MIT.