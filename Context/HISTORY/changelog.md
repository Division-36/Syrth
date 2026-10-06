# Changelog — SYRTH

Append-only. Records meaningful changes: architecture, features, significant bug
fixes, decisions, and context-system events. Not debugging noise.

---

## 2026-10-02 — Context system initialised

**Type:** SYSTEM

**Change:**
Created the persistent project context structure: `Context/00_INDEX.md`,
`00_SCHEMA.md`, `SYSTEM/`, `PROJECT/`, `OPERATIONS/`, `STATE/`, `USER/`,
`HISTORY/`.

**Reason:**
The working session lost substantial context: detection quality was debated
using numbers that were later shown to be untrustworthy, and knowledge about the
v1→v3 transition had to be re-derived. Future agents should not repeat that
exploration.

**Affected:** `Context/` (new)

**Note:**
Bootstrapped from the **working tree**, which is uncommitted (52 paths at commit
`3a38572`). Context therefore describes uncommitted v3 work. Re-verify
`Repository Commit` in `00_INDEX.md` after the first v3 commit.

---

## 2026-10-02 — Guard awareness added; mitigation ranking repaired

**Type:** FEATURE / BUGFIX

**Change:**
Added guard recognition (`syrth/parser/guards.py`) covering terminating
allowlist, denylist, equality and anchored-regex validation. Guards rank a flow
below the reporting threshold instead of clearing it. Added
`GUARD_STRENGTH`, `GUARD_REACHABLE_CATEGORIES`, `TaintValue.guards`, and
`STEP_KIND_GUARD`.

Also repaired the mitigation ranking itself: `MIN_TAINT_CONFIDENCE` (0.55) was
applied *after* the mitigation factor and sat *above* the reporting threshold
(0.5), so no mitigation could ever demote a finding. Guard deductions are now
applied after the floor.

Fixed six further guard defects: inverted `in`/`not in` classification; guard
strength written to `TraceStep.edge` but read from `.detail`; `_string_value`
leaving the opening quote attached; `classify_regex_guard` reading the
`argument_list` wrapper as the pattern; `tree_sitter` attribute lookup; and
`.` / `\D` / `\W` being accepted in regex path-safety checks.

**Result:**
RLTESTS smoke-set false-alarm rate 53.3% → 46.7%. Recall held at 96.0%.
Remaining false alarms are deliberately not suppressed because the guards
constrain only a component of the value (`parsed.netloc`, `parts[0]`), which
cannot soundly constrain the whole.

**Affected:** `syrth/parser/guards.py`, `syrth/taint/engine.py`,
`syrth/parser/python.py`, `syrth/trace.py`, `tests/test_guards.py`

**Reason:**
Guard-blindness was the dominant false-alarm cause: idiomatic allowlist-guarded
Django code was reported as a finding.

---

## 2026-10-02 — `format_html` registered as an XSS kill

**Type:** BUGFIX

**Change:**
`django.utils.html.format_html` registered as a full XSS sanitiser rather than an
XSS producer. Also added `conditional_escape` and `strip_tags`, and added these
names to the reserved set.

**Reason:**
`format_html` escapes its substituted arguments and returns a `SafeString`, so it
neutralises XSS exactly as `escape` does. Registering it as a producer (as
`mark_safe` is) meant Django's recommended way to build markup was reported.

**Affected:** `syrth/registry.py`

---

## 2026-10-02 — Benchmark harness defects found and fixed

**Type:** BUGFIX (measurement infrastructure)

**Change:**
Three defects in `benchmarks/run_benchmarks.py`, each of which had been silently
corrupting reported numbers:

1. `alpha_rename` used two-tuple `tokenize.untokenize`, which rebuilds spacing
   heuristically and truncated a backslash line continuation — changing the
   program under test. Now uses five-tuples to preserve exact layout.
2. `renameable_names` renamed *free* names. In a fragment whose imports are not
   visible, `render_to_response` looked local, so the renamer deleted the sink
   under test. Now renames only names the fragment itself binds.
3. `import_bound_names` froze import *aliases*, so aliased calls could never be
   exercised. Aliases are now renameable (renaming one consistently is sound).

**Result:**
Rename invariance 85.5% → 91.1% on the same corpus. The earlier figures were
measuring the harness.

**Affected:** `benchmarks/run_benchmarks.py`,
`tests/test_patch_and_benchmarks.py`

---

## 2026-10-02 — Real labelled corpus built, then found unsound

**Type:** RESEARCH / BUGFIX

**Change:**
Built a labelled corpus from real security fix commits in five projects (django,
urllib3, werkzeug, sqlalchemy, requests) using the OSV API for advisory metadata
and `git archive` / `git show` for code. Pre-fix revisions are labelled with the
advisory CWE; post-fix revisions are labelled safe.

Along the way, four corpus-generation defects were found and fixed: extracted
methods were indented and therefore unparseable (364 of 510 records); prepending
module context broke dedenting; multi-line imports were truncated by a
line-prefix matcher; and the package loop iterated the same package twice,
double-recording every row.

Extraction was moved to `ast`-based module-context collection so records are
self-contained, and records are validated with `ast.parse` before inclusion.

**Then:**
The corpus was found to be **unsound for accuracy measurement** — it labels every
function changed in a commit with that commit's single CWE, producing 255
vulnerable labels from 151 commits (1.7× inflation). Recorded as KI-002.

**Affected:** `data/cve_pairs.jsonl` (generated, gitignored),
`docs/measurements.md`, `Context/STATE/known_issues.md`

---

## 2026-10-02 — Measured results published with their failure modes

**Type:** DOCUMENTATION

**Change:**
`docs/measurements.md` records the measured numbers, the corpus provenance, the
measurement-path defects found while measuring, and the limits of the corpus
(single source ~93% django, assumed-safe patched revisions, unsupported CWEs
scored as misses, no competitor baseline).

**Result:**
Full-set recall on supported CWEs: 13.4% (24/179). Reported-split recall 8.1%.
False-positive rate on patched code 16.9%. Rename invariance 91.1%. Patch kill
rate 73.3%.

**Affected:** `docs/measurements.md`

---

## 2026-10-02 — `benchmarks/rltests.py` added as a labelled regression gate

**Type:** FEATURE

**Change:**
New module evaluating the 40 hand-written `RLTESTS/` functions using their
section markers as function-level labels. Reports recall, false-alarm rate,
abstention, precision and per-CWE detection.

**Reason:**
`RLTESTS/` carried labels that nothing consumed, so they could not detect
regressions. Explicitly documented as a gate, not a benchmark: every vulnerable
example there was written to be findable, so the set has no real-world negative
class.

**Affected:** `benchmarks/rltests.py`

---

## 2026-10-02 — Dead code and packaging defects removed

**Type:** CLEANUP / BUGFIX

**Change:**

- Deleted `syrth/explain/` and `syrth/vocabulary.py` plus their tests. Both were
  unreachable; only a legacy test imported them, and `explain/risk.py` referenced
  an undefined name in an annotation.
- Created the missing `LICENSE` (MIT) and `syrth/py.typed`, which `pyproject.toml`
  already declared. Replaced the deprecated license classifier with the SPDX
  `license` field, eliminating the setuptools warning.
- Fixed `benchmarks/revision_diff.materialise`, which had **never run**: it passed
  both `capture_output=True` and `stdout=` to `subprocess.run`, leaked an open
  file handle that raised `PermissionError` on Windows and masked the real error,
  and required an external `tar`. Rewritten using Python's `tarfile` with a
  path-escape guard.
- Fixed a duplicate `REQUEST/REQUEST` origin produced when `PARAM` was refined to
  `REQUEST` while already present.
- Fixed an undefined `summary` reference in `interproc._compose`'s fallback
  branch (verified unreachable through the public API, so latent, not live).
- Applied 630 ruff safe fixes (PEP 585/604 modernisation, unused imports, import
  order). `ruff check syrth tests benchmarks` is now clean.
- Added `experiments/scratch/` to `.gitignore` and moved v1 benchmark charts and
  stray root scripts into it.

**Affected:** `syrth/explain/`, `syrth/vocabulary.py`, `LICENSE`,
`syrth/py.typed`, `pyproject.toml`, `benchmarks/revision_diff.py`,
`syrth/parser/python.py`, `syrth/interproc.py`, `.gitignore`

---

## 2026-10-02 — Documentation made honest about withdrawn v1 results

**Type:** DOCUMENTATION

**Change:**

- Rewrote `README.md`, `docs/architecture.md`, `paper/main.tex`.
- Created `paper/WITHDRAWN.md` with a claim-by-claim audit.
- Added withdrawal banners to eight v1-era docs.
- Added a 3.0.0 entry to `docs/CHANGELOG.md` recording the withdrawal.
- Created `legacy/README.md` and `experiments/README.md`.
- Corrected test counts after every change (they drifted repeatedly; final count
  recorded in `OPERATIONS/testing.md`).

**Reason:**
Old figures were presented as current across README, paper, `docs/`, and git
commit messages.

**Affected:** `README.md`, `docs/`, `paper/`, `legacy/`, `experiments/`

---

## 2026-10-02 — v3 pipeline rewrite (earlier in this cycle)

**Type:** ARCHITECTURE

**Change:**
Full analysis rewrite: byte-safe parsing, per-sink argument schemas,
category-typed sanitiser kills, taint amplifiers, interprocedural resolution with
provenance, trace certificates, structural revision diff, mechanical patch
verification, SARIF 2.1.0, grouped leak-free training, C header export.
Package version 3.0.0, entry point `syrth`.

Fixed the C export's tree-to-class mapping, per-class base score, forward
declaration and output size guard; exported probabilities now match live xgboost.

**Affected:** all of `syrth/`, `benchmarks/`, `tests/`, `pyproject.toml`

**Recorded as:** D-001, D-002, D-004, D-005

---

## 2026-10-02 — v1 audit and withdrawal of published results

**Type:** RESEARCH

**Change:**
Audited v1 and found: the meta-learner never executed (wrong bundle key, wrong
feature width, swallowed by a bare `except Exception: pass`); its final step was a
hard-coded RCE class index; it was trained and evaluated with the ground-truth
CWE description as a feature; the split was not grouped; ensemble weights were
fitted to held-out accuracy; and the taint extractor seeded from a regex on
identifier names.

Withdrew 70.8%, 86.8%, 94.2%, 91.6%, 93.4%, and the 100% dev/fast agreement
claim.

**Affected:** `paper/WITHDRAWN.md`, `docs/`, `legacy/`

**Recorded as:** D-001, D-004