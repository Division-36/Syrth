# Known Issues — SYRTH

Verified 2026-10-02 against working tree at `3a38572` (dirty).

---

## KI-010 -- Four of eleven classes have no corpus evidence

- **ID:** KI-010
- **Status:** OPEN (reduced from six classes)
- **Severity:** HIGH
- **Affected Area:** `data/corpus.jsonl`, published coverage claims

**Description**
The corpus covers CWE-22, 79, 89, 94, 502, 601 and 918. CWE-327, 434, 611 and 798
have zero records, so nothing is claimed or measurable about them.

**Evidence**
704 in-scope advisories were harvested from 192 distributions. CWE-89 was
recovered (40 pairs) by adding the `module-proximity` evidence tier, because
Django's SQL fixes build the query in one function and execute it in another. The
remaining four are absent because no harvested advisory both named the class and
tied its fix to a recognisable sink.

**Next step**
Widen the harvest. Do not relax `class_evidence`.

**Fixed this cycle:** CWE-89 (40 pairs) and CWE-918 (4 pairs).

---

## KI-011 -- Registry gap: bare `md5`/`sha1` are not weak-crypto sinks

- **ID:** KI-011
- **Status:** OPEN
- **Severity:** LOW
- **Affected Area:** `syrth/registry.py` crypto sinks

**Description**
`hashlib.md5` and `hashlib.sha1` resolve to `CRYPTO_WEAK`, but a bare `sha1`
imported from a crypto module does not. `_CRYPTO_MODULES` exists but no
`_register_importable` call binds `md5`/`sha1` from those modules, so code that
does `from cryptography.hazmat.primitives import hashes as sha1`-style imports
gets no CWE-327 finding.

**Evidence**
`canonical_sink("sha1")` returns `None`; `canonical_sink("hashlib.sha1")` returns
`CRYPTO_WEAK`. Found while validating corpus labels; it removed one legitimate
CWE-327 candidate.

---

## KI-012 -- Harness kill rate is not comparable across corpora

- **ID:** KI-012
- **Status:** OPEN
- **Severity:** MEDIUM
- **Affected Area:** `benchmarks/risk_metrics.py`, `docs/benchmark.md`

**Description**
Kill rate reads 85.5% on the superseded corpus and 80.7% on the built one. The
difference is corpus difficulty, not analyser regression: the built corpus
contains fixes that add a validation check (keras `ShardedH5IOStore`, notebook's
redirect guard) where the sink call legitimately survives.

**Risk**
Quoting both numbers without this context invites a false regression claim.

---

---

## KI-013 -- Chain elements are reported as if they were sinks

- **ID:** KI-013
- **Status:** OPEN
- **Severity:** MEDIUM
- **Affected Area:** `syrth/registry.py`

**Description**
Ten adjudicated rejections share one shape: the finding names the weakest link in
a chain rather than the dangerous operation. `os.path.abspath` is normalisation,
`jinja2.Environment` is a constructor, `__import__` is a dynamic import. All three
are steps *toward* a vulnerability.

**Evidence**
`os.path.join` is
kept as defensible for CWE-22 because it is where an unsanitised segment enters a
path; the line between chain element and sink is that boundary, and the three
rejected calls fall on the wrong side of it.

**Next step**
Decide per call whether it is a terminal sink or a chain link, and report chain
links as evidence on the finding rather than as the finding's sink. No
architecture change is required.

---

## KI-014 -- Kill-survivors are exported but not adjudicated

- **ID:** KI-014
- **Status:** OPEN (exiting containment guards modelled as evidence; value-level guards still invisible)
- **Severity:** MEDIUM
- **Affected Area:** `syrth/containment.py`, `syrth/parser/python.py`, `syrth/scan.py`, `benchmarks/adjudicate.py`

**Description**
56 patched functions still report their class. A surviving finding is not
automatically a wrong one: the guard may be an idiom with no rule here, or the sink
may be reachable by design, or the diff may not contain enough to decide.
`benchmarks/adjudicate.py` exports the cases for a human to read.

**Resolved 2026-10-05 (partly).** `syrth/containment.py` recognises the *exiting*
containment idiom -- `os.path.commonpath`/`Path.relative_to`/`dirname` compared in
an `if` whose body cannot fall through, with the sink afterwards and sharing state
with the guard. Loop exits are bounded to their loop body, since code after the loop
is reachable on a later iteration.

**The guard is evidence, not a deletion.** An earlier version moved guarded findings
into `report.suppressed` and dropped category coverage from 95.7% to 94.8%, because
removing a guarded sink removes a class name the report is meant to contain. Per
`docs/risk-model.md`, a guard now lowers the finding's likelihood to 0.12 and names
the guard line in `reasons`; the finding stays in the report. Pinned by
`tests/test_scan.py::TestNothingIsSilencedByTheAnalyser`, which asserts the invariant
over the whole report rather than per case.

**Boundary of the model**
The guard model is **type-level** -- does this call neutralise this category -- and
not **value-level** -- does this branch constrain the value. Reproduced: a function
whose only path to `torch.load` runs past an unconditional `raise` still reports
CWE-502, and an early `return None` does not lower CWE-22. A guard whose safety
depends on the value rather than the call is invisible to the analyser by
construction, which is a structural limit, not a missing rule.

**Also invisible: guard and sink refer to different names.** Several corpus survivors
constrain one variable while the sink joins another, so the sharing check declines to
credit the guard. `".." in PurePath(filename).parts` guarding `os.path.join(dirname,
filename)` is the clear case: for `../../etc/passwd` the basename carries no `..`, so
the guard passes while `dirname` still walks upwards. Modelling that needs to know
which argument the guard constrains, which is value-level work. See the rejected
experiment recorded in `syrth/containment.py`.

---

## KI-001 — Detection quality is unquantified

- **ID:** KI-001
- **Status:** OPEN
- **Severity:** CRITICAL
- **Affected Area:** whole detection path (`parser`, `taint`, `interproc`, `registry`)

**Description**
No trustworthy recall or precision figure exists for v3. Every number produced so
far was later invalidated by a defect in the measurement rather than in the
system.

**Evidence**
Three successive benchmark runs of an unchanged engine produced recall
9.4% → 8.1% → 8.1%. Each change traced to a harness or corpus defect, not to
engine behaviour. On the full 249-record vulnerable set the engine detects 24
records; on the reported 124-record split, 5. Same engine, same data, ×4.8
difference — so the split is contributing noise to any figure derived from it.

Of 249 "vulnerable" records, 70 carry a CWE outside the tool's label space
(CWE-400 ×43, CWE-200 ×27) and cannot be detected by construction. Excluding
them, recall is **13.4%** (24/179). This is the most defensible figure produced
so far, and it is still poor.

**Reproduction**
```
python -m benchmarks.run_benchmarks --dataset data/cve_pairs.jsonl
```
Expect precision ≈26%, recall ≈8%, invariance ≈91%, kill rate ≈73%.

**Known Workaround**
None. Treat the tool as an unaudited prototype, not a validated analyser.

**Potential Fix**
Diagnose the missed set before changing anything: sample the records with a
supported CWE that are not detected and determine, per case, whether the failure
is an unknown sink, an unrecognised source, a broken propagation edge, a guard
over-suppression, or a scope mismatch. Only then decide between targeted repair
and a rewrite.

**Last Verified:** 2026-10-02

---

## KI-002 — Corpus label strategy over-assigns vulnerabilities

- **ID:** KI-002
- **Status:** OPEN
- **Severity:** CRITICAL
- **Affected Area:** corpus generation, all accuracy measurement

**Description**
The corpus builder labels **every function changed in a fix commit** with that
commit's single CWE. A commit that fixes one SQLi while refactoring five
functions produces five "vulnerable CWE-89" labels; at most one is correct.

**Evidence**
151 distinct fix commits produced 255 "vulnerable" labels — a **1.7×
inflation**. Distribution of vulnerable labels per commit: 96 commits → 1,
40 → 2, 10 → 3, 3 → 4, 1 → 12, 1 → 25. The 12- and 25-function commits are
refactors, not 12 and 25 distinct vulnerabilities.

Consequently the claim "the engine misses 92% of real vulnerabilities" is not
supportable — most of the missed records were never vulnerable.

**Reproduction**
Count `vulnerable` labels against distinct `(repo, commit)` pairs in the
generator output.

**Known Workaround**
None. This makes every current accuracy number unusable, including the 13.4% in
KI-001.

**Potential Fix**
Identify the actually-vulnerable function per commit by intersecting the commit
diff with the advisory's affected file, or by validating that the pre-fix
function contains the sink the advisory names. Record which method was used per
record. Then regenerate.

**Last Verified:** 2026-10-02

---

## KI-003 — No CI, and no detection regression gate

- **ID:** KI-003
- **Status:** OPEN
- **Severity:** MEDIUM
- **Affected Area:** delivery process

**Description**
`.github/` does not exist. Nothing runs automatically. Detection quality has no
automated guard, so a change that halves recall would not be caught.

**Evidence**
`[FACT]` No CI configuration in the repository. `benchmarks/rltests.py` is
runnable but is not collected by pytest and not invoked by any target.

**Reproduction**
`Test-Path .github` → `False`.

**Known Workaround**
Manual: run the two validation commands before every hand-off.

**Potential Fix**
Add a CI workflow running `pytest` and `ruff`. Add a pytest test that asserts the
`RLTESTS` smoke-set floor so detection regressions fail loudly.

**Last Verified:** 2026-10-02

---

## KI-004 — Rename invariance is below the documented guarantee

- **ID:** KI-004
- **Status:** OPEN
- **Severity:** HIGH
- **Affected Area:** detection path; `benchmarks/run_benchmarks.py`

**Description**
The product claims rename invariance as a core property. Measured invariance on
the corpus is **91.1%**, so ~9% of verdicts change when locals are renamed.

**Evidence**
`python -m benchmarks.run_benchmarks …` reports `rename invariance 91.13%`.
Note this figure was itself inflated by two harness defects (two-tuple
`untokenize` truncating line continuations, and free names being renamed); both
are fixed, and the residual 8.9% is unexplained. A verified spot check showed a
simple case (`request` vs `q` as a parameter name) preserves the CWE verdict, so
the residual failures are narrower than the headline suggests and need
per-case analysis.

**Reproduction**
Run the benchmark and read the invariance warning.

**Known Workaround**
None.

**Potential Fix**
Enumerate the ~9% unstable records and determine per case whether the cause is
the engine (name-derived sources, sink resolution) or still the harness.

**Last Verified:** 2026-10-02

---

## KI-005 — Confirmed flows survive correct sanitisers

- **ID:** KI-005
- **Status:** OPEN
- **Severity:** MEDIUM
- **Affected Area:** `syrth/taint/engine.py`, `syrth/registry.py`

**Description**
26.7% of confirmed flows in the benchmark were not killed by a sanitiser the
engine itself recognised as correct. A patch that genuinely fixes the bug can
therefore still be reported as vulnerable.

**Evidence**
Benchmark warning: "26.7% of confirmed flows survived a correct sanitiser; the
kill model does not yet understand those categories."

**Reproduction**
Run the benchmark and read the kill-rate warnings.

**Known Workaround**
None.

**Potential Fix**
Enumerate the surviving (category, sanitiser) pairs and extend the kill table.

**Last Verified:** 2026-10-02

---

## KI-006 — `make typecheck` cannot run

- **ID:** KI-006
- **Status:** OPEN
- **Severity:** LOW
- **Affected Area:** `Makefile`, `pyproject.toml`

**Description**
`make typecheck` invokes `mypy`, which is not declared in any dependency group.
The package ships `py.typed` and is fully annotated but nothing enforces it.

**Reproduction**
`make typecheck` → command not found.

**Potential Fix**
Add `mypy` to the `dev` extra and run it once to establish a baseline.

**Last Verified:** 2026-10-02

---

## KI-007 — Corpus generation is not reproducible from the repository

- **ID:** KI-007
- **Status:** OPEN
- **Severity:** MEDIUM
- **Affected Area:** benchmarking

**Description**
`data/cve_pairs.jsonl` exists but the scripts that produced it live outside the
repository, so the measurement cannot be reproduced by a future agent.

**Evidence**
Generator scripts were written under `%TEMP%\opencode\probe\`. `data/` is
gitignored, so neither the input nor the tooling ships.

**Reproduction**
Search the repo for the corpus builder: none.

**Potential Fix**
Move both the harvester and the converter into `benchmarks/` (or a `tools/`
directory) with a documented CLI, once KI-002 is fixed.

**Last Verified:** 2026-10-02

---

## KI-008 — Legacy doc files still present with withdrawal banners

- **ID:** KI-008
- **Status:** OPEN (accepted risk)
- **Severity:** LOW
- **Affected Area:** `docs/`

**Description**
`API.md`, `EXAMPLES.md`, `INDEX.md`, `INSTALLATION.md`, `CONTRIBUTING.md`,
`dependency_analysis.md`, `target_specs.md` describe v1 and carry a withdrawal
banner. Historical CHANGELOG entries legitimately retain v1 figures.

**Evidence**
Each affected file opens with a `> ## ⚠ Withdrawn` banner pointing at
`paper/WITHDRAWN.md`.

**Known Workaround**
Banner is prominent at the top of each file.

**Potential Fix**
Either rewrite for v3 or move the directory to `docs/archive/`.

**Last Verified:** 2026-10-02

---

## Resolved this cycle (retained for history)

| ID | Resolved | Note |
|---|---|---|
| KI-R01 | 2026-10-02 | Guard recognitions could not change any verdict: `MIN_TAINT_CONFIDENCE` (0.55) was applied after the mitigation factor and above the reporting threshold (0.5). Guard deductions now applied after the floor. |
| KI-R02 | 2026-10-02 | `in` / `not in` guard classification was inverted. `x not in ALLOWED` now classifies as allowlist. |
| KI-R03 | 2026-10-02 | Guard strength was written to `TraceStep.edge` but read from `.detail`, so it never applied. |
| KI-R04 | 2026-10-02 | `_string_value` left the opening quote attached, breaking every regex guard. |
| KI-R05 | 2026-10-02 | `classify_regex_guard` read the `argument_list` wrapper as the pattern. |
| KI-R06 | 2026-10-02 | `format_html` was registered as an XSS amplifier instead of a kill. |
| KI-R07 | 2026-10-02 | `alpha_rename` used two-tuple `untokenize`, truncating backslash continuations and changing the program. |
| KI-R08 | 2026-10-02 | `renameable_names` renamed free names, deleting the sink under test. Now restricted to locally bound names. |
| KI-R09 | 2026-10-02 | `interproc._compose` referenced an undefined `summary` instead of `sink_summary` in its fallback branch. **Branch verified unreachable through the public API**, so latent rather than live. |
| KI-R10 | 2026-10-02 | Reported origins could contain duplicates (`REQUEST/REQUEST`) when `PARAM` was refined to `REQUEST` while already present. |