# Decisions — SYRTH

Architectural decisions are append-only. A change of mind is recorded as a new
decision that supersedes an old one; the old entry is never rewritten.

---

## D-001 — Retire v1 and rewrite the analysis core

- **Decision ID:** D-001
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** Retire the v1 ensemble + stacking meta-learner. Rewrite the
  analysis core around a trace certificate, a single security registry, and
  mechanical patch verification. Keep the v1 tree on disk as audit provenance
  only.
- **Context:** v1's meta-learner never executed correctly (wrong bundle key and
  wrong feature width, both swallowed by a bare `except Exception: pass`), its
  final step was a hard-coded RCE class index rather than a learned decision,
  and it was trained and evaluated with the ground-truth CWE description
  supplied as a feature. The taint extractor seeded taint from a regex on
  identifier names, making verdicts rename-dependent.
- **Alternatives considered:**
  - Patch v1 in place — rejected: the label leakage and the dead meta-learner
    are structural, not incidental.
  - Keep v1 as a second opinion alongside v3 — rejected: it would reintroduce
    the name-dependent behaviour and the inflated figures.
- **Reason:** The reported results could not be reproduced from the code and
  data, so the results were not usable regardless of the underlying model.
- **Consequences:** All v1 figures withdrawn. `syrth_scan.py` becomes a shim.
  `legacy/`, `experiments/` and root `*.py` are frozen as audit material.
- **Evidence:** `paper/WITHDRAWN.md`, `legacy/README.md`.

---

## D-002 — Single security registry as the only source of security truth

- **Decision ID:** D-002
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** All sinks, sources, sanitisers and CWE mappings live in
  `syrth/registry.py`. Parsers consult it; they never hard-code security facts.
- **Context:** v1 scattered sink knowledge across modules, so behaviour depended
  on which code path ran.
- **Alternatives considered:** Per-language sink tables — rejected: they diverge
  and make "does this sink exist?" unanswerable.
- **Reason:** A single table makes the security model auditable in one place and
  makes label space and sink space verifiable against each other.
- **Consequences:** Adding a sink is a one-file change. Any code that decides
  "is this dangerous?" outside the registry is a bug.
- **Evidence:** `PROJECT/architecture.md`, `syrth/registry.py`.

---

## D-003 — Guards are ranked evidence, never proof

- **Decision ID:** D-003
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** An allowlist / denylist / equality / anchored-regex guard reduces
  a flow's confidence below the reporting threshold and is recorded in the trace.
  It never clears taint and never satisfies patch verification.
- **Context:** Before guard support, guarded code — idiomatic Django templates,
  allowlisted command names — was reported as a finding. The RLTESTS false-alarm
  rate was 53.3%.
- **Alternatives considered:**
  - Treat a terminating allowlist as a full kill — rejected: it is not a proof.
    An allowlist that itself contains a dangerous value is still exploitable, and
    declaring it safe would hide a real bug.
  - Recognise guards only on direct identifiers — adopted. Extending to
    attribute or subscript receivers (`parsed.netloc`, `parts[0]`) is
    **unsound**, because constraining a component does not constrain the whole
    value; those cases are deliberately left reported.
  - Ignore guards entirely — rejected: that is what produced the 53.3% rate.
- **Reason:** A finding that survives review because the guard was misread is
  worse than a review item. Ranking keeps the flow visible and honest.
- **Consequences:** Guarded flows appear as review items, not findings.
  `GUARD_STRENGTH` deductions are applied **after** the confidence floor.
- **Evidence:** `syrth/parser/guards.py`, `tests/test_guards.py`,
  `syrth/taint/engine.py`.

---

## D-004 — Withdraw all published v1 figures rather than restate them

- **Decision ID:** D-004
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** Publish a claim-by-claim withdrawal instead of quietly deleting
  the numbers, and publish no replacement figure until one is reproducible.
- **Context:** Old figures appeared in README, paper, `docs/`, and git commit
  messages. Deleting them would leave no way to understand why the project
  changed.
- **Alternatives considered:** Replace with new numbers immediately — rejected:
  at the time no measurement path was trustworthy.
- **Reason:** An explicit withdrawal is the honest record and prevents the
  figures being re-quoted from history.
- **Consequences:** `paper/WITHDRAWN.md` exists; legacy docs carry withdrawal
  banners; git history still contains the old claims, deliberately.
- **Evidence:** `paper/WITHDRAWN.md`.

---

## D-005 — No PyTorch; optional ML only

- **Decision ID:** D-005
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** Default install has two runtime dependencies. XGBoost, sklearn,
  numpy, joblib and shap are optional extras. No PyTorch anywhere.
- **Context:** v1 required a PyTorch ensemble (~200 MB) and a 476 MB CodeBERT
  checkpoint.
- **Alternatives considered:** Keep the neural ensemble — rejected: it was the
  source of the name-dependent token features and the largest dependency cost.
- **Reason:** A rules-only scanner must stay installable and fast everywhere;
  the learned ranker is a bonus, not a prerequisite.
- **Consequences:** `pyproject.toml` has `ml`, `explain`, `dev`, `benchmark`,
  `all` extras. `syrth_codebert/` is gitignored.
- **Evidence:** `pyproject.toml`.

---

## D-006 — Measure before modifying

- **Decision ID:** D-006
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** No detection change is made until the measurement path producing
  the current number is verified sound.
- **Context:** This cycle fixed bugs first and measured afterwards. Four benchmark
  runs of an "unchanged" engine produced recall 9.4% → 8.1% → 8.1%, and
  invariance 85.9% → 85.5% → 88.7% → 91.1%. Every movement was a harness or
  corpus defect, not engine behaviour. A claim of "92% of real vulnerabilities
  missed" was published from a corpus where most records were never vulnerable.
- **Alternatives considered:**
  - Continue fixing and re-measuring — this is what produced the wrong numbers.
  - Abandon measurement — rejected: it is the only reason the defects were found.
- **Reason:** A number from an unverified harness is worse than no number,
  because it is believed.
- **Consequences:** Benchmark harnesses require a known-answer validation before
  their output is quoted. KI-002 must be fixed before KI-001 can be worked.
- **Evidence:** `STATE/known_issues.md` KI-001, KI-002;
  `SYSTEM/workflow.md` anti-pattern section.

---

## D-009 — SYRTH reports a risk surface, not a verdict

- **Decision ID:** D-009
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** The analyser answers "what is the nearest vulnerability class to
  this code, and how likely is it", not "is this vulnerable". Every sink contact
  is reported with a likelihood in [0,1] and the reasons for it. Nothing is
  withheld for being unlikely.
- **Context:** The previous design was a binary classifier: a confidence
  threshold separated `findings` from `suppressed`, and anything below it was
  hidden. This produced two artefacts that looked like quality problems but were
  reporting artefacts:
  - "13.4% recall" — mostly because the corpus labels are wrong, but also because
    a low-likelihood risk was recorded as no answer at all.
  - "46.7% false alarms on safe code" — these were *correct* observations of a
    sink being touched, suppressed into invisibility and then counted as noise.
  Precision and recall are metrics for a classifier. SYRTH is not a classifier,
  so they were the wrong instruments and produced a misleading number.
- **Alternatives considered:**
  - Keep the threshold, tune it until numbers look better — rejected: that
    optimises a metric for the wrong question, and hides exactly the weak
    evidence a reviewer needs.
  - Report only confirmed flows — rejected: same problem, more severe.
  - Two separate outputs, "vulnerable" and "possible" — rejected: it reinstates
    the binary verdict the user is removing, and forces the reader to decide
    which list matters.
- **Reason:** The reader's question is "where should I look in this system?".
  A suppressed 0.12 risk is an answer; silence is not.
- **Consequences:**
  - `Finding.confidence` is the likelihood. `--threshold` marks a finding
    `below_threshold` so a consumer can filter, but never deletes it.
  - Pattern-level risks (`detector="pattern"`) are emitted for every sink
    category a function touches, one finding per category.
  - A patch removes the *confirmed flow*; the sink call remains, so a
    low-likelihood pattern risk for it is the expected outcome.
  - Benchmark precision/recall are now the wrong headline metrics and the
    harness must be revisited.
- **Evidence:** `syrth/scan.py` (`_weak_findings`, `_dedupe_and_rank`,
  `_render_text`), `tests/test_scan.py::TestReportPolicy`,
  `tests/test_pipeline.py::TestScannerPolicy`.

---

## D-007 — Superseded by D-009: rebuild versus targeted repair

- **Decision ID:** D-007
- **Date:** 2026-10-02
- **Status:** **SUPERSEDED by D-009**
- **Decision:** No rebuild. The decision was reopened and resolved by correcting
  the product definition rather than rewriting the implementation.
- **Context:** The user proposed a full rebuild on the grounds that the
  implementation is bad. Diagnosis showed the supporting number (13.4% recall)
  came from a corpus in which ~85% of positives are not vulnerabilities, and that
  the remaining "false alarms" were correct observations being suppressed by a
  reporting policy rather than engine errors.
- **Alternatives considered:**
  - Full rebuild now — would discard working, tested layers and start from the
    same unverified assumptions.
  - Targeted repair — premature until the missed set is diagnosed.
  - **Recommended: fix the corpus first (KI-002), re-measure, then diagnose the
    missed set.** The answer falls out of that evidence.
- **Reason:** Rebuilding on a number known to be untrustworthy would repeat the
  failure mode that produced the situation.
- **Evidence:** `STATE/current_state.md` "Open decision".

---

## D-008 — Corpus ground truth must come from real fix commits

- **Decision ID:** D-008
- **Date:** 2026-10-02
- **Status:** ACCEPTED
- **Decision:** Label vulnerable code from the pre-fix revision of a real
  security fix commit, and safe code from the post-fix revision of that same
  commit. Avoid synthetic positives for headline accuracy figures.
- **Context:** v1 trained on synthetic variants and advisory text.
- **Alternatives considered:**
  - Hand-written examples (`RLTESTS/`) — accepted **only** as a regression gate.
    Every vulnerable example there was written to be findable, so the set has no
    real negative class and cannot produce a valid accuracy figure.
  - Advisory-text features — rejected: this is the original leakage.
- **Reason:** Real pre/post revisions give genuine negatives, which is the one
  thing a synthetic set cannot provide.
- **Consequences:** The corpus must carry the file's imports and module constants,
  or imported names look locally defined and sinks vanish. Each record is
  deduplicated on `(group, label)` and validated with `ast.parse` before use.
- **Evidence:** `docs/measurements.md`, `STATE/known_issues.md` KI-002.
---

## D-010 -- The corpus is labelled by the product's own registry

- **ID:** D-010
- **Date:** 2026-10-03
- **Status:** ACCEPTED
- **Supersedes:** part of D-009 (the corpus-label rule)

**Context**
A record is only labelled vulnerable if the pre-fix function still contains the
sink its class is defined by. The builder originally kept its own table of
class-to-call-name mappings. It drifted from `syrth/registry.py` and produced
labels the product itself would dispute: `numpy.load` counted as unsafe
deserialisation, and a bare `sha1` counted as broken crypto.

**Decision**
`tools/build_corpus.py` resolves evidence through `syrth.registry`: imports are
bound into a `Bindings` object, each call is resolved with `canonical_sink`, and
the sink's own argument schema decides whether a non-constant value reaches it.
Amplifiers such as `mark_safe` count as evidence for the category they create.

**Consequences**
- One definition of each class, shared by the corpus and the analyser. A corpus
  that cannot measure the product is not worth building.
- The corpus is narrower: 38 pairs rather than the 200+ a name-only rule would
  have admitted. Every record is defensible; some real findings are absent.
- `syrth.registry` becomes a dependency of the corpus tool, so the tool needs the
  project's parser dependencies rather than running on the standard library alone.

---

## D-011 -- The benchmark's expectations stay independent of the analyser

- **ID:** D-011
- **Date:** 2026-10-03
- **Status:** ACCEPTED

**Context**
D-010 makes the *labels* share the analyser's registry. The risk harness must not
do the same for its *expectations*, or agreement between them proves nothing.

**Decision**
`benchmarks/risk_metrics.py` keeps its own AST scan. Where a bare name is
ambiguous it must be qualified by module rather than imported from the registry:
`pickle.loads` and `torch.load` are named explicitly, bare `loads` is not, because
it is CWE-502 after one import and a safe decoder after another.

**Consequences**
The instrument is code and can be wrong. It was: it reported CWE-502 as 0/4 while
SYRTH had named every record correctly. Every harness change needs the same
scrutiny as an analyser change, and the docs record which side a defect was on.

---

## D-012 -- Corpus labels are tiered, never loosened

- **ID:** D-012
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
Single-function labelling cannot express Django's SQL injection fixes:
`PostGISOperator.as_sql` builds `(sql, params)` and a compiler elsewhere calls
`cursor.execute`. 36 of 52 CWE-89/CWE-611 advisories were rejected for exactly
this. Widening the per-function rule would have recovered them by admitting any
function in a file that contains a sink, which is not a claim about that function.

**Decision**
Keep the direct rule pure, and add a second, separately named tier. Every record
carries `evidence` (`direct-sink` or `module-proximity`) and, for the weak tier,
the `module_sink` it relied on. The benchmark reports coverage per tier and never
a single blended figure.

**Consequences**
- The corpus grows from 38 to 175 pairs and from 5 to 7 classes.
- The weaker tier is 108 of 175 pairs, and its coverage is 85.7% against the
  direct tier's 97.9%. Both numbers are published.
- A module-proximity label is checkable against the recorded repo, commit and file,
  but not from the record alone. Naming the module sink is what makes it auditable.

---

## D-013 -- Long harvests checkpoint and bound themselves

- **ID:** D-013
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
A full build is a twenty-minute job over forty repositories. It was killed twice
mid-extraction, both times with nothing written, and one repository could stall
the others indefinitely.

**Decision**
Records are appended to the output file as they are accepted
(`--checkpoint on`), each repository gets a wall-clock budget
(`--repo-budget-seconds`), and full-vs-partial cloning is decided from the
repository's **measured** size plus free disk rather than a hand-maintained list.

**Consequences**
A killed run yields everything it finished. A repository that hits its budget is
recorded in the manifest as skipped with a reason, so missing records cannot be
mistaken for absent findings.


---

## D-014 -- Precision is adjudicated, not inferred from a coarser oracle

- **ID:** D-014
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
Precision was reported as impossible because the corpus labels were unsound. That
reason was wrong: precision against an independent AST scan does not use corpus
labels at all. Measured, it read 59.7% -- and every one of the 75 disagreements was
a sink the oracle's hand-written name table does not contain.

**Decision**
Publish the oracle figure only alongside what it can and cannot see. Establish the
real figure by adjudicating **claims**, not records: "is this sink a sink of this
class" does not vary between records, so 75 disputes reduce to 8 questions.
The verdicts were retired with the audit that consumed them.

**Consequences**
- Adjudicated precision **94.6%**, complete, lower bound equals the value.
- Mechanical mutants cannot substitute. An alpha-rename leaves the code just as
  vulnerable, so it measures invariance; deleting a sink makes it safely trivial,
  so it measures nothing. Every mechanical operator is degenerate, which is why
  realistic negatives need an authority rather than a generator.
- A metric computed against a reference coarser than the system under test is not
  a bound on that system. This applies to every figure in this project.

---

## D-015 -- A finding names only sinks of its own class, as written in the source

- **ID:** D-015
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
Pattern findings set `sink` from the function's entire sink list and `sink_call`
from the same list, so a CWE-79 finding could cite `FILE_OPEN`, and `sink_call`
carried canonical names despite being documented as the call as written. A
consumer resolving the field as a call site cannot. No published metric showed it.

**Decision**
Attribute sinks by category, and recover call names through the same resolver that
produced the canonical sink. An empty `sink_call` is the honest report when a
category is inferred with no attributed call.

**Consequences**
Precision moved 92.5% -> 94.6% purely by fixing the reporting defect. The
invariant is pinned by `TestPatternFindingSinkAttribution`.


---

## D-016 -- Adjudicate guard shapes, not individual findings

- **ID:** D-016
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
57 patched functions still report their class. The question per case is "does the
guard close the path", which is not 57 independent questions: it is a handful of
guard mechanisms repeated.

**Decision**
Classify by the guard primitives the patch introduced and record one verdict per
shape with its rationale. Individual cases are projected onto shapes. Shapes the primitives do not recognise are recorded
`uncertain` rather than forced into a verdict.

**Consequences**
- 26 of 57 came out `uncertain`, mostly because no primitive was recognised. That
  is the honest reading and it bounds the conclusion: the 61% false-positive rate
  is over the 31 decidable cases, not all 57.
- Three defects were found by this route, each with a minimal reproduction, and
  the fix moved the kill rate 76.0% -> 89.0% at unchanged precision.
- The evidence answers a pending strategic question: the surviving reports are
  dominated by registry gaps, not by missing analysis.

---

## D-017 -- A sanitiser applies whether or not its argument was tracked

- **ID:** D-017
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
The sanitiser path returned early when the argument carried no taint, so the kill
was never applied to the returned value. `Markup(escape(x))` was therefore
reported as an XSS amplifier. The early return also contradicted the comment
below it.

**Decision**
Apply the sanitiser unconditionally. Record it even when nothing is tainted, which
is what the neighbouring comment already said was intended.

**Consequences**
The canonical "escape then assert safe" idiom is suppressed. A test whose fixture
used a literal was changed to use a variable, preserving the invariant it was
actually written for -- an assertion about a value of unobservable provenance is
still a finding.

---

## D-018 -- An assertion about a literal is not a finding

- **ID:** D-018
- **Date:** 2026-10-04
- **Status:** ACCEPTED

**Context**
`Markup("<li class=...>")` on a constant was reported. No failure of taint
tracking can make a literal unsafe, so the amplifier's premise -- "the developer
asserted safety and may be wrong" -- does not apply.

**Decision**
Suppress an amplifier whose argument is a literal. Interpolated strings stay
reportable, so `Markup("<b>%s</b>" % value)` is unaffected.

**Consequences**
Removes a finding from Airflow's pagination helper. Broadens the suppression only
as far as constants, which is the defensible line.

## D-019 -- Containment is modelled as an exit-dominates-the-sink proof, not as a value sanitiser

- **Date:** 2026-10-05
- **Status:** ACCEPTED
- **Area:** `syrth/containment.py`, `syrth/parser/python.py`, `syrth/scan.py`

**Context**
The corpus repeatedly showed real fixes of the shape

    if os.path.commonpath([root, target]) != root:
        raise ValueError("outside root")
    return open(target)

which is not a sanitiser. No function rewrites the value, so no kill step can
fire. The tempting registry entry -- treat `commonpath` as killing the sink --
is unsound in both directions: it does not suppress the guarded case above, and
it does suppress the case where `commonpath` is computed and discarded, which is
a real traversal bug. A registry entry would have converted a visible false
positive into an invisible false negative and looked like an improvement.

**Decision**
Recognise the guard shape instead. `syrth.containment` recognises an `if` whose
test reads a containment primitive and whose body cannot fall through, requires
the primitive result to actually be compared, and requires the `if` to have no
`else`. A sink is suppressed only when the guard precedes it, lies in the same
function, and shares state with it: an identifier read by the sink own first
argument must also be read by the guard test. The guard test uses `ast`, not
tree-sitter, because it is a statement-level pattern over a small primitive set;
the existing tree-sitter depth budget still governs whether the pass runs at all.

**Consequences**
- The asymmetric risk is contained deliberately: every negative control in
  `tests/test_scan.py::TestContainmentGuardSuppression` is a real vulnerability
  that must survive, because an over-eager guard deletes findings silently.
- Corpus coverage is unchanged with guards on and off (66/116 either way), so
  the feature bought precision without costing a single true finding.
- `kill-survivors` fell from 57 to 56; reported claims fell from 186 to 181.
- A source `ast` cannot parse, or a tree already truncated by the depth budget,
  yields no guards at all. Degrading to the previous behaviour is the correct
  failure mode; a partial guard set is not.
- Guards constrain control flow, not values. A guard whose result does not
  actually constrain the path is still not understood.

## D-020 -- A guard is evidence attached to a finding, never a reason to remove it

- **Date:** 2026-10-05
- **Status:** ACCEPTED, reversing D-019's delivery mechanism
- **Area:** `syrth/scan.py`, `syrth/containment.py`, `tests/test_scan.py`

**Context**
D-019 recognised containment guards correctly and then delivered them as a
*suppression*. Guarded findings were moved into `report.suppressed`, which the risk
model reserves for decisions the user makes.

Two independent signals said this was wrong:

1. `docs/risk-model.md` says it directly -- "A suppressed 0.12 risk is an answer.
   Silence is not" and "the only things that suppress output are an explicit
   suppression file and an inline ignore comment -- decisions you make, not decisions
   the analyser makes on your behalf".
2. The measurement moved. Category coverage fell from **95.7% to 94.8%** and the kill
   rate from **89/100 to 88/99** while the deletion was in place. Deleting a guarded
   sink deletes a class name the report exists to contain, so the "improvement" was
   destroying coverage to buy a metric that the contract does not define.

**Decision**
A dominating containment check caps the finding's likelihood at
`CONTAINMENT_GUARD_CONFIDENCE = 0.12` -- the value `docs/risk-model.md` already uses
for a confirmed flow constrained by an allowlist guard -- and prepends the reason,
naming the guard line. The finding stays in `report.findings`. `report.suppressed`
is reachable only through `SyrthScanner.suppress(report, SuppressionSet)`.

**Consequences**
- Coverage and kill rate returned to 95.7% and 89/100. The drop was a symptom, and
  the honest measurement had been hiding it.
- The invariant is now tested over the whole report, including a threshold of 0.99
  where every finding falls below the bar, because the previous per-case tests
  passed while the report was being emptied.
- The recognition work from D-019 is unchanged and remains useful: it is the
  *evidence*, and evidence that removed a finding would have been worth less than
  nothing.

## D-021 -- The precision section is withdrawn, and the ledger with it

- **Date:** 2026-10-05
- **Status:** ACCEPTED
- **Area:** removed from the tree

**Context**
A precision figure of 94.5% was computed, published and defended, and
`docs/risk-model.md` defines the
measurements this project reports and precision is not among them: "Precision and
recall are metrics for a decision procedure with a positive and a negative class.
SYRTH makes no decision and has no negative class."

**Decision**
Withdraw the figure and every number derived from it. Do not publish a true/false
verdict on a finding. `benchmarks/adjudicate.py` is kept, since exporting the cases a
human should read is useful under this contract; the *scoring* is what is withdrawn.

**Consequences**
- The 10 "rejected" claims were used as a defect backlog, and acting on them lowered
  coverage. See D-020.
- A second, sharper problem: the adjudicator was the same agent that wrote the
  analyser, on the same cases. There was no blind spot between the instrument and the
  grader, so the ledger was not independent evidence and should not have been
  presented as such.
  therefore **not recoverable from git**. They were left in place rather than deleted,
  because deleting untracked analysis is irreversible and the numbers are already
  withdrawn in the docs. Flagged for the owner to confirm.
