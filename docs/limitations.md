# Limitations

Stated plainly, because a security tool that overstates itself is worse than one
that admits its edges.

## Analysis model

**Flow-insensitive and path-insensitive within a function.** Both branches of a
conditional are analysed. A value assigned on one branch and used on the other is
treated as flowing. This produces false positives on code where the branches are
mutually exclusive.

**Guards are evidence, not proof.** An allowlist guard lowers the likelihood of a
flow; it never removes it and never satisfies patch verification. An allowlist
whose own contents are dangerous is still dangerous, and saying otherwise would
hide a real bug.

**Guards on a component are not recognised.** This is deliberate. In

```python
if parsed.netloc not in allowed:
    return
return HttpResponseRedirect(redirect_uri)
```

the guard constrains `parsed.netloc`, not `redirect_uri`. A URL can have an
acceptable netloc and a hostile path, so treating the guard as constraining the
whole value would be unsound. The flow is reported. This is a known source of
review items, and the alternative is worse.

**No path, field or alias sensitivity.** A value written to an attribute
propagates to every read of that attribute, regardless of object.

**Class-qualified names are merged.** Two methods with the same name in different
classes are not distinguished.

**Libraries are modelled by name.** A library that re-executes a string
internally is invisible. `requests.get(f"http://{host}/x")` where `host` is
attacker-controlled is not an SSRF finding.

**Only Python is analysed.** No C extension, no shell script, no template.

## Coverage

**The sink table is incomplete.** Classes present in real code that the registry
does not yet model are not named. Current measured coverage is 95.7% (111/116)
against the classes the benchmark's independent AST scan can identify, and that
benchmark can only check classes it knows about — so the true coverage is lower by
an unknown amount.

**CWE-79 covers 10 of 12** cases in the measured set. The two misses have not been
diagnosed per case.

**CWE-400, CWE-200 and CWE-327-style resource and information classes are out of
scope.** Resource exhaustion and information disclosure are not taint flows, and
this tool does not attempt them.

## Rename invariance is 100% on the measured corpus

The project's core claim is that a verdict does not depend on identifier
spelling. Measured over 350 real records, every record keeps its reported class
set under renaming, and the renamer itself was verified sound (AST-equivalent
output on every record, free names preserved). That is a result on this corpus,
not a proof for all Python: the renamer covers the identifier shapes it was built
to produce.

## The measurement's scope

**Extracting a function into a snippet loses context.** The corpus stores each
record as the function it is about, with the module's imports and constants, so
that a benchmark can run without the repository. The whole-repository replay
measures what that costs: the snippet study traces the labelled class in 54
pairs and the repository study in 57, and the two disagree on one pair's
outcome. A snippet cannot see a helper defined elsewhere in the module, a
module-level binding, or a flow that only exists once the module is parsed as a
whole. The snippet study is therefore a lower bound, not a substitute.

**Certificate identity is name-based.** A flow is tied to a function by name.
In a large repository a common method name is defined many times — `start` is
defined 172 times in salt at one revision — so matching a flow to a function by
name alone can credit an unrelated function. The whole-repository study pins
cross-function matches to the labelled file as well as the labelled name for
exactly this reason. The certificate key itself carries the same scoping: two
same-named functions with identical flow shapes produce the same `trace_id`.

## Patching

**SQL cannot be patched.** Converting a concatenated query to a parameterised one
cannot be done soundly without deriving placeholders from the original literal,
so the backend declines. This is a refusal, not a gap in effort.

**Patches are textual.** The patcher rewrites the sink argument in place. It does
not refactor, and it does not understand intent beyond the argument expression.

**`--fix --fix-apply` writes to your source.** The three-condition verification
makes it safe against introducing a parse error or a new flow in the same
function. It does not make it safe against breaking your test suite.

**11% of confirmed flows survive a recognised sanitiser.** A patch that genuinely
fixes the bug can still be reported as vulnerable, because the kill model does not
understand those category/sanitiser pairs. The measured patch kill rate is 89%
(89/100).

## Performance

Unmeasured. Analysis is O(nodes) per file with no file-size ceiling. Pathological
input is bounded — a 5000-term expression and 600-level nesting now complete
where they previously crashed — but throughput and memory have not been profiled,
and there is no claim about them.

## Installation and environment

**The C export test is skipped** without a C compiler, so the generated header is
not verified against a real compiler on every machine. CI runs it on Linux, where
`gcc` is present.

**CI covers three operating systems.** Ubuntu, Windows and macOS run at Python
3.10 and 3.12. A regression that only appears on another interpreter version, or
only under a compiler the matrix does not have, can still land silently.

**No type checking is enforced.** The package ships `py.typed` and is fully
annotated, but `mypy` is not wired up.

## What this tool will not tell you

Whether your application is secure. Whether a report is a true positive. Whether
the fix was the right fix. It tells you where the dangerous operations are and
what it believes about them, with its evidence visible, so you can disagree.

Anyone who tells you a static analyser removes that judgement has sold you
something.