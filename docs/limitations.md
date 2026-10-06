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
does not yet model are not named. Current measured coverage is 90.5% against the
classes the benchmark's independent AST scan can identify, and that benchmark can
only check classes it knows about — so the true coverage is lower by an unknown
amount.

**CWE-79 misses 6 of 26** in the measured set. Not yet investigated per case.

**CWE-400, CWE-200 and CWE-327-style resource and information classes are out of
scope.** Resource exhaustion and information disclosure are not taint flows, and
this tool does not attempt them.

## Rename invariance is 99.2%, not 100%

The project's core claim is that a verdict does not depend on identifier
spelling. Measured over 498 real records, **four** change their reported class
set under renaming. The renamer itself was verified sound (AST-equivalent output
on all 498 records, free names preserved), so the residual is in the analyser and
has not been diagnosed.

## Patching

**SQL cannot be patched.** Converting a concatenated query to a parameterised one
cannot be done soundly without deriving placeholders from the original literal,
so the backend declines. This is a refusal, not a gap in effort.

**Patches are textual.** The patcher rewrites the sink argument in place. It does
not refactor, and it does not understand intent beyond the argument expression.

**`--fix --fix-apply` writes to your source.** The three-condition verification
makes it safe against introducing a parse error or a new flow in the same
function. It does not make it safe against breaking your test suite.

**26.7% of confirmed flows survive a recognised sanitiser.** A patch that
genuinely fixes the bug can still be reported as vulnerable, because the kill
model does not understand those category/sanitiser pairs.

## Performance

Unmeasured. Analysis is O(nodes) per file with no file-size ceiling. Pathological
input is bounded — a 5000-term expression and 600-level nesting now complete
where they previously crashed — but throughput and memory have not been profiled,
and there is no claim about them.

## Installation and environment

**The C export test is skipped** without a C compiler, so the generated header is
not verified against a real compiler on this build machine.

**No CI.** Nothing runs automatically. A regression can land silently. This is a
real gap in the project's own quality assurance.

**No type checking is enforced.** The package ships `py.typed` and is fully
annotated, but `mypy` is not wired up.

## What this tool will not tell you

Whether your application is secure. Whether a report is a true positive. Whether
the fix was the right fix. It tells you where the dangerous operations are and
what it believes about them, with its evidence visible, so you can disagree.

Anyone who tells you a static analyser removes that judgement has sold you
something.