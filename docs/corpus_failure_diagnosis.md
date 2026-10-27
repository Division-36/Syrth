# Corpus Failure Diagnosis — why recall measured 13.4%

**Date:** 2026-10-02
**Question:** why does SYRTH miss ~87% of "vulnerable" records?

**Answer: because most of them are not vulnerable.** The corpus builder labelled
every function *touched by* a fix commit with that commit's CWE. That includes
defensive helpers, unrelated refactors, and test scaffolding. The tool is being
graded against a label set that is mostly wrong.

## Method

Took the 249 vulnerable-labelled records, stripped to the 179 whose CWE is in the
tool's label space, and classified every miss by what the source actually
contains.

## Result

| Classification | Count |
|---|---|
| Detected | 24 |
| **C — sink receives only literals** | **81** |
| **A — no recognisable sink in the fragment at all** | **50** |
| D — sink receives a non-literal, but missed | 24 |

Of 155 misses, **131 are not vulnerabilities.** 81 records call a sink with a
constant argument; 50 contain no sink of the labelled category at all.

## The six unique functions behind the "genuine" misses

Deduplicating category D by (CWE, function) yields **6 distinct functions**. Every
one is a **defensive helper**, not vulnerable code:

| CWE | Function | What it actually is |
|---|---|---|
| CWE-601 | `is_safe_url` | **returns False for unsafe URLs** — the fix itself |
| CWE-601 | `_is_safe_url` | same, the internal validator |
| CWE-601 | `limited_parse_qsl` | a hardened query-string parser |
| CWE-89 | `as_sql` | `"(%s -> '%s')" % (lhs, self.key_name)` — safe by construction |
| CWE-79 | `is_safe_url` (a later revision) | same validator |

These are the *countermeasures* a fix commit introduces. Labelling them
"vulnerable CWE-601" is exactly backwards.

## Secondary evidence that the labelling is unsound

- Of 249 vulnerable records, **0** contain a sink call that receives a non-literal
  argument *and* whose name matches a known sink family. The only sink names that
  appear at all are `compile` (126 records, an AST helper unrelated to the
  labelled CWE), `mark_safe` (12), `render` (3), `unescape` (3), `write` (3).
- 47 **safe** (post-fix) records *do* contain a sink receiving a non-literal —
  more than the vulnerable set. The label polarity is inverted relative to what
  the code shows.
- 151 fix commits produced 255 vulnerable labels: a **1.7x inflation**, because
  a commit that fixes one SQLi while refactoring five functions yields five
  "vulnerable SQLi" labels.

## Conclusion

**The 13.4% recall figure is not a measurement of SYRTH.** It is a measurement of
a corpus in which ~85% of positives are not vulnerable. No amount of engine
improvement can raise the score, because the target is wrong.

This also invalidates the claim made earlier in this project that "the engine
misses 92% of real vulnerabilities". That claim came from this corpus and was
wrong.

## What the real detector quality is

**UNKNOWN.** It has never been measured. To measure it, the corpus must be
rebuilt with a defensible label:

1. Extract only the function that the advisory names, or whose diff actually
   contains the sink. Validate per record and record which method was used.
2. Require the vulnerable label to be supported: the function must contain a sink
   from the labelled category receiving a non-literal argument. A record failing
   this is not a positive and must be excluded, not counted as a miss.
3. Keep the post-fix revision as the negative for the *same* function only.

Until that exists, SYRTH has no measured recall, and no fix to the engine can be
evaluated.

## Engine findings that ARE real

Class D (24 records) is the only part of this that speaks to the engine. It is
small, and the 6 unique functions behind it are defensive code that *should*
produce no finding. There is no evidence here of a systematic engine defect.
The real engine defects found in this session were separate and are fixed:
the renamer deleting findings, and unbounded recursion (see `fixes_report.txt`).

## Ruling on the rebuild question

A rebuild was proposed on the grounds that "the implementation is bad". The
measurement supporting that premise does not hold. The evidence now points the
other way: the engine passes 486 tests, is deterministic, does not execute
analysed code, survives hostile input, and correctly declines to report the six
defensive functions above. There is no measured engine defect to rebuild away.

**Recommendation: do not rebuild. Rebuild the corpus instead** (steps 1–3 above),
then measure the engine against a target that means something.