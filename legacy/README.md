# Legacy — the retired v1 pipeline

Nothing in this directory is maintained, installed, or tested, and there is no code
here. It is a record of what the project used to be and why it was replaced.

## Why the code is gone rather than archived

`paper/WITHDRAWN.md` withdraws the v1 results claim by claim. Those are verifiable
claims about specific code: that the meta-learner never executed because it read a
bundle key that did not exist, that the label space leaked the target, that the
split was not grouped, that `collect.py` resolved sinks through a `frozenset` and
so produced different tokens per process.

Keeping the files would have let a reviewer read them. Keeping *runnable* files
that produce numbers nobody may quote is worse than keeping nothing: the v1 scripts
could not be run from a clone in the first place, since their model bundles and
training datasets were never committed, so they were dead code wearing the costume
of a pipeline. The audit now cites each one by commit, which is checkable and does
not invite a run:

```console
$ git show 66ad8a5:legacy/v1-scripts/collect.py    # nondeterministic sink resolution
$ git show 66ad8a5:syrth_scan.py                   # the missing bundle key
```

The audit also records what is *not* recoverable. The bundles
(`syrth_model.joblib`, `syrth_ensemble*.joblib`, `syrth_meta*.joblib`) and the
training datasets were gitignored from the beginning, so no clone can re-derive the
published accuracies even in principle. That is one of the defects the withdrawal
cites, and no amount of archiving would have fixed it.

## Layout

| Path | Contents |
|---|---|
| `README.md` | This file. |
| `v1-artifacts/README.md` | Why the model bundles and datasets were removed rather than kept: the audit works by describing code, and none of a missing bundle key or a feature-vector width mismatch is checkable by opening a pickle. |
| `../experiments/` | Scratch space, and the same record. |
| `../syrth_scan.py` | The v1 inference entry point, now a 94-line shim that forwards to the current CLI and prints a retirement notice. Kept because callers invoke it, and a shim that answers tells them what happened where a missing module only tells them nothing did. |

## What replaced it

The pipeline was rewritten rather than patched: a typed sink and sanitiser registry,
tree-sitter trace extraction, cross-function flow resolution, and a corpus built
from real advisories by `tools/build_corpus.py`. The current architecture is in
[`../docs/architecture.md`](../docs/architecture.md), and the measurements that
replaced the withdrawn ones are in
[`../docs/benchmark.md`](../docs/benchmark.md).