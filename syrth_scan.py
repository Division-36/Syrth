"""
syrth_scan -- compatibility shim
================================
This module used to be SYRTH's inference frontend: a bag-of-tokens PyTorch
ensemble with a meta-learner stage. It has been **retired**.

Why it was retired
------------------
The v1 path contained three defects that made its published numbers
unreproducible, and keeping a second implementation alive next to a corrected
one is how those defects survived:

1.  The meta-learner stage read a bundle key that did not exist and passed a
    20-element feature vector to a model expecting 53. Both failures were caught
    by a bare ``except Exception: pass``, so the "full system" silently *was*
    the ensemble -- visible in the project's own ablation table, where the
    "Full System" and "Ensemble Only" rows are byte-identical.
2.  The classifier's final step was a hard-coded probability swap against a
    hard-coded RCE class index. RCE is the largest class in the test set, so a
    constant index dominated the output while reading as "meta-learning".
3.  The meta-learner was trained with the ground-truth CWE description text
    injected as a feature, and evaluated with the advisory description passed
    in at inference time.

None of those can be fixed in place without rewriting the pipeline, so the
pipeline was rewritten. The archived implementation is kept at
``legacy/v1_syrth_scan.py`` for reference only; **its numbers are not
reproducible and must not be quoted.**

What this shim does
-------------------
Forwards the historical command line to the current CLI so existing scripts keep
working::

    python syrth_scan.py --file app.py --mode dev --json
    python syrth_scan.py --file app.py

``--mode`` is accepted and ignored: there is no longer a separate "fast" C
engine, because the corrected pipeline's output is the trace set and that is
produced identically by both modes. It is exported through ``syrth`` in
``pyproject.toml``; new code should depend on :class:`syrth.SyrthScanner`
directly.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from syrth.scan import __version__, main as _scan_main

_DEPRECATION = (
    "syrth_scan.py is a compatibility shim; the v1 ensemble and meta-learner "
    "have been retired. Routing to the current scanner (syrth {v}). "
    "For the library API use `from syrth import SyrthScanner`."
)


def _translate(argv: List[str]) -> List[str]:
    """Map the historical CLI onto the current one."""
    translated: List[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--mode":
            index += 2          # drop the flag and its value
            continue
        if token.startswith("--mode="):
            index += 1
            continue
        if token == "--engine":
            index += 2
            continue
        if token.startswith("--engine="):
            index += 1
            continue
        if token == "--explain":
            index += 1
            continue
        if token == "--no-json":
            index += 1
            continue
        if token == "--threshold":
            translated.append(token)
            index += 2
            continue
        if token.startswith("--threshold="):
            translated.append(token)
            index += 1
            continue
        if token == "--output":
            index += 2          # the current CLI writes to stdout only
            continue
        if token.startswith("--output="):
            index += 1
            continue
        translated.append(token)
        index += 1
    return translated


def main(argv: Optional[List[str]] = None) -> int:
    """Forward to the current scanner."""
    raw = list(sys.argv[1:] if argv is None else argv)
    print(_DEPRECATION.format(v=__version__), file=sys.stderr)
    return _scan_main(_translate(raw))


if __name__ == "__main__":
    sys.exit(main())
