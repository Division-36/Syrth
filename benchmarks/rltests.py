"""Labelled smoke-set evaluation over ``RLTESTS``.

This is **not** a corpus benchmark. ``RLTESTS`` is 40 hand-written functions
authored by this project, and because every vulnerable example was written to be
findable it contains no real-world negative class. The number it produces is
therefore only useful as a *regression gate*: it must not get worse as the
engine changes.

Labels come from the section markers each file carries::

    # ── VULNERABLE ──
    def login_redirect(request): ...
    # ── SAFE ──
    def safe_login_redirect(request): ...

Every function between the markers is labelled accordingly. Functions before any
marker, and files with no markers at all, are skipped rather than guessed.

What a real benchmark needs, and does not get here:

* an external corpus with real vulnerable *and* real safe code;
* a grouped split so near-duplicate functions cannot straddle it;
* competitor baselines on the same corpus.

See ``benchmarks/run_benchmarks.py`` for the harness that does all three once a
corpus is supplied.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from syrth.scan import SyrthScanner

DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "RLTESTS"

_VULNERABLE = re.compile(r"^\s*#.*\bVULNERABLE\b")
_SAFE = re.compile(r"^\s*#.*\bSAFE\b")
_DEF = re.compile(r"^(\s*)def\s+(\w+)\s*\(")

#: Confidence at or above which a flow counts as reported. Mirrors the CLI.
REPORTING_THRESHOLD = 0.5


@dataclass(frozen=True)
class LabelledFunction:
    """One labelled function from the smoke set."""

    path: Path
    name: str
    label: str  # "vulnerable" or "safe"


@dataclass
class SmokeMetrics:
    """Counts and rates for one evaluation run."""

    vulnerable_total: int = 0
    vulnerable_flagged: int = 0
    safe_total: int = 0
    safe_flagged: int = 0
    missed: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)
    detected_cwes: dict[str, int] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        if not self.vulnerable_total:
            return 0.0
        return self.vulnerable_flagged / self.vulnerable_total

    @property
    def false_alarm_rate(self) -> float:
        if not self.safe_total:
            return 0.0
        return self.safe_flagged / self.safe_total

    @property
    def abstention(self) -> float:
        return 1.0 - self.false_alarm_rate

    @property
    def precision(self) -> float:
        flagged = self.vulnerable_flagged + self.safe_flagged
        if not flagged:
            return 0.0
        return self.vulnerable_flagged / flagged

    def render(self) -> str:
        return (
            f"functions        : {self.vulnerable_total + self.safe_total} "
            f"({self.vulnerable_total} vulnerable / {self.safe_total} safe)\n"
            f"recall           : {self.vulnerable_flagged}/{self.vulnerable_total}"
            f" = {self.recall:.1%}\n"
            f"false alarms     : {self.safe_flagged}/{self.safe_total}"
            f" = {self.false_alarm_rate:.1%}\n"
            f"abstention (safe): {self.abstention:.1%}\n"
            f"precision        : {self.precision:.1%}"
        )


def labelled_functions(path: Path) -> list[LabelledFunction]:
    """Return the labelled functions in one smoke-set file."""
    lines = path.read_text(encoding="utf-8").split("\n")
    label: str | None = None
    out: list[LabelledFunction] = []
    for line in lines:
        if _VULNERABLE.match(line):
            label = "vulnerable"
            continue
        if _SAFE.match(line):
            label = "safe"
            continue
        match = _DEF.match(line)
        if match and label is not None:
            out.append(LabelledFunction(path, match.group(2), label))
    return out


def evaluate(root: Path | None = None, threshold: float = REPORTING_THRESHOLD) -> SmokeMetrics:
    """Scan the smoke set and measure recall, false alarms and abstention."""
    directory = root or DEFAULT_ROOT
    scanner = SyrthScanner()
    metrics = SmokeMetrics()

    for path in sorted(directory.glob("*.py")):
        if path.name == "run_tests.py":
            continue
        labelled = labelled_functions(path)
        if not labelled:
            continue
        report = scanner.scan_source(path.read_text(encoding="utf-8"), str(path))
        reported: dict[str, set[str]] = {}
        for trace in report.traces:
            if trace.confidence >= threshold:
                reported.setdefault(trace.function, set()).add(trace.cwe)

        for item in labelled:
            cwes = reported.get(item.name, set())
            key = f"{path.name}:{item.name}"
            if item.label == "vulnerable":
                metrics.vulnerable_total += 1
                if cwes:
                    metrics.vulnerable_flagged += 1
                    for cwe in cwes:
                        metrics.detected_cwes[cwe] = metrics.detected_cwes.get(cwe, 0) + 1
                else:
                    metrics.missed.append(key)
            else:
                metrics.safe_total += 1
                if cwes:
                    metrics.safe_flagged += 1
                    metrics.false_alarms.append(f"{key} {sorted(cwes)}")

    return metrics


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=None, help="directory of labelled files")
    parser.add_argument("--threshold", type=float, default=REPORTING_THRESHOLD)
    parser.add_argument("--json", default=None, help="write metrics JSON here")
    args = parser.parse_args(argv)

    root = Path(args.root) if args.root else None
    metrics = evaluate(root, args.threshold)
    print("SYRTH labelled smoke set (RLTESTS) -- regression gate, not a benchmark")
    print("=" * 62)
    print(metrics.render())
    if metrics.detected_cwes:
        print("detected by CWE  : " + ", ".join(
            f"{cwe}={count}" for cwe, count in sorted(metrics.detected_cwes.items())
        ))
    if metrics.missed:
        print("missed           : " + ", ".join(metrics.missed))
    if metrics.false_alarms:
        print("false alarms     :")
        for item in metrics.false_alarms:
            print("                   " + item)

    if args.json:
        payload = {
            "note": "curated smoke set; not an external corpus and not a benchmark",
            "vulnerable_total": metrics.vulnerable_total,
            "vulnerable_flagged": metrics.vulnerable_flagged,
            "safe_total": metrics.safe_total,
            "safe_flagged": metrics.safe_flagged,
            "recall": metrics.recall,
            "false_alarm_rate": metrics.false_alarm_rate,
            "abstention": metrics.abstention,
            "precision": metrics.precision,
            "missed": metrics.missed,
            "false_alarms": metrics.false_alarms,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
