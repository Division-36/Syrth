"""Competitor comparison: SYRTH against Bandit and Semgrep on one corpus.

Why this is shaped the way it is
--------------------------------
All three tools are measured against **the same independent ground truth**:
:func:`benchmarks.risk_metrics.expected_classes`, a plain AST scan that shares no
code with the analyser. Comparing SYRTH to Bandit using SYRTH's own output as the
answer key would measure agreement with itself, not coverage.

CWE attribution comes from each tool's **own published metadata**:

* Bandit emits ``issue_cwe: {"id": 502}`` per finding.
* Semgrep emits ``extra.metadata.cwe`` as ``"CWE-502: Deserialization ..."``.

A finding with no CWE metadata is counted as **unmapped**, never guessed into a
class. A rule that says nothing about CWE is not evidence about CWE, and mapping
it by hand would manufacture a number.

Per-tool kill rate
------------------
Coverage alone rewards breadth and says nothing about whether a tool respects a
mitigation. So each tool is also measured on the question ``docs/risk-model.md``
already defines for this project: *does the category's own mitigation remove the
flow it claims to?*

For every pair, a tool scores a **missed mitigation** when it names the class on the
vulnerable side and still names it on the patched side. That is measurable without a
negative class, because it compares a tool against itself across a known change
rather than against an external judgement of vulnerability. The patched side keeps
its sink call by construction, so a tool that reports there has not noticed the fix.

A tool that never names the class on the vulnerable side scores nothing here -- it is
absent from the measurement rather than counted as a pass.

What this does and does not show
--------------------------------
It shows which *vulnerability classes each tool names* on a fixed set of real
functions, how long each took, and whether each notices a fix. It does not show
precision, recall or vulnerability detection: the corpus has no reliable negative
class, and the patched side of each pair still contains its sink call by design.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from benchmarks.risk_metrics import expected_classes
from syrth.registry import CATEGORY_CWE, CWE_TO_CATEGORY
from syrth.scan import SyrthScanner

#: Classes SYRTH models, and therefore the only ones a comparison may score.
IN_SCOPE_LABELS = frozenset(CWE_TO_CATEGORY)

#: Commands used when the tool is not already importable. ``uvx`` pins nothing,
#: so results record the version each tool actually reported.
BANDIT_CMD = ["uvx", "--from", "bandit", "bandit"]
SEMGREP_CMD = ["uvx", "--from", "semgrep", "semgrep"]

#: Extra Semgrep rule sets, each measured as its own tool. A config is part of
#: what a tool ships, so "semgrep with one config" and "semgrep with another"
#: are different instruments and collapsing them would hide which rules did the
#: work.
SEMGREP_CONFIGS = (
    ("semgrep", "p/security-audit"),
    ("semgrep-owasp", "p/owasp-top-ten"),
)

_CWE_IN_TEXT = re.compile(r"CWE-(\d+)")


@dataclass
class ToolResult:
    """One tool's output over the whole corpus."""

    name: str
    version: str = ""
    #: record id -> classes named
    named: dict[str, set[str]] = field(default_factory=dict)
    #: findings whose rule carries no CWE, by record id
    unmapped: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0
    available: bool = True
    error: str = ""

    @property
    def total_unmapped(self) -> int:
        return sum(self.unmapped.values())


def _read_corpus(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise SystemExit(f"{path} not found; build it with tools/build_corpus.py first")
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    if not records:
        raise SystemExit(f"{path} contains no records")
    return records


def record_id(record: dict[str, Any]) -> str:
    """Stable per-record identity, unique across the two sides of a pair."""
    return f"{record['pair_id']}__{record['kind']}"


def safe_filename(identifier: str, index: int) -> str:
    """A filesystem-safe, collision-free file name for a record id.

    ``pair_id`` joins its parts with ``:``, which is legal in a record and illegal
    in a Windows path: there, ``a:b.py`` silently created a file called ``a`` and
    the tools then saw no ``.py`` files at all. The first comparison run reported
    0% coverage for every tool because of it, which is exactly the kind of number
    that must never be published unverified.

    Illegal characters become ``_``, and a short digest of the full identifier is
    appended so two ids that sanitise alike cannot collide.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", identifier)[:60]
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:10]
    return f"{index:04d}_{cleaned}_{digest}.py"


def materialise(records: Iterable[dict[str, Any]], directory: Path) -> dict[str, Path]:
    """Write one ``.py`` file per record.

    Corpus records are already self-contained snippets, so no rewriting is
    needed. See :func:`safe_filename` for why the name is not the raw id.
    """
    paths: dict[str, Path] = {}
    for index, record in enumerate(records):
        identifier = record_id(record)
        target = directory / safe_filename(identifier, index)
        target.write_text(record["source"], encoding="utf-8")
        paths[identifier] = target
    return paths


# ---------------------------------------------------------------------------
# CWE extraction
# ---------------------------------------------------------------------------


def bandit_cwes(result: dict[str, Any]) -> set[str]:
    """Classes from a Bandit finding, via its own ``issue_cwe`` field."""
    cwe = result.get("issue_cwe")
    if isinstance(cwe, dict) and isinstance(cwe.get("id"), int):
        return {f"CWE-{cwe['id']}"}
    if isinstance(cwe, dict) and isinstance(cwe.get("link"), str):
        found = _CWE_IN_TEXT.search(cwe["link"])
        if found:
            return {f"CWE-{found.group(1)}"}
    return set()


def semgrep_cwes(result: dict[str, Any]) -> set[str]:
    """Classes from a Semgrep finding, via ``extra.metadata.cwe``."""
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    found: set[str] = set()
    for key in ("cwe", "cweCategory"):
        value = metadata.get(key) or extra.get(key)
        if isinstance(value, str):
            found.update(f"CWE-{m}" for m in _CWE_IN_TEXT.findall(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    found.update(f"CWE-{m}" for m in _CWE_IN_TEXT.findall(item))
    return found


# ---------------------------------------------------------------------------
# Tool drivers
# ---------------------------------------------------------------------------


def _run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
        cwd=str(cwd) if cwd else None,
    )


def _parse_json_output(raw: str) -> dict[str, Any] | None:
    """Both tools print JSON, but semgrep may precede it with warnings."""
    start = raw.find("{")
    while start != -1:
        try:
            return json.loads(raw[start:])
        except json.JSONDecodeError:
            start = raw.find("{", start + 1)
    return None


def run_bandit(paths: dict[str, Path]) -> ToolResult:
    result = ToolResult(name="bandit")
    by_name = {p.name: rid for rid, p in paths.items()}
    command = BANDIT_CMD + [
        "-f", "json", "-q", "-r",
        str(next(iter(paths.values())).parent),
    ]
    started = time.perf_counter()
    try:
        completed = _run(command)
    except (OSError, subprocess.SubprocessError) as exc:
        result.available = False
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.seconds = time.perf_counter() - started
    payload = _parse_json_output(completed.stdout)
    if payload is None:
        result.available = False
        result.error = (completed.stderr or completed.stdout or "")[:400]
        return result
    metrics = payload.get("metrics") or {}
    result.version = f"bandit (python {metrics.get('_totals', {}).get('loc', '?')} loc reported)"
    for finding in payload.get("results") or []:
        identifier = by_name.get(Path(finding.get("filename", "")).name)
        if identifier is None:
            continue
        classes = bandit_cwes(finding)
        if classes:
            result.named.setdefault(identifier, set()).update(classes)
        else:
            result.unmapped[identifier] = result.unmapped.get(identifier, 0) + 1
    return result


def run_semgrep(paths: dict[str, Path], config: str, name: str = "semgrep") -> ToolResult:
    result = ToolResult(name=name)
    by_name = {p.name: rid for rid, p in paths.items()}
    command = SEMGREP_CMD + [
        "--json", "--quiet", "--config", config,
        "--disable-version-check", "--metrics", "off", "--no-git-ignore",
        "--timeout", "60", "--max-target-bytes", "2000000",
        str(next(iter(paths.values())).parent),
    ]
    started = time.perf_counter()
    try:
        completed = _run(command)
    except (OSError, subprocess.SubprocessError) as exc:
        result.available = False
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.seconds = time.perf_counter() - started
    payload = _parse_json_output(completed.stdout)
    if payload is None:
        result.available = False
        result.error = (completed.stderr or completed.stdout or "")[:400]
        return result
    for finding in payload.get("results") or []:
        identifier = by_name.get(Path(finding.get("path", "")).name)
        if identifier is None:
            identifier = by_name.get(Path(finding.get("path", "")).resolve().name)
        if identifier is None:
            continue
        classes = semgrep_cwes(finding)
        if classes:
            result.named.setdefault(identifier, set()).update(classes)
        else:
            result.unmapped[identifier] = result.unmapped.get(identifier, 0) + 1
    return result


def run_syrth(records: list[dict[str, Any]], threshold: float = 0.5) -> ToolResult:
    """SYRTH over the same records, through the same ground truth comparison."""
    result = ToolResult(name="syrth")
    scanner = SyrthScanner(threshold=threshold)
    started = time.perf_counter()
    for record in records:
        identifier = record_id(record)
        report = scanner.scan_source(record["source"], record["pair_id"])
        classes = {finding.category for finding in report.findings}
        mapped = set()
        for category in classes:
            label = _category_to_cwe(category)
            if label:
                mapped.add(label)
        if mapped:
            result.named[identifier] = mapped
    result.seconds = time.perf_counter() - started
    result.version = "syrth (in-process)"
    return result


def _category_to_cwe(category: str) -> str | None:
    return CATEGORY_CWE.get(category)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


@dataclass
class Coverage:
    name: str
    covered: int = 0
    expected: int = 0
    per_class_covered: Counter = field(default_factory=Counter)
    per_class_expected: Counter = field(default_factory=Counter)
    seconds: float = 0.0
    unmapped: int = 0
    available: bool = True
    error: str = ""
    #: Pairs where this tool named the class on the vulnerable side, i.e. the
    #: population the mitigation rate is over.
    measurable_pairs: int = 0
    #: Of those, how many it also still names after the patch.
    missed_mitigations: int = 0
    #: Of those, how many it stopped naming after the patch.
    noticed_mitigation: int = 0

    @property
    def percent(self) -> float:
        return 100.0 * self.covered / self.expected if self.expected else 0.0

    @property
    def mitigation_percent(self) -> float:
        """Share of visible pairs where this tool stopped reporting after the fix.

        ``None`` would be the honest answer when nothing was measurable, so this
        reports 0.0 and the population is always printed next to it -- a tool that
        names nothing must not be readable as a tool that notices every fix.
        """
        if not self.measurable_pairs:
            return 0.0
        return 100.0 * self.noticed_mitigation / self.measurable_pairs


def compare(
    records: list[dict[str, Any]],
    results: dict[str, ToolResult],
) -> dict[str, Coverage]:
    """Class coverage per tool against the independent expectations."""
    expected: dict[str, set[str]] = {
        record_id(record): expected_classes(record["source"]) & IN_SCOPE_LABELS
        for record in records
    }
    total_expected = sum(len(v) for v in expected.values())
    per_class = Counter()
    for classes in expected.values():
        per_class.update(classes)

    coverages: dict[str, Coverage] = {}
    for name, result in results.items():
        coverage = Coverage(name=name, seconds=result.seconds)
        coverage.available = result.available
        coverage.error = result.error
        coverage.unmapped = result.total_unmapped
        if not result.available:
            coverages[name] = coverage
            continue
        covered = 0
        hit = Counter()
        for identifier, classes in expected.items():
            named = result.named.get(identifier, set())
            for cwe in classes:
                if cwe in named:
                    covered += 1
                    hit[cwe] += 1
        coverage.covered = covered
        coverage.expected = total_expected
        coverage.per_class_covered = hit
        coverage.per_class_expected = per_class
        coverage.measurable_pairs, coverage.missed_mitigations, \
            coverage.noticed_mitigation = mitigation_counts(
                records, result, expected)
        coverages[name] = coverage
    return coverages



def mitigation_counts(
    records: list[dict[str, Any]],
    result: ToolResult,
    expected: dict[str, set[str]],
) -> tuple[int, int, int]:
    """``(measurable, missed, noticed)`` for one tool over the corpus pairs.

    A pair is measurable when the tool named the class on the vulnerable side.
    It then counts as *noticed* if the class is gone from the patched side and as
    *missed* if the tool still reports it, which is the interesting failure: the fix
    is in the file and the tool did not register it.
    """
    # Keyed by ``pair_id``, not by ``record_id``: ``record_id`` appends the side
    # (``__vulnerable`` / ``__patched``), so keying on it and then looking up a
    # bare ``pair_id`` never matches and the whole measurement silently reads
    # zero pairs. A harness that reports 0/0 looks like a tool that never fires.
    vulnerable = {r["pair_id"]: r for r in records if r.get("kind") == "vulnerable"}
    measurable = missed = noticed = 0
    for record in records:
        if record.get("kind") != "patched":
            continue
        pair = record.get("pair_id")
        before = vulnerable.get(pair)
        if before is None:
            continue
        after_id = record_id(record)
        before_id = record_id(before)
        named_before = result.named.get(before_id, set())
        if not named_before:
            continue
        measurable += 1
        if named_before & result.named.get(after_id, set()):
            missed += 1
        else:
            noticed += 1
    return measurable, missed, noticed



#: Corpus pairs used to compare tools. Checked at runtime rather than assumed: a
#: pair whose patched side is byte-identical to its vulnerable side cannot show a
#: mitigation, and including it would dilute every tool's rate toward the average.
def assert_pairs_are_distinct(records: list[dict[str, Any]]) -> int:
    """Verify both sides of every pair really differ, and return the pair count.

    Raises:
        SystemExit: if any patched side is identical to its vulnerable mate, or a
            vulnerable record has no patched mate. Either means the corpus no
            longer measures what the mitigation column claims to measure, and a
            rate computed over it would be arithmetically fine and meaningless.
    """
    def body(source: str) -> str:
        lines = source.split("\n")
        for index, line in enumerate(lines):
            if re.match(r"^\s*(async\s+)?def\s", line):
                return "\n".join(lines[index:])
        return source

    vulnerable = {r["pair_id"]: r for r in records if r.get("kind") == "vulnerable"}
    patched = {r["pair_id"]: r for r in records if r.get("kind") == "patched"}
    identical = [
        pid for pid, after in patched.items()
        if pid in vulnerable
        and body(vulnerable[pid]["source"]) == body(after["source"])
    ]
    orphans = [pid for pid in vulnerable if pid not in patched]
    if identical:
        raise SystemExit(
            f"{len(identical)} patched sides are identical to their vulnerable "
            f"mate, e.g. {identical[0]}; the mitigation column would be measuring "
            f"nothing. Rebuild the corpus before quoting a fix rate."
        )
    if orphans:
        raise SystemExit(
            f"{len(orphans)} vulnerable records have no patched mate, e.g. "
            f"{orphans[0]}; they cannot be measured either way."
        )
    return len(vulnerable)


def render(
    coverages: dict[str, Coverage], corpus: Path, records: int, pairs: int = 0
) -> str:
    lines = ["=" * 74,
             "SYRTH vs Bandit vs Semgrep -- class coverage on one corpus",
             "=" * 74,
             f"corpus : {corpus}  ({records} records, {pairs} pairs)",
             "",
             "Ground truth is an independent AST scan (benchmarks.risk_metrics).",
             "CWE attribution is each tool's own metadata; unmapped findings are",
             "counted, never guessed into a class.",
             ""]
    header = (f"{'tool':<14}{'coverage':>12}{'':>7}"
              f"{'fix noticed':>14}{'still flagged':>15}{'seconds':>9}")
    lines.append(header)
    lines.append("-" * len(header))
    for name, coverage in coverages.items():
        if not coverage.available:
            lines.append(f"{name:<14}{'unavailable':>19}{'-':>7}"
                         f"{'-':>14}{'-':>15}{'-':>9}")
            lines.append(f"               {coverage.error[:58]}")
            continue
        lines.append(
            f"{name:<14}{f'{coverage.covered}/{coverage.expected}':>12}"
            f"{f'{coverage.percent:.1f}%':>7}"
            f"{f'{coverage.noticed_mitigation}/{coverage.measurable_pairs}':>14}"
            f"{f'{coverage.missed_mitigations}/{coverage.measurable_pairs}':>15}"
            f"{coverage.seconds:>9.2f}"
        )

    classes = sorted({c for c in coverages["syrth"].per_class_expected})
    if classes:
        lines += ["", "per class (covered/expected):"]
        for cwe in classes:
            cells = []
            for name, coverage in coverages.items():
                expected = coverage.per_class_expected.get(cwe, 0)
                got = coverage.per_class_covered.get(cwe, 0)
                cells.append(f"{name} {got}/{expected}")
            lines.append(f"  {cwe:<9}" + "   ".join(cells))

        # A class a tool never names is a different situation from one it names
        # and misses. Bandit has no open-redirect rule, so its 0/17 is "does not
        # model this class", not "failed to detect it". Reporting only the first
        # number would let a reader draw the wrong conclusion in either
        # direction, so both are shown.
        modelled = {
            name: set(coverage.per_class_covered)
            for name, coverage in coverages.items()
        }
        lines += ["", "classes each tool models at all (names anywhere on this corpus):"]
        for name in coverages:
            have = sorted(modelled.get(name, ()))
            lines.append(f"  {name:<10} {len(have)} of {len(classes)}: "
                         f"{', '.join(have) if have else 'none'}")
        lines += [
            "",
            "Coverage counts a class as expected whenever its sink is present in",
            "the snippet. For a class a tool does not model, that is a rule-set",
            "difference, not a detection failure -- read the two tables together.",
        ]
    lines += [
        "",
        "coverage       classes named, against the independent AST scan.",
        "fix noticed    pairs where this tool named the class on the vulnerable",
        "               side and stopped naming it on the patched side. This is",
        "               the mitigation question docs/risk-model.md already",
        "               defines for this project, applied to every tool.",
        "still flagged  pairs where it kept reporting after the fix.",
        "",
        "Read the two right-hand columns together with their denominator. A tool",
        "that names nothing has 0 noticed out of 0 measurable pairs, which is not",
        "a perfect score -- it is an absence of measurement, and the population",
        "column is what distinguishes the two.",
        "",
        "This compares which classes each tool NAMES and whether it registers a",
        "fix. It is not a precision or recall measurement: the corpus has no",
        "reliable negative class, and each pair's patched side still contains its",
        "sink call by design.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--skip", nargs="*", default=(),
                        help="tools to skip: bandit semgrep syrth")
    parser.add_argument("--json", default=None, help="write results as JSON")
    args = parser.parse_args(argv)

    corpus = Path(args.dataset)
    records = _read_corpus(corpus)
    pairs = assert_pairs_are_distinct(records)
    results: dict[str, ToolResult] = {}
    if "syrth" not in args.skip:
        results["syrth"] = run_syrth(records)
    directory = Path(tempfile.mkdtemp(prefix="syrth-competitors-"))
    try:
        paths = materialise(records, directory)
        if "bandit" not in args.skip:
            results["bandit"] = run_bandit(paths)
        for name, config in SEMGREP_CONFIGS:
            if name in args.skip:
                continue
            results[name] = run_semgrep(paths, config, name)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    coverages = compare(records, results)
    print(render(coverages, corpus, len(records), pairs))

    if args.json:
        payload = {
            "corpus": str(corpus),
            "records": len(records),
            "pairs": pairs,
            "ground_truth": "benchmarks.risk_metrics.expected_classes",
            "tools": {
                name: {
                    "available": c.available,
                    "error": c.error,
                    "covered": c.covered,
                    "expected": c.expected,
                    "percent": round(c.percent, 2),
                    "unmapped_findings": c.unmapped,
                    "seconds": round(c.seconds, 3),
                    "fix_noticed": c.noticed_mitigation,
                    "still_flagged_after_fix": c.missed_mitigations,
                    "measurable_pairs": c.measurable_pairs,
                    "fix_noticed_percent": round(c.mitigation_percent, 2),
                    "classes_modelled": sorted(
                        {k for k in c.per_class_covered}),
                    "per_class": {
                        cwe: f"{c.per_class_covered.get(cwe, 0)}"
                              f"/{c.per_class_expected.get(cwe, 0)}"
                        for cwe in sorted(c.per_class_expected)
                    },
                }
                for name, c in coverages.items()
            },
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n-> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
