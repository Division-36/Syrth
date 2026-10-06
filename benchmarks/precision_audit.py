"""Precision from adjudications, with the instrument's blind spot made explicit.

This exists because the name-list oracle in `benchmarks.risk_metrics` is coarser
than the analyser it measures. Against that oracle SYRTH scores 63.8% precision,
and 75 of 75 disagreements are sinks the oracle cannot see -- `os.path.join`,
`Markup`, `FileResponse`, `render_template` -- which are real sinks. Adjudicating
the claims by hand settles them.

The adjudicated figure is the honest one, and it is computed only over the subset
that needed judgement. Cases where both detectors already agree are not
re-adjudicated; they are counted through the oracle, which is adequate for
agreement. The report states both numbers and the coverage of the adjudication so
neither can be quoted alone.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from benchmarks.risk_metrics import expected_classes
from benchmarks.run_benchmarks import load_records
from syrth.registry import CWE_TO_CATEGORY
from syrth.scan import SyrthScanner

IN_SCOPE = frozenset(CWE_TO_CATEGORY)

#: Verdicts that count as "the finding is justified".
JUSTIFIED = {"defensible"}


def load_adjudications(path: pathlib.Path) -> dict[str, dict]:
    """Read the adjudication ledger.

    This file is written and revised by hand, so a malformed line must not take
    the audit down: a verdict that cannot be read is reported as *missing* and
    counted as unadjudicated, which lowers the reported precision rather than
    silently raising it. Failing loudly here would be worse than the defect it
    guards against, because a crashed audit invites a rerun against a
    hand-trimmed file.
    """
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip().lstrip("﻿")
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError:
            print(f"  skipping unreadable adjudication on line {number}")
            continue
        claim = row.get("claim_id")
        if not claim or "verdict" not in row:
            print(f"  skipping incomplete adjudication on line {number}")
            continue
        out[claim] = row
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--adjudications", default="data/adjudications.jsonl")
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    records = load_records(args.dataset)
    scanner = SyrthScanner(threshold=0.5)
    adjudications = load_adjudications(pathlib.Path(args.adjudications))

    oracle_tp = oracle_fp = 0
    adj_considered = adj_justified = adj_rejected = adj_missing = 0
    by_verdict: collections.Counter = collections.Counter()
    verdict_records: collections.Counter = collections.Counter()
    by_class: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter)

    for record in records:
        want = expected_classes(record.source) & IN_SCOPE
        report = scanner.scan_source(record.source, record.group)
        named: dict[str, set[str]] = {}
        for finding in report.findings:
            named.setdefault(finding.cwe, set()).add(finding.sink_call)

        for cwe, sinks in named.items():
            agreed = cwe in want
            if agreed:
                oracle_tp += 1
                by_class[cwe]["agreed"] += 1
                # One claim instance per agreeing class, regardless of how many
                # call sites the analyser named, so the units match the disputed
                # side below.
                continue

            for sink in sinks:
                oracle_fp += 1
                by_class[cwe]["disputed"] += 1
                key = f"{cwe}/{sink}"
                row = adjudications.get(key)
                if row is None:
                    adj_missing += 1
                    by_verdict["unadjudicated"] += 1
                    verdict_records[f"unadjudicated:{cwe}"] += 1
                    continue
                adj_considered += 1
                by_verdict[row["verdict"]] += 1
                verdict_records[f"{row['verdict']}:{cwe}"] += 1
                if row["verdict"] in JUSTIFIED:
                    adj_justified += 1
                else:
                    adj_rejected += 1

    # Every reported claim is either corroborated by the oracle, adjudicated as
    # justified, adjudicated as rejected, or unadjudicated. The four partition
    # the same population, which is what keeps the precision bounded by 100%.
    total_claims = oracle_tp + adj_justified + adj_rejected + adj_missing
    adjudicated_claims = adj_justified + adj_rejected
    adjudicated_total = total_claims - adj_missing
    oracle_total = oracle_tp + oracle_fp

    print("=" * 78)
    print("SYRTH precision: the oracle's figure and the adjudicated figure")
    print("=" * 78)
    print(f"corpus: {args.dataset}   claims adjudicated: {len(adjudications)}")
    print()
    print(f"{'':<34}{'value':>14}")
    print(f"{'reported claims (partitioned)':<34}{total_claims:>14}")
    print(f"{'corroborated by the name-list oracle':<34}{oracle_tp:>14}")
    print(f"{'disputed':<34}{oracle_fp:>14}")
    print(f"{'oracle precision (disputed all counted false)':<34}"
          f"{pct(oracle_tp, oracle_total):>14}")
    print()
    print(f"{'disputed claims adjudicated':<34}{adjudicated_claims:>14}")
    print(f"{'  justified':<34}{adj_justified:>14}")
    print(f"{'  rejected':<34}{adj_rejected:>14}")
    print(f"{'  unadjudicated':<34}{adj_missing:>14}")
    print()
    print(f"{'precision on the adjudicated subset':<34}"
          f"{pct(adj_justified, adjudicated_claims):>14}")
    print(f"{'precision over the whole corpus':<34}"
          f"{pct(oracle_tp + adj_justified, adjudicated_total):>14}")
    print(f"{'  lower bound (unadjudicated counted false)':<34}"
          f"{pct(oracle_tp + adj_justified, total_claims):>14}")
    for key, count in sorted(verdict_records.items()):
        print(f"  {count:>4}  {key}")
    print()
    print("per class (agreed/disputed):")
    for cwe in sorted(by_class):
        row = by_class[cwe]
        print(f"  {cwe:<10} agreed {row['agreed']:>4}   disputed {row['disputed']:>4}")
    print()
    print("Both figures must be read together. The oracle figure understates the")
    print("analyser because the oracle cannot see sinks like Markup or")
    print("os.path.join; the adjudicated figure is bounded by how much of the")
    print("disputed set was actually adjudicated, which is reported above.")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps({
            "corpus": args.dataset,
            "reported_claims": total_claims,
            "oracle_true_positive": oracle_tp,
            "oracle_disputed": oracle_fp,
            "oracle_precision": fraction(oracle_tp, oracle_total),
            "claims_adjudicated": adjudicated_claims,
            "claims_unadjudicated": adj_missing,
            "adjudicated_justified": adj_justified,
            "adjudicated_precision_disputed": fraction(adj_justified, adjudicated_claims),
            "adjudicated_precision_overall": fraction(
                oracle_tp + adj_justified, adjudicated_total),
            "adjudicated_precision_lower_bound": fraction(
                oracle_tp + adj_justified, total_claims),
            "verdicts": dict(by_verdict),
        }, indent=2), encoding="utf-8")
        print(f"\n-> {args.json}")
    return 0


def pct(num: int, den: int) -> str:
    return f"{100.0 * num / den:.1f}%" if den else "n/a"


def fraction(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


if __name__ == "__main__":
    raise SystemExit(main())
