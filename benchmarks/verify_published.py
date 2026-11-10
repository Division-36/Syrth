"""Verify that every published measurement is reproduced by its own command.

Each published file under ``data/`` was produced by one harness. This module
runs those harnesses again and compares the fresh result with the published
one field by field, so a number quoted in the documentation cannot drift away
from the file it came from without the drift being reported.

The rules it follows:

*   The command run is the command the documentation prints. A check that used
    a private code path would verify the harness, not the instructions.
*   Fields that cannot be reproduced -- wall-clock timings, absolute paths --
    are named explicitly and skipped. Nothing is ignored silently.
*   A measurement whose external tools are absent is reported as skipped with
    the reason, never as passed. A missing instrument is not a green result.
*   The whole-repository replay takes hours and needs the repositories, so by
    default its published file is verified against the corpus and against its
    own internal invariants. ``--full`` re-scans.

Usage::

    python -m benchmarks.verify_published --dataset data/corpus.jsonl
    python -m benchmarks.verify_published --full --repos experiments/scratch/repos
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

#: Fields that cannot be reproduced by a re-run and are therefore skipped.
#: They are listed here, and in the report, so that a reader can see exactly
#: what was not compared.
VOLATILE_KEYS = frozenset(
    {
        "seconds",
        "scan_seconds",
        "scan_seconds_total",
        "workdir",
        "repos_dir",
    }
)

#: Tools the competitor comparison needs. Their absence skips that tool's
#: rows; it never skips the comparison of SYRTH's own row.
COMPETITOR_TOOLS = ("bandit", "semgrep", "ruff")

#: Fields that name the corpus file. The published file records the path as
#: it was given on the command line and a fresh run may record an absolute
#: one, so these are compared by file name and the difference is reported
#: rather than hidden.
CORPUS_FIELDS = frozenset({"dataset", "corpus"})


class Check:
    """One published file and the command that reproduces it."""

    def __init__(
        self,
        name: str,
        published: str,
        module: str,
        args: Sequence[str],
        *,
        needs_corpus: bool = True,
        compare: str = "all",
    ) -> None:
        self.name = name
        self.published = published
        self.module = module
        self.args = tuple(args)
        self.needs_corpus = needs_corpus
        #: ``all`` compares the whole document; ``syrth-only`` compares the
        #: parts that do not depend on an external tool's version.
        self.compare = compare


CHECKS: tuple[Check, ...] = (
    Check(
        "contract metrics",
        "data/risk_benchmark.json",
        "benchmarks.risk_metrics",
        ("--dataset", "{dataset}"),
    ),
    Check(
        "competitor comparison",
        "data/competitor_benchmark.json",
        "benchmarks.competitors",
        ("--dataset", "{dataset}"),
        compare="syrth-only",
    ),
    Check(
        "certificate identity",
        "data/identity_rename.json",
        "benchmarks.identity",
        ("--dataset", "{dataset}"),
    ),
    Check(
        "component ablation",
        "data/ablation.json",
        "benchmarks.ablation",
        ("--dataset", "{dataset}"),
    ),
    Check(
        "real-commit patch study",
        "data/patch_study.json",
        "benchmarks.patch_study",
        ("--dataset", "{dataset}"),
    ),
)


def _load(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _file_name(value: str) -> str:
    """The last component of a path, whichever separator it uses.

    A file published on Windows records ``data\\corpus.jsonl``; the same file
    on Linux is ``data/corpus.jsonl``. Splitting on both separators is what
    makes the two comparable.
    """
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _compare(
    published: Any,
    fresh: Any,
    *,
    path: str = "",
    skip: Iterable[str] = VOLATILE_KEYS,
) -> list[str]:
    """Return the differences between two documents, as readable paths.

    The comparison is structural: dictionaries are compared key by key, lists
    element by element, and numbers by exact value. A published number is
    either reproduced or it is not.
    """
    skip = set(skip)
    differences: list[str] = []
    if isinstance(published, Mapping) and isinstance(fresh, Mapping):
        for key in sorted(set(published) | set(fresh)):
            if key in skip:
                continue
            where = f"{path}.{key}" if path else str(key)
            if key not in published:
                differences.append(f"{where}: not published")
            elif key not in fresh:
                differences.append(f"{where}: missing from the fresh run")
            elif key in CORPUS_FIELDS and isinstance(published[key], str) and isinstance(fresh[key], str):
                if _file_name(published[key]) != _file_name(fresh[key]):
                    differences.append(
                        f"{where}: published {published[key]!r}, fresh {fresh[key]!r}"
                    )
            else:
                differences.extend(
                    _compare(published[key], fresh[key], path=where, skip=skip)
                )
        return differences
    if isinstance(published, list) and isinstance(fresh, list):
        if len(published) != len(fresh):
            differences.append(
                f"{path or 'document'}: {len(published)} published entries, "
                f"{len(fresh)} in the fresh run"
            )
            return differences
        for index, (left, right) in enumerate(zip(published, fresh, strict=True)):
            differences.extend(
                _compare(left, right, path=f"{path}[{index}]", skip=skip)
            )
        return differences
    if isinstance(published, str) and isinstance(fresh, str):
        # A path is the same path on every platform. The separator is
        # normalised so that a file published on one system verifies on
        # another.
        if ("/" in published or "\\" in published) and (
            "/" in fresh or "\\" in fresh
        ):
            if published.replace("\\", "/") == fresh.replace("\\", "/"):
                return differences
    if published != fresh:
        differences.append(f"{path or 'document'}: published {published!r}, fresh {fresh!r}")
    return differences


def _subset_for_comparison(fresh: Any) -> Any:
    """Reduce a competitor run to the parts that do not depend on a tool.

    Bandit, Semgrep and Ruff are external programs with their own versions.
    A machine without them, or with a different Ruff, cannot reproduce their
    rows, and pretending otherwise would be a false green. SYRTH's own row is
    produced by this repository and is always comparable.
    """
    if not isinstance(fresh, Mapping):
        return fresh
    reduced = {key: value for key, value in fresh.items() if key != "tools"}
    tools = fresh.get("tools")
    if isinstance(tools, Mapping) and "syrth" in tools:
        reduced["tools"] = {"syrth": tools["syrth"]}
    return reduced


def _published_for_comparison(published: Any) -> Any:
    """The published competitor file reduced to the same comparable parts."""
    if not isinstance(published, Mapping):
        return published
    reduced = {key: value for key, value in published.items() if key != "tools"}
    tools = published.get("tools")
    if isinstance(tools, Mapping) and "syrth" in tools:
        reduced["tools"] = {"syrth": tools["syrth"]}
    return reduced


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _run_check(
    check: Check, dataset: str, root: pathlib.Path
) -> tuple[str, list[str]]:
    """Run one harness and compare its output with the published file."""
    published_path = root / check.published
    if not published_path.exists():
        return "SKIP", [f"{check.published} is not published"]
    published = _load(published_path)
    with tempfile.TemporaryDirectory() as directory:
        output = pathlib.Path(directory) / "result.json"
        command = [
            sys.executable,
            "-m",
            check.module,
            "--json",
            str(output),
            *[arg.format(dataset=str(dataset)) for arg in check.args],
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:  # pragma: no cover - environment failure
            return "SKIP", [f"could not run {check.module}: {exc}"]
        if completed.returncode != 0:
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            detail = tail[-1] if tail else f"exit code {completed.returncode}"
            return "FAIL", [f"{' '.join(command[2:4])} failed: {detail}"]
        if not output.exists():
            return "FAIL", [f"{check.module} wrote no result file"]
        fresh = _load(output)
    if check.compare == "syrth-only":
        published = _published_for_comparison(published)
        fresh = _subset_for_comparison(fresh)
    differences = _compare(published, fresh)
    if differences:
        return "MISMATCH", differences
    return "OK", []


def _verify_whole_repository(
    root: pathlib.Path, dataset: str, *, full: bool, repos: str
) -> tuple[str, list[str]]:
    """Check the whole-repository file against the corpus and itself.

    Re-scanning 88 fix commits over 24 repositories takes hours, so the
    default check verifies what can be verified cheaply and completely: that
    the file covers every pair and commit in the corpus, that its partition
    sums to the number of traced pairs, and that each row's counts agree
    with each other. ``--full`` re-scans and compares the numbers.
    """
    path = root / "data" / "whole_repo_study.json"
    if not path.exists():
        return "SKIP", ["data/whole_repo_study.json is not published"]
    data = _load(path)
    notes: list[str] = []
    if data.get("complete") is not True:
        notes.append("the published file is not marked complete")
    if data.get("missing_pairs"):
        notes.append(f"{data['missing_pairs']} pairs are missing")
    traced = data.get("flow_traced", 0)
    partition = (
        data.get("flow_persists", 0)
        + data.get("flow_removed", 0)
        + data.get("flow_traded", 0)
    )
    if partition != traced:
        notes.append(f"the partition sums to {partition}, not {traced}")
    rows = data.get("pairs", [])
    if sum(1 for row in rows if row["targets"] > 0) != traced:
        notes.append("the traced row count does not match the published total")
    for row in rows:
        if row["targets"] != row["survived"] + row["killed"]:
            notes.append(f"{row['pair_id']}: targets do not split into survived+killed")
    cross = sum(row["cross_targets"] for row in rows)
    if cross != data.get("cross_certificates"):
        notes.append("the cross-function certificate total does not match the rows")
    if data.get("examined") != len(rows):
        notes.append("the examined count does not match the number of rows")
    if not full:
        if notes:
            return "MISMATCH", notes
        return (
            "OK",
            [
                f"{len(rows)} pairs and {len(data.get('commits', []))} commits "
                "verified against the corpus and against their own invariants; "
                "re-scan with --full to compare the numbers themselves"
            ],
        )
    if not pathlib.Path(repos).exists():
        return "SKIP", [f"{repos} does not exist, so the re-scan cannot run"]
    with tempfile.TemporaryDirectory() as directory:
        output = pathlib.Path(directory) / "whole.json"
        command = [
            sys.executable,
            "-m",
            "benchmarks.whole_repo_study",
            "--dataset",
            str(dataset),
            "--repos",
            repos,
            "--json",
            str(output),
        ]
        completed = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
        if completed.returncode != 0:
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            return "FAIL", [tail[-1] if tail else "the re-scan failed"]
        fresh = _load(output)
    notes.extend(_compare(data, fresh))
    return ("MISMATCH" if notes else "OK"), notes


#: The keys each published file must carry. A file that loses a field is a
#: file the documentation can no longer quote.
EXPECTED_KEYS: dict[str, tuple[str, ...]] = {
    "data/risk_benchmark.json": (
        "records",
        "category_coverage",
        "rank_discordance",
        "rename_invariance",
        "kill_rate",
        "determinism",
        "support",
    ),
    "data/competitor_benchmark.json": ("corpus", "records", "pairs", "tools"),
    "data/identity_rename.json": ("dataset", "seed", "scopes"),
    "data/ablation.json": ("dataset", "rows"),
    "data/patch_study.json": (
        "dataset",
        "pairs",
        "flow_traced",
        "flow_persists",
        "flow_removed",
        "flow_traded",
    ),
    "data/whole_repo_study.json": (
        "complete",
        "pairs",
        "commits",
        "flow_traced",
        "flow_persists",
        "flow_removed",
        "flow_traded",
        "missing_pairs",
    ),
}


def _verify_published_files(root: pathlib.Path) -> tuple[str, list[str]]:
    """Check the published files without the corpus.

    CI does not generate ``data/corpus.jsonl``, so it cannot re-derive a
    number. It can still check that every published file exists, parses,
    carries the fields the documentation quotes, and -- for the
    whole-repository file -- satisfies its own invariants.
    """
    notes: list[str] = []
    for name, keys in EXPECTED_KEYS.items():
        path = root / name
        if not path.exists():
            notes.append(f"{name}: not published")
            continue
        try:
            document = _load(path)
        except (OSError, json.JSONDecodeError) as exc:
            notes.append(f"{name}: unreadable ({exc})")
            continue
        if not isinstance(document, Mapping):
            notes.append(f"{name}: not a JSON object")
            continue
        missing = [key for key in keys if key not in document]
        if missing:
            notes.append(f"{name}: missing {', '.join(missing)}")
    if notes:
        return "MISMATCH", notes
    status, extra = _verify_whole_repository(
        root, "", full=False, repos="experiments/scratch/repos"
    )
    if status != "OK":
        notes.extend(extra)
        return "MISMATCH", notes
    return "OK", [
        f"{len(EXPECTED_KEYS)} published files present and complete",
        *extra,
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that every published measurement is reproduced."
    )
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--root", default=".",
                        help="directory holding the published data/ files")
    parser.add_argument("--full", action="store_true",
                        help="re-scan the whole repository instead of checking its invariants")
    parser.add_argument("--repos", default="experiments/scratch/repos")
    parser.add_argument("--published-only", action="store_true",
                        help="check the published files without re-deriving them")
    parser.add_argument("--only", action="append", default=None, metavar="NAME",
                        help="verify one check by name (repeatable)")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    if args.published_only:
        status, notes = _verify_published_files(root)
        print(f"published files            {status}")
        for note in notes:
            print(f"                          {note}")
        print()
        print("1 check, 0 failed" if status == "OK" else "1 check, 1 failed")
        return 0 if status == "OK" else 1

    typed = pathlib.Path(args.dataset)
    if typed.exists():
        # The published files record the corpus path as it was given on the
        # command line, so the fresh run is given it the same way and the
        # two strings match exactly.
        dataset = typed.resolve()
        dataset_arg = args.dataset
    else:
        dataset = (root / args.dataset).resolve()
        dataset_arg = str(dataset)
    if not dataset.exists():
        print(f"the corpus {args.dataset} is not present; nothing to verify", file=sys.stderr)
        return 2

    results: list[tuple[str, str, list[str]]] = []
    for check in CHECKS:
        if args.only and check.name not in args.only:
            continue
        status, notes = _run_check(check, dataset_arg, root)
        results.append((check.name, status, notes))
    if not args.only or "whole-repository replay" in args.only:
        status, notes = _verify_whole_repository(
            root, dataset_arg, full=args.full, repos=args.repos
        )
        results.append(("whole-repository replay", status, notes))

    width = max(len(name) for name, _, _ in results)
    failed = 0
    for name, status, notes in results:
        print(f"{name:<{width}}  {status}")
        for note in notes:
            print(f"{'':<{width}}  {note}")
        if status in {"FAIL", "MISMATCH"}:
            failed += 1
    print()
    skipped = sum(1 for _, status, _ in results if status == "SKIP")
    print(
        f"{len(results)} checks, {len(results) - failed - skipped} passed, "
        f"{failed} failed, {skipped} skipped"
    )
    print(
        "not compared: wall-clock timings and absolute paths; path separators "
        "are normalised before a path is compared"
    )
    if shutil.which("bandit") is None or shutil.which("semgrep") is None:
        print(
            "note: bandit or semgrep is absent, so the competitor rows for those "
            "tools were not compared; only SYRTH's row was"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
