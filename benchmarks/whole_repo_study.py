"""Real-commit whole-repository patch study.

The corpus contains real fix commits, but the patch study only scanned the
extracted function. This harness asks the same advisory-level question over
full working trees: did the flow the fix was about survive in the repository?

Two revisions are scanned per fix commit: ``<commit>~1`` (vulnerable) and
``<commit>`` (patched). The trees are reused per repository, and identical
revision scans are cached in memory. Every aggregate reported here
has its denominator in the JSON output.

The outcome partition is per *corpus pair* (one vulnerable/patched pair = one
function-level fix record), restricted to the labelled CWE in the labelled
function and file; that is the flow this advisory was about. It does not credit
the pair for unrelated flows of the same class elsewhere in the tree, and an
introduced flow counts toward ``traded`` only when it appears in the same
function. The partition is over intraprocedural certificates, matching the
function-level study. Cross-function certificates to the same sink function are
reported separately with their own counts: they answer whether the sink remains
reachable from callers, not whether the fix changed the flow it patched.
Whole-repository, any-class statistics are reported separately and are never
folded into the partition.

Usage::

    python -m benchmarks.whole_repo_study --dataset data/corpus.jsonl \
        --repos experiments/scratch/repos --json data/whole_repo_study.json
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from typing import Any

from syrth.scan import SyrthScanner

REPO_DIR = pathlib.Path(__file__).resolve().parents[1]


def _git(root: pathlib.Path, *args: str) -> None:
    try:
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"git -C {root} {' '.join(args)} failed ({exc.returncode})"
        ) from exc


def _read_pairs(dataset: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    with open(dataset, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["pair_id"]].append(row)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for pair_id, sides in grouped.items():
        if len(sides) != 2:
            raise SystemExit(f"pair {pair_id}: expected 2 sides, got {len(sides)}")
        vulnerable = [s for s in sides if s["label"]]
        patched = [s for s in sides if not s["label"]]
        if len(vulnerable) != 1 or len(patched) != 1:
            raise SystemExit(f"pair {pair_id}: not a labelled vulnerable/patched pair")
        pair = (vulnerable[0], patched[0])
        if pair[0]["file"] != pair[1]["file"]:
            raise SystemExit(f"pair {pair_id}: file path moved between corpus sides")
        pairs.append(pair)
    return pairs


def _rel(path: str, root: pathlib.Path) -> str:
    rel = os.path.relpath(path, str(root))
    if rel.startswith(".."):
        return path
    return rel.replace(os.sep, "/")


def _items(report, root: pathlib.Path) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for trace in report.traces:
        if not trace.file:
            continue
        items.append(
            {"kind": "trace", "id": trace.trace_id, "cwe": trace.cwe,
             "path": _rel(trace.file, root), "function": trace.function}
        )
    for trace in report.cross_function:
        if not trace.sink_file:
            continue
        items.append(
            {"kind": "cross", "id": trace.trace_id, "cwe": trace.cwe,
             "path": _rel(trace.sink_file, root),
             "function": trace.chain[-1] if trace.chain else ""}
        )
    return items


def _summary(report, root: pathlib.Path, revision: str, seconds: float) -> dict[str, Any]:
    return {
        "revision": revision,
        "scan_seconds": round(seconds, 2),
        "files_scanned": report.files_scanned,
        "functions_scanned": report.functions_scanned,
        "traces": len(report.traces),
        "cross_function": len(report.cross_function),
        "parse_errors": len(report.parse_errors),
        "errors": len(report.errors),
        "items": _items(report, root),
    }


def _classify(
    before: dict[str, Any], after: dict[str, Any],
    vuln: dict[str, Any], patched_path_exists: bool,
) -> dict[str, Any]:
    label = vuln["label"]
    record_file = vuln["file"]
    before_items = before["items"]
    after_items = after["items"]

    def key(item: dict[str, str]) -> tuple[str, str]:
        return (item["kind"], item["id"])

    def tail(name: str) -> str:
        return name.rpartition(".")[2]

    # The unit is the advisory's own flow: the labelled class *in the labelled
    # function*. A repository-wide class match is not the fix this advisory is
    # about -- one unrelated flow of the same class would make every pair look
    # persistent -- so the vulnerable side is pinned to the record's file and
    # function. The patched side is matched by trace identity anywhere in the
    # tree, because a function may legitimately move files between revisions.
    #
    # The partition is over *intraprocedural* traces, exactly as in the
    # function-level study. Cross-function traces whose sink is the labelled
    # function in the labelled file are reported separately: they answer "is the
    # sink still reachable from some callers", not "did this fix change the flow
    # in the function it patched". The file is part of the match because method
    # names such as ``start`` and ``save`` are defined many times in a large
    # repository; a name-only match would credit unrelated functions.
    # Folding cross traces in would make persistence nearly automatic on a
    # function reached from thousands of entry points, which is not a
    # measurement of the fix.
    labelled_function = tail(vuln["function"])

    def in_labelled_function(item: dict[str, str]) -> bool:
        return tail(item.get("function", "")) == labelled_function

    targets_items = [
        i for i in before_items
        if i["kind"] == "trace"
        and i["cwe"] == label
        and in_labelled_function(i)
        and i["path"] == record_file
    ]
    target_ids = {key(i) for i in targets_items}
    cross_items = [
        i for i in before_items
        if i["kind"] == "cross"
        and i["cwe"] == label
        and in_labelled_function(i)
        and i["path"] == record_file
    ]
    cross_target_ids = {key(i) for i in cross_items}
    after_labelled_ids = {
        key(i) for i in after_items
        if i["cwe"] == label and in_labelled_function(i)
    }
    after_all_ids = {key(i) for i in after_items}
    before_all_ids = {key(i) for i in before_items}
    survived_ids = target_ids & after_labelled_ids
    killed_ids = target_ids - after_labelled_ids
    killed_repo_ids = target_ids - after_all_ids
    killed_any_ids = before_all_ids - after_all_ids
    new_labelled_all = after_labelled_ids - {
        key(i) for i in before_items
        if i["cwe"] == label and in_labelled_function(i)
    }
    new_labelled_function = [
        i for i in after_items
        if i["kind"] == "trace"
        and i["cwe"] == label
        and key(i) in new_labelled_all
        and in_labelled_function(i)
    ]
    new_all = after_all_ids - before_all_ids

    target_paths = {i["path"] for i in targets_items}
    surviving_items = [i for i in after_items if key(i) in survived_ids]
    surviving_outside = (
        bool(surviving_items)
        and all(i["path"] != record_file for i in surviving_items)
    )

    if not target_ids:
        # A pair with no labelled intraprocedural trace is outside the
        # partition. Labeling it "removed" would read as a fix that changed the
        # flow, and labeling it "traded" would read as a replacement; neither
        # happened, the flow was never traced at this scope.
        outcome = "untraced"
    elif survived_ids:
        outcome = "persists"
    elif new_labelled_function:
        outcome = "traded"
    else:
        outcome = "removed"

    return {
        "pair_id": vuln["pair_id"],
        "repo": vuln["repo"],
        "commit": vuln["commit"],
        "tier": vuln.get("tier") or vuln.get("evidence") or "",
        "cwe": label,
        "file": record_file,
        "outcome": outcome,
        "targets": len(target_ids),
        "survived": len(survived_ids),
        "killed": len(killed_ids),
        "cross_targets": len(cross_target_ids),
        "cross_survived": len(cross_target_ids & after_labelled_ids),
        "cross_killed": len(cross_target_ids - after_labelled_ids),
        "target_files_moved": sorted(target_paths - {record_file}),
        "survived_outside_file": surviving_outside,
        "new_labelled_same_function": len(new_labelled_function),
        "new_same_cwe_repo": len(new_labelled_all),
        "introduced_any_class_repo": len(new_all),
        "patched_file_present": patched_path_exists,
        "patched_file_missing": not patched_path_exists,
        "killed_any_class": bool(killed_any_ids),
        "target_killed_repo_anywhere": bool(killed_repo_ids),
    }


def _aggregate(
    pair_results: list[dict[str, Any]],
    commit_results: list[dict[str, Any]],
    *,
    pairs_in_repo: int,
    unique_commits: int,
    missing_repos: list[str],
) -> dict[str, Any]:
    """Recompute every published aggregate from raw pair/commit rows."""
    stats: dict[str, Any] = {
        "pairs_in_repo": pairs_in_repo,
        "examined": len(pair_results),
        "missing_repos": missing_repos,
        "missing_pairs": pairs_in_repo - len(pair_results),
        "unique_commits": unique_commits,
        "flow_traced": 0,
        "flow_persists": 0,
        "flow_persists_partial": 0,
        "flow_persists_new": 0,
        "flow_removed": 0,
        "flow_traded": 0,
        "any_killed": 0,
        "killed_pairs_all": 0,
        "regression_pairs_any": 0,
        "patched_file_missing": 0,
        "survived_outside_file": 0,
        "cross_pairs": 0,
        "cross_certificates": 0,
        "cross_survived": 0,
        "cross_killed": 0,
        "cross_only_pairs": 0,
    }
    by_cwe: dict[str, Counter] = defaultdict(Counter)
    by_repo: dict[str, Counter] = defaultdict(Counter)
    by_tier: dict[str, Counter] = defaultdict(Counter)
    for result in pair_results:
        if result["targets"] == 0:
            continue
        stats["flow_traced"] += 1
        row = by_cwe[result["cwe"]]
        repo_row = by_repo[result["repo"]]
        row["traced"] += 1
        repo_row["traced"] += 1
        tier_row = by_tier[result["tier"]] if result["tier"] else None
        if tier_row is not None:
            tier_row["traced"] += 1
        if result["outcome"] == "persists":
            stats["flow_persists"] += 1
            row["persists"] += 1
            repo_row["persists"] += 1
            if tier_row is not None:
                tier_row["persists"] += 1
            if result["killed"]:
                stats["flow_persists_partial"] += 1
            if result["new_labelled_same_function"]:
                stats["flow_persists_new"] += 1
        elif result["outcome"] == "traded":
            stats["flow_traded"] += 1
            row["traded"] += 1
            repo_row["traded"] += 1
            if tier_row is not None:
                tier_row["traded"] += 1
        else:
            stats["flow_removed"] += 1
            row["removed"] += 1
            repo_row["removed"] += 1
            if tier_row is not None:
                tier_row["removed"] += 1
        if result["killed"]:
            stats["any_killed"] += 1
    for result in pair_results:
        if result["killed_any_class"]:
            stats["killed_pairs_all"] += 1
        if result["introduced_any_class_repo"]:
            stats["regression_pairs_any"] += 1
        if result["patched_file_missing"]:
            stats["patched_file_missing"] += 1
        if result["survived_outside_file"]:
            stats["survived_outside_file"] += 1
        if result["cross_targets"]:
            stats["cross_pairs"] += 1
            stats["cross_certificates"] += result["cross_targets"]
            stats["cross_survived"] += result["cross_survived"]
            stats["cross_killed"] += result["cross_killed"]
        if result["targets"] == 0 and result["cross_targets"]:
            stats["cross_only_pairs"] += 1

    introduced_commit_by_cwe: Counter = Counter()
    for commit in commit_results:
        introduced_commit_by_cwe.update(commit["introduced_by_cwe"])
    commit_stats = {
        "commits_scanned": len(commit_results),
        "commits_with_new_flows": sum(
            1 for commit in commit_results if commit["introduced_total"]
        ),
        "scan_seconds_total": round(
            sum(commit["scan_seconds"] for commit in commit_results), 2
        ),
    }
    return {
        **stats,
        **commit_stats,
        "introduced_commit_by_cwe": dict(introduced_commit_by_cwe),
        "by_cwe": {c: dict(r) for c, r in sorted(by_cwe.items())},
        "by_repo": {r: dict(v) for r, v in sorted(by_repo.items())},
        "by_tier": {t: dict(v) for t, v in sorted(by_tier.items())},
    }


def merge_parts(paths: list[str], dataset: str) -> dict[str, Any]:
    """Combine per-repository part files into one published result.

    Incomplete parts are accepted so a run can be inspected while it is still
    going; the result records which parts were incomplete, and ``missing_pairs``
    is computed from the raw rows rather than trusted from any part.
    """
    pair_results: dict[str, dict[str, Any]] = {}
    commit_results: dict[tuple[str, str], dict[str, Any]] = {}
    missing_repos: list[str] = []
    incomplete: list[str] = []
    threshold: float | None = None
    for raw in paths:
        data = json.loads(pathlib.Path(raw).read_text(encoding="utf-8"))
        if threshold is None:
            threshold = data.get("threshold")
        if not data.get("complete", False):
            incomplete.append(raw)
        missing_repos.extend(data.get("missing_repos", []))
        for pair in data.get("pairs", []):
            pair_results[pair["pair_id"]] = pair
        for commit in data.get("commits", []):
            commit_results[(commit["repo"], commit["commit"])] = commit

    expected = _read_pairs(dataset)
    expected_commits = {(v["repo"], v["commit"]) for v, _ in expected}
    pairs = sorted(pair_results.values(), key=lambda p: p["pair_id"])
    commits = sorted(commit_results.values(), key=lambda c: (c["repo"], c["commit"]))
    return {
        "dataset": dataset,
        "repos_dir": None,
        "workdir": None,
        "threshold": threshold,
        "scope": {"whole_repo": True, "pruned_directories": True},
        "complete": not incomplete,
        "incomplete_parts": incomplete,
        **_aggregate(
            pairs,
            commits,
            pairs_in_repo=len(expected),
            unique_commits=len(expected_commits),
            missing_repos=missing_repos,
        ),
        "pairs": pairs,
        "commits": commits,
    }


def measure(
    dataset: str,
    repos: str,
    workdir: str,
    threshold: float = 0.5,
    limit: int | None = None,
    keep_worktrees: bool = False,
    only: list[str] | None = None,
    resume_path: str | None = None,
) -> dict[str, Any]:
    """Scan every ``(commit~1, commit)`` pair, one commit at a time.

    Results are written to ``resume_path`` after each commit, so a killed run
    keeps everything it finished and a rerun skips those commits. Only the two
    revision summaries of the current commit are alive at once: a
    repository-scale revision can hold hundreds of thousands of traces, and
    caching every revision would exhaust memory before the last commit.
    """
    pairs = _read_pairs(dataset)
    if only:
        wanted = set(only)
        known = {v["repo"] for v, _ in pairs}
        unknown = sorted(wanted - known)
        if unknown:
            raise SystemExit(f"unknown repository/repositories: {', '.join(unknown)}")
        pairs = [(v, p) for v, p in pairs if v["repo"] in wanted]

    groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for pair in pairs:
        groups[pair[0]["repo"]].append(pair)

    unique_commits = sorted({(v["repo"], v["commit"]) for v, _ in pairs})
    if limit is not None:
        unique_commits = unique_commits[:limit]
    commit_set = set(unique_commits)
    scope_pairs = [(v, p) for v, p in pairs if (v["repo"], v["commit"]) in commit_set]

    pair_rows: dict[str, dict[str, Any]] = {}
    commit_rows: dict[tuple[str, str], dict[str, Any]] = {}
    missing_repos: list[str] = []
    if resume_path and pathlib.Path(resume_path).exists():
        try:
            previous = json.loads(
                pathlib.Path(resume_path).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[warn] cannot read {resume_path}: {exc}; starting fresh", file=sys.stderr)
            previous = {}
        in_scope = {v["pair_id"] for v, _ in scope_pairs}
        for row in previous.get("pairs", []):
            if row.get("pair_id") in in_scope:
                pair_rows[row["pair_id"]] = row
        for row in previous.get("commits", []):
            key = (row.get("repo", ""), row.get("commit", ""))
            if key in commit_set:
                commit_rows[key] = row
        print(
            f"[resume] {len(commit_rows)}/{len(commit_set)} commits already scanned",
            flush=True,
        )

    workdir_path = pathlib.Path(workdir)
    workdir_path.mkdir(parents=True, exist_ok=True)

    def snapshot(complete: bool) -> dict[str, Any]:
        return {
            "dataset": dataset,
            "repos_dir": repos,
            "workdir": str(workdir_path),
            "threshold": threshold,
            "scope": {"whole_repo": True, "pruned_directories": True},
            "complete": complete,
            **_aggregate(
                [pair_rows[key] for key in sorted(pair_rows)],
                [commit_rows[key] for key in sorted(commit_rows)],
                pairs_in_repo=len(scope_pairs),
                unique_commits=len(commit_set),
                missing_repos=missing_repos,
            ),
            "pairs": [pair_rows[key] for key in sorted(pair_rows)],
            "commits": [commit_rows[key] for key in sorted(commit_rows)],
        }

    def write_snapshot(complete: bool) -> None:
        if not resume_path:
            return
        path = pathlib.Path(resume_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(snapshot(complete), indent=2, default=str), encoding="utf-8"
        )
        os.replace(temporary, path)

    for repo, repo_pairs in sorted(groups.items()):
        selected = [(v, p) for v, p in repo_pairs if (repo, v["commit"]) in commit_set]
        if not selected:
            continue
        clone = pathlib.Path(repos) / repo
        if not (clone / ".git").exists():
            missing_repos.append(repo)
            print(f"[skip] {repo}: clone missing at {clone}", file=sys.stderr)
            continue
        scanned = {commit for name, commit in commit_rows if name == repo}
        pending = sorted({v["commit"] for v, _ in selected} - scanned)
        if not pending:
            print(f"[skip] {repo}: all commits already scanned", flush=True)
            continue
        repo_worktree = workdir_path / repo
        # Remove leftovers from an interrupted run before scanning. A stale
        # worktree can carry an index lock or a corrupted .git file, which
        # would otherwise abort this repository as a whole.
        if repo_worktree.exists():
            try:
                _git(clone, "worktree", "remove", "--force", str(repo_worktree))
            except RuntimeError:
                shutil.rmtree(repo_worktree, ignore_errors=True)
        _git(clone, "worktree", "prune")
        print(
            f"[repo] {repo}: {len(selected)} pairs, {len(pending)} commits to scan",
            flush=True,
        )
        for commit in pending:
            before: dict[str, Any] | None = None
            after: dict[str, Any] | None = None
            for rev in (commit + "~1", commit):
                try:
                    if not (repo_worktree / ".git").exists():
                        repo_worktree.parent.mkdir(parents=True, exist_ok=True)
                        _git(clone, "worktree", "add", "--detach", "--force",
                             str(repo_worktree), rev)
                    else:
                        _git(repo_worktree, "checkout", "--detach", "--quiet", rev)
                    print(f"[scan] {repo} @ {rev[:8]}", flush=True)
                    scanner = SyrthScanner(threshold=threshold, interprocedural=True)
                    start = time.perf_counter()
                    report = scanner.scan_paths([str(repo_worktree)], interprocedural=True)
                    elapsed = time.perf_counter() - start
                    summary = _summary(report, repo_worktree, rev, elapsed)
                    print(
                        f"       {report.files_scanned} files, "
                        f"{report.functions_scanned} functions, "
                        f"{len(report.traces) + len(report.cross_function)} traces, "
                        f"{elapsed:.1f}s",
                        flush=True,
                    )
                    if rev == commit:
                        after = summary
                    else:
                        before = summary
                except RuntimeError as exc:
                    print(f"[error] {exc}", file=sys.stderr)
                    missing_repos.append(f"{repo}:{rev[:8]}: {exc}")
                    break
            if before is None or after is None:
                continue
            for vuln, _ in selected:
                if vuln["commit"] != commit:
                    continue
                candidate = repo_worktree.joinpath(*vuln["file"].split("/"))
                row = _classify(before, after, vuln, candidate.is_file())
                pair_rows[row["pair_id"]] = row
            before_all = {(i["kind"], i["id"]) for i in before["items"]}
            after_all = {(i["kind"], i["id"]) for i in after["items"]}
            introduced = [
                i for i in after["items"] if (i["kind"], i["id"]) not in before_all
            ]
            dropped = [
                i for i in before["items"] if (i["kind"], i["id"]) not in after_all
            ]
            commit_rows[(repo, commit)] = {
                "repo": repo,
                "commit": commit,
                "files_scanned": after["files_scanned"],
                "scan_seconds": round(
                    before["scan_seconds"] + after["scan_seconds"], 2
                ),
                "traces_before": len(before["items"]),
                "traces_after": len(after["items"]),
                "introduced_total": len(introduced),
                "introduced_by_cwe": dict(Counter(i["cwe"] for i in introduced)),
                "dropped_total": len(dropped),
            }
            before = after = None
            write_snapshot(False)
            print(
                f"[progress] {repo} {commit[:8]}: "
                f"{len(commit_rows)}/{len(commit_set)} commits, "
                f"{len(pair_rows)}/{len(scope_pairs)} pairs",
                flush=True,
            )
        if not keep_worktrees:
            _git(clone, "worktree", "remove", "--force", str(repo_worktree))
            _git(clone, "worktree", "prune")

    result = snapshot(complete=len(commit_rows) == len(commit_set))
    write_snapshot(True)
    return result


def _render(result: dict[str, Any]) -> str:
    traced = result["flow_traced"]
    lines = [
        f"pairs selected for this scope               : {result['pairs_in_repo']}",
        f"pairs with both revisions scanned           : {result['examined']}/{result['pairs_in_repo']}",
        f"unique fix commits scanned                  : {result['commits_scanned']}/{result['unique_commits']}",
        f"total scan time                             : {result['scan_seconds_total']:.1f}s",
        f"labelled flow traced on the vulnerable side : {traced}/{result['examined']}",
        f"  labelled certificate persists             : "
        f"{result['flow_persists']}/{traced}",
        f"  labelled flow fully removed               : "
        f"{result['flow_removed']}/{traced}",
        f"  labelled flow traded for a new one        : "
        f"{result['flow_traded']}/{traced}",
        f"pairs where the commit introduced any flow  : {result['regression_pairs_any']}",
        f"commits introducing any flow                : "
        f"{result['commits_with_new_flows']}/{result['commits_scanned']}",
        f"targets whose patched file is missing       : {result['patched_file_missing']}",
        f"persisted flows outside the patched file    : {result['survived_outside_file']}",
        f"pairs with cross-function certificates      : {result['cross_pairs']}",
        f"  cross-function certificates on vuln side   : {result['cross_certificates']}",
        f"  of which the same id survives             : "
        f"{result['cross_survived']}/{result['cross_certificates']}",
        f"  pairs traced only across functions        : {result['cross_only_pairs']}",
        "",
        "introduced flows by class (per unique commit): "
        + ", ".join(
            f"{cwe}={n}" for cwe, n in sorted(result["introduced_commit_by_cwe"].items())
        ),
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Real-commit whole-repository patch study.")
    parser.add_argument("--dataset", required=True, help="JSONL corpus records")
    parser.add_argument("--repos", default=str(REPO_DIR / "experiments" / "scratch" / "repos"))
    parser.add_argument("--workdir", default="/tmp/whole-repo-study")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--limit", type=int, default=None,
                        help="process only the first N selected fix commits")
    parser.add_argument("--only", action="append", default=None, metavar="REPO",
                        help="restrict to one repository (repeatable); useful for chunked runs")
    parser.add_argument("--merge", nargs="+", default=None, metavar="JSON",
                        help="merge complete per-repository part files instead of scanning")
    parser.add_argument("--keep-worktrees", action="store_true")
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    if args.merge and args.only:
        parser.error("--merge and --only are mutually exclusive")
    if args.merge:
        result = merge_parts(args.merge, args.dataset)
    else:
        result = measure(
            args.dataset, args.repos, args.workdir, args.threshold,
            limit=args.limit, keep_worktrees=args.keep_worktrees,
            only=args.only, resume_path=args.json,
        )
    print(_render(result))
    if args.json:
        path = pathlib.Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
