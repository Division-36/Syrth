"""Cross-tool comparison on full repositories.

The registered experiment in ``docs/experiments/tool-comparison-preregistration.md``.
Each instrument is pointed at the same 24 repositories at the same fix
commits, and what it reports is compared by *co-location* with certificates:
a tool's finding either lands in a file+function where SYRTH emitted a
certificate or it does not. That is not precision or recall -- there is no
negative class here -- and the results are reported with their denominators.

Usage::

    python -m benchmarks.tool_comparison \
        --dataset data/corpus.jsonl --repos experiments/scratch/repos \
        --json data/tool_comparison.json
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import Any

TOOLS = ("syrth", "bandit", "semgrep", "ruff")

#: Bandit, Semgrep and Ruff report a file and a line, never the enclosing
#: function. Deriving it from the same source is what makes co-location a
#: function-level measurement instead of a file-level one.
_FUNCTION_CACHE: dict[str, list[tuple[int, int, str]]] = {}


def _function_at(source_path: pathlib.Path, line: int) -> str:
    """The innermost function containing ``line``, or an empty name."""
    key = str(source_path)
    if key not in _FUNCTION_CACHE:
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            _FUNCTION_CACHE[key] = []
            return ""
        spans: list[tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                spans.append((node.lineno, node.end_lineno or node.lineno, node.name))
        _FUNCTION_CACHE[key] = spans
    matching = [
        (end - start, name)
        for start, end, name in _FUNCTION_CACHE[key]
        if start <= line <= end
    ]
    return min(matching)[1] if matching else ""


def _relative(path: str, worktree: pathlib.Path) -> str:
    """Normalize a tool's path into a path relative to the scanned tree."""
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = worktree / candidate
    try:
        return str(candidate.resolve().relative_to(worktree.resolve())).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def _git(clone: pathlib.Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(clone), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"git -C {clone} {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _repositories(dataset: str, repos: str) -> list[dict[str, str]]:
    """Pick the vulnerable revision of one commit per repository, in corpus order."""
    repositories: dict[str, dict[str, str]] = {}
    with open(dataset, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            repo = record["repo"]
            if repo not in repositories and record.get("label"):
                repositories[repo] = {
                    "repo": repo,
                    "commit": record["commit"],
                    "file": record["file"],
                    "function": record["function"].rpartition(".")[2],
                }
    return [repositories[name] for name in sorted(repositories)]


def _summary(report: Any, root: pathlib.Path) -> dict[str, Any]:
    """Turn a SYRTH scan into the same shape the external tools produce."""
    files: set[str] = set()
    functions: set[tuple[str, str]] = set()
    for trace in report.traces:
        if not trace.file:
            continue
        path = pathlib.Path(trace.file).resolve()
        try:
            rel = str(path.relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            rel = str(path)
        files.add(rel)
        functions.add((rel, trace.function.rpartition(".")[2]))
    for trace in report.cross_function:
        if not trace.sink_file:
            continue
        path = pathlib.Path(trace.sink_file).resolve()
        try:
            rel = str(path.relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            rel = str(path)
        files.add(rel)
        functions.add((rel, trace.chain[-1] if trace.chain else ""))
    return {
        "findings": len(report.traces) + len(report.cross_function),
        "files": files,
        "functions": functions,
    }


def _run_tool(
    tool: str, worktree: pathlib.Path, root: pathlib.Path
) -> dict[str, Any]:
    """Run one tool and normalize its findings into file+function pairs."""
    start = time.perf_counter()
    if tool == "syrth":
        from syrth.scan import SyrthScanner

        report = SyrthScanner(threshold=0.5, interprocedural=True).scan_paths(
            [str(worktree)], interprocedural=True
        )
        summary = _summary(report, worktree)
        return {
            "tool": tool,
            "findings": summary["findings"],
            "files_touched": len(summary["files"]),
            "functions_touched": len(summary["functions"]),
            "files": sorted(summary["files"]),
            "functions": sorted(f"{path}:{name}" for path, name in summary["functions"]),
            "seconds": round(time.perf_counter() - start, 2),
            "available": True,
            "error": "",
        }

    commands: dict[str, list[str]] = {
        "bandit": [sys.executable, "-m", "bandit", "-q", "-f", "json", "-r", "."],
        "semgrep": [
            shutil.which("semgrep") or "semgrep",
            "scan", "--config", "p/security-audit", "--json", "--quiet", ".",
        ],
        "ruff": [sys.executable, "-m", "ruff", "check", "--select", "S", "--output-format", "json", "."],
    }
    command = commands[tool]
    try:
        completed = subprocess.run(
            command, cwd=worktree, capture_output=True, text=True, check=False,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "tool": tool,
            "findings": 0,
            "files_touched": 0,
            "functions_touched": 0,
            "files": [],
            "functions": [],
            "seconds": round(time.perf_counter() - start, 2),
            "available": False,
            "error": str(exc),
        }
    files: set[str] = set()
    functions: set[tuple[str, str]] = set()
    count = 0
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        payload = []
    if isinstance(payload, Mapping):
        rows = payload.get("results", []) or payload.get("issues", [])
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        count += 1
        raw_path = str(row.get("filename") or row.get("path") or "")
        if not raw_path:
            continue
        path = _relative(raw_path, worktree)
        files.add(path)
        line = row.get("line_number") or row.get("noqa_row")
        if line is None:
            location = row.get("location") or row.get("start")
            if isinstance(location, Mapping):
                line = location.get("row") or location.get("line")
        try:
            number = int(line)
        except (TypeError, ValueError):
            continue
        name = _function_at(worktree / path, number)
        if name:
            functions.add((path, name))
    return {
        "tool": tool,
        "findings": count,
        "files_touched": len(files),
        "functions_touched": len(functions),
        "files": sorted(files),
        "functions": sorted(f"{path}:{name}" for path, name in functions),
        "seconds": round(time.perf_counter() - start, 2),
        "available": True,
        "error": "",
    }


def _aggregate(repositories: list[dict[str, str]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute every published aggregate from the per-repository rows."""
    indexed = {row["repo"]: row for row in rows}
    per_tool: dict[str, Any] = {}
    for tool in TOOLS:
        available = [
            indexed[repo["repo"]]["tools"][tool]
            for repo in repositories
            if repo["repo"] in indexed
            and indexed[repo["repo"]]["tools"].get(tool, {}).get("available")
        ]
        counts = [entry["findings"] for entry in available]
        co_hit = sum(entry["certificate_co_location"][0] for entry in available)
        co_total = sum(entry["certificate_co_location"][1] for entry in available)
        per_tool[tool] = {
            "repositories": len(available),
            "total_findings": sum(counts),
            "median_findings_per_repository": (
                sorted(counts)[len(counts) // 2] if counts else 0
            ),
            "labelled_file_hits": (
                sum(1 for entry in available if entry["labelled_file_hit"]),
                len(available),
            ),
            "labelled_function_hits": (
                sum(1 for entry in available if entry["labelled_function_hit"]),
                len(available),
            ),
            "certificate_co_location": (co_hit, co_total),
            "seconds": round(sum(entry["seconds"] for entry in available), 2),
        }
    return {
        "dataset": DATASET,
        "repos": REPOS,
        "repositories": len(repositories),
        "tools": TOOLS,
        "scope": {
            "one_commit_per_repository": True,
            "whole_worktree": True,
            "co_location_not_precision": True,
        },
        "complete": len(rows) == len(repositories),
        "per_tool": per_tool,
        "rows": sorted(rows, key=lambda row: row["repo"]),
    }


DATASET = "data/corpus.jsonl"
REPOS = "experiments/scratch/repos"


def measure(dataset: str, repos: str, resume_path: str | None = None) -> dict[str, Any]:
    """Scan every repository with every instrument; checkpoint after each."""
    global DATASET, REPOS
    DATASET, REPOS = dataset, repos
    repositories = _repositories(dataset, repos)
    rows: dict[str, dict[str, Any]] = {}
    if resume_path and pathlib.Path(resume_path).exists():
        try:
            previous = json.loads(pathlib.Path(resume_path).read_text(encoding="utf-8"))
            for row in previous.get("rows", []):
                rows[row["repo"]] = row
            print(f"[resume] {len(rows)}/{len(repositories)} repositories already scanned", flush=True)
        except (OSError, json.JSONDecodeError):
            pass

    def checkpoint() -> None:
        if not resume_path:
            return
        path = pathlib.Path(resume_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(_aggregate(repositories, list(rows.values())), indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    for repo in repositories:
        if repo["repo"] in rows:
            continue
        clone = pathlib.Path(repos) / repo["repo"]
        if not (clone / ".git").exists():
            rows[repo["repo"]] = {
                "repo": repo["repo"],
                "commit": repo["commit"],
                "error": f"clone missing at {clone}",
                "tools": {},
            }
            checkpoint()
            continue
        worktree = pathlib.Path("/tmp/cross-tool-worktree")
        if worktree.exists():
            subprocess.run(
                ["git", "-C", str(clone), "worktree", "remove", "--force", str(worktree)],
                capture_output=True,
            )
        if worktree.exists():
            # A killed run leaves the checkout behind. Git's worktree
            # metadata may still point at another clone, so a force-remove
            # through this clone is not enough; clear the stale directory.
            shutil.rmtree(worktree, ignore_errors=True)
        _git(clone, "worktree", "prune")
        _git(
            clone, "worktree", "add", "--detach", "--force",
            str(worktree), repo["commit"],
        )
        tools: dict[str, Any] = {}
        for tool in TOOLS:
            result = _run_tool(tool, worktree, clone)
            tools[tool] = result
            print(
                f"[{repo['repo']:16s} {repo['commit'][:8]}] {tool:8s} "
                f"{result['findings']:6d} findings, {result['files_touched']:4d} files, "
                f"{result['seconds']:6.1f}s"
                + (f" ERROR {result['error'][:60]}" if result["error"] else ""),
                flush=True,
            )
        syrth_functions = set(tools["syrth"]["functions"])
        syrth_files = set(tools["syrth"]["files"])
        for tool in TOOLS:
            result = tools[tool]
            result["labelled_file_hit"] = repo["file"] in result["files"]
            result["labelled_function_hit"] = any(
                entry.startswith(repo["file"] + ":") and entry.endswith(":" + repo["function"])
                for entry in result["functions"]
            )
            result["certificate_co_location"] = (
                sum(1 for entry in result["functions"] if entry in syrth_functions),
                result["functions_touched"],
            )
            if tool != "syrth":
                result["files_in_common_with_syrth"] = (
                    len(syrth_files & set(result["files"])),
                    result["files_touched"],
                )
        rows[repo["repo"]] = {
            "repo": repo["repo"],
            "commit": repo["commit"],
            "labelled_file": repo["file"],
            "labelled_function": repo["function"],
            "tools": tools,
        }
        checkpoint()
        subprocess.run(
            ["git", "-C", str(clone), "worktree", "remove", "--force", str(worktree)],
            capture_output=True,
        )
        _git(clone, "worktree", "prune")

    return _aggregate(repositories, list(rows.values()))


def _render(result: dict[str, Any]) -> str:
    lines = [
        f"repositories scanned: {result['repositories']}",
        "",
        f"{'tool':10s} {'findings':>10s} {'files':>7s} "
        f"{'co-located':>12s} {'labelled file':>14s} {'seconds':>9s}",
    ]
    for tool, row in result["per_tool"].items():
        hit, total = row["certificate_co_location"]
        file_hit, file_total = row["labelled_file_hits"]
        lines.append(
            f"{tool:10s} {row['total_findings']:10d} "
            f"{'':7s} {hit:5d}/{total:<6d} {file_hit:5d}/{file_total:<8d} "
            f"{row['seconds']:9.1f}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-tool comparison on full repositories.")
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--repos", default="experiments/scratch/repos")
    parser.add_argument("--json", default=None,
                        help="checkpoint path: a killed run resumes from it")
    args = parser.parse_args(argv)
    result = measure(args.dataset, args.repos, resume_path=args.json)
    print(_render(result))
    if args.json:
        path = pathlib.Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
