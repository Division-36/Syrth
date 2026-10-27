"""
Revision Diff CLI
=================
Compares two revisions of a repository and reports which source-to-sink flows a
change introduced, killed, or left in place.

Why this is a command and not a report
--------------------------------------
Answering "did this patch fix it?" requires comparing two trees, and that is a
CI job rather than something an engineer does by eye. The output is chosen for
that use: a non-zero exit status when a patch introduces a flow or fails to
remove the one it claimed to, and machine-readable JSON for a review bot.

Usage::

    python -m benchmarks.revision_diff --base HEAD~1 --head HEAD
    python -m benchmarks.revision_diff --base v1.2.0 --head v1.3.0 --json out.json
    python -m benchmarks.revision_diff --base main --head feature --fail-on-regression
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from syrth.diff import DiffReport, diff_reports, patch_status
from syrth.scan import SyrthScanner


class RevisionError(RuntimeError):
    """Raised when a revision cannot be materialised."""


def _git(args: list[str], cwd: str | None = None) -> str:
    """Run a git command and return stdout.

    Raises:
        RevisionError: If git is unavailable or the command fails.
    """
    if shutil.which("git") is None:
        raise RevisionError("git is not on PATH, so revisions cannot be compared")
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        raise RevisionError(
            f"git {' '.join(args)} failed: {(exc.stderr or exc.stdout or '').strip()}"
        ) from exc
    return result.stdout


def materialise(revision: str, repo: str, destination: str) -> str:
    """Extract ``revision`` into ``destination``.

    Only Python files are checked out, because those are the only ones the
    analyser consumes, and the whole tree of a real repository is too large to
    copy per comparison. Extraction goes through :mod:`tarfile` rather than an
    external ``tar`` binary so that the behaviour is identical on every
    platform and no temporary archive is left on disk.

    Raises:
        RevisionError: If the revision cannot be resolved or extracted.
    """
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()

    try:
        completed = subprocess.run(
            ["git", "archive", "--format=tar", revision, "--", "*.py"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        payload = completed.stdout
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr or b""
        raise RevisionError(
            f"cannot export {revision!r}: {detail.decode('utf-8', 'replace').strip()}"
        ) from exc
    except FileNotFoundError as exc:
        raise RevisionError("git is not available on PATH") from exc

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                if not member.isfile() or not member.name.endswith(".py"):
                    continue
                destination_path = (target / member.name).resolve()
                # Refuse anything that escapes the destination tree, so a
                # malicious archive cannot write outside it.
                if not destination_path.is_relative_to(root):
                    raise RevisionError(
                        f"archive member {member.name!r} escapes {destination!r}"
                    )
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    continue
                with source, destination_path.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
    except tarfile.TarError as exc:
        raise RevisionError(f"cannot extract {revision!r}: {exc}") from exc

    return str(target)


def compare(
    base: str,
    head: str,
    repo: str = ".",
    scanner: SyrthScanner | None = None,
) -> DiffReport:
    """Analyse two revisions and diff their flow sets.

    Args:
        base: Baseline revision.
        head: Compared revision.
        repo: Repository to read revisions from.
        scanner: Scanner to use. A fresh one is built when omitted.

    Returns:
        A :class:`~syrth.diff.DiffReport`.

    Raises:
        RevisionError: If either revision cannot be materialised.
    """
    scanner = scanner or SyrthScanner()
    workspace = tempfile.mkdtemp(prefix="syrth-diff-")
    try:
        base_dir = materialise(base, repo, os.path.join(workspace, "base"))
        head_dir = materialise(head, repo, os.path.join(workspace, "head"))
        return diff_reports(
            scanner.scan_paths([base_dir]),
            scanner.scan_paths([head_dir]),
            base,
            head,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="benchmarks.revision_diff",
        description="Compare source-to-sink flows across two revisions",
    )
    parser.add_argument("--base", required=True, help="Baseline revision")
    parser.add_argument("--head", required=True, help="Compared revision")
    parser.add_argument("--repo", default=".", help="Repository to read revisions from")
    parser.add_argument("--json", default=None, help="Write the diff JSON here")
    parser.add_argument("--fail-on-regression", action="store_true",
                        help="Exit 1 when a change introduces a flow")
    parser.add_argument("--expect-killed", action="append", default=[],
                        help="CWE the patch claims to fix; repeatable")
    parser.add_argument("--threshold", type=float, default=0.5)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    scanner = SyrthScanner(threshold=args.threshold)
    try:
        result = compare(args.base, args.head, args.repo, scanner)
    except RevisionError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    print(result.render())

    accepted, reasons = patch_status(result, args.expect_killed)
    if args.expect_killed or args.fail_on_regression:
        print("patch verification: " + ("ACCEPTED" if accepted else "REJECTED"))
        for reason in reasons:
            print(f"  - {reason}")
        print()

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )

    if args.fail_on_regression and result.introduced:
        return 1
    if args.expect_killed and not accepted:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
