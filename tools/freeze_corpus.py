"""Freeze the benchmark corpus into a citable artifact.

The corpus is regenerable from advisory data and 24 pinned repositories, but
"regenerable" is not the same as "citable": a paper that quotes a rate over 350
records should name the exact bytes it measured. This tool writes a deterministic
archive with a manifest so the same object can be deposited (Zenodo, an
institutional repository, a release asset) and referenced by DOI.

Determinism matters more than it looks: a tarball built twice from identical
inputs must hash identically, or "the frozen corpus" is not one object. Tar
member order is sorted, mtimes are zeroed, and ownership is stripped.

Usage::

    python tools/freeze_corpus.py --dataset data/corpus.jsonl --outdir dist/freeze
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
from collections import Counter
from typing import Any


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_head(root: pathlib.Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    pairs = {record["pair_id"] for record in records}
    repos = Counter(record["repo"] for record in records)
    classes = Counter(record["cwe"] for record in records)
    tiers = Counter(record.get("evidence") or record.get("tier") or "" for record in records)
    groups = Counter(record["group"] for record in records)

    if len(records) % 2:
        raise SystemExit(f"refusing to freeze an odd record count: {len(records)}")
    if len(pairs) * 2 != len(records):
        raise SystemExit(
            f"refusing to freeze: {len(records)} records but {len(pairs)} pairs"
        )

    return {
        "records": len(records),
        "pairs": len(pairs),
        "repositories": len(repos),
        "classes": dict(sorted(classes.items())),
        "evidence_tiers": dict(sorted(tiers.items())),
        "groups": dict(sorted(groups.items())),
        "repos": dict(sorted(repos.items())),
    }


_README = """# SYRTH benchmark corpus

Frozen benchmark corpus for the SYRTH trace-certificate measurements.

- Records: {records} ({pairs} vulnerable/patched pairs)
- Repositories: {repositories}
- Classes: {classes}
- SHA-256 of `corpus.jsonl`: `{corpus_sha}`
- SHA-256 of this archive: see `SHA256SUMS`
- Source revision of the harness: `{commit}`

## What a record is

Each record pins one function at one revision of one repository:

```
repo, commit, file, function, qualname
```

`source` is the function body as extracted at that revision. `group` is the pair
identifier; a pair's two records are the vulnerable and patched sides of the same
fix commit. `cwe` is the class the advisory reports, `evidence` is the tier
(`direct-sink` or `module-proximity`), and `origin_source` / `sink_call` record
how the record was accepted.

The corpus contains third-party source under the licences of the repositories it
was drawn from. It is distributed for research reproducibility, not as a
relicensed derivative. Each record names its repository and commit so the
upstream licence can be checked.

## Reproducing the measurements

```
python -m benchmarks.risk_metrics --dataset data/corpus.jsonl
python -m benchmarks.competitors --dataset data/corpus.jsonl
python -m benchmarks.ablation --dataset data/corpus.jsonl
python -m benchmarks.identity --dataset data/corpus.jsonl
```

## Rebuilding the corpus

`tools/build_corpus.py` regenerates it from the advisory feed and the pinned
repositories. Rebuilding is not guaranteed to reproduce these exact bytes: the
harvester accepts a record only when the source parses and the sink resolves, and
both depend on the parser version. That is why this archive exists.
"""


def freeze(dataset: pathlib.Path, outdir: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    records = [
        json.loads(line)
        for line in dataset.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary = _summarise(records)
    corpus_sha = _sha256(dataset)
    commit = _git_head(root)
    stamp = summary["records"]

    outdir.mkdir(parents=True, exist_ok=True)
    archive_name = f"syrth-corpus-{stamp}.tar.gz"
    archive_path = outdir / archive_name

    with tempfile.TemporaryDirectory() as staging:
        stage = pathlib.Path(staging) / "syrth-corpus"
        stage.mkdir()
        (stage / "corpus.jsonl").write_bytes(dataset.read_bytes())
        manifest = {
            "corpus_sha256": corpus_sha,
            "harness_commit": commit,
            **summary,
        }
        (stage / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        (stage / "README.md").write_text(
            _README.format(
                records=summary["records"],
                pairs=summary["pairs"],
                repositories=summary["repositories"],
                classes=", ".join(
                    f"{cwe} ({count})" for cwe, count in summary["classes"].items()
                ),
                corpus_sha=corpus_sha,
                commit=commit,
            ),
            encoding="utf-8",
        )

        with archive_path.open("wb") as raw:
            # gzip embeds a timestamp by default, which would make two freezes of
            # the same bytes hash differently. mtime=0 and an empty stored name
            # are what make this archive reproducible.
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
            ) as gz:
                with tarfile.open(
                    fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT
                ) as tar:
                    for path in sorted(stage.iterdir()):
                        info = tar.gettarinfo(
                            str(path), arcname=f"syrth-corpus/{path.name}"
                        )
                        info.mtime = 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        with path.open("rb") as handle:
                            tar.addfile(info, handle)

    archive_sha = _sha256(archive_path)
    (outdir / "SHA256SUMS").write_text(
        f"{archive_sha}  {archive_name}\n{corpus_sha}  corpus.jsonl\n",
        encoding="utf-8",
    )
    return {
        "archive": str(archive_path),
        "archive_sha256": archive_sha,
        "corpus_sha256": corpus_sha,
        "harness_commit": commit,
        **summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze the benchmark corpus.")
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--outdir", default="dist/freeze")
    parser.add_argument("--json", default=None, help="write the manifest here")
    args = parser.parse_args(argv)

    root = pathlib.Path(__file__).resolve().parent.parent
    dataset = (root / args.dataset).resolve()
    outdir = (root / args.outdir).resolve()
    result = freeze(dataset, outdir, root)

    print(json.dumps(result, indent=2, sort_keys=True))
    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
