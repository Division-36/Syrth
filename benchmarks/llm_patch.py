"""Certificate-verified patch repair: propose a fix, then let the certificate judge it.

This is the experiment registered in
``docs/experiments/paper2-preregistration.md``. The protocol there is fixed
before any patch is generated; this module is the instrument that carries it
out.

The flow has three steps, and the separation between them is what makes the
result auditable:

1.  ``prepare`` writes one prompt per pair to a JSON Lines file. The prompt is
    built from the vulnerable record and the certificate only. It is checked
    mechanically against the patched side of the corpus, the advisory
    identifier, the commit and the repository name, and the preparation fails
    if any of them appear.
2.  Something else -- in this project, an agent -- answers the prompts, and
    the answers are recorded in a second JSON Lines file. The model is not a
    fixed public checkpoint, so the recorded answers, not the model, are the
    artefact of record.
3.  ``verify`` applies each answer, re-scans it with the same analyser, and
    decides the outcome by comparing certificates. The diff is never read to
    decide whether a flow is gone.

Every rate is reported as ``n/N`` with its denominator, and every proportion
carries a Wilson interval, because the sample is small and the intervals are
wider than the percentages suggest.

Usage::

    python -m benchmarks.llm_patch prepare --dataset data/corpus.jsonl \
        --json data/llm_patch_prompts.jsonl
    python -m benchmarks.llm_patch verify --dataset data/corpus.jsonl \
        --responses data/llm_patch_responses.jsonl \
        --json data/llm_patch.json
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import json
import pathlib
import re
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from benchmarks.run_benchmarks import load_records
from syrth.scan import SyrthScanner

#: Which generator produced the answers. It is recorded with every attempt
#: because it is not a fixed public checkpoint: the answers, not the model,
#: are the artefact of record.
MODEL_IDENTIFIER = "minimax-m3.1-flash-free"
MODEL_PROVIDER = "opencode"

#: The whole-repository results, used to widen the population to the pairs
#: whose flow is confirmed only when the module is scanned whole.
WHOLE_REPO_RESULTS = "data/whole_repo_study.json"

#: Fragments that must never appear anywhere in a prompt: the advisory and the
#: commit identify the upstream fix.
FORBIDDEN_FIELDS = ("advisory_id", "commit")

#: Fragments that must never appear in the prompt's *instructions*. The
#: vulnerable source may legitimately name its own project -- a Django module
#: says "django" in its imports -- and removing that would mean editing the
#: code the model is asked to fix.
FORBIDDEN_IN_INSTRUCTIONS = ("repo",)

#: A line shorter than this is too generic to be evidence of leakage.
MIN_LEAK_LINE = 24


class LeakageError(RuntimeError):
    """A prompt contained material it must not contain."""


def wilson(successes: int, total: int, z: float = 1.959963985) -> tuple[float, float]:
    """Wilson score interval for a proportion.

    The normal approximation is wrong at these sample sizes and with the
    proportions near zero that this experiment produces, so the interval is
    the one that behaves.
    """
    if total <= 0:
        return (0.0, 0.0)
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    spread = z * ((proportion * (1 - proportion) / total + z * z / (4 * total * total)) ** 0.5)
    return (
        max(0.0, (centre - spread) / denominator),
        min(1.0, (centre + spread) / denominator),
    )


def _pairs(records: Iterable[Any]) -> list[tuple[Any, Any]]:
    """Group the records into vulnerable/patched pairs."""
    grouped: dict[str, list[Any]] = {}
    for record in records:
        grouped.setdefault(record.pair_id, []).append(record)
    pairs: list[tuple[Any, Any]] = []
    for sides in grouped.values():
        vulnerable = [side for side in sides if side.label]
        patched = [side for side in sides if not side.label]
        if len(vulnerable) == 1 and len(patched) == 1:
            pairs.append((vulnerable[0], patched[0]))
    return pairs


def _metadata(dataset: str) -> dict[str, dict[str, Any]]:
    """The corpus fields the harness needs, keyed by pair identifier.

    The loaded record carries the source, the label and the group; the
    repository, the file, the sink call and the advisory live in the corpus
    file itself, and the advisory and the commit must never reach a prompt.
    """
    metadata: dict[str, dict[str, Any]] = {}
    with open(dataset, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("label"):
                metadata[row["pair_id"]] = row
    return metadata


def _labelled_function(name: str) -> str:
    """The plain function name of a possibly qualified name."""
    return name.rpartition(".")[2]


def _traces(report: Any, label: str) -> set[str]:
    """The identities of the traces of one class in a report."""
    return {trace.trace_id for trace in report.traces if trace.cwe == label}


def _all_trace_ids(report: Any) -> set[str]:
    return {trace.trace_id for trace in report.traces}


def _significant_lines(source: str) -> list[str]:
    """The lines of a source that could identify it."""
    return [
        line.strip()
        for line in source.splitlines()
        if len(line.strip()) >= MIN_LEAK_LINE
    ]


def _normalise(text: str) -> str:
    """Collapse whitespace, so that indentation cannot hide a shared line."""
    return " ".join(text.split())


def assert_no_leakage(
    prompt: str, instructions: str, meta: Mapping[str, Any], patched_source: str
) -> None:
    """Fail if the prompt contains anything it must not contain.

    The patched side of the corpus is the real upstream fix. The advisory
    identifier and the commit point at it and must not appear at all. The
    repository name must not appear in the instructions; it may appear inside
    the vulnerable source, because the source is the code under repair and
    its own imports name the project.

    The prompt is built from the vulnerable record alone, and this check
    proves it.
    """
    for field in FORBIDDEN_FIELDS:
        value = meta.get(field) or ""
        if value and value in prompt:
            raise LeakageError(f"the prompt contains the corpus {field}: {value!r}")
    for field in FORBIDDEN_IN_INSTRUCTIONS:
        value = meta.get(field) or ""
        if value and value in instructions:
            raise LeakageError(
                f"the prompt's instructions name the corpus {field}: {value!r}"
            )
    vulnerable_lines = {_normalise(line) for line in meta.get("source", "").splitlines()}
    prompt_lines = {_normalise(line) for line in prompt.splitlines()}
    patched_only = {
        _normalise(line)
        for line in patched_source.splitlines()
        if len(line.strip()) >= MIN_LEAK_LINE
    } - vulnerable_lines
    leaked = sorted(patched_only & prompt_lines)
    if leaked:
        raise LeakageError(
            f"the prompt contains a line of the patched source: {leaked[0]!r}"
        )
    for line in _significant_lines(meta.get("source", "")):
        if _normalise(line) not in prompt_lines:
            raise LeakageError(
                "the prompt does not carry the vulnerable source; it was built wrongly"
            )


PROMPT_INSTRUCTIONS = """\
You are asked to fix one security defect in a Python file.

Vulnerability class: {cwe}
Sink call: {sink_call}
Tainted parameter: {origin}

The flow that must be removed: {origin} reaches {sink_call}.

Fix the defect so that this flow no longer reaches the sink. Keep the
function's purpose and its public behaviour otherwise unchanged, do not add
dependencies, and do not remove the check that the caller relies on.

Return the complete corrected file. Return only the file content: no
explanation, no markdown fences, no commentary.
"""


def build_prompt(
    vulnerable: Any, meta: Mapping[str, Any], scanner: SyrthScanner
) -> tuple[str, str, dict[str, Any]]:
    """Build the prompt for one pair, its instructions, and the facts in it.

    The certificate facts are read from the analyser's own report of the
    vulnerable source, so the prompt describes the flow the tool actually
    sees rather than the label the corpus carries.
    """
    report = scanner.scan_source(vulnerable.source, vulnerable.group)
    traces = [trace for trace in report.traces if trace.cwe == vulnerable.label]
    sink_call = meta.get("sink_call") or ""
    origin = meta.get("origin_source") or ""
    if traces:
        first = traces[0]
        sink_call = first.sink_call or sink_call
        if first.origins:
            origin = ", ".join(sorted(first.origins))
    instructions = PROMPT_INSTRUCTIONS.format(
        cwe=vulnerable.label,
        sink_call=sink_call,
        origin=origin or "the request data",
    )
    prompt = f"{instructions}\n--- file ---\n{vulnerable.source}\n--- end of file ---\n"
    facts = {
        "cwe": vulnerable.label,
        "sink_call": sink_call,
        "origin": origin,
        "traces": len(traces),
        "evidence": meta.get("evidence", ""),
    }
    return prompt, instructions, facts


def strip_fences(text: str) -> str:
    """Remove the markdown fences a response may be wrapped in."""
    stripped = text.strip()
    if "```" not in stripped:
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    while lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines)


def _tokens(lines: Iterable[str]) -> set[str]:
    return {
        token
        for line in lines
        for token in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", line)
    }


def _changed_lines(before: str, after: str) -> list[str]:
    """The lines that differ between two sources, as a set of texts."""
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
    changed: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changed.extend(before_lines[i1:i2])
        changed.extend(after_lines[j1:j2])
    return changed


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _outcome(row: Mapping[str, Any]) -> str:
    """The single label a response earns.

    ``verified-kill`` is the outcome the certificate endorses: the file
    parses, the labelled flow is gone, and no new flow appeared. The
    distinction between it and ``guard-only`` is the point of the
    experiment, so the labels are decided here and not anywhere else.
    """
    if not row["parsed"]:
        return "unusable"
    if row["flow_gone"] and not row["new_flow"]:
        return "verified-kill"
    if row["flow_gone"] and row["new_flow"]:
        return "kill-with-new-flow"
    if row["guard_only"]:
        return "guard-only"
    if row["flow_replaced"]:
        return "flow-replaced"
    return "flow-persists"


def prepare(dataset: str, output: str) -> int:
    """Write one prompt per confirmed pair, and refuse to write a leaky one."""
    records = load_records(dataset)
    metadata = _metadata(dataset)
    scanner = SyrthScanner(threshold=0.5)
    pairs = _pairs(records)

    confirmed: dict[str, tuple[Any, Any]] = {}
    for vulnerable, patched in pairs:
        report = scanner.scan_source(vulnerable.source, vulnerable.group)
        if _traces(report, vulnerable.label):
            confirmed[vulnerable.pair_id] = (vulnerable, patched)

    whole = pathlib.Path(WHOLE_REPO_RESULTS)
    if whole.exists():
        published = json.loads(whole.read_text(encoding="utf-8"))
        for row in published.get("pairs", []):
            if row.get("targets", 0) > 0 and row["pair_id"] not in confirmed:
                for vulnerable, patched in pairs:
                    if vulnerable.pair_id == row["pair_id"]:
                        confirmed[vulnerable.pair_id] = (vulnerable, patched)

    path = pathlib.Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        for pair_id in sorted(confirmed):
            vulnerable, patched = confirmed[pair_id]
            meta = metadata.get(pair_id, {})
            prompt, instructions, facts = build_prompt(vulnerable, meta, scanner)
            assert_no_leakage(prompt, instructions, meta, patched.source)
            handle.write(
                json.dumps(
                    {
                        "pair_id": pair_id,
                        "repo": meta.get("repo", ""),
                        "file": meta.get("file", ""),
                        "function": meta.get("function", ""),
                        "cwe": vulnerable.label,
                        "certificate": facts,
                        "instructions": instructions,
                        "prompt": prompt,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    print(f"pairs in the corpus                         : {len(pairs)}")
    print(f"pairs with a confirmed labelled flow       : {len(confirmed)}")
    print(f"prompts written                            : {written}")
    print(f"prompt file                                : {output}")
    return 0


def verify(dataset: str, responses: str, output: str) -> int:
    """Apply the recorded answers, judge them with the certificate, report."""
    records = load_records(dataset)
    metadata = _metadata(dataset)
    by_pair = {vulnerable.pair_id: (vulnerable, patched) for vulnerable, patched in _pairs(records)}
    scanner = SyrthScanner(threshold=0.5)

    answers: dict[str, str] = {}
    metadata_rows: dict[str, dict[str, Any]] = {}
    with open(responses, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            answers[row["pair_id"]] = row.get("response", "")
            metadata_rows[row["pair_id"]] = {
                key: row[key]
                for key in ("model", "provider", "agent", "date", "attempt")
                if key in row
            }

    results: list[dict[str, Any]] = []
    for pair_id in sorted(answers):
        vulnerable, patched = by_pair[pair_id]
        meta = metadata.get(pair_id, {})
        answer = strip_fences(answers[pair_id])
        before = scanner.scan_source(vulnerable.source, vulnerable.group)
        after = scanner.scan_source(answer, vulnerable.group)
        before_ids = _traces(before, vulnerable.label)
        after_ids = _traces(after, vulnerable.label)
        new_label_ids = after_ids - before_ids
        new_any_ids = _all_trace_ids(after) - _all_trace_ids(before)
        flow_gone = bool(before_ids) and not after_ids
        function_present = re.search(
            rf"^\s*def\s+{re.escape(_labelled_function(meta.get('function', '')))}\b",
            answer,
            re.M,
        ) is not None
        parsed = not after.parse_errors and function_present
        sink_call = meta.get("sink_call") or ""
        sink_present = bool(sink_call) and sink_call in answer
        changed = _changed_lines(vulnerable.source, answer)
        reference_changed = _changed_lines(vulnerable.source, patched.source)
        similarity = _jaccard(_tokens(changed), _tokens(reference_changed))
        row = {
            "pair_id": pair_id,
            "repo": meta.get("repo", ""),
            "file": meta.get("file", ""),
            "function": meta.get("function", ""),
            "cwe": vulnerable.label,
            "evidence": meta.get("evidence", ""),
            "attempted": True,
            "parsed": parsed,
            "flow_gone": flow_gone,
            "flow_replaced": bool(new_label_ids),
            "new_flow": bool(new_any_ids),
            "sink_call_present": sink_present,
            "guard_only": bool((not flow_gone) and sink_present and changed),
            "lines_changed": len(changed),
            "reference_similarity": round(similarity, 4),
            "before_traces": len(before_ids),
            "after_traces": len(after_ids),
            "parse_errors": len(after.parse_errors),
            **metadata_rows.get(pair_id, {}),
        }
        row["outcome"] = _outcome(row)
        results.append(row)

    attempted = len(results)
    parsed = sum(1 for row in results if row["parsed"])
    gone = sum(1 for row in results if row["flow_gone"] and row["parsed"])
    verified = sum(
        1 for row in results if row["parsed"] and row["flow_gone"] and not row["new_flow"]
    )
    guard_only = sum(1 for row in results if row["guard_only"])
    replaced = sum(1 for row in results if row["flow_replaced"])
    new_flow = sum(1 for row in results if row["new_flow"])
    similarities = [row["reference_similarity"] for row in results]

    def interval(count: int) -> list[float]:
        low, high = wilson(count, attempted)
        return [round(low, 4), round(high, 4)]

    summary = {
        "dataset": dataset,
        "responses": responses,
        "population": len(by_pair),
        "attempted": attempted,
        "not_attempted": len(by_pair) - attempted,
        "parsed": parsed,
        "flow_gone": gone,
        "verified_kill": verified,
        "guard_only": guard_only,
        "flow_replaced": replaced,
        "new_flow": new_flow,
        "rates": {
            "parsed": {"count": parsed, "of": attempted, "ci95": interval(parsed)},
            "verified_kill": {"count": verified, "of": attempted, "ci95": interval(verified)},
            "guard_only": {"count": guard_only, "of": attempted, "ci95": interval(guard_only)},
            "new_flow": {"count": new_flow, "of": attempted, "ci95": interval(new_flow)},
        },
        "reference_similarity": {
            "median": round(statistics.median(similarities), 4) if similarities else 0.0,
            "min": round(min(similarities), 4) if similarities else 0.0,
            "max": round(max(similarities), 4) if similarities else 0.0,
            "over_half": sum(1 for value in similarities if value > 0.5),
        },
        "by_class": {
            label: dict(Counter(row["outcome"] for row in results if row["cwe"] == label))
            for label in sorted({row["cwe"] for row in results})
        },
        "results": results,
    }

    path = pathlib.Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    print(f"pairs in the corpus                         : {len(by_pair)}")
    print(f"pairs attempted                             : {attempted}")
    print(f"  the returned file parses                  : {parsed}/{attempted}")
    print(f"  the labelled flow is gone                 : {gone}/{attempted}")
    print(f"  certificate-verified kill (no new flow)   : {verified}/{attempted}")
    print(f"  the fix is a guard, the flow persists     : {guard_only}/{attempted}")
    print(f"  the flow was replaced by another one      : {replaced}/{attempted}")
    print(f"  a new flow of any class appeared          : {new_flow}/{attempted}")
    if similarities:
        print(
            f"  similarity to the upstream change         : median "
            f"{summary['reference_similarity']['median']}, "
            f"{summary['reference_similarity']['over_half']}/{attempted} above 0.5"
        )
    print(f"results file                                : {output}")
    return 0


def collect(manifest_path: str, answers_dir: str, output: str, agent: str) -> int:
    """Turn the recorded answer files into the responses the verifier reads.

    The answers are files, one per pair, written by whatever produced them.
    Collecting them here keeps the metadata -- which model, which provider,
    which date -- in one place, and records the pairs that have no answer, so
    that a missing attempt is visible rather than silently absent.
    """
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    directory = pathlib.Path(answers_dir)
    date = datetime.date.today().isoformat()
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for entry in manifest:
        answer_path = directory / entry["answer"]
        if not answer_path.exists():
            missing.append(entry["index"])
            continue
        rows.append(
            {
                "pair_id": entry["pair_id"],
                "response": answer_path.read_text(encoding="utf-8"),
                "model": MODEL_IDENTIFIER,
                "provider": MODEL_PROVIDER,
                "agent": agent,
                "date": date,
                "attempt": 1,
            }
        )
    path = pathlib.Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"pairs in the manifest                      : {len(manifest)}")
    print(f"answers collected                          : {len(rows)}")
    print(f"pairs with no answer                       : {len(missing)}")
    if missing:
        print(f"  missing indices                          : {', '.join(missing)}")
    print(f"responses file                             : {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Certificate-verified patch repair."
    )
    parser.add_argument("step", choices=("prepare", "collect", "verify"))
    parser.add_argument("--dataset", default="data/corpus.jsonl")
    parser.add_argument("--responses", default="data/llm_patch_responses.jsonl")
    parser.add_argument("--manifest", default="experiments/scratch/llm-patch/manifest.json")
    parser.add_argument("--answers-dir", default="experiments/scratch/llm-patch")
    parser.add_argument("--agent", default="opencode subagent")
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    if args.step == "prepare":
        if not args.json:
            parser.error("--json is required for prepare")
        return prepare(args.dataset, args.json)
    if args.step == "collect":
        if not args.json:
            parser.error("--json is required for collect")
        return collect(args.manifest, args.answers_dir, args.json, args.agent)
    if not args.json:
        parser.error("--json is required for verify")
    return verify(args.dataset, args.responses, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
