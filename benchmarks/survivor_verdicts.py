"""Verdicts for the kill-survivors, recorded by guard shape.

A survivor is a patched function that still reports its class. The question is
never "is the class right" -- the corpus established that -- it is **"does the
guard the patch added actually close the path to the sink"**. That question has
the same answer for every case sharing a guard shape, so verdicts are recorded
per shape and projected onto cases. Writing 59 individual rows would have
produced the same numbers with no way to re-derive them.

Verdict vocabulary
------------------
``correct``            the sink is still reachable after the patch; the report
                       stands. Policy gates and guards upstream documents as
                       incomplete land here.
``false_positive``     the guard closes the path and we report anyway.
``fixed``              was a false positive, and is now suppressed.
``unmodelled_guard``   the guard closes the path but the analyser has no rule
                       for that idiom. A false positive that needs a registry
                       entry, not new analysis.
``uncertain``          the diff does not contain enough to decide. Recorded as
                       uncertainty rather than guessed either way.
"""

from __future__ import annotations

import argparse
import collections
import difflib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

#: Guard signature -> (verdict, rationale). The signature is the set of
#: recognisable guard primitives in the lines the patch added, so a new corpus
#: build that produces a known shape is classified without re-reading it.
#: Ordered most-specific-first, and that order is part of the contract: when two
#: shapes rank equally, the earlier one wins. A bare ``{"raise"}`` therefore sits
#: last, so it only classifies a signature that carries no containment primitive at
#: all. It cannot outrank ``{"commonpath"}`` on a signature that has one, which is
#: what it used to do whenever the two overlapped -- and that silently turned
#: ``commonpath + raise`` containment fixes into "the sink is reachable by
#: design", a verdict that credits the report as correct when it is a false positive.
SHAPES: list[frozenset] = [
    # --- upstream itself says the guard is incomplete, or it is a policy gate
    # --- the guard is a real containment check we do not model
    (frozenset({"commonpath"}),
     "unmodelled_guard",
     "os.path.commonpath is the canonical containment check for path "
     "traversal; the registry does not type it as a sanitiser"),
    (frozenset({"realpath", "raise"}),
     "unmodelled_guard",
     "resolve()/realpath() followed by a containment raise is the standard "
     "containment idiom and is not a modelled kill"),
    (frozenset({"normpath"}),
     "unmodelled_guard",
     "normpath-then-prefix-check is the older containment idiom, used by "
     "cherrypy and Django session code, and is not a modelled kill"),
    (frozenset({"dirname", "raise"}),
     "unmodelled_guard",
     "a parent-directory comparison with a raise is a containment check"),
    (frozenset({"resolve", "raise"}),
     "unmodelled_guard",
     "Path.resolve() with a containment raise is a containment check"),
    (frozenset({"verify"}),
     "unmodelled_guard",
     "the patched code delegates to an application-specific validator the "
     "analyser cannot know about"),
    (frozenset({"escape", "join"}),
     "unmodelled_guard",
     "the value is escaped and then substituted into a markup template; the "
     "escape is not followed through the format call"),
    (frozenset({"escape", "check", "urlparse"}),
     "correct",
     "escape() is applied on one branch only; the branch that still reaches the "
     "assertion is unescaped, so the report is right"),
    (frozenset({"escape"}),
     "fixed",
     "escape() applied to the asserted value is a known sanitiser and now "
     "suppresses the amplifier"),
    (frozenset({"raise"}),
     "correct",
     "an unconditional raise that only fires when a policy flag allows the "
     "operation leaves the sink reachable by design, which is what the "
     "maintainers shipped"),
    # --- deliberately reachable
    (frozenset({"safe_mode", "in_safe_mode"}),
     "correct",
     "the deserialisation is gated behind an explicit opt-in that the shipped "
     "fix intends to keep"),
    (frozenset({"True"}),
     "uncertain",
     "a single-token change to a boolean condition is not enough to tell "
     "whether the reachable path is narrowed"),
    (frozenset({"MarkdownIt"}),
     "uncertain",
     "a configuration toggle for raw HTML; whether it is safe depends on the "
     "deployment default, which the diff does not show"),
    # --- nothing to judge
    (frozenset(),
     "uncertain",
     "the patch added no recognisable guard to this function"),
]

RECORD_PRIMITIVES = {
    "commonpath", "realpath", "abspath", "normpath", "dirname", "isabs",
    "resolve", "relative_to", "escape", "safe_mode", "in_safe_mode",
    "urlparse", "quote", "raise", "startswith",
}


def added_lines(case: dict) -> list[str]:
    vulnerable = case.get("vulnerable_source", "")
    patched = case["source"]
    diff = difflib.unified_diff(
        _body(vulnerable).split("\n"), _body(patched).split("\n"),
        lineterm="", n=0,
    )
    return [line[1:] for line in diff
            if line.startswith("+") and not line.startswith("+++")]


def _body(source: str) -> str:
    lines = source.split("\n")
    for index, line in enumerate(lines):
        if re.match(r"^\s*(async\s+)?def\s", line):
            return "\n".join(lines[index:])
    return source


def signature(case: dict) -> frozenset[str]:
    found: set[str] = set()
    for line in added_lines(case):
        for token in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", line):
            if token in RECORD_PRIMITIVES:
                found.add(token)
    return frozenset(found)


#: Calls whose argument is asserted safe, and whose argument therefore names the
#: values that actually reach the output.
_ASSERTION_CALLS = ("Markup", "mark_safe", "SafeString")


def injected_names(case: dict) -> set[str]:
    """Names the reported assertion actually emits.

    ``Markup('<a href="{url}">{title}</a>'.format(**locals()))`` emits ``url`` and
    ``title``. Finding ``escape`` somewhere in the same function says nothing about
    which of those two reached the output escaped, so the claim has to be checked
    against these names rather than against the whole function.
    """
    names: set[str] = set()
    for line in added_lines(case):
        for call in _ASSERTION_CALLS:
            if call + "(" in line:
                names.update(re.findall(r"\{(\w+)\}", line))
        join = re.search(r"\.join\(([^()]*)\)", line)
        if join:
            names.update(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", join.group(1)))
    return names


def uncovered_names(names: set[str], case: dict, sanitisers: set[str]) -> set[str]:
    """Emitted names that no recorded sanitiser is applied to.

    Coverage has to mean the name passed *through* a sanitiser, in either
    direction: ``escape(title)`` or ``title = escape(m.run_id)``. Plain assignment
    does not count. ``url = url_for(...)`` is an assignment and ``url_for`` is not a
    sanitiser, so ``url`` stays exposed even though the line looks handled -- which
    is exactly the shape that made these cases look fixed.

    Requiring *every* emitted name keeps this honest too: an assertion that escapes
    one of three substitutions is a partial mitigation, and filing it as fixed
    would credit the tool with a safety property it has not established.
    """
    if not sanitisers:
        return set(names)
    pattern = "|".join(re.escape(s) for s in sorted(sanitisers))
    lines = added_lines(case)
    uncovered: set[str] = set()
    for name in names:
        inline = re.compile(r"\b(?:" + pattern + r")\s*\([^()]*\b" + re.escape(name) + r"\b")
        assigned = re.compile(r"\b" + re.escape(name) + r"\s*=\s*[^\n]*\b(?:" + pattern + r")\s*\(")
        if any(inline.search(line) or assigned.search(line) for line in lines):
            continue
        uncovered.add(name)
    return uncovered


def classify(case: dict) -> tuple[str, str, str]:
    """Verdict for one case, matched on the most specific shape present."""
    sig = signature(case)
    if not sig:
        return ("uncertain", sig, "the patch added no recognisable guard to this function")

    # Rank shapes rather than taking the first that overlaps. Scoring on overlap
    # alone tied an exact match against a half match, and tied a bare {"raise"}
    # against {"commonpath"} whenever both were present -- in both cases list
    # order decided, and in both cases it decided in favour of the verdict that
    # claims more. Ranking, in order: an exact match, then a shape whose every
    # primitive is present, then the larger overlap, then the smaller shape.
    def rank(row: tuple[frozenset[str], str, str]) -> tuple[int, int, int, int]:
        primitives, _, _ = row
        exact = int(frozenset(primitives) == sig)
        whole = int(bool(primitives) and primitives <= sig)
        return (exact, whole, len(primitives & sig), -len(primitives))

    ordered = sorted(
        (row for row in SHAPES if row[0] & sig), key=rank, reverse=True
    )
    if not ordered:
        return ("uncertain", sig, "no guard primitives recognised")
    verdict, why = ordered[0][1], ordered[0][2]

    # A guard verdict asserts a sanitiser closes the path. Check the sanitiser
    # reaches a value the claim actually emits before believing it. Without this,
    # ``escape(m.run_id)`` elsewhere in the function was read as covering a format
    # placeholder fed by an unescaped ``url_for`` result, and the case was filed
    # as "needs a registry entry" when it is not decidable from this function.
    if verdict in ("unmodelled_guard", "fixed", "false_positive"):
        names = injected_names(case)
        exposed = uncovered_names(names, case, set(sig)) if names else set()
        if exposed:
            verb = "partly" if len(exposed) < len(names) else "does not"
            return (
                "uncertain",
                sig,
                f"the sanitiser {verb} cover every value the assertion emits; "
                f"{sorted(exposed)} reach the output untouched, so whether the "
                "emitted value is safe is not decidable from this function",
            )
    return (verdict, sig, why)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--queue", default="data/adjudication_queue.json")
    parser.add_argument("--out", default="data/survivor_ledger.jsonl")
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    queue = pathlib.Path(args.queue)
    if not queue.exists():
        print(f"{queue} not found; run benchmarks/adjudicate.py first")
        return 1
    cases = [c for c in json.loads(queue.read_text(encoding="utf-8"))
             if c["case"].startswith("survivor")]

    rows = []
    for case in cases:
        verdict, sig, why = classify(case)
        rows.append({
            "case": case["case"],
            "pair_id": case.get("pair_id", ""),
            "class": case["label"],
            "tier": case.get("tier", ""),
            "sinks": case["claimed_sinks"].get(case["label"], []),
            "guard_primitives": sorted(sig),
            "verdict": verdict,
            "rationale": why,
        })

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8",
    )

    verdicts: collections.Counter = collections.Counter(r["verdict"] for r in rows)
    total = sum(verdicts.values())
    print("=" * 78)
    print(f"kill-survivor verdicts: {total} cases")
    print("=" * 78)
    for verdict, count in verdicts.most_common():
        print(f"  {count:>4}  {verdict}")
    print()
    false_positive = verdicts["false_positive"] + verdicts["unmodelled_guard"]
    decided = total - verdicts["uncertain"]
    print(f"false positives among decided cases: "
          f"{false_positive}/{decided} = "
          f"{100.0 * false_positive / decided:.0f}%" if decided else "n/a")
    print()
    print("by class:")
    for cls in sorted({r["class"] for r in rows}):
        subset = [r for r in rows if r["class"] == cls]
        counts = collections.Counter(r["verdict"] for r in subset)
        print(f"  {cls:<9} {dict(counts)}")
    print()
    print("distinct guard shapes recorded:")
    shapes = collections.Counter(tuple(r["guard_primitives"]) for r in rows)
    for shape, count in shapes.most_common():
        print(f"  {count:>3}  {', '.join(shape) or '(no primitive)'}")
    print(f"\n-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
