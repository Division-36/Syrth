"""Characterise the kill-survivors: what guard did the patch add?

For each patched function that still reports its class, show the added and removed
lines between the vulnerable and patched sides. The added lines are the guard, and
the question is whether that guard actually closes the path to the claimed sink.

Grouping is by (class, claimed sink, shape of the added lines) because the
adjudication question is identical within a shape: 59 survivors should reduce to
a handful of distinct guard mechanisms.
"""
from __future__ import annotations

import collections
import difflib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

GUARD_VOCAB = {
    "raise", "return", "if", "not", "and", "or", "is", "in", "None", "True",
    "False", "commonpath", "realpath", "abspath", "normpath", "basename",
    "dirname", "isabs", "isfile", "isdir", "exists", "resolve", "join",
    "escape", "quote", "int", "str", "lower", "startswith", "endswith",
    "safe_mode", "in_safe_mode", "enable_unsafe_deserialization", "allowed",
    "whitelist", "allowlist", "is_safe", "sanitize", "sanitise", "validate",
    "check", "verify", "assert", "urlsplit", "urlparse", "hostname", "netloc",
    "scheme", "split", "replace", "strip", "rstrip", "lstrip", "partition",
    "compare_digest", "hexdigest", "secrets", "hashlib", "sha256",
}


QUEUE = pathlib.Path(r"D:\Axioms\Syrth\data\adjudication_queue.json")
cases = json.loads(QUEUE.read_text(encoding="utf-8"))
survivors = [c for c in cases if c["case"].startswith("survivor")]

print("=" * 80)
print(f"kill-survivors: {len(survivors)}")
print("=" * 80)
by_class = collections.Counter(c["label"] for c in survivors)
print(f"by class: {dict(by_class.most_common())}")
print(f"by tier : {dict(collections.Counter(c['tier'] for c in survivors))}")
print(f"by detector: "
      f"{dict(collections.Counter(d for c in survivors for ds in c['detector'].values() for d in ds))}")
print()


def body_of(source: str) -> str:
    """Strip the module preamble so the diff shows the function, not imports."""
    lines = source.split("\n")
    for index, line in enumerate(lines):
        if re.match(r"^\s*(async\s+)?def\s", line):
            return "\n".join(lines[index:])
    return source


def added_lines(case) -> list[str]:
    vulnerable = case.get("vulnerable_source", "")
    patched = case["source"]
    diff = difflib.unified_diff(
        body_of(vulnerable).split("\n"),
        body_of(patched).split("\n"),
        lineterm="", n=0,
    )
    return [line[1:].strip() for line in diff
            if line.startswith("+") and not line.startswith("+++")]


shapes: dict[tuple, list[str]] = collections.defaultdict(list)
for case in survivors:
    added = added_lines(case)
    # Shape = the vocabulary of the guard, not its exact text.
    vocab = tuple(sorted({
        token
        for line in added
        for token in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", line)
        if token in GUARD_VOCAB
    }))
    sink = tuple(case["claimed_sinks"].get(case["label"], ()))
    shapes[(case["label"], sink, vocab)].append(case["case"])

print("distinct guard shapes:")
print("=" * 80)
for (label, sink, vocab), names in sorted(shapes.items(), key=lambda kv: -len(kv[1])):
    print(f"{len(names):>3}  {label:<9} sink={','.join(sink) or '-'}")
    print(f"     guard vocabulary: {', '.join(vocab) or '(none detected)'}")
    print(f"     cases: {names[:4]}{' ...' if len(names) > 4 else ''}")
    print()

GUARD_VOCAB = {
    "raise", "return", "if", "not", "and", "or", "is", "in", "None", "True",
    "False", "commonpath", "realpath", "abspath", "normpath", "basename",
    "dirname", "isabs", "isfile", "isdir", "exists", "resolve", "join",
    "escape", "quote", "int", "str", "lower", "startswith", "endswith",
    "safe_mode", "in_safe_mode", "enable_unsafe_deserialization", "allowed",
    "whitelist", "allowlist", "is_safe", "sanitize", "sanitise", "validate",
    "check", "verify", "assert", "urlsplit", "urlparse", "hostname", "netloc",
    "scheme", "split", "replace", "strip", "rstrip", "lstrip", "partition",
    "compare_digest", "hexdigest", "secrets", "hashlib", "sha256",
}
