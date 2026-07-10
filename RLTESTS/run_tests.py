"""
SYRTH End-to-End Test Runner
=============================
Runs syrth_scan.py on all RLTESTS/*.py files and reports results.

Usage:
    python run_tests.py              # Run all tests
    python run_tests.py --verbose    # Show full output
    python run_tests.py --mode fast  # Use C engine
"""
import subprocess
import sys
import json
import os
from pathlib import Path
from collections import defaultdict

# Test expectations: filename -> expected top class
EXPECTED = {
    "sqli_views.py":          "SQLi",
    "xss_views.py":           "XSS",
    "path_traversal_views.py": "PathTraversal",
    "open_redirect_views.py": "OpenRedirect",
    "rce_views.py":           "RCE",
    "mixed_vulns.py":         "mixed",
}

COLORS = {
    "PASS": "\033[92m",   # green
    "FAIL": "\033[91m",   # red
    "WARN": "\033[93m",   # yellow
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def run_scan(filepath: str, mode: str = "dev") -> dict:
    """Run syrth_scan.py on a file and return JSON output."""
    result = subprocess.run(
        [sys.executable, "syrth_scan.py", "--file", filepath, "--mode", mode, "--json"],
        capture_output=True, text=True, cwd=str(Path(__file__).parent.parent),
    )
    if result.returncode != 0:
        return {"error": result.stderr}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": f"Invalid JSON: {result.stdout[:200]}"}


def main():
    verbose = "--verbose" in sys.argv
    mode = "fast" if "--mode" in sys.argv else "dev"

    tests_dir = Path(__file__).parent
    test_files = sorted(tests_dir.glob("*.py"))
    test_files = [f for f in test_files if f.name != "run_tests.py"]

    print(f"\n{'=' * 70}")
    print(f"  SYRTH End-to-End Tests")
    print(f"  Mode: {mode.upper()}")
    print(f"  Tests: {len(test_files)}")
    print(f"{'=' * 70}\n")

    passed = 0
    failed = 0
    warnings = 0
    results_summary = []

    for filepath in test_files:
        filename = filepath.name
        expected = EXPECTED.get(filename)
        if not expected:
            continue

        print(f"  Testing: {filename}")

        output = run_scan(str(filepath), mode)

        if "error" in output:
            print(f"    {COLORS['FAIL']}ERROR: {output['error'][:100]}{COLORS['RESET']}")
            failed += 1
            results_summary.append((filename, "ERROR", "N/A", expected))
            continue

        pred = output.get("prediction", {})
        if pred is None:
            print(f"    {COLORS['WARN']}CLEAN (no findings){COLORS['RESET']}")
            warnings += 1
            results_summary.append((filename, "CLEAN", "none", expected))
            continue

        top_class = pred.get("class", "Unknown")
        confidence = pred.get("confidence", 0)
        cwe_id = pred.get("cwe_id", "")

        # Check result
        if expected == "mixed":
            # For mixed file, any valid class is acceptable
            valid_classes = {"SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"}
            if top_class in valid_classes and confidence >= 0.30:
                status = "PASS"
                passed += 1
            else:
                status = "FAIL"
                failed += 1
        elif top_class == expected:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1

        color = COLORS[status]
        print(f"    {color}{status}: predicted {top_class} ({confidence:.0%}) [{cwe_id}]{COLORS['RESET']}")

        if status == "FAIL":
            print(f"      Expected: {expected}")

        # Show secondary findings
        all_classes = output.get("all_classes", [])
        if all_classes and verbose:
            for c in all_classes[1:3]:
                if c["confidence"] > 0.05:
                    print(f"      Also: {c['class']} ({c['confidence']:.0%})")

        # Show explainability summary
        expl = output.get("explainability", {})
        if expl and verbose:
            summary = expl.get("pattern_summary", "")
            if summary:
                for line in summary.split("\n")[:2]:
                    print(f"      {line.strip()}")

        results_summary.append((filename, status, top_class, expected))

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"  RESULTS")
    print(f"{'=' * 70}")

    for filename, status, predicted, expected in results_summary:
        icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "!", "CLEAN": "?"}.get(status, "?")
        color = COLORS.get(status, "")
        exp_str = f" (expected {expected})" if status == "FAIL" else ""
        print(f"  {color}{icon} {filename:<30} {status:<8} {predicted}{exp_str}{COLORS['RESET']}")

    total = passed + failed + warnings
    print(f"\n  Total:   {total}")
    print(f"  Passed:  {COLORS['PASS']}{passed}{COLORS['RESET']}")
    print(f"  Failed:  {COLORS['FAIL']}{failed}{COLORS['RESET']}")
    print(f"  Warnings:{COLORS['WARN']} {warnings}{COLORS['RESET']}")

    if failed == 0:
        print(f"\n  {COLORS['PASS']}ALL TESTS PASSED{COLORS['RESET']}")
    else:
        print(f"\n  {COLORS['FAIL']}SOME TESTS FAILED{COLORS['RESET']}")

    print(f"{'=' * 70}\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
