"""Rule-based classifier for vulnerability detection.

Deterministic patterns based on:
- SCAT tokens (sink categories)
- Import patterns (os, subprocess, sqlite3, django, flask, etc.)
- Specific sink names
- Function name patterns
- Decorator patterns
"""
from collections import Counter
from dataclasses import dataclass, field
from typing import List

CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]
CLASS_SQLI, CLASS_XSS, CLASS_PATH, CLASS_REDIR, CLASS_RCE = range(5)

# Map SCAT tokens to class
SCAT_TO_CLASS = {
    "SCAT:SQL": CLASS_SQLI,
    "SCAT:XSS": CLASS_XSS,
    "SCAT:FILE": CLASS_PATH,
    "SCAT:EXEC": CLASS_RCE,
    "SCAT:NET": CLASS_RCE,      # SSRF often looks like RCE in patterns
    "SCAT:REDIRECT": CLASS_REDIR,
    "SCAT:DESER": CLASS_RCE,
}

# Sink name → class (more specific than SCAT)
SINK_TO_CLASS = {
    "execute": CLASS_SQLI, "executemany": CLASS_SQLI, "raw": CLASS_SQLI,
    "RawSQL": CLASS_SQLI, "extra": CLASS_SQLI, "cursor.execute": CLASS_SQLI,
    "connection.execute": CLASS_SQLI, "Model.objects.raw": CLASS_SQLI,
    "render": CLASS_XSS, "render_to_string": CLASS_XSS,
    "render_to_response": CLASS_XSS, "mark_safe": CLASS_XSS,
    "HttpResponse": CLASS_XSS, "render_template": CLASS_XSS,
    "render_template_string": CLASS_XSS, "make_response": CLASS_XSS,
    "Response": CLASS_XSS, "JsonResponse": CLASS_XSS, "jsonify": CLASS_XSS,
    "HTMLResponse": CLASS_XSS, "TemplateResponse": CLASS_XSS,
    "format_html": CLASS_XSS, "autoescape_off": CLASS_XSS,
    "open": CLASS_PATH, "shutil.copy": CLASS_PATH, "shutil.rmtree": CLASS_PATH,
    "os.remove": CLASS_PATH, "send_file": CLASS_PATH, "send_from_directory": CLASS_PATH,
    "FileResponse": CLASS_PATH, "os.makedirs": CLASS_PATH,
    "os.system": CLASS_RCE, "subprocess.run": CLASS_RCE,
    "subprocess.call": CLASS_RCE, "subprocess.Popen": CLASS_RCE,
    "subprocess.getoutput": CLASS_RCE, "popen": CLASS_RCE,
    "os.popen": CLASS_RCE, "eval": CLASS_RCE, "exec": CLASS_RCE,
    "compile": CLASS_RCE, "subprocess.check_output": CLASS_RCE,
    "redirect": CLASS_REDIR, "HttpResponseRedirect": CLASS_REDIR,
    "HttpResponsePermanentRedirect": CLASS_REDIR, "RedirectResponse": CLASS_REDIR,
    "pickle.loads": CLASS_RCE, "yaml.load": CLASS_RCE, "marshal.loads": CLASS_RCE,
}

# Import patterns → class weights
IMPORT_PATTERNS = {
    "sql": CLASS_SQLI, "sqlite3": CLASS_SQLI, "psycopg2": CLASS_SQLI,
    "pymysql": CLASS_SQLI, "django.db": CLASS_SQLI, "sqlalchemy": CLASS_SQLI,
    "flask": CLASS_XSS, "django.template": CLASS_XSS, "jinja2": CLASS_XSS,
    "markupsafe": CLASS_XSS, "html": CLASS_XSS,
    "os.path": CLASS_PATH, "pathlib": CLASS_PATH, "shutil": CLASS_PATH,
    "os": CLASS_RCE, "subprocess": CLASS_RCE, "commands": CLASS_RCE,
    "requests": CLASS_RCE, "httpx": CLASS_RCE, "urllib": CLASS_RCE,
    "pickle": CLASS_RCE, "yaml": CLASS_RCE, "marshal": CLASS_RCE,
    "django.shortcuts.redirect": CLASS_REDIR, "flask.redirect": CLASS_REDIR,
}

# Function name patterns → class
FN_PATTERNS = {
    "sql": CLASS_SQLI, "query": CLASS_SQLI, "execute": CLASS_SQLI,
    "render": CLASS_XSS, "template": CLASS_XSS, "html": CLASS_XSS,
    "path": CLASS_PATH, "file": CLASS_PATH, "open": CLASS_PATH,
    "redirect": CLASS_REDIR, "url": CLASS_REDIR,
    "exec": CLASS_RCE, "system": CLASS_RCE, "shell": CLASS_RCE,
    "command": CLASS_RCE, "run": CLASS_RCE, "eval": CLASS_RCE,
}

# Decorator patterns → class
DECORATOR_PATTERNS = {
    "api_view": CLASS_RCE, "csrf_exempt": CLASS_XSS, "permission_classes": CLASS_RCE,
    "authentication_classes": CLASS_RCE, "login_required": CLASS_RCE,
}


@dataclass
class RuleResult:
    predicted_class: int
    confidence: float
    votes: Counter = field(default_factory=Counter)
    reasons: List[str] = field(default_factory=list)


def classify_by_rules(tokens: List[str]) -> RuleResult:
    """Classify using deterministic rules on token sequence."""
    votes = Counter()
    reasons = []

    # 1. SCAT tokens (strongest signal)
    scat_counts = Counter()
    for t in tokens:
        if t.startswith("SCAT:") and t in SCAT_TO_CLASS:
            scat_counts[SCAT_TO_CLASS[t]] += 1

    # 2. Sink tokens
    sink_counts = Counter()
    for t in tokens:
        if t.startswith("sink:"):
            sink = t[5:]
            if sink in SINK_TO_CLASS:
                sink_counts[SINK_TO_CLASS[sink]] += 1

    # 3. Taint tokens (highest precision)
    taint_counts = Counter()
    for t in tokens:
        if t.startswith("tainted:"):
            sink = t[8:]
            if sink in SINK_TO_CLASS:
                taint_counts[SINK_TO_CLASS[sink]] += 2  # weight taint higher

    # 4. Import patterns
    import_counts = Counter()
    for t in tokens:
        if t.startswith("import:") or t.startswith("import:"):
            imp = t.split(":", 1)[1] if ":" in t else t
            for pat, cls in IMPORT_PATTERNS.items():
                if pat in imp:
                    import_counts[cls] += 1
                    break

    # 5. Function name patterns
    fn_counts = Counter()
    for t in tokens:
        if t.startswith("def:"):
            fn = t[4:]
            for pat, cls in FN_PATTERNS.items():
                if pat in fn:
                    fn_counts[cls] += 1
                    break

    # 6. Decorator patterns
    dec_counts = Counter()
    for t in tokens:
        if t.startswith("@"):
            dec = t[1:]
            for pat, cls in DECORATOR_PATTERNS.items():
                if pat in dec:
                    dec_counts[cls] += 1
                    break

    # Aggregate all votes with weights
    WEIGHTS = {
        "scat": 3.0,
        "sink": 2.0,
        "taint": 5.0,
        "import": 1.5,
        "fn": 1.0,
        "decorator": 1.5,
    }

    for cls, cnt in scat_counts.items():
        votes[cls] += cnt * WEIGHTS["scat"]
    for cls, cnt in sink_counts.items():
        votes[cls] += cnt * WEIGHTS["sink"]
    for cls, cnt in taint_counts.items():
        votes[cls] += cnt * WEIGHTS["taint"]
    for cls, cnt in import_counts.items():
        votes[cls] += cnt * WEIGHTS["import"]
    for cls, cnt in fn_counts.items():
        votes[cls] += cnt * WEIGHTS["fn"]
    for cls, cnt in dec_counts.items():
        votes[cls] += cnt * WEIGHTS["decorator"]

    if not votes:
        return RuleResult(CLASS_RCE, 0.2, votes, ["no signals"])

    # Normalize to confidence
    total = sum(votes.values())
    pred = votes.most_common(1)[0][0]
    conf = votes[pred] / total if total > 0 else 0.0

    # Build reasons
    for source, cnts in [
        ("scat", scat_counts), ("sink", sink_counts), ("taint", taint_counts),
        ("import", import_counts), ("fn", fn_counts), ("decorator", dec_counts)
    ]:
        if cnts:
            top = cnts.most_common(1)[0]
            reasons.append(f"{source}: {CLASS_NAMES[top[0]]}x{top[1]}")

    return RuleResult(pred, conf, votes, reasons)


def quick_classify(tokens: List[str]) -> int:
    """Fast classification returning only the class."""
    return classify_by_rules(tokens).predicted_class


if __name__ == "__main__":
    # Quick test
    test_tokens = ["def:view", "arg:request", "sink:execute", "SCAT:SQL", "tainted:execute"]
    r = classify_by_rules(test_tokens)
    print(f"Pred: {CLASS_NAMES[r.predicted_class]}, Conf: {r.confidence:.2f}")
    print(f"Reasons: {r.reasons}")
    print(f"Votes: {r.votes}")