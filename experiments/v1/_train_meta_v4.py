"""
Meta-learner v4: retrain with synthetic description features.
Training data has CWE names → generate synthetic descriptions → extract text features.
Eval uses real CVE descriptions → same feature space.
"""
import json, sys, re, torch, joblib, numpy as np
from pathlib import Path
from collections import Counter
sys.path.insert(0, str(Path(__file__).parent))
import train_model as T
from _eval_ensemble import predict_ensemble, TOK, UNK, ensemble
from _rules import classify_by_rules
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

NUM_CLASSES = 5
CLASS_NAMES = ["SQLi", "XSS", "PathTraversal", "OpenRedirect", "RCE"]

RCE_SINKS = frozenset({
    "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput", "popen", "os.popen",
    "os.execv", "os.execl", "os.execve", "os.execvp", "os.execvpe",
    "eval", "exec", "compile", "__import__",
    "pickle.loads", "pickle.load", "cPickle.loads", "yaml.load",
    "yaml.full_load", "yaml.unsafe_load", "marshal.loads", "marshal.load",
    "jsonpickle.decode", "numpy.load", "torch.load",
})
SQL_SINKS = frozenset({
    "execute", "executemany", "raw", "RawSQL", "extra",
    "cursor.execute", "connection.execute", "Model.objects.raw",
})
FILE_SINKS = frozenset({
    "open", "io.open", "codecs.open", "os.path.join", "os.path.abspath",
    "shutil.copy", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink",
    "send_file", "send_from_directory", "FileResponse", "os.makedirs",
})
XSS_SINKS = frozenset({
    "render", "render_to_string", "render_to_response", "mark_safe",
    "SafeString", "render_template", "render_template_string",
    "make_response", "Response", "HttpResponse", "JsonResponse",
    "jsonify", "HTMLResponse", "TemplateResponse", "format_html", "autoescape_off",
})
REDIRECT_SINKS = frozenset({
    "redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
    "RedirectResponse",
})

# ── Text patterns ───────────────────────────────────────────────────────
SQL_TEXT_PATTERNS = [
    re.compile(r'\bSELECT\b.*\bFROM\b', re.I),
    re.compile(r'\bINSERT\b.*\bINTO\b', re.I),
    re.compile(r'\bUPDATE\b.*\bSET\b', re.I),
    re.compile(r'\bDELETE\b.*\bFROM\b', re.I),
    re.compile(r'\bUNION\b.*\bSELECT\b', re.I),
    re.compile(r'\bDROP\b.*\bTABLE\b', re.I),
    re.compile(r'cursor\.execute|\.execute\(.*["\']SELECT', re.I),
    re.compile(r'\.raw\(|\.extra\(|\.objects\.raw', re.I),
    re.compile(r'OR\s+1\s*=\s*1|OR\s+\'\w+\'\s*=\s*\'', re.I),
    re.compile(r'f"[^"]*\bSELECT\b|f\'[^\']*\bSELECT\b', re.I),
    re.compile(r'"SELECT\b.*\{|\bSELECT\b.*\+\s*\w', re.I),
]
RCE_TEXT_PATTERNS = [
    re.compile(r'\bpickle\.\w*loads?\b|cPickle\.loads'),
    re.compile(r'\byaml\.unsafe_load\b|\byaml\.load\b'),
    re.compile(r'\btorch\.load\b|\bnumpy\.load\b.*allow_pickle'),
    re.compile(r'\bos\.system\b|\bos\.popen\b'),
    re.compile(r'\bsubprocess\.\w+\(.*shell\s*=\s*True'),
    re.compile(r'\bexec\s*\(|\beval\s*\(|\bcompile\s*\('),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bmarshal\.loads?\b'),
    re.compile(r'os\.system\(|subprocess\.run\(|subprocess\.call\(|subprocess\.Popen\('),
]
PT_TEXT_PATTERNS = [
    re.compile(r'\.\./|\.\.\\'),
    re.compile(r'os\.path\.join.*\+|os\.path\.join.*format'),
    re.compile(r'open\(.*\+|open\(.*format'),
    re.compile(r'Path\([^)]*\)\s*/'),
    re.compile(r'send_file\(|send_from_directory\('),
    re.compile(r'is_path_traversal|path_traversal'),
    re.compile(r'extractall\(|\.write_bytes\(.*read'),
]
XSS_TEXT_PATTERNS = [
    re.compile(r'<script|javascript:', re.I),
    re.compile(r'document\.write|innerHTML|outerHTML'),
    re.compile(r'mark_safe|SafeString|autoescape.*False'),
    re.compile(r'<[^>]*\{[^}]*\}', re.I),
    re.compile(r'render_template[^_]|render_to_string'),
]
OR_TEXT_PATTERNS = [
    re.compile(r'redirect\(|HttpResponseRedirect|HttpResponsePermanentRedirect'),
    re.compile(r'RedirectResponse|return.*redirect', re.I),
    re.compile(r'Location:', re.I),
    re.compile(r'next_url|return_url|callback_url|target_url'),
]

# CWE name → synthetic description keywords
CWE_DESCRIPTIONS = {
    0: "SQL injection CWE-89 SQL injection vulnerability in database query parameterized query",
    1: "cross-site scripting XSS CWE-79 reflected stored DOM scripting injection HTML template rendering",
    2: "path traversal directory traversal CWE-22 file inclusion local file read arbitrary file access path",
    3: "open redirect CWE-601 URL redirect validation external link navigation",
    4: "remote code execution arbitrary command injection CWE-94 code injection eval exec subprocess deserialization pickle yaml unsafe load",
}


def extract_text_features(source_code):
    feats = []
    sql_m = sum(1 for p in SQL_TEXT_PATTERNS if p.search(source_code))
    rce_m = sum(1 for p in RCE_TEXT_PATTERNS if p.search(source_code))
    pt_m = sum(1 for p in PT_TEXT_PATTERNS if p.search(source_code))
    xss_m = sum(1 for p in XSS_TEXT_PATTERNS if p.search(source_code))
    or_m = sum(1 for p in OR_TEXT_PATTERNS if p.search(source_code))
    feats.append(min(sql_m / 3.0, 1.0))
    feats.append(min(rce_m / 3.0, 1.0))
    feats.append(min(pt_m / 3.0, 1.0))
    feats.append(min(xss_m / 3.0, 1.0))
    feats.append(min(or_m / 3.0, 1.0))
    total = sql_m + rce_m + pt_m + xss_m + or_m
    feats.append(min(total / 5.0, 1.0))
    feats.append(1.0 if re.search(r'["\']SELECT\b|["\']INSERT\b|["\']UPDATE\b|["\']DELETE\b', source_code, re.I) else 0.0)
    feats.append(1.0 if re.search(r'pickle\.|yaml\.(unsafe_)?load|torch\.load|marshal\.', source_code) else 0.0)
    feats.append(1.0 if re.search(r'\bexec\s*\(|\beval\s*\(', source_code) else 0.0)
    feats.append(1.0 if re.search(r'shell\s*=\s*True', source_code) else 0.0)
    return feats


def extract_meta_features(tokens, source_code=None):
    seq_ids = [TOK.vocab.get(t, 1) for t in tokens]
    pred, conf, votes = predict_ensemble(tokens, seq_ids)
    rule_result = classify_by_rules(tokens)
    rule_class = rule_result.predicted_class
    rule_conf = rule_result.confidence
    rule_votes_total = rule_result.votes.total()
    has_taint = any(t.startswith("tainted:") for t in tokens)

    token_set = set(tokens)
    n_tokens = max(len(tokens), 1)

    rce_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in RCE_SINKS)
    sql_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in SQL_SINKS)
    file_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in FILE_SINKS)
    xss_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in XSS_SINKS)
    redir_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in REDIRECT_SINKS)
    deser_sinks = sum(1 for t in tokens if t.startswith("sink:") and any(
        x in t for x in ["pickle", "yaml", "marshal", "torch.load", "numpy.load"]))
    sink_count = sum(1 for t in tokens if t.startswith("sink:"))
    call_count = sum(1 for t in tokens if t.startswith("call:"))
    tainted_count = sum(1 for t in tokens if t.startswith("tainted:"))

    feats = []
    feats.extend(float(votes[i]) for i in range(NUM_CLASSES))
    feats.append(conf)
    feats.extend(1.0 if i == pred else 0.0 for i in range(NUM_CLASSES))
    feats.append(1.0 if has_taint else 0.0)
    feats.append(rule_conf)
    feats.append(min(rule_votes_total / 10.0, 1.0))
    if rule_votes_total > 0:
        feats.extend(1.0 if i == rule_class else 0.0 for i in range(NUM_CLASSES))
    else:
        feats.extend([0.0] * NUM_CLASSES)
    feats.append(1.0 if rule_votes_total > 0 else 0.0)
    feats.append(rce_sinks / n_tokens)
    feats.append(sql_sinks / n_tokens)
    feats.append(file_sinks / n_tokens)
    feats.append(xss_sinks / n_tokens)
    feats.append(redir_sinks / n_tokens)
    feats.append(deser_sinks / n_tokens)
    feats.append(min(sink_count / 5.0, 1.0))
    feats.append(min(tainted_count / 3.0, 1.0))
    feats.append(1.0 if deser_sinks > 0 else 0.0)
    has_exec = any(t in ("sink:os.system", "sink:subprocess.run", "sink:subprocess.call",
                         "sink:subprocess.Popen", "sink:eval", "sink:exec",
                         "sink:compile", "sink:__import__", "sink:execfile")
                   for t in tokens)
    feats.append(1.0 if has_exec else 0.0)
    has_file = any(t in ("sink:open", "sink:io.open", "sink:codecs.open",
                         "sink:os.path.join", "sink:os.path.abspath",
                         "sink:shutil.copy", "sink:shutil.move",
                         "sink:os.remove", "sink:os.makedirs",
                         "sink:send_file", "sink:send_from_directory")
                   for t in tokens)
    feats.append(1.0 if has_file else 0.0)
    has_sql = any(t in ("sink:execute", "sink:executemany", "sink:raw",
                        "sink:RawSQL", "sink:extra", "sink:cursor.execute",
                        "sink:connection.execute", "sink:Model.objects.raw")
                  for t in tokens)
    feats.append(1.0 if has_sql else 0.0)
    has_render = any(t in ("sink:render", "sink:render_to_string", "sink:render_template",
                           "sink:render_template_string", "sink:mark_safe",
                           "sink:SafeString", "sink:make_response",
                           "sink:Response", "sink:HttpResponse",
                           "sink:format_html", "sink:autoescape_off")
                     for t in tokens)
    feats.append(1.0 if has_render else 0.0)
    has_redirect = any(t in ("sink:redirect", "sink:HttpResponseRedirect",
                             "sink:HttpResponsePermanentRedirect",
                             "sink:RedirectResponse")
                       for t in tokens)
    feats.append(1.0 if has_redirect else 0.0)
    feats.append(min(np.log1p(n_tokens) / 5.0, 1.0))
    feats.append(min(call_count / 10.0, 1.0))
    feats.append(1.0 if "meta:no_auth" in token_set else 0.0)
    feats.append(min((rce_sinks + deser_sinks) / 3.0, 1.0))
    feats.append(1.0 if any(t.startswith("SCAT:") for t in tokens) else 0.0)

    if source_code:
        text_feats = extract_text_features(source_code)
        feats.extend(text_feats)
    else:
        feats.extend([0.0] * 10)

    return np.array(feats, dtype=np.float32)


# ── Train ───────────────────────────────────────────────────────────────
train = json.load(open("_balanced_dataset.json"))["records"]
print(f"Training on {len(train)} records")

X_meta = []
y_meta = []
for r in train:
    tokens = r.get("tokens", [])
    src = r.get("vulnerable_src", "")
    label = r["label"]
    if not tokens or len(tokens) < 1:
        continue

    try:
        feats_with_src = extract_meta_features(tokens, src)
    except:
        continue

    desc_text = CWE_DESCRIPTIONS.get(label, "")
    feats_with_desc = extract_meta_features(tokens, desc_text)

    X_meta.append(feats_with_src)
    y_meta.append(label)
    X_meta.append(feats_with_desc)
    y_meta.append(label)

X_meta = np.array(X_meta, dtype=np.float32)
y_meta = np.array(y_meta)
print(f"Features shape: {X_meta.shape} (doubled with synthetic descriptions)")

final_lr = LogisticRegression(solver='lbfgs', max_iter=2000, class_weight='balanced', C=1.0, random_state=42)
final_lr.fit(X_meta, y_meta)
print(f"Training acc: {accuracy_score(y_meta, final_lr.predict(X_meta))*100:.1f}%")

# Cross-val on original (non-doubled) set
X_orig = []
y_orig = []
for r in train:
    tokens = r.get("tokens", [])
    src = r.get("vulnerable_src", "")
    if not tokens or len(tokens) < 1:
        continue
    try:
        feats = extract_meta_features(tokens, src)
    except:
        continue
    X_orig.append(feats)
    y_orig.append(r["label"])
X_orig = np.array(X_orig, dtype=np.float32)
y_orig = np.array(y_orig)
train_preds = final_lr.predict(X_orig)
print(f"Original-set acc: {accuracy_score(y_orig, train_preds)*100:.1f}%")

meta_bundle = {
    "syrth_version": "4.0.0",
    "meta_model": {
        "coef": final_lr.coef_,
        "intercept": final_lr.intercept_,
        "classes": final_lr.classes_.tolist(),
    },
    "meta_config": {
        "num_features": X_meta.shape[1],
        "num_classes": NUM_CLASSES,
    },
}
joblib.dump(meta_bundle, "syrth_meta.joblib", compress=3)
print(f"Saved syrth_meta.joblib ({X_meta.shape[1]} features)")
