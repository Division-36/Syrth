"""
Meta-learner v10: context-aware features from call: tokens + expanded taint rule.
The key insight: cursor.execute (SQLi) vs subprocess.run (RCE) vs os.path.join (PT)
are all collapsed to sink:exec by SCypher, but the call: tokens preserve this context.
"""
import json, sys, re, torch, joblib, numpy as np
from pathlib import Path
from collections import Counter
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
sys.path.insert(0, str(Path(__file__).parent))
import train_model as T
from _eval_ensemble import predict_ensemble, TOK, UNK, ensemble
from _rules import classify_by_rules

NUM_CLASSES = 5
CODE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)

RCE_SINKS = frozenset({"os.system","subprocess.run","subprocess.call","subprocess.Popen","subprocess.getoutput","subprocess.getstatusoutput","popen","os.popen","os.execv","os.execl","os.execve","os.execvp","os.execvpe","eval","exec","compile","__import__","pickle.loads","pickle.load","cPickle.loads","yaml.load","yaml.full_load","yaml.unsafe_load","marshal.loads","marshal.load","jsonpickle.decode","numpy.load","torch.load"})
SQL_SINKS = frozenset({"execute","executemany","raw","RawSQL","extra","cursor.execute","connection.execute","Model.objects.raw"})
FILE_SINKS = frozenset({"open","io.open","codecs.open","os.path.join","os.path.abspath","shutil.copy","shutil.move","shutil.rmtree","os.remove","os.unlink","send_file","send_from_directory","FileResponse","os.makedirs"})
XSS_SINKS = frozenset({"render","render_to_string","render_to_response","mark_safe","SafeString","render_template","render_template_string","make_response","Response","HttpResponse","JsonResponse","jsonify","HTMLResponse","TemplateResponse","format_html","autoescape_off"})
REDIRECT_SINKS = frozenset({"redirect","HttpResponseRedirect","HttpResponsePermanentRedirect","RedirectResponse"})
SQL_TEXT_PATTERNS = [re.compile(r'\bSELECT\b.*\bFROM\b',re.I),re.compile(r'\bINSERT\b.*\bINTO\b',re.I),re.compile(r'\bUPDATE\b.*\bSET\b',re.I),re.compile(r'\bDELETE\b.*\bFROM\b',re.I),re.compile(r'\bUNION\b.*\bSELECT\b',re.I),re.compile(r'\bDROP\b.*\bTABLE\b',re.I),re.compile(r'cursor\.execute|\.execute\(.*["\']SELECT',re.I),re.compile(r'\.raw\(|\.extra\(|\.objects\.raw',re.I),re.compile(r'OR\s+1\s*=\s*1|OR\s+\'\w+\'\s*=\s*\'',re.I),re.compile(r'f"[^"]*\bSELECT\b|f\'[^\']*\bSELECT\b',re.I),re.compile(r'"SELECT\b.*\{|\bSELECT\b.*\+\s*\w',re.I)]
RCE_TEXT_PATTERNS = [re.compile(r'\bpickle\.\w*loads?\b|cPickle\.loads'),re.compile(r'\byaml\.unsafe_load\b|\byaml\.load\b'),re.compile(r'\btorch\.load\b|\bnumpy\.load\b.*allow_pickle'),re.compile(r'\bos\.system\b|\bos\.popen\b'),re.compile(r'\bsubprocess\.\w+\(.*shell\s*=\s*True'),re.compile(r'\bexec\s*\(|\beval\s*\(|\bcompile\s*\('),re.compile(r'\b__import__\s*\('),re.compile(r'\bmarshal\.loads?\b'),re.compile(r'os\.system\(|subprocess\.run\(|subprocess\.call\(|subprocess\.Popen\(')]
PT_TEXT_PATTERNS = [re.compile(r'\.\./|\.\.\\'),re.compile(r'os\.path\.join.*\+|os\.path\.join.*format'),re.compile(r'open\(.*\+|open\(.*format'),re.compile(r'Path\([^)]*\)\s*/'),re.compile(r'send_file\(|send_from_directory\('),re.compile(r'is_path_traversal|path_traversal'),re.compile(r'extractall\(|\.write_bytes\(.*read')]
XSS_TEXT_PATTERNS = [re.compile(r'<script|javascript:',re.I),re.compile(r'document\.write|innerHTML|outerHTML'),re.compile(r'mark_safe|SafeString|autoescape.*False'),re.compile(r'<[^>]*\{[^}]*\}',re.I),re.compile(r'render_template[^_]|render_to_string')]
OR_TEXT_PATTERNS = [re.compile(r'redirect\(|HttpResponseRedirect|HttpResponsePermanentRedirect'),re.compile(r'RedirectResponse|return.*redirect',re.I),re.compile(r'Location:',re.I),re.compile(r'next_url|return_url|callback_url|target_url')]
CWE_DESCRIPTIONS = {
    0: "SQL injection CWE-89 SQL injection vulnerability in database query parameterized query",
    1: "cross-site scripting XSS CWE-79 reflected stored DOM scripting injection HTML template rendering",
    2: "path traversal directory traversal CWE-22 file inclusion local file read arbitrary file access path",
    3: "open redirect CWE-601 URL redirect validation external link navigation",
    4: "remote code execution arbitrary command injection CWE-94 code injection eval exec subprocess deserialization pickle yaml unsafe load",
}

# ============================================================
# Expanded taint sinks — more class-specific sinks
# ============================================================
SQL_TAINT_SINKS = frozenset({"execute", "cursor.execute", "raw", "extra", "executemany",
                              "Model.objects.raw", "connection.execute", "engine.execute",
                              "session.execute", "orm.execute", "db.execute"})
XSS_TAINT_SINKS = frozenset({"render", "HttpResponse", "mark_safe", "render_template",
                              "render_template_string", "render_to_string", "format_html",
                              "autoescape_off", "SafeString", "make_response", "Response",
                              "HtmlResponse", "TemplateResponse"})
PT_TAINT_SINKS = frozenset({"open", "send_file", "send_from_directory", "os.path.join",
                             "shutil.copy", "shutil.move", "os.remove", "os.unlink",
                             "os.makedirs", "FileResponse"})
OR_TAINT_SINKS = frozenset({"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
                             "RedirectResponse"})
RCE_TAINT_SINKS = frozenset({"os.system", "subprocess.run", "subprocess.Popen", "eval", "exec",
                              "popen", "os.popen", "__import__", "compile", "pickle.loads",
                              "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads",
                              "subprocess.call", "subprocess.getoutput", "execfile"})


def extract_text_features(source_code):
    feats = []
    sql_m = sum(1 for p in SQL_TEXT_PATTERNS if p.search(source_code))
    rce_m = sum(1 for p in RCE_TEXT_PATTERNS if p.search(source_code))
    pt_m = sum(1 for p in PT_TEXT_PATTERNS if p.search(source_code))
    xss_m = sum(1 for p in XSS_TEXT_PATTERNS if p.search(source_code))
    or_m = sum(1 for p in OR_TEXT_PATTERNS if p.search(source_code))
    feats.append(min(sql_m/3.0,1.0));feats.append(min(rce_m/3.0,1.0));feats.append(min(pt_m/3.0,1.0));feats.append(min(xss_m/3.0,1.0));feats.append(min(or_m/3.0,1.0))
    total = sql_m+rce_m+pt_m+xss_m+or_m;feats.append(min(total/5.0,1.0))
    feats.append(1.0 if re.search(r'["\']SELECT\b|["\']INSERT\b|["\']UPDATE\b|["\']DELETE\b',source_code,re.I) else 0.0)
    feats.append(1.0 if re.search(r'pickle\.|yaml\.(unsafe_)?load|torch\.load|marshal\.',source_code) else 0.0)
    feats.append(1.0 if re.search(r'\bexec\s*\(|\beval\s*\(',source_code) else 0.0)
    feats.append(1.0 if re.search(r'shell\s*=\s*True',source_code) else 0.0)
    return feats


# ============================================================
# Context-aware features: distinguish call patterns
# ============================================================
SQL_CALL_KEYWORDS = frozenset(["cursor.execute", "db.execute", "connection.execute",
                                "engine.execute", "session.execute", "orm.execute",
                                "cur.execute", "conn.execute", "sqlite3.connect",
                                "Model.objects.raw", "User.objects.raw",
                                "cursor.fetchall", "connection.cursor", "conn.cursor"])
RCE_CALL_KEYWORDS = frozenset(["subprocess.run", "subprocess.call", "subprocess.Popen",
                                "subprocess.check_output", "subprocess.check_call",
                                "os.system", "os.popen", "os.exec", "eval", "exec",
                                "compile", "__import__", "exec_module", "evaljs",
                                "popen", "WinExecGetter", "system.get"])
PT_CALL_KEYWORDS = frozenset(["os.path.join", "os.path.realpath", "os.path.normpath",
                               "os.path.expanduser", "os.path.commonpath", "os.path.split",
                               "os.listdir", "os.getcwd", "tar.extractall", "tar.getmembers",
                               "zipfile.ZipFile.extractall", "send_file", "send_from_directory",
                               "gzip.open", "shutil.copy", "shutil.move", "FileNotFoundError"])
XSS_CALL_KEYWORDS = frozenset(["HttpResponse", "mark_safe", "format_html",
                                "render_template_string", "render_to_string",
                                "template.render", "ctx.render", "response.write",
                                "out.write", "escape", "HtmlResponse"])
REDIR_CALL_KEYWORDS = frozenset(["redirect", "HttpResponseRedirect", "RedirectResponse",
                                  "HttpResponsePermanentRedirect"])


def _count_call_pattern(tokens, keywords):
    """Count call: tokens matching a set of keywords."""
    count = 0
    for t in tokens:
        if t.startswith("call:"):
            callee = t[5:].lower()
            for kw in keywords:
                if kw.lower() in callee:
                    count += 1
                    break
    return count


def extract_meta_features_full(tokens, source_code=None):
    """Extract features with context-aware call patterns."""
    seq_ids = [TOK.vocab.get(t, 1) for t in tokens]
    pred, conf, votes = predict_ensemble(tokens, seq_ids)
    rule_result = classify_by_rules(tokens)
    rule_class = rule_result.predicted_class
    rule_conf = rule_result.confidence
    rule_votes_total = rule_result.votes.total()
    has_taint = any(t.startswith("tainted:") for t in tokens)
    token_set = set(tokens); token_list = tokens; n_tokens = max(len(tokens), 1)

    rce_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in RCE_SINKS)
    sql_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in SQL_SINKS)
    file_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in FILE_SINKS)
    xss_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in XSS_SINKS)
    redir_sinks = sum(1 for t in tokens if t.startswith("sink:") and t[5:] in REDIRECT_SINKS)
    deser_sinks = sum(1 for t in tokens if t.startswith("sink:") and any(x in t for x in ["pickle","yaml","marshal","torch.load","numpy.load"]))
    sink_count = sum(1 for t in tokens if t.startswith("sink:"))
    call_count = sum(1 for t in tokens if t.startswith("call:"))
    tainted_count = sum(1 for t in tokens if t.startswith("tainted:"))

    all_feats = []
    # [0-4] Ensemble votes
    all_feats.extend(float(votes[i]) for i in range(NUM_CLASSES))
    # [5] Ensemble confidence
    all_feats.append(conf)
    # [6-10] Ensemble predicted (one-hot)
    all_feats.extend(1.0 if i == pred else 0.0 for i in range(NUM_CLASSES))
    # [11] Has taint
    all_feats.append(1.0 if has_taint else 0.0)
    # [12-18] Rule features (noisy, will be removed)
    all_feats.append(rule_conf)
    all_feats.append(min(rule_votes_total/10.0,1.0))
    if rule_votes_total > 0: all_feats.extend(1.0 if i == rule_class else 0.0 for i in range(NUM_CLASSES))
    else: all_feats.extend([0.0]*NUM_CLASSES)
    all_feats.append(1.0 if rule_votes_total > 0 else 0.0)
    # [19-25] Sink ratios (noisy, will be removed)
    all_feats.append(rce_sinks/n_tokens);all_feats.append(sql_sinks/n_tokens);all_feats.append(file_sinks/n_tokens)
    all_feats.append(xss_sinks/n_tokens);all_feats.append(redir_sinks/n_tokens);all_feats.append(deser_sinks/n_tokens)
    # [26-27] Sink/taint counts (noisy, will be removed)
    all_feats.append(min(sink_count/5.0,1.0));all_feats.append(min(tainted_count/3.0,1.0))
    # [28] Has deserialization
    all_feats.append(1.0 if deser_sinks > 0 else 0.0)
    # [29-33] Has exec/file/sql/render/redirect + token_count + call_count
    has_exec = any(t in ("sink:os.system","sink:subprocess.run","sink:subprocess.call","sink:subprocess.Popen","sink:eval","sink:exec","sink:compile","sink:__import__","sink:execfile") for t in tokens)
    all_feats.append(1.0 if has_exec else 0.0)
    has_file = any(t in ("sink:open","sink:io.open","sink:codecs.open","sink:os.path.join","sink:os.path.abspath","sink:shutil.copy","sink:shutil.move","sink:os.remove","sink:os.makedirs","sink:send_file","sink:send_from_directory") for t in tokens)
    all_feats.append(1.0 if has_file else 0.0)
    has_sql = any(t in ("sink:execute","sink:executemany","sink:raw","sink:RawSQL","sink:extra","sink:cursor.execute","sink:connection.execute","sink:Model.objects.raw") for t in tokens)
    all_feats.append(1.0 if has_sql else 0.0)
    has_render = any(t in ("sink:render","sink:render_to_string","sink:render_template","sink:render_template_string","sink:mark_safe","sink:SafeString","sink:make_response","sink:Response","sink:HttpResponse","sink:format_html","sink:autoescape_off") for t in tokens)
    all_feats.append(1.0 if has_render else 0.0)
    has_redirect = any(t in ("sink:redirect","sink:HttpResponseRedirect","sink:HttpResponsePermanentRedirect","sink:RedirectResponse") for t in tokens)
    all_feats.append(1.0 if has_redirect else 0.0)
    all_feats.append(min(np.log1p(n_tokens)/5.0,1.0))
    all_feats.append(min(call_count/10.0,1.0))
    all_feats.append(1.0 if "meta:no_auth" in token_set else 0.0)
    all_feats.append(min((rce_sinks+deser_sinks)/3.0,1.0))
    all_feats.append(1.0 if any(t.startswith("SCAT:") for t in tokens) else 0.0)

    # Text features [39-48]
    if source_code: all_feats.extend(extract_text_features(source_code))
    else: all_feats.extend([0.0]*10)

    # ============================================================
    # v10 NEW: Context-aware call pattern features
    # These distinguish cursor.execute (SQLi) from subprocess.run (RCE)
    # ============================================================

    # [49-53] Argument name pattern features (from v5)
    arg_tokens = [t for t in tokens if t.startswith("arg:")]
    arg_names = set(t[4:].lower() for t in arg_tokens)
    all_feats.append(1.0 if any(a in arg_names for a in ["db","query","database","table","sql","cursor","connection"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["path","file","dir","folder","filename","filepath","<file_path>"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["html","template","content","render","response","text"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["url","redirect","next","callback","target","return_url","<url_param>"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["cmd","command","exec","code","payload","<secret>"]) else 0.0)

    # [54-58] Specific call pattern features (from v5)
    sqli_calls = any(tk.startswith("call:") and any(x in tk[5:].lower() for x in ["select","where","filter","query","execute"]) for tk in token_list)
    all_feats.append(1.0 if sqli_calls else 0.0)
    xss_calls = any(any(x in tk.lstrip("@").lower() for x in ["app.get","app.post","render","response","mark_safe","format_html"]) for tk in token_list if tk.startswith("call:") or tk.startswith("@"))
    all_feats.append(1.0 if xss_calls else 0.0)
    pt_calls = any(tk.startswith("call:") and any(x in tk[5:].lower() for x in ["os.path","path(","open(","isfile","isdir","exists"]) for tk in token_list)
    all_feats.append(1.0 if pt_calls else 0.0)
    or_calls = any(tk.startswith("call:") and any(x in tk[5:].lower() for x in ["redirect","httpurlredirect","location"]) for tk in token_list)
    all_feats.append(1.0 if or_calls else 0.0)
    rce_calls = any((tk.startswith("def:") and tk[4:].lower() in ("__reduce__","__reduce_ex__","__getstate__","__setstate__")) or (tk.startswith("call:") and any(x in tk[5:].lower() for x in ["pickle","yaml.load","marshal","torch.load"])) for tk in token_list)
    all_feats.append(1.0 if rce_calls else 0.0)

    # [59-63] Decorator features (from v5)
    all_feats.append(1.0 if any(tk.startswith("@app.get") or tk=="call:app.get" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk.startswith("@app.post") or tk=="call:app.post" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk.startswith("@") and ("route" in tk or "get" in tk or "post" in tk) for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk=="decorator:@property" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk=="decorator:@staticmethod" for tk in token_list) else 0.0)

    # [64-68] Argument name count ratios (from v5)
    n_args = max(len(arg_tokens),1)
    all_feats.append(min(sum(1 for a in arg_names if "sql" in a or "db" in a or "query" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "path" in a or "file" in a or "dir" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "html" in a or "template" in a or "render" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "url" in a or "redirect" in a or "next" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "cmd" in a or "exec" in a or "code" in a)/n_args,1.0))

    # ============================================================
    # v10 NEW: Context-aware call pattern counts
    # ============================================================
    sql_call_count = _count_call_pattern(tokens, SQL_CALL_KEYWORDS)
    rce_call_count = _count_call_pattern(tokens, RCE_CALL_KEYWORDS)
    pt_call_count = _count_call_pattern(tokens, PT_CALL_KEYWORDS)
    xss_call_count = _count_call_pattern(tokens, XSS_CALL_KEYWORDS)
    redir_call_count = _count_call_pattern(tokens, REDIR_CALL_KEYWORDS)

    # [69-73] Call pattern counts (normalized)
    all_feats.append(min(sql_call_count / 3.0, 1.0))
    all_feats.append(min(rce_call_count / 3.0, 1.0))
    all_feats.append(min(pt_call_count / 3.0, 1.0))
    all_feats.append(min(xss_call_count / 3.0, 1.0))
    all_feats.append(min(redir_call_count / 3.0, 1.0))

    # [74-78] Call pattern presence
    all_feats.append(1.0 if sql_call_count > 0 else 0.0)
    all_feats.append(1.0 if rce_call_count > 0 else 0.0)
    all_feats.append(1.0 if pt_call_count > 0 else 0.0)
    all_feats.append(1.0 if xss_call_count > 0 else 0.0)
    all_feats.append(1.0 if redir_call_count > 0 else 0.0)

    # [79] Dominant call pattern (which class has most calls)
    call_counts = [sql_call_count, 0, pt_call_count, redir_call_count, rce_call_count]
    # XSS is tricky — use a broader check
    xss_broad = sum(1 for t in tokens if t.startswith("call:") and
                    any(x in t[5:].lower() for x in ["httpresponse", "mark_safe", "render", "template", "response.write", "out.write", "escape"]))
    call_counts[1] = xss_broad
    dominant = max(range(5), key=lambda i: call_counts[i])
    all_feats.append(dominant / 4.0)

    # [80] Has DB-specific call (cursor.execute, db.execute, etc.)
    all_feats.append(1.0 if sql_call_count > 0 else 0.0)
    # [81] Has OS-level exec (subprocess, os.system, eval, exec)
    all_feats.append(1.0 if rce_call_count > 0 else 0.0)
    # [82] Has file path manipulation (os.path.*, send_file, etc.)
    all_feats.append(1.0 if pt_call_count > 0 else 0.0)

    all_feats = np.array(all_feats, dtype=np.float32)

    # Remove noisy features (rule_feats 12-18, sink_ratios 19-25, sink_taint_count 26-27)
    keep = list(range(0, 12)) + list(range(28, len(all_feats)))
    return all_feats[keep]


def predict_meta_expanded_taint(taint_hits, tokens, full_desc, src):
    """Level 1: expanded taint rule. Level 2: meta-learner."""
    # Level 1: Taint
    if taint_hits:
        return Counter(taint_hits).most_common(1)[0][0], 0.90

    # Level 2: Meta-learner ensemble (average predictions)
    context = full_desc or src
    feats = extract_meta_features_full(tokens, source_code=context)
    if len(meta_models) > 1:
        all_probas = []
        for mm in meta_models:
            all_probas.append(mm.predict_proba(feats.reshape(1, -1))[0])
        avg_proba = np.mean(all_probas, axis=0)
        pred = int(np.argmax(avg_proba))
        conf = float(avg_proba[pred])
    else:
        proba = meta_models[0].predict_proba(feats.reshape(1, -1))[0]
        pred = int(np.argmax(proba))
        conf = float(proba[pred])
    return pred, conf


def main():
    train = json.load(open("_balanced_dataset.json"))["records"]
    print(f"Building features for {len(train)} records...")

    X_all = []
    y_all = []
    skipped = 0
    for r in train:
        tokens = r.get("tokens", [])
        src = r.get("vulnerable_src", "")
        label = r["label"]
        if not tokens or len(tokens) < 1:
            skipped += 1
            continue
        desc_text = CWE_DESCRIPTIONS.get(label, "")
        try:
            feats_src = extract_meta_features_full(tokens, src)
            feats_desc = extract_meta_features_full(tokens, desc_text)
        except:
            skipped += 1
            continue
        X_all.append(feats_src); y_all.append(label)
        X_all.append(feats_desc); y_all.append(label)

    X_all = np.array(X_all, dtype=np.float32)
    y_all = np.array(y_all)
    print(f"Features: {X_all.shape} (v10: context-aware call patterns)")
    print(f"Skipped: {skipped}")

    # Train ensemble of LRs
    c_values = [0.1, 0.3, 0.5, 1.0, 2.0, 5.0, 10.0]
    meta_models_train = []
    for c in c_values:
        lr = LogisticRegression(solver='lbfgs', max_iter=2000, class_weight='balanced', C=c, random_state=42)
        lr.fit(X_all, y_all)
        meta_models_train.append(lr)
        print(f"  C={c}: train_acc={accuracy_score(y_all, lr.predict(X_all))*100:.1f}%")

    meta_bundle = {
        "syrth_version": "10.0.0",
        "meta_models": [],
        "meta_config": {
            "num_features": X_all.shape[1],
            "num_classes": NUM_CLASSES,
        },
    }
    for m in meta_models_train:
        meta_bundle["meta_models"].append({
            "coef": m.coef_,
            "intercept": m.intercept_,
            "classes": m.classes_.tolist(),
            "C": m.C,
        })

    joblib.dump(meta_bundle, "syrth_meta.joblib", compress=3)
    print(f"\nSaved {len(meta_models_train)} meta-learner models ({X_all.shape[1]} features)")


if __name__ == "__main__":
    main()
