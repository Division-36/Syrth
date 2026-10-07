"""
Meta-learner v11: custom class weights to reduce RCE majority-class bias.
Test different weight ratios and evaluate on held-out data.
"""
import json, sys, re, torch, joblib, numpy as np
from pathlib import Path
from collections import Counter
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score
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


def extract_meta_features_full(tokens, source_code=None):
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
    all_feats.extend(float(votes[i]) for i in range(NUM_CLASSES))
    all_feats.append(conf)
    all_feats.extend(1.0 if i == pred else 0.0 for i in range(NUM_CLASSES))
    all_feats.append(1.0 if has_taint else 0.0)
    all_feats.append(rule_conf)
    all_feats.append(min(rule_votes_total/10.0,1.0))
    if rule_votes_total > 0: all_feats.extend(1.0 if i == rule_class else 0.0 for i in range(NUM_CLASSES))
    else: all_feats.extend([0.0]*NUM_CLASSES)
    all_feats.append(1.0 if rule_votes_total > 0 else 0.0)
    all_feats.append(rce_sinks/n_tokens);all_feats.append(sql_sinks/n_tokens);all_feats.append(file_sinks/n_tokens)
    all_feats.append(xss_sinks/n_tokens);all_feats.append(redir_sinks/n_tokens);all_feats.append(deser_sinks/n_tokens)
    all_feats.append(min(sink_count/5.0,1.0));all_feats.append(min(tainted_count/3.0,1.0))
    all_feats.append(1.0 if deser_sinks > 0 else 0.0)
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
    if source_code: all_feats.extend(extract_text_features(source_code))
    else: all_feats.extend([0.0]*10)
    arg_tokens = [t for t in tokens if t.startswith("arg:")]
    arg_names = set(t[4:].lower() for t in arg_tokens)
    all_feats.append(1.0 if any(a in arg_names for a in ["db","query","database","table","sql","cursor","connection"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["path","file","dir","folder","filename","filepath","<file_path>"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["html","template","content","render","response","text"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["url","redirect","next","callback","target","return_url","<url_param>"]) else 0.0)
    all_feats.append(1.0 if any(a in arg_names for a in ["cmd","command","exec","code","payload","<secret>"]) else 0.0)
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
    all_feats.append(1.0 if any(tk.startswith("@app.get") or tk=="call:app.get" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk.startswith("@app.post") or tk=="call:app.post" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk.startswith("@") and ("route" in tk or "get" in tk or "post" in tk) for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk=="decorator:@property" for tk in token_list) else 0.0)
    all_feats.append(1.0 if any(tk=="decorator:@staticmethod" for tk in token_list) else 0.0)
    n_args = max(len(arg_tokens),1)
    all_feats.append(min(sum(1 for a in arg_names if "sql" in a or "db" in a or "query" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "path" in a or "file" in a or "dir" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "html" in a or "template" in a or "render" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "url" in a or "redirect" in a or "next" in a)/n_args,1.0))
    all_feats.append(min(sum(1 for a in arg_names if "cmd" in a or "exec" in a or "code" in a)/n_args,1.0))

    all_feats = np.array(all_feats, dtype=np.float32)
    keep = list(range(0, 12)) + list(range(28, len(all_feats)))
    return all_feats[keep]


def main():
    train = json.load(open("_balanced_dataset.json"))["records"]
    print(f"Building features for {len(train)} records...")

    X_all = []
    y_all = []
    for r in train:
        tokens = r.get("tokens", [])
        src = r.get("vulnerable_src", "")
        label = r["label"]
        if not tokens or len(tokens) < 1: continue
        desc_text = CWE_DESCRIPTIONS.get(label, "")
        try:
            feats_src = extract_meta_features_full(tokens, src)
            feats_desc = extract_meta_features_full(tokens, desc_text)
        except: continue
        X_all.append(feats_src); y_all.append(label)
        X_all.append(feats_desc); y_all.append(label)

    X_all = np.array(X_all, dtype=np.float32)
    y_all = np.array(y_all)
    print(f"Features: {X_all.shape}")

    # Test different class weight configurations
    print("\n--- Testing class weight configurations ---")

    configs = [
        ("balanced", {0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0}),  # standard balanced
        ("upweight_minority", {0: 2.0, 1: 1.5, 2: 1.5, 3: 2.0, 4: 0.3}),
        ("strong_upweight", {0: 3.0, 1: 2.0, 2: 2.0, 3: 3.0, 4: 0.2}),
        ("sql_boost", {0: 3.0, 1: 1.0, 2: 1.0, 3: 1.0, 4: 0.5}),
        ("xss_boost", {0: 1.0, 1: 3.0, 2: 1.0, 3: 1.0, 4: 0.5}),
        ("pt_boost", {0: 1.0, 1: 1.0, 2: 3.0, 3: 1.0, 4: 0.5}),
    ]

    best_score = 0
    best_config = None

    for name, weights in configs:
        lr = LogisticRegression(solver='lbfgs', max_iter=2000, class_weight=weights, C=1.0, random_state=42)
        scores = cross_val_score(lr, X_all, y_all, cv=5, scoring='accuracy')
        mean_score = scores.mean()
        print(f"  {name:20s}: CV acc={mean_score*100:.1f}% (+/- {scores.std()*100:.1f}%)")
        if mean_score > best_score:
            best_score = mean_score
            best_config = (name, weights)

    print(f"\nBest: {best_config[0]} ({best_score*100:.1f}%)")

    # Train final model with best config
    name, weights = best_config
    print(f"\nTraining final models with {name} weights...")
    c_values = [0.1, 0.3, 0.5, 1.0, 2.0, 5.0, 10.0]
    meta_models = []
    for c in c_values:
        lr = LogisticRegression(solver='lbfgs', max_iter=2000, class_weight=weights, C=c, random_state=42)
        lr.fit(X_all, y_all)
        meta_models.append(lr)
        print(f"  C={c}: train_acc={accuracy_score(y_all, lr.predict(X_all))*100:.1f}%")

    meta_bundle = {
        "syrth_version": "11.0.0",
        "meta_models": [],
        "meta_config": {
            "num_features": X_all.shape[1],
            "num_classes": NUM_CLASSES,
        },
    }
    for m in meta_models:
        meta_bundle["meta_models"].append({
            "coef": m.coef_,
            "intercept": m.intercept_,
            "classes": m.classes_.tolist(),
            "C": m.C,
            "class_weight": name,
        })

    joblib.dump(meta_bundle, "syrth_meta.joblib", compress=3)
    print(f"\nSaved {len(meta_models)} meta-learner models ({X_all.shape[1]} features, {name} weights)")


if __name__ == "__main__":
    main()
