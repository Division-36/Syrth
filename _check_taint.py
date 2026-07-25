"""Check if expanded taint rule catches more blocks."""
import json, sys, numpy as np
from collections import Counter
sys.path.insert(0, '.')
import collect
import _rules
from _eval_ensemble import predict_ensemble, TOK, ensemble

with open('_full_dataset_5class.json') as f:
    raw = json.load(f)
data = raw['records']

# Old taint rule
old_taint_sinks = {
    0: {"execute", "cursor.execute", "raw", "extra"},
    1: {"render", "HttpResponse", "mark_safe", "render_template"},
    2: {"open", "send_file"},
    3: {"redirect", "HttpResponseRedirect", "RedirectResponse"},
    4: {"os.system", "subprocess.run", "subprocess.Popen", "eval", "exec", "popen"},
}

# Expanded taint rule
new_taint_sinks = {
    0: {"execute", "cursor.execute", "raw", "extra", "executemany",
        "Model.objects.raw", "connection.execute", "engine.execute",
        "session.execute", "orm.execute", "db.execute"},
    1: {"render", "HttpResponse", "mark_safe", "render_template",
        "render_template_string", "render_to_string", "format_html",
        "autoescape_off", "SafeString", "make_response", "Response"},
    2: {"open", "send_file", "send_from_directory", "os.path.join",
        "shutil.copy", "shutil.move", "os.remove", "os.makedirs", "FileResponse"},
    3: {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"},
    4: {"os.system", "subprocess.run", "subprocess.Popen", "eval", "exec",
        "popen", "os.popen", "__import__", "compile", "pickle.loads",
        "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads",
        "subprocess.call"},
}

def count_taint_hits(data, taint_sinks):
    old_hits = 0
    new_hits = 0
    old_correct = 0
    new_correct = 0
    new_only_hits = 0
    new_only_correct = 0
    
    for r in data:
        src = r.get('vulnerable_src', '')
        if not src:
            continue
        try:
            ft = collect.extract_traces_from_source(src, label='x')
        except:
            continue
        seq = []
        taint_hits_old = []
        taint_hits_new = []
        for fn in ft.functions:
            s = fn.to_token_sequence()
            if s:
                seq.extend(s)
                for t in s:
                    if t.startswith("tainted:"):
                        sink_name = t.split(":", 1)[1]
                        if sink_name in old_taint_sinks.get(r['label'], set()):
                            taint_hits_old.append(r['label'])
                        if sink_name in new_taint_sinks.get(r['label'], set()):
                            taint_hits_new.append(r['label'])
        
        if taint_hits_old:
            old_hits += 1
            pred = Counter(taint_hits_old).most_common(1)[0][0]
            if pred == r['label']:
                old_correct += 1
        if taint_hits_new:
            new_hits += 1
            pred = Counter(taint_hits_new).most_common(1)[0][0]
            if pred == r['label']:
                new_correct += 1
        if taint_hits_new and not taint_hits_old:
            new_only_hits += 1
            pred = Counter(taint_hits_new).most_common(1)[0][0]
            if pred == r['label']:
                new_only_correct += 1
    
    return old_hits, old_correct, new_hits, new_correct, new_only_hits, new_only_correct

old_h, old_c, new_h, new_c, new_only_h, new_only_c = count_taint_hits(data, new_taint_sinks)
print(f'Old taint rule: {old_h} hits, {old_c} correct')
print(f'New taint rule: {new_h} hits, {new_c} correct')
print(f'New-only taint hits: {new_only_h} (additional), {new_only_c} correct')
print(f'Taint improvement: +{new_h - old_h} hits, +{new_c - old_c} correct')
