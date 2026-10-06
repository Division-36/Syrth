"""
Synthetic benchmark dataset
===========================
Deterministic generator of vulnerable / clean Python snippets across the
15 CWE classes, plus a parallel "hard" set with evasion patterns
(parameterised queries, escaping, authentication decorators).

Ground truth is a per-sample dict: ``code``, ``label`` (0/1), ``cwe``.
"""

from __future__ import annotations

import random

# --- vulnerable templates: (code, cwe) ---------------------------------------
# {u} = user-controlled variable name (request-derived), {x} = target name
_VULN_TEMPLATES: list[tuple[str, str]] = [
    # CWE-89 SQLi
    ("""def get_user(request):
    {x} = request.GET.get('id')
    cursor.execute("SELECT * FROM users WHERE id = '" + {x} + "'")
    return cursor.fetchall()
""", "CWE-89"),
    ("""def login(request):
    {x} = request.form['username']
    db.execute("SELECT * FROM accounts WHERE user = '" + {x} + "'")
""", "CWE-89"),
    # CWE-79 XSS
    ("""def profile(request):
    {x} = request.args.get('name')
    return render_template_string("<h1>Hello " + {x} + "</h1>")
""", "CWE-79"),
    ("""def view(request):
    {x} = request.POST['comment']
    return mark_safe("{x}") if False else HttpResponse({x})
""", "CWE-79"),
    # CWE-22 path traversal
    ("""def download(request):
    {x} = request.GET.get('file')
    return send_file(os.path.join(UPLOAD_DIR, {x}))
""", "CWE-22"),
    ("""def read_file(request):
    {x} = request.args['path']
    with open({x}) as f:
        return f.read()
""", "CWE-22"),
    # CWE-601 open redirect
    ("""def redirect_view(request):
    {x} = request.GET.get('next')
    return redirect({x})
""", "CWE-601"),
    ("""def go(request):
    {x} = request.values['url']
    return HttpResponseRedirect({x})
""", "CWE-601"),
    # CWE-94 RCE
    ("""def run(request):
    {x} = request.form['cmd']
    os.system({x})
    return {x}
""", "CWE-94"),
    ("""def exec_code(request):
    {x} = request.POST['payload']
    eval({x})
""", "CWE-94"),
    # CWE-502 deserialization
    ("""def load_obj(request):
    {x} = request.files['data'].read()
    return pickle.loads({x})
""", "CWE-502"),
    ("""def parse(request):
    {x} = request.data
    return yaml.load({x})
""", "CWE-502"),
    # CWE-798 hardcoded credentials
    ("""def connect():
    return mysql.connect(host="db", user="admin", password="P@ssw0rd123")
""", "CWE-798"),
    # CWE-918 SSRF
    ("""def fetch(request):
    {x} = request.GET.get('url')
    return requests.get({x})
""", "CWE-918"),
    ("""def proxy(request):
    {x} = request.args['target']
    import urllib.request
    return urllib.request.urlopen({x}).read()
""", "CWE-918"),
    # CWE-434 unrestricted upload
    ("""def upload(request):
    {x} = request.files['file']
    {x}.save(os.path.join(UPLOAD_DIR, {x}.filename))
    return "ok"
""", "CWE-434"),
    # CWE-611 XXE
    ("""def parse_xml(request):
    {x} = request.data
    tree = etree.fromstring({x})
    return tree.tag
""", "CWE-611"),
]

# --- safe (clean) templates --------------------------------------------------
_SAFE_TEMPLATES: list[tuple[str, str]] = [
    ("""def get_user(request):
    {x} = request.GET.get('id')
    row = cursor.execute("SELECT * FROM users WHERE id = ?", ({x},))
    return row
""", "CWE-89"),
    ("""def profile(request):
    {x} = request.args.get('name')
    return render_template("profile.html", name=escape({x}))
""", "CWE-79"),
    ("""def download(request):
    {x} = request.GET.get('file')
    safe = os.path.basename({x})
    return send_from_directory(UPLOAD_DIR, safe)
""", "CWE-22"),
    ("""@login_required
def run(request):
    {x} = request.form['cmd']
    return subprocess.run(shlex.split({x}))
""", "CWE-94"),
    ("""def add(a, b):
    return a + b
""", None),
    ("""def greet(name):
    return "Hello, " + name.title() + "!"
""", None),
    ("""class Calculator:
    def __init__(self):
        self.total = 0

    def add(self, value):
        self.total += value
        return self.total
""", None),
]


def _make_sample(template: str, rng: random.Random) -> str:
    u = rng.choice(["uid", "payload", "q", "item", "data", "arg"])
    x = rng.choice(["val", "value", "content", "target", "entry"])
    return template.format(u=u, x=x)


def generate_dataset(
    n_vulnerable: int = 120,
    n_clean: int = 80,
    seed: int = 42,
) -> list[dict]:
    """
    Generate a deterministic benchmark dataset.

    Args:
        n_vulnerable: number of vulnerable samples
        n_clean: number of clean samples
        seed: RNG seed for reproducible samples

    Returns:
        list of dicts: {code, label, cwe, kind}
    """
    rng = random.Random(seed)
    samples: list[dict] = []

    for i in range(n_vulnerable):
        template, cwe = _VULN_TEMPLATES[i % len(_VULN_TEMPLATES)]
        samples.append({
            "id": f"vuln-{i}",
            "code": _make_sample(template, rng),
            "label": 1,
            "cwe": cwe,
            "kind": "vulnerable",
        })

    for i in range(n_clean):
        template, cwe = _SAFE_TEMPLATES[i % len(_SAFE_TEMPLATES)]
        samples.append({
            "id": f"clean-{i}",
            "code": _make_sample(template, rng),
            "label": 0,
            "cwe": cwe,
            "kind": "clean",
        })

    return samples


def generate_file_pairs(
    n_files: int = 200,
    functions_per_file: int = 3,
    seed: int = 1,
) -> list[dict]:
    """
    Generate realistic multi-function files for latency benchmarking.

    Returns:
        list of dicts: {id, code}
    """
    rng = random.Random(seed)
    files: list[dict] = []
    for i in range(n_files):
        funcs: list[str] = []
        for j in range(functions_per_file):
            if rng.random() < 0.5:
                template, _ = _VULN_TEMPLATES[(i + j) % len(_VULN_TEMPLATES)]
            else:
                template, _ = _SAFE_TEMPLATES[(i + j) % len(_SAFE_TEMPLATES)]
            funcs.append(_make_sample(template, rng))
        files.append({
            "id": f"file-{i}",
            "code": "\n".join(funcs),
        })
    return files


if __name__ == "__main__":
    data = generate_dataset(20, 10)
    print(f"generated {len(data)} samples; "
          f"{sum(s['label'] for s in data)} vulnerable")
