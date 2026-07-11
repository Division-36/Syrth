"""
SYRTH: Scan Your Risk Trace History
====================================
collect.py — AST-based logic trace extractor.

Exports required by harvester.py (DO NOT RENAME):
    diff_traces, extract_traces_from_source, normalise_token, SINK_REGISTRY

Token format matches training vocabulary:
    @decorator  def:name  arg:name  call:name  sink:canonical  ret:name
    framework:X  severity:X  (additional real-data signals, only when sinks found)

Usage:
    python collect.py --old-file vuln.py --new-file patched.py
    python collect.py --single-file target.py
"""

from __future__ import annotations

import ast
import argparse
import json
import sys
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# SINK_REGISTRY — frozenset of base sink names.
# ⚠ Imported by harvester.py for _tokenise_description(). Names must match
#   the sink token vocabulary in the training dataset.
# ---------------------------------------------------------------------------

SINK_REGISTRY: frozenset[str] = frozenset({
    # SQL execution
    "execute", "executemany", "raw", "RawSQL", "extra", "cursor.execute",
    "connection.execute", "Model.objects.raw",
    # OS / subprocess
    "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput", "popen", "os.popen",
    "commands.getoutput", "commands.getstatusoutput", "popen2", "popen3", "popen4",
    "os.execv", "os.execl", "os.execve", "os.execvp", "os.execvpe",
    # Code execution
    "eval", "exec", "compile", "execfile", "__import__", "os.system",
    # Template rendering / XSS
    "render", "render_to_string", "render_to_response", "mark_safe", "SafeString",
    "render_template", "render_template_string", "make_response", "Response",
    "HttpResponse", "JsonResponse", "jsonify", "HTMLResponse", "TemplateResponse",
    "format_html", "autoescape_off",
    # File system
    "open", "io.open", "codecs.open", "os.path.join", "os.path.abspath",
    "shutil.copy", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink",
    "send_file", "send_from_directory", "FileResponse", "os.makedirs",
    # Network / SSRF
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.request",
    "urllib.request.urlopen", "aiohttp.request", "urlopen", "socket.create_connection",
    # Redirect
    "redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
    "RedirectResponse", "return HttpResponseRedirect",
    # Deserialization
    "pickle.loads", "pickle.load", "cPickle.loads", "yaml.load", "yaml.full_load",
    "yaml.unsafe_load", "marshal.loads", "marshal.load", "jsonpickle.decode",
    "numpy.load", "torch.load",
    # Auth signals
    "is_authenticated", "has_perm", "get_object_or_404", "login", "authenticate",
})

# ---------------------------------------------------------------------------
# SINK_EXTENDED — additional call names that map to canonical training names.
# These are NOT in SINK_REGISTRY (so harvester text search won't pick them up)
# but are detected at AST inference time and emit the canonical sink token.
# ---------------------------------------------------------------------------

SINK_EXTENDED: dict[str, str] = {
    # Flask / Jinja rendering → "render"
    "render_template":              "render",
    "render_template_string":       "render",
    "make_response":                "render",
    "Response":                     "render",
    "HttpResponse":                 "render",
    "JsonResponse":                 "render",
    "jsonify":                      "render",
    "HTMLResponse":                 "render",
    "TemplateResponse":             "render",
    "format_html":                  "render",
    # Redirect variants → "redirect"
    "HttpResponsePermanentRedirect": "redirect",
    "RedirectResponse":             "redirect",
    # subprocess → "exec"
    "subprocess.check_output":      "exec",
    "subprocess.check_call":        "exec",
    "check_output":                 "exec",
    "check_call":                   "exec",
    # OS → "os.system"
    "os.execv":                     "os.system",
    "os.execve":                    "os.system",
    "os.popen":                     "os.system",
    "system":                       "os.system",
    # File → "open"
    "send_file":                    "open",
    "send_from_directory":          "open",
    "FileResponse":                 "open",
    # Network → "requests.get"
    "requests.put":                 "requests.get",
    "requests.delete":              "requests.get",
    "requests.patch":               "requests.get",
    "requests.head":                "requests.get",
    "requests.request":             "requests.get",
    "httpx.put":                    "httpx.get",
    "httpx.request":                "httpx.get",
    "urlopen":                      "urllib.request.urlopen",
    "aiohttp.request":              "requests.get",
    # Deserialization → canonical
    "pickle.load":                  "pickle.loads",
    "yaml.unsafe_load":             "yaml.load",
    "marshal.load":                 "marshal.loads",
    # Code exec → "exec"
    "execfile":                     "exec",
    "__import__":                   "exec",
}

# Framework detection from imports
_FRAMEWORK_MAP: list[tuple[str, str]] = [
    ("django",    "framework:django"),
    ("flask",     "framework:flask"),
    ("fastapi",   "framework:fastapi"),
    ("starlette", "framework:fastapi"),
    ("tornado",   "framework:fastapi"),
    ("aiohttp",   "framework:fastapi"),
    ("bottle",    "framework:flask"),
    ("falcon",    "framework:fastapi"),
]

# Auth-relevant decorators
SECURITY_DECORATORS: frozenset[str] = frozenset({
    "login_required", "permission_required", "staff_member_required",
    "superuser_required", "require_http_methods", "require_POST", "require_GET",
    "api_view", "permission_classes", "authentication_classes",
    "jwt_required", "token_required", "auth_required", "requires_auth",
    "authenticated", "Depends", "csrf_exempt",
})

# High-risk sinks → severity:high
_HIGH_RISK_SINKS: frozenset[str] = frozenset({
    "eval", "exec", "compile", "pickle.loads", "yaml.load", "marshal.loads",
    "os.system", "subprocess.Popen", "subprocess.run", "subprocess.call",
})

# ---------------------------------------------------------------------------
# Token normalisation
# ⚠ Imported by harvester.py as `normalise_token` — do not rename.
# ---------------------------------------------------------------------------

_TOKEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(user_?id|uid|user\.id|request\.user\.pk|user\.pk|owner_id|author_id|self\.user\.pk|self\.user\.id)\b"), "<USER_ID>"),
    (re.compile(r"\b(pk|object_id|obj_id|item_id|record_id|document_id|doc_id)\b"),           "<OBJ_ID>"),
    (re.compile(r"(self\.)?request\.(GET|POST|data|body|query_params|form|args|json|values|files|headers)"), "<REQUEST_INPUT>"),
    (re.compile(r"\b(req|request)\b"), "<REQUEST_INPUT>"),
    (re.compile(r"\b(self\.)?user\b"), "<USER_ID>"),
    (re.compile(r"\b(password|passwd|secret|token|api_key|auth_token|access_token|private_key|credential)\b"), "<SECRET>"),
    (re.compile(r"\b(file_?path|filepath|upload_?path|filename|file_name|directory|dir_path|path|upload_path)\b"), "<FILE_PATH>"),
    (re.compile(r"\b(url|redirect_url|next|callback_url|target|destination|href|location|return_url|next_url|redirect|url_path)\b"), "<URL_PARAM>"),
    (re.compile(r"\b(command|cmd|shell_cmd|exec_cmd|command_str)\b"), "<CMD>"),
    (re.compile(r"\b(query|sql|sql_query|raw_query|statement|sql_str)\b"), "<SQL>"),
    (re.compile(r"\"[^\"]{0,120}\"|'[^']{0,120}'"), "<STR_LITERAL>"),
    (re.compile(r"\b\d+\b"), "<INT_LITERAL>"),
]

# Normalised token values that represent user-controlled or sensitive inputs.
# Used to emit data-flow tokens (flow:<SOURCE>-><SINK>) in to_token_sequence().
_SOURCE_TOKEN_VALUES: frozenset[str] = frozenset({
    "<REQUEST_INPUT>", "<USER_ID>", "<OBJ_ID>", "<SECRET>",
    "<FILE_PATH>", "<URL_PARAM>", "<CMD>", "<SQL>",
})

_SQL_KEYWORDS: tuple[str, ...] = (
    "SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM",
    "DROP TABLE", "EXEC ", "EXECUTE ", "UNION SELECT", "OR 1=1",
)


def normalise_token(name: str) -> str:
    """
    Apply token-normalisation patterns to a raw identifier string.
    ⚠ Imported by harvester.py — do not rename.
    """
    for pattern, replacement in _TOKEN_PATTERNS:
        name = pattern.sub(replacement, name)
    return name


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionTrace:
    name: str
    decorators: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)   # canonical sink names
    returns: list[str] = field(default_factory=list)
    flows: list[str] = field(default_factory=list)   # taint edges: flow:<SRC>-><SINK>
    has_sql_string: bool = False
    has_auth_decorator: bool = False
    has_csrf_exempt: bool = False
    lineno: int = 0

    def to_token_sequence(self) -> list[str]:
        """
        Flatten into normalised token sequence (training-compatible format):
            @decorator  def:name  arg:name  call:name  sink:name  ret:name
            flow:<SOURCE>-><SINK>   (data-flow edge: user input reaches a sink)

        ⚠ Called by diff_traces() which harvester uses for synthetic record
          generation. This format must stay compatible with training vocabulary.
        """
        tokens: list[str] = []

        for dec in self.decorators:
            tokens.append(f"@{dec}")

        tokens.append(f"def:{normalise_token(self.name)}")

        for arg in self.args:
            tokens.append(f"arg:{normalise_token(arg)}")

        for call in self.calls:
            tokens.append(f"call:{normalise_token(call)}")

        for sink in self.sinks:
            tokens.append(f"sink:{sink}")

        # Raw SQL in function body
        if self.has_sql_string and "execute" not in self.sinks:
            tokens.append("sink:execute")

        for ret in self.returns:
            tokens.append(f"ret:{normalise_token(ret)}")

        # Unguarded sink: sinks present but no auth decorator
        if self.sinks and not self.has_auth_decorator:
            tokens.append("meta:no_auth")

        # ── Data-flow tokens ──────────────────────────────────────────────
        # Taint edges computed by TraceVisitor: a user-controlled / sensitive
        # input reaches a dangerous sink (e.g. flow:<REQUEST_INPUT>->execute).
        # This captures the *vulnerability pattern* that flat Bag-of-Words
        # tokens alone cannot express.
        for flow in self.flows:
            tokens.append(flow)

        return tokens


@dataclass
class FileTrace:
    path: str
    imports: list[str] = field(default_factory=list)
    framework_tokens: list[str] = field(default_factory=list)
    functions: list[FunctionTrace] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class TraceVisitor(ast.NodeVisitor):

    def __init__(self, source_path: str) -> None:
        self.file_trace = FileTrace(path=source_path)
        self._current_func: FunctionTrace | None = None
        self._taint: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.file_trace.imports.append(alias.name)
            self._detect_framework(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        self.file_trace.imports.append(module)
        self._detect_framework(module)
        for alias in node.names:
            self.file_trace.imports.append(f"{module}.{alias.name}")
        self.generic_visit(node)

    def _detect_framework(self, name: str) -> None:
        lower = name.lower()
        for key, token in _FRAMEWORK_MAP:
            if key in lower:
                if token not in self.file_trace.framework_tokens:
                    self.file_trace.framework_tokens.append(token)
                break

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_any_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_any_function(node)

    def _visit_any_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        trace = FunctionTrace(name=node.name, lineno=node.lineno)

        for dec in node.decorator_list:
            dec_name = self._resolve_name(dec)
            if dec_name:
                trace.decorators.append(dec_name)
                if dec_name == "csrf_exempt":
                    trace.has_csrf_exempt = True
                elif dec_name in SECURITY_DECORATORS:
                    trace.has_auth_decorator = True

        all_args = (
            node.args.args + node.args.kwonlyargs
            + ([node.args.vararg] if node.args.vararg else [])
            + ([node.args.kwarg] if node.args.kwarg else [])
        )
        for arg in all_args:
            if arg.arg not in ("self", "cls"):
                trace.args.append(arg.arg)
                norm = normalise_token(arg.arg)
                if norm in _SOURCE_TOKEN_VALUES:
                    self._taint[arg.arg] = norm

        parent = self._current_func
        parent_taint = self._taint
        self._current_func = trace
        self._taint = {}
        self.generic_visit(node)
        self._current_func = parent
        self._taint = parent_taint

        self.file_trace.functions.append(trace)

    def visit_Constant(self, node: ast.Constant) -> None:
        if self._current_func is not None and isinstance(node.value, str):
            upper = node.value.upper()
            if any(kw in upper for kw in _SQL_KEYWORDS):
                self._current_func.has_sql_string = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._current_func is None:
            self.generic_visit(node)
            return

        call_name = self._resolve_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        self._current_func.calls.append(call_name)

        # 1. Check SINK_REGISTRY: exact match or suffix match
        canonical: str | None = None
        for sink_name in SINK_REGISTRY:
            if call_name == sink_name or call_name.endswith(f".{sink_name}"):
                canonical = sink_name  # use registry name = training vocabulary name
                break

        # 2. Fallback: check SINK_EXTENDED
        if canonical is None:
            last = call_name.split(".")[-1]
            canonical = SINK_EXTENDED.get(call_name) or SINK_EXTENDED.get(last)

        # 3. Append canonical sink name (deduplicated)
        if canonical is not None and canonical not in self._current_func.sinks:
            self._current_func.sinks.append(canonical)

        # 4. Taint flow: does a user-controlled / sensitive input reach this sink?
        if canonical is not None:
            for arg in node.args:
                self._emit_flow_if_tainted(arg, canonical)
            for kw in node.keywords:
                if kw.arg is None:  # **kwargs passthrough
                    continue
                self._emit_flow_if_tainted(kw.value, canonical)

        self.generic_visit(node)

    def _source_token_of(self, node: ast.expr) -> str | None:
        """Return the normalised source token for an expression, or None."""
        name = self._resolve_name(node)
        if name:
            norm = normalise_token(name)
            if norm in _SOURCE_TOKEN_VALUES:
                return norm
        return None

    def _emit_flow_if_tainted(self, arg_node: ast.expr, sink_canonical: str) -> None:
        trace = self._current_func
        if trace is None:
            return
        src = self._source_token_of(arg_node)
        if src is None and isinstance(arg_node, ast.Name) and arg_node.id in self._taint:
            src = self._taint[arg_node.id]
        if src is not None:
            tok = f"flow:{src}->{sink_canonical}"
            if tok not in trace.flows:
                trace.flows.append(tok)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._current_func is not None:
            src = self._source_token_of(node.value)
            if src is None and isinstance(node.value, ast.Name) and node.value.id in self._taint:
                src = self._taint[node.value.id]
            if src is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._taint[target.id] = src
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self._current_func is not None and node.value is not None:
            src = self._source_token_of(node.value)
            if src is None and isinstance(node.value, ast.Name) and node.value.id in self._taint:
                src = self._taint[node.value.id]
            if src is not None and isinstance(node.target, ast.Name):
                self._taint[node.target.id] = src
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if self._current_func is not None and node.value is not None:
            ret_name = self._resolve_name(node.value)
            if ret_name:
                self._current_func.returns.append(ret_name)
        self.generic_visit(node)

    def _resolve_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            v = self._resolve_name(node.value)
            return f"{v}.{node.attr}" if v else node.attr
        if isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        if isinstance(node, ast.Subscript):
            return self._resolve_name(node.value)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_traces(source_path: str) -> FileTrace:
    path = Path(source_path)
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {source_path}")
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=source_path)
    except SyntaxError as exc:
        raise ValueError(f"Cannot parse {source_path}: {exc}") from exc
    visitor = TraceVisitor(source_path=source_path)
    visitor.visit(tree)
    return visitor.file_trace


def extract_traces_from_source(source: str, label: str = "<memory>") -> FileTrace:
    """
    Parse Python source from a string (used by harvester.py).
    ⚠ Imported by harvester.py — do not rename or change signature.
    """
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        raise ValueError(f"Cannot parse source for {label}: {exc}") from exc
    visitor = TraceVisitor(source_path=label)
    visitor.visit(tree)
    return visitor.file_trace


def diff_traces(old: FileTrace, new: FileTrace) -> dict[str, Any]:
    """
    Structural diff between vulnerable and patched traces.
    ⚠ Imported by harvester.py — do not rename or change return structure.
    """
    old_funcs = {f.name: f for f in old.functions}
    new_funcs = {f.name: f for f in new.functions}

    removed = [
        {"name": n, "tokens": old_funcs[n].to_token_sequence()}
        for n in old_funcs if n not in new_funcs
    ]
    added = [
        {"name": n, "tokens": new_funcs[n].to_token_sequence()}
        for n in new_funcs if n not in old_funcs
    ]
    modified = []
    for name in old_funcs:
        if name not in new_funcs:
            continue
        old_tok = old_funcs[name].to_token_sequence()
        new_tok = new_funcs[name].to_token_sequence()
        if old_tok != new_tok:
            modified.append({
                "name": name,
                "vulnerable_tokens": old_tok,
                "patched_tokens": new_tok,
                "added_decorators": [
                    d for d in new_funcs[name].decorators
                    if d not in old_funcs[name].decorators
                ],
                "removed_sinks": [
                    s for s in old_funcs[name].sinks
                    if s not in new_funcs[name].sinks
                ],
                "added_sinks": [
                    s for s in new_funcs[name].sinks
                    if s not in old_funcs[name].sinks
                ],
            })

    return {
        "syrth_version": "1.0.0",
        "old_file": old.path,
        "new_file": new.path,
        "import_diff": {
            "added": [i for i in new.imports if i not in old.imports],
            "removed": [i for i in old.imports if i not in new.imports],
        },
        "functions": {"removed": removed, "added": added, "modified": modified},
    }


def single_file_trace(source_path: str) -> dict[str, Any]:
    """
    Inference mode: returns combined token sequence for syrth_scan.py.
    Tokens are EMPTY when no sinks found → syrth_scan exits cleanly.
    """
    trace = extract_traces(source_path)

    # Collect sinks and function tokens across all functions
    all_func_tokens: list[str] = []
    all_sinks: set[str] = set()
    has_unguarded = False

    for func in trace.functions:
        func_toks = func.to_token_sequence()
        all_func_tokens.extend(func_toks)
        all_sinks.update(func.sinks)
        if func.sinks and not func.has_auth_decorator:
            has_unguarded = True

    # Combined token sequence — only built when sinks are present.
    # Clean files (models.py, utils.py etc.) produce no tokens → clean exit.
    combined: list[str] = []

    if all_sinks:
        # Framework tokens (real-data vocabulary)
        combined.extend(trace.framework_tokens)
        # Function tokens (synthetic-data vocabulary: def:, arg:, sink:, etc.)
        combined.extend(all_func_tokens)
        # Severity (real-data vocabulary)
        if any(s in _HIGH_RISK_SINKS for s in all_sinks) or has_unguarded:
            combined.append("severity:high")
        else:
            combined.append("severity:low")

    return {
        "syrth_version": "1.0.0",
        "mode": "single",
        "file": source_path,
        "imports": trace.imports,
        "framework_tokens": trace.framework_tokens,
        "tokens": combined,  # used directly by syrth_scan.py
        "functions": [
            {
                "name": f.name,
                "lineno": f.lineno,
                "tokens": f.to_token_sequence(),
                "has_auth_decorator": f.has_auth_decorator,
                "has_csrf_exempt": f.has_csrf_exempt,
                "sink_count": len(f.sinks),
                "sinks": f.sinks,
                "has_sql_string": f.has_sql_string,
            }
            for f in trace.functions
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collect.py",
        description="SYRTH — AST trace extractor",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--diff", action="store_true",
                      help="Diff mode: requires --old-file and --new-file")
    mode.add_argument("--single-file", metavar="PATH",
                      help="Single-file scan mode (for inference)")
    parser.add_argument("--old-file", metavar="PATH")
    parser.add_argument("--new-file", metavar="PATH")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.diff:
            if not args.old_file or not args.new_file:
                parser.error("--diff requires both --old-file and --new-file")
            result = diff_traces(
                extract_traces(args.old_file),
                extract_traces(args.new_file),
            )
        else:
            result = single_file_trace(args.single_file)

        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.write("\n")
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"[SYRTH collect] ERROR: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
