"""
SYRTH Canonical Registries
==========================
Single source of truth for sources, sinks, sanitizers (kills), frameworks and
categories.

Design invariants enforced here
-------------------------------
1.  **One canonical sink per vulnerability operation.** ``cursor.execute(...)``,
    ``conn.execute(...)`` and ``cur.executemany(...)`` all resolve to the single
    canonical sink ``SQL_EXECUTE``. The previous registry keyed sinks by literal
    call spelling, which produced several distinct "sinks" for the same
    operation and made ``flow:`` tokens disagree with the feature vector.

2.  **Deterministic resolution.** Every lookup iterates a *sorted* candidate
    list, never a ``set``/``frozenset``. String hashing is randomised per
    process (``PYTHONHASHSEED``), so set-order-dependent resolution makes the
    token stream -- and therefore the model vocabulary -- differ between the
    training process and the inference process.

3.  **No bare-name over-matching.** Short, ambiguous base names (``load``,
    ``loads``, ``run``, ``new``, ``write``) are *only* sinks when the program
    imported them from a module that makes them dangerous
    (``from pickle import loads``). Unambiguous builtins (``eval``, ``exec``,
    ``open``, ``redirect``) remain suffix-matchable.

4.  **Argument-position awareness.** Every sink carries an argument schema. A
    parameterised query ``cursor.execute(sql, params)`` passes its second
    argument through a *structural kill*; the tainted value never reaches the
    SQL interpreter. Treating every argument as dangerous -- which the previous
    version did -- is what made safe code indistinguishable from unsafe code.

5.  **Typed kills.** Sanitisers declare which sink *categories* they neutralise
    and whether they are full or partial kills. A kill is category-typed:
    ``os.path.basename`` kills path traversal but is meaningless against SQL
    injection, while ``shlex.quote`` kills shell command injection only.

6.  **Sources are typed by origin, never by identifier spelling.** Every
    function parameter is a source whatever it is called (see
    :data:`Origin.PARAM`). Identifier names influence a weak auxiliary hint
    feature only, never a taint verdict. This is what makes findings invariant
    under consistent alpha-renaming of the analysed program.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from re import Pattern

# ---------------------------------------------------------------------------
# Category constants -- the closed set of vulnerability operations SYRTH models.
# ---------------------------------------------------------------------------


class Category:
    """Sink categories. This is a closed set; every finding maps into it."""

    SQL = "SQL"
    XSS = "XSS"
    FILE = "FILE"
    EXEC = "EXEC"
    NET = "NET"
    REDIRECT = "REDIRECT"
    DESER = "DESER"
    CRYPTO = "CRYPTO"
    CRED = "CRED"
    UPLOAD = "UPLOAD"
    XXE = "XXE"


CATEGORIES: tuple[str, ...] = (
    Category.SQL,
    Category.XSS,
    Category.FILE,
    Category.EXEC,
    Category.NET,
    Category.REDIRECT,
    Category.DESER,
    Category.CRYPTO,
    Category.CRED,
    Category.UPLOAD,
    Category.XXE,
)

#: Primary CWE for each category. This is the *only* place a category becomes a
#: CWE identifier, so the rule classifier and the ML classifier emit labels from
#: one shared, closed label space.
CATEGORY_CWE: dict[str, str] = {
    Category.SQL: "CWE-89",
    Category.XSS: "CWE-79",
    Category.FILE: "CWE-22",
    Category.EXEC: "CWE-94",
    Category.NET: "CWE-918",
    Category.REDIRECT: "CWE-601",
    Category.DESER: "CWE-502",
    Category.CRYPTO: "CWE-327",
    Category.CRED: "CWE-798",
    Category.UPLOAD: "CWE-434",
    Category.XXE: "CWE-611",
}

CWE_TO_CATEGORY: dict[str, str] = {v: k for k, v in CATEGORY_CWE.items()}

#: Categories whose confirmed flow implies code execution or credential
#: compromise. Used for severity ordering, never for classification.
HIGH_RISK_CATEGORIES: frozenset[str] = frozenset(
    {Category.EXEC, Category.DESER, Category.CRED}
)


# ---------------------------------------------------------------------------
# Taint origins
# ---------------------------------------------------------------------------


class Origin:
    """Taint-origin constants.

    ``PARAM`` is the rename-invariant origin: *every* function parameter is
    treated as attacker-influenced regardless of its name. The remaining
    origins describe how a value entered the program when that is observable
    (request object, environment, file read, ...).
    """

    PARAM = "PARAM"
    REQUEST = "REQUEST"
    ENV = "ENV"
    STDIN = "STDIN"
    CLI = "CLI"
    FILE_READ = "FILE_READ"
    NET_READ = "NET_READ"
    DB_READ = "DB_READ"
    GLOBAL = "GLOBAL"


ORIGINS: tuple[str, ...] = (
    Origin.PARAM,
    Origin.REQUEST,
    Origin.ENV,
    Origin.STDIN,
    Origin.CLI,
    Origin.FILE_READ,
    Origin.NET_READ,
    Origin.DB_READ,
    Origin.GLOBAL,
)

#: Origins whose presence means the value is externally attacker-controlled.
EXTERNAL_ORIGINS: frozenset[str] = frozenset(
    {
        Origin.PARAM,
        Origin.REQUEST,
        Origin.ENV,
        Origin.STDIN,
        Origin.CLI,
        Origin.NET_READ,
    }
)


# ---------------------------------------------------------------------------
# Sink specifications
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SinkSpec:
    """Canonical definition of one vulnerability-producing operation.

    Attributes:
        name: Canonical sink identifier, e.g. ``SQL_EXECUTE``. Stable across
            releases and used verbatim in ``flow:`` tokens and trace objects.
        category: One member of :class:`Category`.
        cwe: Primary CWE identifier for the category.
        danger_positions: Positional argument indices that carry attacker data
            into the operation. ``None`` means "every argument is dangerous",
            the conservative default for sinks whose schema is not modelled.
        safe_positions: Positional indices that pass data through a structural
            kill (e.g. the ``parameters`` argument of a DB-API ``execute``).
        danger_kwargs: Keyword-argument names that carry attacker data.
        safe_kwargs: Keyword-argument names that are structurally safe.
        high_risk: Membership in :data:`HIGH_RISK_CATEGORIES`.
        description: Human-readable description used in reports.
    """

    name: str
    category: str
    cwe: str
    danger_positions: tuple[int, ...] | None = None
    safe_positions: tuple[int, ...] = ()
    danger_kwargs: frozenset[str] = frozenset()
    safe_kwargs: frozenset[str] = frozenset()
    high_risk: bool = False
    description: str = ""

    @property
    def scat_token(self) -> str:
        """``SCAT:<CATEGORY>`` token form."""
        return f"SCAT:{self.category}"

    def is_dangerous_position(self, index: int) -> bool:
        """True when positional argument ``index`` is dangerous for this sink."""
        if index in self.safe_positions:
            return False
        if self.danger_positions is None:
            return True
        return index in self.danger_positions

    def is_dangerous_keyword(self, name: str | None) -> bool:
        """True when keyword argument ``name`` is dangerous for this sink.

        ``name is None`` means a ``**kwargs`` splat, whose target is unknown.
        The conservative answer is "dangerous", except for sinks whose entire
        argument list is structurally safe.
        """
        if name is None:
            return True
        if name in self.safe_kwargs:
            return False
        return True


def _sink(
    name: str,
    category: str,
    *,
    danger_positions: tuple[int, ...] | None = None,
    safe_positions: tuple[int, ...] = (),
    danger_kwargs: Iterable[str] = (),
    safe_kwargs: Iterable[str] = (),
    description: str = "",
) -> SinkSpec:
    return SinkSpec(
        name=name,
        category=category,
        cwe=CATEGORY_CWE[category],
        danger_positions=danger_positions,
        safe_positions=safe_positions,
        danger_kwargs=frozenset(danger_kwargs),
        safe_kwargs=frozenset(safe_kwargs),
        high_risk=category in HIGH_RISK_CATEGORIES,
        description=description,
    )


SINK_SPECS: dict[str, SinkSpec] = {
    spec.name: spec
    for spec in (
        _sink(
            "SQL_EXECUTE",
            Category.SQL,
            # DB-API execute(sql, parameters): only the statement is interpreted
            # as SQL. The parameters argument is a structural kill.
            danger_positions=(0,),
            safe_positions=(1, 2),
            danger_kwargs=("sql", "query", "statement", "operation", "raw", "text"),
            safe_kwargs=("parameters", "params", "args", "multiparams", "paramstyle"),
            description="SQL statement passed to a database driver",
        ),
        _sink(
            "XSS_TEMPLATE_BODY",
            Category.XSS,
            # ``render_template_string(source)`` interpolates ``source`` itself.
            danger_positions=(0,),
            danger_kwargs=("source", "template_string", "string", "body"),
            description="Template source built from untrusted input",
        ),
        _sink(
            "XSS_TEMPLATE_NAME",
            Category.XSS,
            # ``render(request, template_name, context)``: argument 0 is the
            # request object, which is attacker-influenced by construction and
            # is not itself the injection vector. Only the template selection is.
            danger_positions=(1,),
            safe_positions=(0, 2, 3),
            danger_kwargs=("template_name", "template"),
            safe_kwargs=("request", "context", "context_instance", "content_type"),
            description="Template name selected from untrusted input",
        ),
        _sink(
            "XSS_TEMPLATE_PATH",
            Category.XSS,
            # ``render_to_string(template_name, context)`` shortcut: the template
            # is argument 0 here rather than argument 1.
            danger_positions=(0,),
            safe_positions=(1, 2),
            danger_kwargs=("template_name", "template"),
            safe_kwargs=("context", "request", "using"),
            description="Template path selected from untrusted input",
        ),
        _sink(
            "XSS_RESPONSE_BODY",
            Category.XSS,
            danger_positions=(0,),
            danger_kwargs=("content", "text", "value", "body", "string"),
            description="Untrusted value written to an HTML response body",
        ),
        _sink(
            "XSS_MAIL_BODY",
            Category.XSS,
            danger_positions=(0, 1, 3),
            safe_positions=(2,),
            danger_kwargs=("subject", "message", "body", "html_message"),
            safe_kwargs=("from_email", "recipient_list", "to", "fail_silently"),
            description="Untrusted value placed in an outbound message header or body",
        ),
        _sink(
            "FILE_OPEN",
            Category.FILE,
            danger_positions=(0,),
            safe_positions=(1, 2),
            danger_kwargs=("file", "filename", "path", "name", "f"),
            description="Filesystem path built from untrusted input",
        ),
        _sink(
            "EXEC_COMMAND",
            Category.EXEC,
            # ``subprocess.run(args=[...], shell=False)`` passes argv-style
            # arguments that a shell never re-parses. The ``shell=False`` keyword
            # combined with a list/tuple first argument is therefore a
            # structural kill; see ``_argv_structural_kill``.
            danger_positions=(0,),
            danger_kwargs=("args", "command", "cmd", "shell_command", "popen", "args_list"),
            safe_kwargs=("env", "cwd", "input", "stdout", "stderr", "universal_newlines"),
            description="Operating-system command built from untrusted input",
        ),
        _sink(
            "NET_REQUEST",
            Category.NET,
            danger_positions=(0,),
            safe_positions=(1,),
            danger_kwargs=("url", "target", "endpoint"),
            safe_kwargs=("params", "data", "json", "headers", "timeout", "allow_redirects"),
            description="Outbound network request to an attacker-influenced URL",
        ),
        _sink(
            "REDIRECT_NAV",
            Category.REDIRECT,
            danger_positions=(0,),
            danger_kwargs=("location", "to", "next", "url", "redirect_url"),
            description="HTTP redirect to an attacker-influenced location",
        ),
        _sink(
            "DESER_UNSAFE",
            Category.DESER,
            danger_positions=(0,),
            danger_kwargs=("data", "payload", "stream", "object", "b"),
            description="Untrusted data passed to an unsafe deserialiser",
        ),
        _sink(
            "CRYPTO_WEAK",
            Category.CRYPTO,
            danger_positions=(0,),
            safe_positions=(1,),
            danger_kwargs=("name", "algorithm", "algo"),
            safe_kwargs=("data", "digest", "salt", "password"),
            description="Weak or non-cryptographic primitive used for security",
        ),
        _sink(
            "CRED_HARDCODED",
            Category.CRED,
            danger_positions=(0,),
            danger_kwargs=("password", "secret", "token", "key", "credential"),
            description="Credential embedded directly in source",
        ),
        _sink(
            "UPLOAD_WRITE",
            Category.UPLOAD,
            danger_positions=(0, 1),
            danger_kwargs=("filename", "name", "path", "content"),
            description="File written into a storage area reachable by uploads",
        ),
        _sink(
            "XXE_PARSE",
            Category.XXE,
            danger_positions=(0,),
            danger_kwargs=("source", "file", "xml", "text"),
            safe_kwargs=("parser", "resolver", "base_url"),
            description="XML parser invoked on untrusted input",
        ),
    )
}

#: Reverse index: canonical sink name -> category token, a derived view so that
#: callers of the previous ``SINK_CATEGORIES`` keep working.
SINK_CATEGORIES: dict[str, str] = {n: s.scat_token for n, s in SINK_SPECS.items()}

#: Canonical names whose taint reaching them implies code execution.
HIGH_RISK_SINKS: frozenset[str] = frozenset(n for n, s in SINK_SPECS.items() if s.high_risk)


# ---------------------------------------------------------------------------
# Call-name -> canonical sink mapping
# ---------------------------------------------------------------------------
#
# Three resolution tiers, consulted in order:
#   _SINK_EXACT  fully qualified names; exact match, then dotted-suffix match
#                from longest to shortest. Always safe to match.
#   _SINK_IMPORT bare names that are only sinks when imported from a specific
#                dangerous module (``from pickle import loads``).
#   _SINK_SUFFIX short, unambiguous base names, safe to suffix-match.

_SINK_EXACT: dict[str, str] = {}
_SINK_IMPORT: dict[str, tuple[frozenset[str], str]] = {}
_SINK_SUFFIX: dict[str, str] = {}
_SINK_SUFFIX_ORDER: tuple[str, ...] = ()

#: Fully qualified safe APIs. Checked before the sink tables so that
#: ``yaml.safe_load`` / ``json.loads`` are never mistaken for dangerous
#: deserialisers. Exact and dotted-suffix matching only.
_SAFE_EXACT: frozenset[str] = frozenset(
    {
        "json.loads", "json.load", "json.JSONDecoder.decode",
        "json.JSONDecoder.raw_decode",
        "yaml.safe_load", "yaml.safe_load_all",
        "yaml.CSafeLoader", "yaml.FullLoader",
        "defusedxml.fromstring", "defusedxml.parse", "defusedxml.iterparse",
        "defusedxml.ElementTree.fromstring", "defusedxml.ElementTree.parse",
        "defusedxml.xmlrpc.fromstring", "defusedxml.lxml.fromstring",
        "defusedxml.lxml.parse",
        "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser",
        "markupsafe.escape", "markupsafe.escape_silent", "html.escape",
        "django.utils.html.format_html", "format_html", "conditional_escape",
        "strip_tags", "flask.escape", "werkzeug.utils.escape",
        "bleach.clean", "nh3.clean", "lxml.html.cleanup", "lxml.html.sanitize",
        "shlex.quote", "shlex.quote_plus", "pipes.quote",
        "jsonpickle.decode",
        "configparser.ConfigParser.read",
        "ast.literal_eval",
        # ``re.compile`` builds a pattern, never code. It shares a base name with
        # the ``compile`` RCE sink, so it must be excluded explicitly.
        "re.compile", "re.purge", "regex.compile", "sre_compile.compile",
    }
)


def _register_sink(call_name: str, canonical: str) -> None:
    """Register a fully qualified ``call_name`` as an alias of ``canonical``."""
    _SINK_EXACT[call_name] = canonical


def _register_qualified(names: Iterable[str], canonical: str) -> None:
    for name in names:
        _register_sink(name, canonical)


def _register_importable(name: str, canonical: str, modules: Iterable[str]) -> None:
    """Register a bare ``name`` as a sink only when bound from ``modules``."""
    _SINK_IMPORT[name] = (frozenset(modules), canonical)


def _register_unambiguous(names: Iterable[str], canonical: str) -> None:
    """Register base names that are safe to suffix-match without import info."""
    for name in names:
        _SINK_SUFFIX[name] = canonical


_DB_MODULES = (
    "sqlite3", "psycopg2", "psycopg", "pymysql", "MySQLdb", "sqlalchemy",
    "django", "cx_Oracle", "pyodbc", "asyncpg", "databases",
)
_DESER_MODULES = ("pickle", "cPickle", "jsonpickle", "marshal", "yaml", "dill", "shelve", "joblib")
_XML_MODULES = ("lxml", "xml", "xmlrpc", "defusedxml")
_NET_MODULES = ("requests", "httpx", "urllib", "aiohttp", "http", "socket", "urllib3")
_EXEC_MODULES = ("subprocess", "commands", "os", "popen2", "popen4")
_CRYPTO_MODULES = ("Crypto", "Cryptodome", "cryptography", "random", "pycrypto")
_UPLOAD_MODULES = ("django", "storages", "werkzeug", "flask", "fastapi", "aiohttp", "starlette")


def _register_all_sinks() -> None:
    """Populate the sink alias tables. Called once at import time."""
    _SINK_EXACT.clear()
    _SINK_SUFFIX.clear()
    _SINK_IMPORT.clear()

    # ---- SQL ------------------------------------------------------------
    _register_qualified(
        (
            "cursor.execute", "cursor.executemany", "cursor.executescript",
            "connection.execute", "conn.execute", "db.execute",
            "session.execute", "engine.execute", "Model.objects.raw",
            "cursor.execute_sql", "connection.cursor",
            "sqlite3.Connection.execute", "sqlalchemy.text",
        ),
        "SQL_EXECUTE",
    )
    _register_unambiguous(
        ("execute", "executemany", "executescript", "execute_sql", "exec_sql",
         "execute_query", "executeUpdate", "executeQuery", "raw"),
        "SQL_EXECUTE",
    )
    _register_importable("execute", "SQL_EXECUTE", _DB_MODULES)
    _register_importable("executemany", "SQL_EXECUTE", _DB_MODULES)
    _register_importable("cursor", "SQL_EXECUTE", _DB_MODULES)

    # ---- XSS ------------------------------------------------------------
    # Response body constructors.
    _register_qualified(
        (
            "HttpResponse", "JsonResponse", "HTMLResponse", "StreamingHttpResponse",
            "SimpleTemplateResponse", "TemplateResponse",
            "flask.Response", "fastapi.responses.JSONResponse",
            "fastapi.responses.HTMLResponse", "make_response", "jsonify",
        ),
        "XSS_RESPONSE_BODY",
    )
    _register_unambiguous(
        ("HttpResponse", "JsonResponse", "HTMLResponse", "StreamingHttpResponse",
         "make_response", "jsonify"),
        "XSS_RESPONSE_BODY",
    )
    _register_importable("Response", "XSS_RESPONSE_BODY",
                          ("flask", "django", "fastapi", "aiohttp", "starlette"))

    # Template-source sinks: the template text itself is the injection vector.
    _register_qualified(
        (
            "render_template_string", "format_html", "Template",
            "django.template.Template", "django.template.base.Template",
        ),
        "XSS_TEMPLATE_BODY",
    )
    _register_unambiguous(("render_template_string", "format_html"), "XSS_TEMPLATE_BODY")

    # Template-selection sinks. ``render(request, template, context)`` is the
    # Django shortcut (the template is argument 1); ``render_to_string`` is the
    # argument-0 form. Both are registered separately because their signatures
    # differ, and Flask's ``render_template`` is pinned to the argument-0 spec by
    # an exact name so it does not inherit Django's positions.
    _register_qualified(
        ("render_template", "TemplateResponse", "SimpleTemplateResponse"),
        "XSS_TEMPLATE_NAME",
    )
    _register_unambiguous(("render", "render_template"), "XSS_TEMPLATE_NAME")
    _register_qualified(
        ("render_to_string", "get_template", "select_template", "render_to_response"),
        "XSS_TEMPLATE_PATH",
    )
    _register_unambiguous(
        ("render_to_string", "render_to_response"), "XSS_TEMPLATE_PATH"
    )
    # Pin Flask/Jinja to the argument-0 spec; an exact name outranks the suffix
    # table, so this wins over the Django entry above.
    for _flask in ("flask.render_template", "jinja2.render_template",
                   "render_template_string"):
        _SINK_EXACT[_flask] = (
            "XSS_TEMPLATE_BODY" if _flask == "render_template_string"
            else "XSS_TEMPLATE_PATH"
        )

    # Mail sinks.
    _register_qualified(("send_mail", "send_mail_subject", "mail_admins"),
                        "XSS_MAIL_BODY")
    _register_importable("send_mail", "XSS_MAIL_BODY",
                         ("django.core.mail", "django", "flask_mail"))

    # ---- Redirect ---------------------------------------------------------
    _register_qualified(
        (
            "redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
            "RedirectResponse", "flask.redirect", "django.shortcuts.redirect",
            "django.http.HttpResponseRedirect",
        ),
        "REDIRECT_NAV",
    )
    _register_unambiguous(
        ("redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
         "RedirectResponse"),
        "REDIRECT_NAV",
    )

    # ---- File system ---------------------------------------------------------
    _register_qualified(
        (
            "send_file", "send_from_directory", "FileResponse",
            "os.remove", "os.unlink", "os.rename", "os.removedirs", "os.rmdir",
            "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move",
            "shutil.rmtree", "io.open", "codecs.open", "os.open",
        ),
        "FILE_OPEN",
    )
    _register_unambiguous(
        ("open", "openat", "creat", "send_file", "send_from_directory",
         "FileResponse", "remove", "unlink", "rmdir", "removedirs"),
        "FILE_OPEN",
    )
    _register_qualified(("os.path.join", "os.path.abspath"), "FILE_OPEN")

    # ---- Command execution ------------------------------------------------------
    _register_qualified(
        (
            "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
            "os.execvpe", "os.execl", "os.execlp", "os.execle", "os.spawnl",
            "os.spawnv", "os.spawnve", "os.posix_spawn",
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_call", "subprocess.check_output",
            "subprocess.getoutput", "subprocess.getstatusoutput",
            "commands.getoutput", "commands.getstatusoutput",
            "popen2", "popen3", "popen4", "pty.spawn",
        ),
        "EXEC_COMMAND",
    )
    _register_unambiguous(
        ("system", "popen", "execv", "execve", "execvp", "execl", "spawnl",
         "spawnv", "getoutput", "getstatusoutput", "spawn"),
        "EXEC_COMMAND",
    )
    # Builtins that construct or execute code. These are the highest-signal RCE
    # sinks in Python and the base names are unambiguous.
    _register_unambiguous(
        ("eval", "exec", "compile", "execfile", "__import__"),
        "EXEC_COMMAND",
    )
    _register_importable("run", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("call", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("check_call", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("check_output", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("Popen", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("getoutput", "EXEC_COMMAND", _EXEC_MODULES)
    _register_importable("getstatusoutput", "EXEC_COMMAND", _EXEC_MODULES)

    # ---- Outbound network ------------------------------------------------------------
    for package in ("requests", "httpx", "aiohttp", "urllib3"):
        for verb in ("get", "post", "put", "patch", "delete", "head",
                     "options", "request", "open"):
            _register_sink(f"{package}.{verb}", "NET_REQUEST")
    _register_qualified(
        (
            "urllib.request.urlopen", "urllib.request.Request",
            "urllib.request.urlretrieve", "urllib.request.OpenerDirector.open",
            "socket.create_connection", "http.client.HTTPSConnection",
            "http.client.HTTPConnection", "ftplib.FTP",
        ),
        "NET_REQUEST",
    )
    _register_unambiguous(("urlopen", "urlretrieve"), "NET_REQUEST")
    _register_importable("urlopen", "NET_REQUEST", _NET_MODULES)
    _register_importable("urlretrieve", "NET_REQUEST", _NET_MODULES)

    # ---- Unsafe deserialisation ---------------------------------------------------------
    _register_qualified(
        (
            "pickle.loads", "pickle.load", "pickle.Unpickler",
            "cPickle.loads", "cPickle.load",
            "jsonpickle.decode", "jsonpickle.unpickler.decode",
            "jsonpickle.unpickler.Unpickler",
            "marshal.loads", "marshal.load",
            "numpy.load", "torch.load", "joblib.load", "shelve.open",
            "dill.loads", "dill.load", "yaml.load", "yaml.full_load",
            "yaml.unsafe_load", "yaml.load_all",
        ),
        "DESER_UNSAFE",
    )
    _register_importable("loads", "DESER_UNSAFE", _DESER_MODULES)
    _register_importable("load", "DESER_UNSAFE", _DESER_MODULES)
    _register_importable("Unpickler", "DESER_UNSAFE", _DESER_MODULES)

    # ---- Weak cryptography ----------------------------------------------------------------
    _register_qualified(
        (
            "hashlib.md5", "hashlib.sha1", "hashlib.new", "hashlib.pbkdf2_hmac",
            "hashlib.shake_128", "hashlib.shake_256",
            "Crypto.Cipher.DES.new", "Crypto.Cipher.ARC2.new",
            "Crypto.Random.new", "random.random", "random.getrandbits",
            "random.choice", "random.randrange", "random.randint",
            "cryptography.hazmat.primitives.ciphers",
        ),
        "CRYPTO_WEAK",
    )
    _register_importable("md5", "CRYPTO_WEAK", ("hashlib", "Crypto", "Cryptodome", "cryptography"))
    _register_importable("sha1", "CRYPTO_WEAK", ("hashlib", "Crypto", "Cryptodome", "cryptography"))
    _register_importable("DES", "CRYPTO_WEAK", ("Crypto", "Cryptodome", "cryptography"))
    _register_importable("new", "CRYPTO_WEAK", _CRYPTO_MODULES)
    _register_importable("random", "CRYPTO_WEAK", _CRYPTO_MODULES)
    _register_importable("getrandbits", "CRYPTO_WEAK", _CRYPTO_MODULES)
    _register_importable("randint", "CRYPTO_WEAK", _CRYPTO_MODULES)
    _register_importable("choice", "CRYPTO_WEAK", _CRYPTO_MODULES)

    # ---- Unrestricted upload ------------------------------------------------------------------
    _register_qualified(
        (
            "FileSystemStorage.save", "default_storage.save",
            "Storage.save", "FileStorage.save", "form.save",
            "UploadFile", "save_upload", "store_file",
        ),
        "UPLOAD_WRITE",
    )
    _register_importable("save", "UPLOAD_WRITE", _UPLOAD_MODULES)

    # ---- XXE -------------------------------------------------------------------------------
    _register_qualified(
        (
            "etree.parse", "etree.fromstring", "etree.iterparse",
            "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
            "xml.etree.ElementTree.iterparse", "xml.etree.ElementTree.XMLParser",
            "lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.iterparse",
            "lxml.etree.XMLParser", "minidom.parse", "minidom.parseString",
            "xml.dom.pulldom.parse", "xmlrpc.server.loads",
        ),
        "XXE_PARSE",
    )
    _register_importable("parse", "XXE_PARSE", _XML_MODULES)
    _register_importable("fromstring", "XXE_PARSE", _XML_MODULES)
    _register_importable("iterparse", "XXE_PARSE", _XML_MODULES)
    _register_importable("XMLParser", "XXE_PARSE", _XML_MODULES)

    # Sort longest-first so that a more specific base name always wins.
    global _SINK_SUFFIX_ORDER
    _SINK_SUFFIX_ORDER = tuple(sorted(_SINK_SUFFIX, key=lambda k: (-len(k), k)))


#: Legacy view kept for downstream compatibility: canonical sink names.
SINK_REGISTRY: frozenset[str] = frozenset(SINK_SPECS)


def _build_sink_extended_view() -> dict[str, str]:
    """Build the legacy ``SINK_EXTENDED`` alias map, deterministically."""
    view: dict[str, str] = {}
    for name in sorted(_SINK_EXACT):
        view[name] = _SINK_EXACT[name]
    for name in sorted(_SINK_SUFFIX):
        view[name] = _SINK_SUFFIX[name]
    for name in sorted(_SINK_IMPORT):
        view[name] = _SINK_IMPORT[name][1]
    return view


# ---------------------------------------------------------------------------
# Sanitisers (kills)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KillSpec:
    """A sanitiser: a call that neutralises (or amplifies) taint.

    Attributes:
        name: Canonical sanitiser identifier.
        kills: Sink categories this sanitiser neutralises.
        produces: Sink categories this sanitiser may *create*. ``mark_safe``
            belongs here: it does not remove taint, it asserts safety, which
            turns any value -- clean or not -- into a confirmed injection sink.
        arg_index: Which argument of the sanitiser call the kill applies to.
        full: ``True`` for a complete neutraliser, ``False`` for a partial one
            (which suppresses noise but is not by itself a proof of safety).
        description: Human-readable description used in reports.
    """

    name: str
    kills: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    arg_index: int = 0
    full: bool = True
    description: str = ""


def _kill(
    name: str,
    kills: Iterable[str] = (),
    produces: Iterable[str] = (),
    arg_index: int = 0,
    full: bool = True,
    description: str = "",
) -> KillSpec:
    return KillSpec(
        name=name,
        kills=frozenset(kills),
        produces=frozenset(produces),
        arg_index=arg_index,
        full=full,
        description=description,
    )


_KILL_EXACT: dict[str, KillSpec] = {}
_KILL_SUFFIX: dict[str, KillSpec] = {}
_KILL_IMPORT: dict[str, tuple[frozenset[str], KillSpec]] = {}
_KILL_SUFFIX_ORDER: tuple[str, ...] = ()


def _register_all_kills() -> None:
    """Populate sanitiser tables. Called once at import time."""
    _KILL_EXACT.clear()
    _KILL_SUFFIX.clear()
    _KILL_IMPORT.clear()

    # ---- Shell command injection ------------------------------------------------
    shlex_quote = _kill(
        "shlex.quote",
        kills=[Category.EXEC],
        description="Shell-metacharacter escaping for a single command argument",
    )
    _KILL_EXACT["shlex.quote"] = shlex_quote
    _KILL_EXACT["shlex.quote_plus"] = shlex_quote
    _KILL_EXACT["pipes.quote"] = shlex_quote
    _KILL_IMPORT["quote"] = (frozenset({"shlex", "pipes"}), shlex_quote)

    # ---- Path traversal ---------------------------------------------------------
    basename = _kill(
        "os.path.basename",
        kills=[Category.FILE],
        description="Strips every directory component from a path",
    )
    _KILL_EXACT["os.path.basename"] = basename
    _KILL_IMPORT["basename"] = (frozenset({"os.path", "pathlib", "ntpath", "posixpath"}), basename)
    normpath = _kill(
        "os.path.normpath",
        kills=[Category.FILE],
        full=False,
        description="Collapses ``..`` segments but does not prevent them",
    )
    _KILL_EXACT["os.path.normpath"] = normpath
    _KILL_EXACT["os.path.realpath"] = _kill(
        "os.path.realpath",
        kills=[Category.FILE],
        full=False,
        description="Resolves symlinks; does not by itself prevent traversal",
    )

    # ---- Cross-site scripting ------------------------------------------------------
    html_escape = _kill(
        "html.escape",
        kills=[Category.XSS],
        description="HTML output encoding",
    )
    _KILL_EXACT["html.escape"] = html_escape
    _KILL_EXACT["markupsafe.escape"] = _kill(
        "markupsafe.escape", kills=[Category.XSS],
        description="Context-aware HTML output encoding",
    )
    _KILL_SUFFIX["escape"] = html_escape
    _KILL_IMPORT["escape"] = (frozenset({"html", "markupsafe", "cgi", "html_escapers"}), html_escape)
    # ``format_html(fmt, *args)`` escapes every substituted argument and returns
    # a SafeString, so it neutralises XSS exactly as ``escape`` does. Without
    # this, idiomatic Django template code -- the framework's *recommended* way
    # to build markup -- was reported as a finding.
    format_html = _kill(
        "django.utils.html.format_html",
        kills=[Category.XSS],
        description="Escapes substituted arguments and returns a SafeString",
    )
    _KILL_EXACT["django.utils.html.format_html"] = format_html
    _KILL_EXACT["format_html"] = format_html
    _KILL_SUFFIX["format_html"] = format_html
    _KILL_IMPORT["format_html"] = (frozenset({"django", "django.utils.html"}), format_html)
    # Framework wrappers around escaping that are easy to miss.
    _KILL_SUFFIX["conditional_escape"] = html_escape
    _KILL_SUFFIX["strip_tags"] = _kill(
        "strip_tags", kills=[Category.XSS],
        description="Removes HTML tags from a string",
    )
    html_clean = _kill(
        "bleach.clean", kills=[Category.XSS],
        description="HTML sanitiser allow-list",
    )
    _KILL_EXACT["bleach.clean"] = html_clean
    _KILL_EXACT["nh3.clean"] = html_clean
    _KILL_EXACT["lxml.html.cleanup"] = html_clean
    _KILL_IMPORT["clean"] = (frozenset({"bleach", "nh3", "lxml"}), html_clean)
    _KILL_SUFFIX["clean"] = html_clean
    _KILL_IMPORT["sanitize"] = (
        frozenset({"bleach", "nh3", "lxml", "html_sanitizer"}),
        _kill("sanitize", kills=[Category.XSS], full=False,
              description="Generic sanitiser, assumed HTML-oriented"),
    )

    # ---- Structural decoders ---------------------------------------------------------
    # These make the value a literal rather than removing the attack; recording
    # them as full kills keeps numeric identifiers from dominating the FP set.
    for coerce in ("int", "float", "bool"):
        spec = _kill(
            coerce,
            kills=[Category.SQL, Category.EXEC, Category.FILE, Category.XSS,
                   Category.REDIRECT, Category.NET],
            description="Numeric/boolean coercion yields a literal value",
        )
        _KILL_SUFFIX[coerce] = spec

    url_quote = _kill(
        "urllib.parse.quote",
        kills=[Category.XSS, Category.FILE],
        description="URL percent-encoding",
    )
    _KILL_EXACT["urllib.parse.quote"] = url_quote
    _KILL_EXACT["urllib.parse.quote_plus"] = url_quote
    _KILL_IMPORT["quote"] = (frozenset({"shlex", "pipes", "urllib.parse", "urllib"}), url_quote)
    _KILL_IMPORT["quote_plus"] = (frozenset({"urllib.parse", "urllib"}), url_quote)

    _KILL_SUFFIX["urlencode"] = _kill(
        "urlencode", kills=[Category.SQL, Category.XSS],
        description="Form encoding",
    )
    _KILL_SUFFIX["literal_eval"] = _kill(
        "ast.literal_eval", kills=[Category.DESER],
        description="Parses literals only; no code construction",
    )
    # ---- SQL ------------------------------------------------------------------------------
    _KILL_EXACT["re.escape"] = _kill(
        "re.escape", kills=[Category.SQL, Category.EXEC],
        description="Regex metacharacter escaping",
    )
    _KILL_EXACT["sqlalchemy.sql.text"] = _kill(
        "sqlalchemy.sql.text", kills=[Category.SQL], full=False,
        description="Binds parameters; unsafe when concatenated with a percent sign",
    )
    _KILL_IMPORT["sql_text"] = (frozenset({"sqlalchemy"}), _KILL_EXACT["sqlalchemy.sql.text"])
    _KILL_SUFFIX["mogrify"] = _kill(
        "cursor.mogrify", kills=[Category.SQL],
        description="Client-side parameter substitution",
    )

    # ---- Redirect -----------------------------------------------------------------------------
    _KILL_IMPORT["urlparse"] = (
        frozenset({"urllib.parse", "urllib", "urlparse"}),
        _kill("urllib.parse.urlparse", kills=[Category.REDIRECT], full=False,
              description="URL parsing; must be followed by an allow-list check"),
    )

    # ---- XXE -------------------------------------------------------------------------------
    for name in ("defusedxml.fromstring", "defusedxml.parse", "defusedxml.iterparse",
                 "defusedxml.ElementTree.fromstring", "defusedxml.ElementTree.parse",
                 "defusedxml.lxml.fromstring", "defusedxml.lxml.parse",
                 "defusedxml.xmlrpc.fromstring"):
        _KILL_EXACT[name] = _kill(
            "defusedxml", kills=[Category.XXE],
            description="Hardened XML parser",
        )

    # ---- Deserialisation -------------------------------------------------------------------
    _KILL_IMPORT["safe_load"] = (
        frozenset({"yaml"}),
        _kill("yaml.safe_load", kills=[Category.DESER],
              description="Safe YAML loader (no object construction)"),
    )
    json_loads = _kill(
        "json.loads", kills=[Category.DESER],
        description="Data-only deserialiser",
    )
    _KILL_EXACT["json.loads"] = json_loads
    _KILL_EXACT["json.load"] = json_loads
    _KILL_EXACT["json.JSONDecoder"] = _kill(
        "json.JSONDecoder", kills=[Category.DESER], description="Data-only decoder"
    )
    _KILL_EXACT["yaml.safe_load"] = _kill(
        "yaml.safe_load", kills=[Category.DESER],
        description="Safe YAML loader (no object construction)",
    )
    _KILL_EXACT["yaml.safe_load_all"] = _KILL_EXACT["yaml.safe_load"]
    _KILL_EXACT["ast.literal_eval"] = _kill(
        "ast.literal_eval", kills=[Category.DESER],
        description="Parses literals only; no code construction",
    )
    _KILL_IMPORT["safe_load"] = (frozenset({"yaml"}), _KILL_EXACT["yaml.safe_load"])
    _KILL_IMPORT["loads"] = (frozenset({"json"}), json_loads)
    _KILL_IMPORT["load"] = (frozenset({"json"}), json_loads)
    _KILL_IMPORT["JSONDecoder"] = (frozenset({"json", "simplejson"}),
                                   _KILL_EXACT["json.JSONDecoder"])

    # ---- Taint amplifiers ---------------------------------------------------------------------
    mark_safe = _kill(
        "mark_safe", produces=[Category.XSS],
        description="Asserts a value is HTML-safe; creates an XSS sink",
    )
    _KILL_SUFFIX["mark_safe"] = mark_safe
    _KILL_SUFFIX["SafeString"] = mark_safe
    _KILL_SUFFIX["Markup"] = mark_safe
    _KILL_EXACT["django.utils.html.mark_safe"] = mark_safe
    _KILL_EXACT["django.utils.safestring.mark_safe"] = mark_safe
    _KILL_EXACT["markupsafe.Markup"] = mark_safe
    _KILL_IMPORT["mark_safe"] = (frozenset({"django", "markupsafe"}), mark_safe)
    _KILL_IMPORT["Markup"] = (frozenset({"markupsafe"}), mark_safe)
    _KILL_IMPORT["SafeString"] = (frozenset({"django", "django.utils.safestring"}), mark_safe)
    # Disabling autoescaping is an assertion of safety applied to a whole
    # template, so it is an amplifier for every category the template can emit.
    _KILL_SUFFIX["autoescape_off"] = _kill(
        "autoescape_off",
        produces=[Category.XSS],
        description="Autoescaping disabled for this template",
    )
    _KILL_EXACT["jinja2.Environment"] = _kill(
        "jinja2.Environment.autoescape=False",
        produces=[Category.XSS],
        description="Jinja environment constructed with autoescaping disabled",
    )

    global _KILL_SUFFIX_ORDER
    _KILL_SUFFIX_ORDER = tuple(sorted(_KILL_SUFFIX, key=lambda k: (-len(k), k)))


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

_SOURCE_CALLS: dict[str, str] = {}
_SOURCE_SUFFIX: dict[str, str] = {}
_SOURCE_SUFFIX_ORDER: tuple[str, ...] = ()


def _register_all_sources() -> None:
    """Populate the taint-source tables. Called once at import time."""
    _SOURCE_CALLS.clear()
    _SOURCE_SUFFIX.clear()

    def exact(origin: str, *names: str) -> None:
        for name in names:
            _SOURCE_CALLS[name] = origin

    def suffix(origin: str, *names: str) -> None:
        for name in names:
            _SOURCE_SUFFIX[name] = origin

    exact(Origin.STDIN, "input", "raw_input", "readline", "getpass", "getpass.getpass")
    exact(Origin.CLI, "sys.argv", "os.sys.argv")
    suffix(Origin.CLI, "argv", "getopt", "parse_args")
    exact(Origin.ENV, "os.environ", "os.environ.get", "os.getenv", "environ.get")
    suffix(Origin.ENV, "getenv", "environ")

    # Request-payload accessors, matched on the trailing dotted component.
    suffix(
        Origin.REQUEST,
        "GET", "POST", "PUT", "PATCH", "DELETE", "query_params", "form",
        "FILES", "cookies", "raw_data", "get_data", "get_json",
        "get_param", "values", "META",
    )
    suffix(Origin.DB_READ, "fetchone", "fetchall", "fetchmany", "fetch_array", "fetch_row")
    suffix(Origin.GLOBAL, "current_user", "get_current_user")

    global _SOURCE_SUFFIX_ORDER
    _SOURCE_SUFFIX_ORDER = tuple(sorted(_SOURCE_SUFFIX, key=lambda k: (-len(k), k)))


#: Attribute prefixes that identify a web-framework request object.
REQUEST_OBJECT_PREFIXES: tuple[str, ...] = (
    "self.request.",
    "self._request.",
    "request.",
    "req.",
    "http_request.",
    "flask.request",
    "starlette.request.",
    "aiohttp.",
)

#: Bare identifiers that denote a framework request object. This is a closed
#: list of conventional framework globals, not a naming heuristic.
REQUEST_OBJECT_NAMES: frozenset[str] = frozenset({"request", "req", "http_request"})

#: Attributes on a request object that carry the request payload.
REQUEST_PAYLOAD_ATTRS: frozenset[str] = frozenset(
    {
        "GET", "POST", "PUT", "PATCH", "DELETE", "body", "data", "args", "form",
        "query_params", "FILES", "files", "headers", "cookies", "values", "json",
        "raw_data", "META", "user", "path_params", "match_info",
    }
)

#: Receiver prefixes used to disambiguate the ``read``/``text``/``json`` readers.
_NET_RECEIVERS: tuple[str, ...] = (
    "requests", "httpx", "response", "resp", "session", "urllib", "aiohttp",
    "client", "http", "r",
)
_FILE_RECEIVERS: tuple[str, ...] = ("f", "fh", "fp", "file", "handle", "stream", "src", "inp", "g")


def source_origin(name: str) -> str | None:
    """Classify ``name`` as a taint source and return its origin, or ``None``.

    A name is a source when it is a known external-state reader (``input``,
    ``os.environ``, ``request.GET``, ``cursor.fetchall``, ``fh.read``) or when
    it is rooted at a framework request object.

    This function is deliberately independent of what an identifier is
    *called*: an arbitrary parameter name is never a source here. Parameters
    are seeded by the analysis scope, which is what makes the verdict invariant
    under alpha-renaming.
    """
    if not name:
        return None

    for prefix in REQUEST_OBJECT_PREFIXES:
        if name.startswith(prefix):
            return Origin.REQUEST
    if name in REQUEST_OBJECT_NAMES:
        return Origin.REQUEST

    origin = _SOURCE_CALLS.get(name)
    if origin is not None:
        return origin

    head, dot, tail = name.rpartition(".")
    if dot:
        if tail in ("read", "readline", "readlines"):
            if head.startswith(_NET_RECEIVERS):
                return Origin.NET_READ
            if head.startswith(("self", "request", "req")):
                return Origin.REQUEST
            return Origin.FILE_READ
        if tail in ("text", "content"):
            return Origin.NET_READ
        origin = _SOURCE_SUFFIX.get(tail)
        if origin is not None:
            return origin
    return None


# ---------------------------------------------------------------------------
# Framework / decorator / literal metadata
# ---------------------------------------------------------------------------

FRAMEWORK_MAP: tuple[tuple[str, str], ...] = (
    ("django", "framework:django"),
    ("flask", "framework:flask"),
    ("fastapi", "framework:fastapi"),
    ("starlette", "framework:fastapi"),
    ("tornado", "framework:fastapi"),
    ("aiohttp", "framework:fastapi"),
    ("bottle", "framework:flask"),
    ("falcon", "framework:fastapi"),
)

#: Decorators/annotations indicating an access-control decision precedes the
#: body. Recorded as an auxiliary risk modifier only: an authentication check
#: does not make a SQL-injection sink safe, so this never suppresses a
#: confirmed taint flow.
SECURITY_DECORATORS: frozenset[str] = frozenset(
    {
        "login_required", "permission_required", "staff_member_required",
        "superuser_required", "require_http_methods", "require_POST",
        "require_GET", "require_PUT", "require_DELETE", "api_view",
        "permission_classes", "authentication_classes", "jwt_required",
        "token_required", "auth_required", "requires_auth", "csrf_protect",
        "IsAuthenticated", "AllowAny", "IsAdminUser", "method_decorator",
        "validates_schema",
    }
)

#: Decorators that explicitly remove a protection and therefore raise risk.
RISK_AMPLIFYING_DECORATORS: frozenset[str] = frozenset({"csrf_exempt"})

SQL_KEYWORDS: tuple[str, ...] = (
    "SELECT ", "INSERT INTO", "INSERT IGNORE", "UPDATE ", "DELETE FROM",
    "DROP TABLE", "DROP DATABASE", "CREATE TABLE", "ALTER TABLE",
    "TRUNCATE TABLE", "EXEC ", "EXECUTE ", "UNION SELECT", "OR 1=1",
    "MERGE INTO", "GRANT ", "REVOKE ",
)

#: Assignment-target names that indicate credential material. Used *only* for
#: the hardcoded-credential category, where the identifier is the specification
#: (there is no other signal for "this literal is a password").
CREDENTIAL_NAME_PATTERN: Pattern[str] = re.compile(
    r"(?i)\b(pass(word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token"
    r"|private[_-]?key|credential[s]?|client[_-]?secret)\b"
)

#: Minimum length for a string literal to be treated as a credential value.
CREDENTIAL_MIN_LENGTH = 8


# ---------------------------------------------------------------------------
# Name normalisation (auxiliary hint feature only)
# ---------------------------------------------------------------------------

#: Regexes mapping an identifier to a coarse semantic hint. These feed the
#: ``name_hint`` features and human-readable reports. They must never influence
#: a taint verdict.
TOKEN_PATTERNS: tuple[tuple[Pattern[str], str], ...] = (
    (re.compile(r"(?i)(?:self\.)?\b(req|request)\b\."
                r"(GET|POST|PUT|PATCH|DELETE|body|data|query_params|form|args|"
                r"json|values|files|headers|cookies)"), "<REQUEST_INPUT>"),
    (re.compile(r"(?i)\b(request|req)\b"), "<REQUEST_INPUT>"),
    (re.compile(r"(?i)\b(user|user_?id|uid|owner|author)\b"), "<USER_ID>"),
    (re.compile(r"(?i)\b(pk|obj(ect)?_?id|item_?id|record_?id|doc_?id)\b"), "<OBJ_ID>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api_key|auth_token"
                r"|access_token|private_key|credential)\b"), "<SECRET>"),
    (re.compile(r"(?i)(?<![\w.])(file_?path|filepath|upload_?path|filename"
                r"|file_name|directory_path|dir_path|upload_path)\b"), "<FILE_PATH>"),
    (re.compile(r"(?i)\b(url|redirect_url|next|callback_url|target"
                r"|destination|href|location|return_url|next_url)\b"), "<URL_PARAM>"),
    (re.compile(r"(?i)\b(command|cmd|shell_cmd|exec_cmd|command_str)\b"), "<CMD>"),
    (re.compile(r"(?i)\b(query|sql|sql_query|raw_query|statement|sql_str)\b"), "<SQL>"),
)

#: Values produced by :func:`normalise_token`. Retained for compatibility.
SOURCE_TOKEN_VALUES: frozenset[str] = frozenset(
    replacement for _, replacement in TOKEN_PATTERNS
)
EXTRA_SOURCE_CALLS: frozenset[str] = frozenset(
    {"os.environ", "os.getenv", "sys.argv", "input"}
)
SOURCE_TOKEN_PATTERNS: tuple[tuple[str, str], ...] = tuple(
    (p.pattern, r) for p, r in TOKEN_PATTERNS
)


def normalise_token(name: str) -> str:
    """Map an identifier to a coarse semantic hint.

    The result is an *auxiliary* signal only. It never participates in the
    taint verdict, which is what keeps SYRTH's findings invariant under
    consistent alpha-renaming of the analysed program.
    """
    result = name
    for pattern, replacement in TOKEN_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def name_hints(name: str) -> frozenset[str]:
    """Return the set of semantic hints present in ``name``."""
    normalised = normalise_token(name)
    return frozenset(v for v in SOURCE_TOKEN_VALUES if v in normalised)


# ---------------------------------------------------------------------------
# Resolution API
# ---------------------------------------------------------------------------


def _module_in(module: str, candidates: frozenset[str]) -> bool:
    """Whether a dotted import path belongs to one of ``candidates``.

    Matching the **last** segment as well as the whole path and the root package
    is what makes ``from django.utils.html import escape`` bind to the same kill
    as ``from html import escape``. Matching only the root package left every
    re-exported or namespaced helper unbound: ``django.utils.html`` is the
    ``html`` module's namespace, but its root is ``django``, which matches
    nothing. The visible effect was that ``Markup(escape(x))`` -- the canonical
    safe pattern -- was reported as an XSS amplifier, because ``escape`` had not
    been recognised as a sanitiser at all.

    The last segment is the precise choice. Any segment would be too loose: a
    module ``a.b.models`` contains the segment ``models``, and binding on that
    would let an unrelated package shadow a rule. The residual risk is a
    third-party module literally named like a namespace we know, such as a local
    ``html`` package, being treated as the standard one. That trades a possible
    missed finding for removing a class of false amplifier reports, and it is the
    same direction the existing root-segment rule already accepts.
    """
    if module in candidates:
        return True
    parts = module.split(".")
    return bool(parts) and (parts[0] in candidates or parts[-1] in candidates)


class Bindings:
    """Import bindings that disambiguate bare call names.

    ``from pickle import loads`` binds the bare name ``loads`` to the dangerous
    ``pickle.loads``; ``from json import loads`` binds it to a safe decoder.
    Without this information every bare ``loads``/``load``/``run``/``new`` would
    have to be guessed, and guessing is what produced both the false positives
    and the false negatives in the previous release.
    """

    __slots__ = ("_sink", "_kill", "_origin")

    def __init__(self) -> None:
        self._sink: dict[str, str] = {}
        self._kill: dict[str, KillSpec] = {}
        self._origin: dict[str, str] = {}

    def bind_import(self, module: str, name: str) -> None:
        """Record ``from <module> import <name>``."""
        qualified = f"{module}.{name}"
        # Sanitiser first: a safe import must win over a same-named sink import.
        if qualified in _SAFE_EXACT:
            return
        sink = _SINK_EXACT.get(qualified)
        if sink is None and name in _SINK_IMPORT:
            modules, canonical = _SINK_IMPORT[name]
            if _module_in(module, modules):
                sink = canonical
        if sink is not None:
            self._sink[name] = sink
            return
        kill = _KILL_EXACT.get(qualified)
        if kill is None and name in _KILL_IMPORT:
            modules, spec = _KILL_IMPORT[name]
            if _module_in(module, modules):
                kill = spec
        if kill is not None:
            self._kill[name] = kill
            return
        origin = source_origin(qualified)
        if origin is not None:
            self._origin[name] = origin

    def qualify(self, call_name: str) -> str:
        """Expand a bare name using the import bindings, if one applies."""
        if "." in call_name:
            return call_name
        sink = self._sink.get(call_name)
        if sink is not None:
            return sink
        kill = self._kill.get(call_name)
        if kill is not None:
            return call_name
        return call_name

    def sink_for(self, call_name: str) -> str | None:
        """Canonical sink for a bare name bound by an import, else ``None``."""
        return self._sink.get(call_name)

    def kill_for(self, call_name: str) -> KillSpec | None:
        """Kill spec for a bare name bound by an import, else ``None``."""
        return self._kill.get(call_name)

    def origin_for(self, name: str) -> str | None:
        """Taint origin for a bare name bound by an import, else ``None``."""
        return self._origin.get(name)

    def __len__(self) -> int:
        return len(self._sink) + len(self._kill) + len(self._origin)


def canonical_sink(call_name: str, bindings: Bindings | None = None) -> str | None:
    """Resolve a call name to its canonical sink name, deterministically.

    Resolution order:
        1. Explicit safe-API table (exact, then longest dotted suffix).
        2. Exact match on the full dotted call name.
        3. Import binding, for bare names (``from pickle import loads``).
        4. Longest-suffix match over a pre-sorted table of unambiguous base names.

    Args:
        call_name: Resolved call expression, e.g. ``cursor.execute``.
        bindings: Optional import bindings for bare-name disambiguation.

    Returns:
        Canonical sink name such as ``SQL_EXECUTE``, or ``None``.
    """
    if not call_name:
        return None

    # 1. Safe APIs win outright.
    if call_name in _SAFE_EXACT:
        return None
    parts = call_name.split(".")
    for start in range(1, len(parts)):
        if ".".join(parts[start:]) in _SAFE_EXACT:
            return None

    # 2. Fully qualified names.
    canonical = _SINK_EXACT.get(call_name)
    if canonical is not None:
        return canonical
    for start in range(1, len(parts)):
        canonical = _SINK_EXACT.get(".".join(parts[start:]))
        if canonical is not None:
            return canonical

    # 3. Import binding for bare names.
    if bindings is not None and "." not in call_name:
        canonical = bindings.sink_for(call_name)
        if canonical is not None:
            return canonical

    # 4. Unambiguous base-name suffix match, longest first.
    for suffix in _SINK_SUFFIX_ORDER:
        if call_name == suffix or call_name.endswith("." + suffix):
            return _SINK_SUFFIX[suffix]
    return None


def is_sink(call_name: str, bindings: Bindings | None = None) -> bool:
    """True when ``call_name`` resolves to a sink."""
    return canonical_sink(call_name, bindings) is not None


def sink_spec(call_name: str, bindings: Bindings | None = None) -> SinkSpec | None:
    """Return the :class:`SinkSpec` for ``call_name``, or ``None``."""
    canonical = canonical_sink(call_name, bindings)
    if canonical is None:
        return None
    return SINK_SPECS[canonical]


def sink_spec_for(canonical: str) -> SinkSpec | None:
    """Return the spec for an already-canonical sink name."""
    return SINK_SPECS.get(canonical)


def kill_for(call_name: str, bindings: Bindings | None = None) -> KillSpec | None:
    """Resolve a call name to a :class:`KillSpec`, deterministically.

    A call that is a known sink is never treated as a sanitiser: ``pickle.loads``
    is a sink, not a sanitiser, even though ``json.loads`` is a sanitiser.
    """
    if not call_name:
        return None
    if canonical_sink(call_name, bindings) is not None:
        return None
    if bindings is not None and "." not in call_name:
        spec = bindings.kill_for(call_name)
        if spec is not None:
            return spec
    spec = _KILL_EXACT.get(call_name)
    if spec is not None:
        return spec
    parts = call_name.split(".")
    for start in range(1, len(parts)):
        spec = _KILL_EXACT.get(".".join(parts[start:]))
        if spec is not None:
            return spec
    for suffix in _KILL_SUFFIX_ORDER:
        if call_name == suffix or call_name.endswith("." + suffix):
            return _KILL_SUFFIX[suffix]
    if bindings is not None and "." not in call_name:
        return bindings.kill_for(call_name)
    return None


def amplifier_for(call_name: str, bindings: Bindings | None = None) -> KillSpec | None:
    """Resolve a call that *creates* an injection sink rather than removing one.

    ``mark_safe``, ``SafeString`` and ``Markup`` assert that a value is safe to
    emit as markup. When that assertion is wrong, the value becomes a sink even
    though no untrusted data reached it. This lookup deliberately ignores the
    "a sink is never a sanitiser" precedence rule used by :func:`kill_for`,
    because the amplifier behaviour is what has to be observed here.
    """
    if not call_name:
        return None
    if bindings is not None and "." not in call_name:
        spec = bindings.kill_for(call_name)
        if spec is not None and spec.produces:
            return spec
    spec = _KILL_EXACT.get(call_name)
    if spec is not None and spec.produces:
        return spec
    parts = call_name.split(".")
    for start in range(1, len(parts)):
        spec = _KILL_EXACT.get(".".join(parts[start:]))
        if spec is not None and spec.produces:
            return spec
    for suffix in _KILL_SUFFIX_ORDER:
        if call_name == suffix or call_name.endswith("." + suffix):
            candidate = _KILL_SUFFIX[suffix]
            if candidate.produces:
                return candidate
    return None


def all_sink_names() -> tuple[str, ...]:
    """All canonical sink names, sorted."""
    return tuple(sorted(SINK_SPECS))


def all_kill_names() -> tuple[str, ...]:
    """All canonical sanitiser names, sorted and de-duplicated."""
    names = {s.name for s in _KILL_EXACT.values()}
    names |= {s.name for s in _KILL_SUFFIX.values()}
    names |= {spec.name for _, spec in _KILL_IMPORT.values()}
    return tuple(sorted(names))


_register_all_sinks()
_register_all_kills()
_register_all_sources()

#: Legacy alias map, built after the tables are populated.
SINK_EXTENDED: dict[str, str] = _build_sink_extended_view()


__all__ = [
    "Bindings",
    "Category",
    "CATEGORIES",
    "Origin",
    "ORIGINS",
    "EXTERNAL_ORIGINS",
    "SinkSpec",
    "KillSpec",
    "SINK_SPECS",
    "SINK_CATEGORIES",
    "SINK_REGISTRY",
    "SINK_EXTENDED",
    "HIGH_RISK_SINKS",
    "HIGH_RISK_CATEGORIES",
    "CATEGORY_CWE",
    "CWE_TO_CATEGORY",
    "FRAMEWORK_MAP",
    "SECURITY_DECORATORS",
    "RISK_AMPLIFYING_DECORATORS",
    "SQL_KEYWORDS",
    "CREDENTIAL_NAME_PATTERN",
    "CREDENTIAL_MIN_LENGTH",
    "TOKEN_PATTERNS",
    "SOURCE_TOKEN_VALUES",
    "EXTRA_SOURCE_CALLS",
    "SOURCE_TOKEN_PATTERNS",
    "normalise_token",
    "name_hints",
    "source_origin",
    "canonical_sink",
    "is_sink",
    "sink_spec",
    "sink_spec_for",
    "kill_for",
    "amplifier_for",
    "all_sink_names",
    "all_kill_names",
]
