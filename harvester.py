import argparse
import json
import os
import random
import re
import sys
import time
import textwrap
import zipfile
import io
from pathlib import Path
from typing import Any

try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

sys.path.insert(0, str(Path(__file__).parent))
from collect import (
    diff_traces,
    extract_traces_from_source,
    normalise_token,
    SINK_REGISTRY,
)

# ---------------------------------------------------------------------------
# CWE shortlist
# ---------------------------------------------------------------------------

CWE_LABELS: dict[str, int] = {
    "CWE-89":  0,   # SQL Injection
    "CWE-79":  1,   # Cross-Site Scripting
    "CWE-22":  2,   # Path Traversal
    "CWE-601": 3,   # Open Redirect
    "CWE-94":  4,   # RCE / Code Injection
}

CWE_NAMES: dict[str, str] = {
    "CWE-89":  "SQLi",
    "CWE-79":  "XSS",
    "CWE-22":  "PathTraversal",
    "CWE-601": "OpenRedirect",
    "CWE-94":  "RCE",
}

# Broader CWE IDs that map onto our 5 classes
CWE_ALIASES: dict[str, str] = {
    "CWE-943": "CWE-89",   "CWE-564": "CWE-89",
    "CWE-80":  "CWE-79",   "CWE-83":  "CWE-79",
    "CWE-23":  "CWE-22",   "CWE-36":  "CWE-22",
    "CWE-73":  "CWE-22",
    "CWE-183": "CWE-601",
    "CWE-78":  "CWE-94",   "CWE-77":  "CWE-94",
    "CWE-95":  "CWE-94",   "CWE-96":  "CWE-94",
}


def resolve_cwe(cwe_id: str) -> str | None:
    """Map a raw CWE ID to one of our 8 SYRTH classes."""
    if cwe_id in CWE_LABELS:
        return cwe_id
    return CWE_ALIASES.get(cwe_id)


# ---------------------------------------------------------------------------
# In-memory diff helper — NO temp files, NO disk writes
# ---------------------------------------------------------------------------

def diff_from_source(
    vuln_src: str,
    patched_src: str,
    vuln_label: str = "vulnerable",
    patched_label: str = "patched",
) -> dict[str, Any]:
    """
    Run a structural diff between two source strings entirely in memory.
    Uses extract_traces_from_source() — never touches the filesystem.
    """
    old_trace = extract_traces_from_source(vuln_src, label=vuln_label)
    new_trace = extract_traces_from_source(patched_src, label=patched_label)
    return diff_traces(old_trace, new_trace)


def tokens_from_diff(diff: dict[str, Any]) -> list[str]:
    """Flatten the vulnerable-side token sequences out of a diff result."""
    tokens: list[str] = []
    for func in diff["functions"].get("modified", []):
        tokens.extend(func.get("vulnerable_tokens", []))
    for func in diff["functions"].get("removed", []):
        tokens.extend(func.get("tokens", []))
    return tokens


# ---------------------------------------------------------------------------
# Synthetic template library — 82 hand-crafted vulnerable / patched pairs
# ---------------------------------------------------------------------------

_T = textwrap.dedent

# Each entry: (cwe_id, vulnerable_source, patched_source, variant_tag)
_TEMPLATES: list[tuple[str, str, str, str]] = [

    # ════════════════════════════════════════════════════════════════════════
    # CWE-89  SQL Injection  (12 variants)
    # ════════════════════════════════════════════════════════════════════════

    ("CWE-89", _T("""\
        from django.db import connection
        def get_user_by_id(request):
            uid = request.GET.get('id')
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id=" + uid)
            return cursor.fetchone()
    """), _T("""\
        from django.db import connection
        def get_user_by_id(request):
            uid = request.GET.get('id')
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id=%s", [uid])
            return cursor.fetchone()
    """), "django_raw_concat"),

    ("CWE-89", _T("""\
        from django.db import models
        def search_products(request):
            q = request.GET.get('q', '')
            return Product.objects.raw(f"SELECT * FROM products WHERE name='{q}'")
    """), _T("""\
        from django.db import models
        def search_products(request):
            q = request.GET.get('q', '')
            return Product.objects.filter(name__icontains=q)
    """), "django_raw_fstring"),

    ("CWE-89", _T("""\
        from django.db import connection
        def get_orders(request):
            status = request.POST.get('status')
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM orders WHERE status='%s'" % status)
            return cursor.fetchall()
    """), _T("""\
        from django.db import connection
        def get_orders(request):
            status = request.POST.get('status')
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM orders WHERE status=%s", [status])
            return cursor.fetchall()
    """), "django_percent_format"),

    ("CWE-89", _T("""\
        from fastapi import APIRouter
        from sqlalchemy import text
        router = APIRouter()
        def search_users(q: str, db=None):
            result = db.execute(text("SELECT * FROM users WHERE name='" + q + "'"))
            return result.fetchall()
    """), _T("""\
        from fastapi import APIRouter
        from sqlalchemy import text
        router = APIRouter()
        def search_users(q: str, db=None):
            result = db.execute(text("SELECT * FROM users WHERE name=:q"), {"q": q})
            return result.fetchall()
    """), "fastapi_sqlalchemy_concat"),

    ("CWE-89", _T("""\
        from django.db import connection
        def filter_by_category(request):
            cat = request.GET.get('category', 'all')
            sql = f"SELECT id, name FROM items WHERE category='{cat}' ORDER BY name"
            cursor = connection.cursor()
            cursor.execute(sql)
            return cursor.fetchall()
    """), _T("""\
        from django.db import connection
        def filter_by_category(request):
            cat = request.GET.get('category', 'all')
            cursor = connection.cursor()
            cursor.execute(
                "SELECT id, name FROM items WHERE category=%s ORDER BY name",
                [cat],
            )
            return cursor.fetchall()
    """), "django_fstring_order"),

    ("CWE-89", _T("""\
        import sqlite3
        def login_check(request):
            username = request.POST.get('username')
            password = request.POST.get('password')
            conn = sqlite3.connect('db.sqlite3')
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM auth_user WHERE username='"
                + username + "' AND password='" + password + "'"
            )
            return cur.fetchone()
    """), _T("""\
        import sqlite3
        def login_check(request):
            username = request.POST.get('username')
            password = request.POST.get('password')
            conn = sqlite3.connect('db.sqlite3')
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM auth_user WHERE username=? AND password=?",
                (username, password),
            )
            return cur.fetchone()
    """), "sqlite3_login"),

    ("CWE-89", _T("""\
        from django.db import models
        def admin_search(request):
            term = request.GET.get('term', '')
            return User.objects.raw(
                'SELECT * FROM auth_user WHERE email LIKE "%' + term + '%"'
            )
    """), _T("""\
        from django.db import models
        def admin_search(request):
            term = request.GET.get('term', '')
            return User.objects.filter(email__icontains=term)
    """), "django_like_injection"),

    ("CWE-89", _T("""\
        def generate_report(start, end, db=None):
            query = f"SELECT * FROM sales WHERE date BETWEEN '{start}' AND '{end}'"
            return db.execute(query).fetchall()
    """), _T("""\
        from sqlalchemy import text
        def generate_report(start, end, db=None):
            return db.execute(
                text("SELECT * FROM sales WHERE date BETWEEN :s AND :e"),
                {"s": str(start), "e": str(end)},
            ).fetchall()
    """), "fastapi_date_range"),

    ("CWE-89", _T("""\
        from django.db import connection
        class OrderView:
            def get(self, request, order_id):
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT * FROM shop_order WHERE id=" + str(order_id)
                )
                return cursor.fetchone()
    """), _T("""\
        from django.db import connection
        class OrderView:
            def get(self, request, order_id):
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT * FROM shop_order WHERE id=%s", [order_id]
                )
                return cursor.fetchone()
    """), "cbv_str_concat"),

    ("CWE-89", _T("""\
        from django.db import models
        def bulk_update(request):
            ids = request.POST.get('ids', '')
            User.objects.raw(
                f"UPDATE auth_user SET is_active=0 WHERE id IN ({ids})"
            )
    """), _T("""\
        from django.db import models
        def bulk_update(request):
            ids_raw = request.POST.get('ids', '')
            ids = [int(i) for i in ids_raw.split(',') if i.strip().isdigit()]
            User.objects.filter(id__in=ids).update(is_active=False)
    """), "django_in_clause"),

    ("CWE-89", _T("""\
        def delete_record(table, record_id, db=None):
            db.execute(f"DELETE FROM {table} WHERE id={record_id}")
            db.commit()
    """), _T("""\
        from sqlalchemy import text
        ALLOWED_TABLES = frozenset({'product', 'comment', 'tag'})
        def delete_record(table, record_id, db=None):
            if table not in ALLOWED_TABLES:
                raise ValueError('Disallowed table')
            db.execute(text(f"DELETE FROM {table} WHERE id=:rid"), {"rid": record_id})
            db.commit()
    """), "fastapi_table_injection"),

    ("CWE-89", _T("""\
        from django.db import connection
        def paginate(request):
            page = request.GET.get('page', '1')
            limit = request.GET.get('limit', '10')
            offset = (int(page) - 1) * int(limit)
            cursor = connection.cursor()
            cursor.execute(f"SELECT * FROM posts LIMIT {limit} OFFSET {offset}")
            return cursor.fetchall()
    """), _T("""\
        from django.db import connection
        def paginate(request):
            page = max(1, int(request.GET.get('page', '1')))
            limit = min(100, max(1, int(request.GET.get('limit', '10'))))
            offset = (page - 1) * limit
            cursor = connection.cursor()
            cursor.execute(
                "SELECT * FROM posts LIMIT %s OFFSET %s", [limit, offset]
            )
            return cursor.fetchall()
    """), "django_limit_offset"),

    # ════════════════════════════════════════════════════════════════════════
    # CWE-79  XSS  (10 variants)
    # ════════════════════════════════════════════════════════════════════════

    ("CWE-79", _T("""\
        from django.http import HttpResponse
        def greet(request):
            name = request.GET.get('name', 'World')
            return HttpResponse(f'<h1>Hello, {name}!</h1>')
    """), _T("""\
        from django.http import HttpResponse
        from django.utils.html import escape
        def greet(request):
            name = request.GET.get('name', 'World')
            return HttpResponse(f'<h1>Hello, {escape(name)}!</h1>')
    """), "django_response_fstring"),

    ("CWE-79", _T("""\
        from django.utils.safestring import mark_safe
        def render_comment(request):
            body = request.POST.get('body', '')
            safe_body = mark_safe(body)
            return render(request, 'comment.html', {'body': safe_body})
    """), _T("""\
        from django.utils.html import escape
        def render_comment(request):
            body = request.POST.get('body', '')
            safe_body = escape(body)
            return render(request, 'comment.html', {'body': safe_body})
    """), "django_mark_safe"),

    ("CWE-79", _T("""\
        from fastapi.responses import HTMLResponse
        def show_bio(username: str):
            bio = get_bio(username)
            return HTMLResponse(f'<p>{bio}</p>')
    """), _T("""\
        from fastapi.responses import HTMLResponse
        import html
        def show_bio(username: str):
            bio = html.escape(get_bio(username))
            return HTMLResponse(f'<p>{bio}</p>')
    """), "fastapi_html_response"),

    ("CWE-79", _T("""\
        from django.http import HttpResponse
        def search_results(request):
            q = request.GET.get('q', '')
            results = Product.objects.filter(name__icontains=q)
            out = f'<h2>Results for: {q}</h2>'
            for r in results:
                out += f'<p>{r.name}</p>'
            return HttpResponse(out)
    """), _T("""\
        from django.http import HttpResponse
        from django.utils.html import escape
        def search_results(request):
            q = request.GET.get('q', '')
            results = Product.objects.filter(name__icontains=q)
            parts = [f'<h2>Results for: {escape(q)}</h2>']
            for r in results:
                parts.append(f'<p>{escape(r.name)}</p>')
            return HttpResponse(''.join(parts))
    """), "django_loop_xss"),

    ("CWE-79", _T("""\
        from django.shortcuts import render
        def profile(request):
            name = request.user.profile.display_name
            return render(request, 'profile.html', {'title': '<b>' + name + '</b>'})
    """), _T("""\
        from django.shortcuts import render
        from django.utils.html import format_html
        def profile(request):
            name = request.user.profile.display_name
            return render(request, 'profile.html', {'title': format_html('<b>{}</b>', name)})
    """), "django_template_context"),

    ("CWE-79", _T("""\
        from fastapi.responses import HTMLResponse
        async def post_comment(body: str):
            save_comment(body)
            return HTMLResponse('<div class=comment>' + body + '</div>')
    """), _T("""\
        from fastapi.responses import HTMLResponse
        import html
        async def post_comment(body: str):
            save_comment(body)
            return HTMLResponse(f'<div class=comment>{html.escape(body)}</div>')
    """), "fastapi_async_comment"),

    ("CWE-79", _T("""\
        from django.http import HttpResponse
        def autocomplete(request):
            q = request.GET.get('q', '')
            matches = Tag.objects.filter(name__startswith=q).values_list('name', flat=True)
            html_opts = ''.join(f'<option>{m}</option>' for m in matches)
            return HttpResponse(f'<datalist>{html_opts}</datalist>')
    """), _T("""\
        from django.http import HttpResponse
        from django.utils.html import escape
        def autocomplete(request):
            q = request.GET.get('q', '')
            matches = Tag.objects.filter(name__startswith=q).values_list('name', flat=True)
            html_opts = ''.join(f'<option>{escape(m)}</option>' for m in matches)
            return HttpResponse(f'<datalist>{html_opts}</datalist>')
    """), "django_datalist"),

    ("CWE-79", _T("""\
        from django.http import HttpResponse
        def error_page(request):
            msg = request.GET.get('msg', 'An error occurred')
            return HttpResponse(
                f'<html><body><h1>Error</h1><p>{msg}</p></body></html>',
                status=400,
            )
    """), _T("""\
        from django.http import HttpResponse
        from django.utils.html import escape
        def error_page(request):
            msg = escape(request.GET.get('msg', 'An error occurred'))
            return HttpResponse(
                f'<html><body><h1>Error</h1><p>{msg}</p></body></html>',
                status=400,
            )
    """), "django_error_page"),

    ("CWE-79", _T("""\
        from django.template import Template, Context
        def render_notice(request):
            tmpl_str = request.POST.get('template', '')
            t = Template(tmpl_str)
            return HttpResponse(t.render(Context({})))
    """), _T("""\
        from django.shortcuts import render
        def render_notice(request):
            message = request.POST.get('message', '')
            return render(request, 'notice.html', {'message': message})
    """), "django_template_injection"),

    ("CWE-79", _T("""\
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory='templates')
        def welcome(request, username: str):
            html = templates.get_template('welcome.html')
            return html.render({'username': username, 'autoescape': False})
    """), _T("""\
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory='templates')
        def welcome(request, username: str):
            return templates.TemplateResponse(
                'welcome.html', {'request': request, 'username': username}
            )
    """), "jinja2_autoescape_off"),

    # ════════════════════════════════════════════════════════════════════════
    # CWE-22  Path Traversal  (10 variants)
    # ════════════════════════════════════════════════════════════════════════

    ("CWE-22", _T("""\
        import os
        def serve_file(request):
            filename = request.GET.get('file')
            path = os.path.join('/var/uploads', filename)
            with open(path, 'rb') as f:
                return f.read()
    """), _T("""\
        import os
        def serve_file(request):
            filename = os.path.basename(request.GET.get('file', ''))
            path = os.path.realpath(os.path.join('/var/uploads', filename))
            if not path.startswith('/var/uploads'):
                raise PermissionError('Path traversal blocked')
            with open(path, 'rb') as f:
                return f.read()
    """), "django_static_serve"),

    ("CWE-22", _T("""\
        from pathlib import Path
        from fastapi.responses import FileResponse
        BASE = Path('/data/reports')
        def download_report(filename: str):
            return FileResponse(BASE / filename)
    """), _T("""\
        from pathlib import Path
        from fastapi.responses import FileResponse
        BASE = Path('/data/reports').resolve()
        def download_report(filename: str):
            target = (BASE / filename).resolve()
            if not str(target).startswith(str(BASE)):
                raise ValueError('Path traversal blocked')
            return FileResponse(target)
    """), "fastapi_pathlib_traversal"),

    ("CWE-22", _T("""\
        import os
        def read_log(request):
            log_name = request.GET.get('log', 'app.log')
            log_path = '/var/log/app/' + log_name
            with open(log_path) as f:
                return f.read()
    """), _T("""\
        import os
        LOG_DIR = os.path.realpath('/var/log/app')
        def read_log(request):
            log_name = os.path.basename(request.GET.get('log', 'app.log'))
            log_path = os.path.realpath(os.path.join(LOG_DIR, log_name))
            if not log_path.startswith(LOG_DIR + os.sep):
                raise PermissionError('Access denied')
            with open(log_path) as f:
                return f.read()
    """), "django_log_read"),

    ("CWE-22", _T("""\
        import shutil
        from django.http import JsonResponse
        def copy_template(request):
            src = request.POST.get('src')
            dst = request.POST.get('dst')
            shutil.copy('/templates/' + src, '/output/' + dst)
            return JsonResponse({'ok': True})
    """), _T("""\
        import shutil, os
        from django.http import JsonResponse
        TEMPLATE_DIR = os.path.realpath('/templates')
        OUTPUT_DIR = os.path.realpath('/output')
        def _safe(base: str, name: str) -> str:
            full = os.path.realpath(os.path.join(base, name))
            if not full.startswith(base):
                raise PermissionError('Traversal blocked')
            return full
        def copy_template(request):
            src = _safe(TEMPLATE_DIR, request.POST.get('src', ''))
            dst = _safe(OUTPUT_DIR, request.POST.get('dst', ''))
            shutil.copy(src, dst)
            return JsonResponse({'ok': True})
    """), "django_shutil_copy"),

    ("CWE-22", _T("""\
        from fastapi import UploadFile
        import aiofiles
        async def upload_file(file: UploadFile, subdir: str = ''):
            dest = f'/uploads/{subdir}/{file.filename}'
            async with aiofiles.open(dest, 'wb') as f:
                await f.write(await file.read())
            return {'path': dest}
    """), _T("""\
        from fastapi import UploadFile
        from pathlib import Path
        import aiofiles
        UPLOAD_ROOT = Path('/uploads').resolve()
        async def upload_file(file: UploadFile, subdir: str = ''):
            safe_name = Path(file.filename).name
            safe_sub = Path(subdir).name
            dest = (UPLOAD_ROOT / safe_sub / safe_name).resolve()
            if not str(dest).startswith(str(UPLOAD_ROOT)):
                raise ValueError('Path traversal blocked')
            dest.parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(dest, 'wb') as f:
                await f.write(await file.read())
            return {'path': str(dest.relative_to(UPLOAD_ROOT))}
    """), "fastapi_upload_traversal"),

    ("CWE-22", _T("""\
        import os
        from django.http import HttpResponse
        def export_csv(request):
            report_name = request.GET.get('name')
            path = os.path.join('/exports', report_name + '.csv')
            with open(path) as f:
                return HttpResponse(f.read(), content_type='text/csv')
    """), _T("""\
        import os, re
        from django.http import HttpResponse
        EXPORT_DIR = os.path.realpath('/exports')
        def export_csv(request):
            name = request.GET.get('name', '')
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', name):
                raise ValueError('Invalid report name')
            path = os.path.realpath(os.path.join(EXPORT_DIR, name + '.csv'))
            if not path.startswith(EXPORT_DIR):
                raise PermissionError('Traversal blocked')
            with open(path) as f:
                return HttpResponse(f.read(), content_type='text/csv')
    """), "django_csv_export"),

    ("CWE-22", _T("""\
        import zipfile
        def extract_archive(request):
            archive_path = request.POST.get('archive')
            extract_to = '/tmp/extracted'
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(extract_to)
            return {'extracted': True}
    """), _T("""\
        import zipfile, os
        EXTRACT_BASE = os.path.realpath('/tmp/extracted')
        def extract_archive(request):
            archive_path = request.POST.get('archive', '')
            with zipfile.ZipFile(archive_path) as zf:
                for member in zf.namelist():
                    dest = os.path.realpath(os.path.join(EXTRACT_BASE, member))
                    if not dest.startswith(EXTRACT_BASE):
                        raise PermissionError(f'Zip slip: {member}')
                zf.extractall(EXTRACT_BASE)
            return {'extracted': True}
    """), "zip_slip"),

    ("CWE-22", _T("""\
        from fastapi.responses import FileResponse
        from pathlib import Path
        THEMES_ROOT = Path('/static/themes')
        def get_skin(theme: str, filename: str):
            return FileResponse(THEMES_ROOT / theme / filename)
    """), _T("""\
        from fastapi.responses import FileResponse
        from pathlib import Path
        THEMES_ROOT = Path('/static/themes').resolve()
        ALLOWED_EXTS = frozenset({'.css', '.png', '.svg'})
        def get_skin(theme: str, filename: str):
            target = (THEMES_ROOT / Path(theme).name / Path(filename).name).resolve()
            if not str(target).startswith(str(THEMES_ROOT)):
                raise ValueError('Traversal blocked')
            if target.suffix not in ALLOWED_EXTS:
                raise ValueError('Disallowed file type')
            return FileResponse(target)
    """), "fastapi_theme_traversal"),

    ("CWE-22", _T("""\
        import os
        from django.http import JsonResponse
        def delete_cache(request):
            key = request.POST.get('key')
            cache_file = '/cache/' + key + '.cache'
            if os.path.exists(cache_file):
                os.remove(cache_file)
            return JsonResponse({'deleted': True})
    """), _T("""\
        import os, re
        from django.http import JsonResponse
        CACHE_DIR = os.path.realpath('/cache')
        def delete_cache(request):
            key = request.POST.get('key', '')
            if not re.fullmatch(r'[a-f0-9]{32}', key):
                raise ValueError('Invalid cache key')
            cache_file = os.path.realpath(os.path.join(CACHE_DIR, key + '.cache'))
            if not cache_file.startswith(CACHE_DIR):
                raise PermissionError('Traversal blocked')
            if os.path.exists(cache_file):
                os.remove(cache_file)
            return JsonResponse({'deleted': True})
    """), "django_cache_delete"),

    ("CWE-22", _T("""\
        import subprocess
        def process_file(filename: str):
            result = subprocess.run(
                ['convert', '/uploads/' + filename, '-resize', '100x100', '/thumbs/' + filename],
                capture_output=True,
            )
            return {'ok': result.returncode == 0}
    """), _T("""\
        import subprocess
        from pathlib import Path
        UPLOAD_ROOT = Path('/uploads').resolve()
        THUMB_ROOT = Path('/thumbs').resolve()
        ALLOWED_EXTS = frozenset({'.jpg', '.jpeg', '.png', '.webp'})
        def process_file(filename: str):
            safe_name = Path(filename).name
            src = (UPLOAD_ROOT / safe_name).resolve()
            dst = (THUMB_ROOT / safe_name).resolve()
            if not str(src).startswith(str(UPLOAD_ROOT)) or src.suffix not in ALLOWED_EXTS:
                raise ValueError('Invalid file')
            subprocess.run(['convert', str(src), '-resize', '100x100', str(dst)], capture_output=True)
            return {'ok': True}
    """), "fastapi_imagemagick_traversal"),

    # ════════════════════════════════════════════════════════════════════════
    # CWE-601  Open Redirect  (8 variants)
    # ════════════════════════════════════════════════════════════════════════

    ("CWE-601", _T("""\
        from django.shortcuts import redirect
        def login_view(request):
            next_url = request.GET.get('next', '/')
            return redirect(next_url)
    """), _T("""\
        from django.shortcuts import redirect
        from django.utils.http import url_has_allowed_host_and_scheme
        def login_view(request):
            next_url = request.GET.get('next', '/')
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                next_url = '/'
            return redirect(next_url)
    """), "django_login_next"),

    ("CWE-601", _T("""\
        from fastapi.responses import RedirectResponse
        def oauth_callback(state: str, code: str):
            return RedirectResponse(url=state)
    """), _T("""\
        from fastapi.responses import RedirectResponse
        from urllib.parse import urlparse
        ALLOWED_HOSTS = frozenset({'app.example.com'})
        def oauth_callback(state: str, code: str):
            parsed = urlparse(state)
            if parsed.hostname not in ALLOWED_HOSTS:
                return RedirectResponse(url='/dashboard')
            return RedirectResponse(url=state)
    """), "fastapi_oauth_redirect"),

    ("CWE-601", _T("""\
        from django.http import HttpResponseRedirect
        def after_logout(request):
            return_to = request.GET.get('return_to', '/')
            return HttpResponseRedirect(return_to)
    """), _T("""\
        from django.http import HttpResponseRedirect
        from django.utils.http import url_has_allowed_host_and_scheme
        def after_logout(request):
            return_to = request.GET.get('return_to', '/')
            if not url_has_allowed_host_and_scheme(return_to, allowed_hosts=None, require_https=True):
                return_to = '/'
            return HttpResponseRedirect(return_to)
    """), "django_logout_redirect"),

    ("CWE-601", _T("""\
        from fastapi.responses import RedirectResponse
        def exit_page(url: str = '/'):
            return RedirectResponse(url=url)
    """), _T("""\
        from fastapi.responses import RedirectResponse
        from urllib.parse import urlparse
        def exit_page(url: str = '/'):
            parsed = urlparse(url)
            if parsed.scheme or parsed.netloc:
                url = '/'
            return RedirectResponse(url=url)
    """), "fastapi_exit_redirect"),

    ("CWE-601", _T("""\
        from django.shortcuts import redirect
        def download_redirect(request):
            cdn_url = request.GET.get('cdn')
            if cdn_url:
                return redirect(cdn_url)
            return redirect('/downloads/')
    """), _T("""\
        from django.shortcuts import redirect
        from urllib.parse import urlparse
        CDN_HOST = 'cdn.myapp.com'
        def download_redirect(request):
            cdn_url = request.GET.get('cdn', '')
            parsed = urlparse(cdn_url)
            if cdn_url and parsed.hostname == CDN_HOST and parsed.scheme == 'https':
                return redirect(cdn_url)
            return redirect('/downloads/')
    """), "django_cdn_redirect"),

    ("CWE-601", _T("""\
        from rest_framework.response import Response
        from rest_framework.views import APIView
        class SSOView(APIView):
            def get(self, request):
                relay_state = request.GET.get('RelayState', '/')
                return Response(headers={'Location': relay_state}, status=302)
    """), _T("""\
        from rest_framework.response import Response
        from rest_framework.views import APIView
        from urllib.parse import urlparse
        SAFE_HOSTS = frozenset({'app.corp.com', 'portal.corp.com'})
        class SSOView(APIView):
            def get(self, request):
                relay_state = request.GET.get('RelayState', '/')
                parsed = urlparse(relay_state)
                if parsed.hostname and parsed.hostname not in SAFE_HOSTS:
                    relay_state = '/'
                return Response(headers={'Location': relay_state}, status=302)
    """), "drf_sso_relay"),

    ("CWE-601", _T("""\
        from django.shortcuts import redirect
        def payment_return(request):
            success_url = request.POST.get('success_url')
            cancel_url = request.POST.get('cancel_url')
            if request.GET.get('status') == 'ok':
                return redirect(success_url)
            return redirect(cancel_url)
    """), _T("""\
        from django.shortcuts import redirect
        from django.utils.http import url_has_allowed_host_and_scheme
        def payment_return(request):
            host = request.get_host()
            success_url = request.POST.get('success_url', '/payment/success/')
            cancel_url = request.POST.get('cancel_url', '/payment/cancel/')
            if not url_has_allowed_host_and_scheme(success_url, allowed_hosts={host}):
                success_url = '/payment/success/'
            if not url_has_allowed_host_and_scheme(cancel_url, allowed_hosts={host}):
                cancel_url = '/payment/cancel/'
            if request.GET.get('status') == 'ok':
                return redirect(success_url)
            return redirect(cancel_url)
    """), "django_payment_redirect"),

    ("CWE-601", _T("""\
        from fastapi.responses import RedirectResponse
        def referral_bounce(dest: str, ref_id: str):
            track_referral(ref_id)
            return RedirectResponse(url=dest)
    """), _T("""\
        from fastapi.responses import RedirectResponse
        from urllib.parse import urlparse
        ALLOWED_HOSTS = frozenset({'partner1.com', 'partner2.com'})
        def referral_bounce(dest: str, ref_id: str):
            p = urlparse(dest)
            if p.scheme != 'https' or p.hostname not in ALLOWED_HOSTS:
                return RedirectResponse(url='/')
            track_referral(ref_id)
            return RedirectResponse(url=dest)
    """), "fastapi_referral_redirect"),

    # ════════════════════════════════════════════════════════════════════════
    # CWE-94  RCE / Code Injection  (10 variants)
    # ════════════════════════════════════════════════════════════════════════

    ("CWE-94", _T("""\
        def run_formula(request):
            expr = request.POST.get('formula')
            result = eval(expr)
            return result
    """), _T("""\
        import ast as ast_mod
        def run_formula(request):
            expr = request.POST.get('formula', '')
            try:
                result = ast_mod.literal_eval(expr)
            except (ValueError, SyntaxError):
                result = None
            return result
    """), "django_eval"),

    ("CWE-94", _T("""\
        import subprocess
        def ping_host(host: str):
            result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)
            return {'output': result.stdout.decode()}
    """), _T("""\
        import subprocess, re
        HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}$')
        def ping_host(host: str):
            if not HOSTNAME_RE.match(host):
                raise ValueError('Invalid hostname')
            result = subprocess.run(['ping', '-c', '1', host], capture_output=True, timeout=5)
            return {'output': result.stdout.decode()}
    """), "fastapi_shell_true"),

    ("CWE-94", _T("""\
        import os
        from django.http import JsonResponse
        def run_script(request):
            script_name = request.POST.get('script')
            output = os.system(f'python /scripts/{script_name}.py')
            return JsonResponse({'exit': output})
    """), _T("""\
        import subprocess, re
        from django.http import JsonResponse
        SAFE_NAME = re.compile(r'^[a-z0-9_]{1,32}$')
        def run_script(request):
            script_name = request.POST.get('script', '')
            if not SAFE_NAME.match(script_name):
                return JsonResponse({'error': 'Invalid script name'}, status=400)
            result = subprocess.run(
                ['python', f'/scripts/{script_name}.py'],
                capture_output=True, timeout=30,
            )
            return JsonResponse({'exit': result.returncode})
    """), "django_os_system"),

    ("CWE-94", _T("""\
        import pickle, base64
        from django.http import JsonResponse
        def load_state(request):
            raw = request.POST.get('state')
            data = pickle.loads(base64.b64decode(raw))
            return JsonResponse({'loaded': True})
    """), _T("""\
        import json
        from django.http import JsonResponse
        def load_state(request):
            raw = request.POST.get('state', '{}')
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'invalid'}, status=400)
            return JsonResponse({'loaded': True})
    """), "django_pickle_loads"),

    ("CWE-94", _T("""\
        import yaml
        def load_config(body: str):
            cfg = yaml.load(body)
            apply_config(cfg)
            return {'ok': True}
    """), _T("""\
        import yaml
        def load_config(body: str):
            cfg = yaml.safe_load(body)
            apply_config(cfg)
            return {'ok': True}
    """), "fastapi_yaml_load"),

    ("CWE-94", _T("""\
        from django.http import JsonResponse
        def math_eval(request):
            expr = request.GET.get('expr', '1+1')
            result = eval(compile(expr, '<string>', 'eval'))
            return JsonResponse({'result': result})
    """), _T("""\
        import ast as ast_mod
        from django.http import JsonResponse
        def math_eval(request):
            expr = request.GET.get('expr', '1+1')
            try:
                result = ast_mod.literal_eval(expr)
            except Exception:
                result = None
            return JsonResponse({'result': result})
    """), "django_compile_eval"),

    ("CWE-94", _T("""\
        import subprocess
        def convert_doc(filename: str, fmt: str):
            subprocess.run(
                f'libreoffice --headless --convert-to {fmt} /docs/{filename}',
                shell=True,
            )
            return {'done': True}
    """), _T("""\
        import subprocess
        from pathlib import Path
        ALLOWED_FORMATS = frozenset({'pdf', 'docx', 'odt'})
        DOCS_DIR = Path('/docs').resolve()
        def convert_doc(filename: str, fmt: str):
            if fmt not in ALLOWED_FORMATS:
                raise ValueError('Disallowed format')
            src = (DOCS_DIR / Path(filename).name).resolve()
            if not str(src).startswith(str(DOCS_DIR)):
                raise ValueError('Invalid filename')
            subprocess.run(['libreoffice', '--headless', '--convert-to', fmt, str(src)], timeout=60)
            return {'done': True}
    """), "fastapi_libreoffice"),

    ("CWE-94", _T("""\
        import marshal
        from django.http import JsonResponse
        def restore_session(request):
            raw = bytes.fromhex(request.COOKIES.get('sess', ''))
            data = marshal.loads(raw)
            return JsonResponse(data)
    """), _T("""\
        import hmac, os, json
        from django.http import JsonResponse
        SESSION_KEY = os.environ.get('SESSION_KEY', '').encode()
        def restore_session(request):
            cookie = request.COOKIES.get('sess', '')
            parts = cookie.split('.', 1)
            if len(parts) != 2:
                return JsonResponse({})
            sig, payload = parts
            expected = hmac.new(SESSION_KEY, payload.encode(), 'sha256').hexdigest()
            if not hmac.compare_digest(sig, expected):
                return JsonResponse({})
            return JsonResponse(json.loads(payload))
    """), "django_marshal_loads"),

    ("CWE-94", _T("""\
        from jinja2 import Template
        def render_template(tmpl: str, context: dict):
            t = Template(tmpl)
            return {'html': t.render(**context)}
    """), _T("""\
        from jinja2 import Environment, select_autoescape
        ALLOWED_TEMPLATES = frozenset({'welcome', 'confirm', 'invoice'})
        env = Environment(autoescape=select_autoescape())
        def render_template(tmpl_name: str, context: dict):
            if tmpl_name not in ALLOWED_TEMPLATES:
                raise ValueError('Unknown template')
            t = env.get_template(tmpl_name + '.html')
            return {'html': t.render(**context)}
    """), "fastapi_jinja2_ssti"),

    ("CWE-94", _T("""\
        import subprocess
        from django.http import JsonResponse
        def run_ffmpeg(request):
            input_url = request.POST.get('url')
            output = request.POST.get('output', 'out.mp4')
            import os
            os.system(f'ffmpeg -i {input_url} {output}')
            return JsonResponse({'done': True})
    """), _T("""\
        import subprocess, re
        from urllib.parse import urlparse
        from django.http import JsonResponse
        OUTPUT_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}\\.(mp4|webm|mp3)$')
        def run_ffmpeg(request):
            input_url = request.POST.get('url', '')
            output = request.POST.get('output', 'out.mp4')
            if urlparse(input_url).scheme not in ('https', 'http'):
                return JsonResponse({'error': 'Invalid URL'}, status=400)
            if not OUTPUT_RE.match(output):
                return JsonResponse({'error': 'Invalid output name'}, status=400)
            subprocess.run(['ffmpeg', '-i', input_url, f'/tmp/{output}'], timeout=300, capture_output=True)
            return JsonResponse({'done': True})
    """), "django_ffmpeg_injection"),
]


def _make_record(
    cwe_id: str,
    vuln_src: str,
    patched_src: str,
    variant: str,
) -> dict[str, Any]:
    """
    Build a dataset record from two source strings, entirely in memory.
    No temp files are ever written to disk.
    """
    diff = diff_from_source(
        vuln_src, patched_src,
        vuln_label=f"vuln:{variant}",
        patched_label=f"patched:{variant}",
    )
    tokens = tokens_from_diff(diff)

    return {
        "source": "synthetic",
        "variant": variant,
        "cwe_id": cwe_id,
        "cwe_name": CWE_NAMES[cwe_id],
        "label": CWE_LABELS[cwe_id],
        "tokens": tokens,
        "vulnerable_src": vuln_src.strip(),
        "patched_src": patched_src.strip(),
    }


# ---------------------------------------------------------------------------
# Deterministic synthetic-variant generator (code-derived training tokens)
# ---------------------------------------------------------------------------
# These are NOT hand-written templates; they are generated by combining a set
# of (taint source, dangerous sink) signatures per class. Every generated
# sample is REAL, syntactically-valid Python that collect.py can parse into the
# EXACT same token vocabulary syrth_scan.py emits at inference time
# (def:/arg:/call:/sink:/ret:/@decorator/meta:). This guarantees the training
# vocabulary matches production scanner output -- the prerequisite for honest,
# generalisable accuracy. Deterministic (fixed iteration order, no RNG) so the
# dataset is reproducible bit-for-bit.
#
# Each sample is a (vulnerable_source, patched_source) pair sharing the SAME
# function name, so diff_from_source() extracts the vulnerable-side tokens as
# the labelled training example. The patched side only exists to anchor the
# diff; it is never used as a training label.

_SYNTH_SPECS: dict[str, dict] = {
    "CWE-89": {
        "imports": (
            "import sqlite3\n"
            "from django.db import connection\n"
            "from sqlalchemy import text\n"
            "import sys\n"
            "import os\n"
        ),
        "sources": [
            "user_val = request.GET.get('id', '')",
            "user_val = request.POST.get('q', '')",
            "user_val = request.args.get('term', '')",
            "user_val = params.get('name', '')",
            "user_val = body.get('val', '')",
            "user_val = os.environ.get('INPUT', '')",
            "user_val = input('enter: ')",
            "user_val = sys.argv[1] if len(sys.argv) > 1 else ''",
            "user_val = req.json.get('x', '')",
            "user_val = form.cleaned_data.get('field', '')",
        ],
        "pairs": [
            ("output = cursor.execute('SELECT * FROM users WHERE id=' + user_val)",
             "output = cursor.execute('SELECT * FROM users WHERE id=%s', [user_val])"),
            ("output = connection.execute(f'SELECT * FROM t WHERE name=\"{user_val}\"')",
             "output = connection.execute(text('SELECT * FROM t WHERE name=:n'), {'n': user_val})"),
            ("output = db.session.execute(text('SELECT * FROM t WHERE x=' + user_val))",
             "output = db.session.execute(text('SELECT * FROM t WHERE x=:x'), {'x': user_val})"),
            ("output = User.objects.raw('SELECT * FROM auth WHERE id=' + user_val)",
             "output = User.objects.filter(id__exact=user_val)"),
            ("output = cur.execute('INSERT INTO log VALUES (' + user_val + ')')",
             "output = cur.execute('INSERT INTO log VALUES (%s)', [user_val])"),
            ("output = engine.execute('UPDATE t SET a=' + user_val + ' WHERE id=1')",
             "output = engine.execute(text('UPDATE t SET a=:a WHERE id=1'), {'a': user_val})"),
            ("output = session.execute('SELECT * FROM u WHERE n=' + user_val)",
             "output = session.execute(text('SELECT * FROM u WHERE n=:n'), {'n': user_val})"),
            ("output = conn.execute(\"DELETE FROM t WHERE id='\" + user_val + \"'\")",
             "output = conn.execute('DELETE FROM t WHERE id=%s', [user_val])"),
            ("output = Model.objects.raw('SELECT * FROM m WHERE k=' + user_val)",
             "output = Model.objects.filter(k__exact=user_val)"),
            ("output = cursor.execute(\"SELECT * FROM u WHERE n='\" + user_val + \"'\")",
             "output = cursor.execute('SELECT * FROM u WHERE n=%s', [user_val])"),
            ("output = db.execute('SELECT * FROM p WHERE v=' + user_val)",
             "output = db.execute(text('SELECT * FROM p WHERE v=:v'), {'v': user_val})"),
            ("output = orm.execute('SELECT * FROM w WHERE q=' + user_val)",
             "output = orm.execute(text('SELECT * FROM w WHERE q=:q'), {'q': user_val})"),
        ],
    },
    "CWE-79": {
        "imports": (
            "from django.http import HttpResponse\n"
            "from django.utils.html import escape\n"
            "from django.utils.safestring import mark_safe\n"
            "from django.template.loader import render_to_string\n"
            "from flask import request\n"
            "import html\n"
        ),
        "sources": [
            "user_val = request.GET.get('name', '')",
            "user_val = request.POST.get('comment', '')",
            "user_val = request.args.get('q', '')",
            "user_val = data.get('input', '')",
            "user_val = user_input",
            "user_val = comment_body",
            "user_val = req.headers.get('X-Name', '')",
            "user_val = kwargs.get('text', '')",
        ],
        "pairs": [
            ("output = mark_safe(user_val)",
             "output = mark_safe(escape(user_val))"),
            ("output = HttpResponse(f'<p>{user_val}</p>')",
             "output = HttpResponse(f'<p>{escape(user_val)}</p>')"),
            ("output = render_template_string(tmpl, user_val)",
             "output = render_template_string(tmpl, escape(user_val))"),
            ("output = HttpResponse('<div>' + user_val + '</div>')",
             "output = HttpResponse('<div>' + escape(user_val) + '</div>')"),
            ("output = response.write(user_val)",
             "output = response.write(escape(user_val))"),
            ("output = template.render(user_val)",
             "output = template.render(escape(user_val))"),
            ("output = HttpResponse(f'<b>{user_val}</b>')",
             "output = HttpResponse(f'<b>{escape(user_val)}</b>')"),
            ("output = render_to_string('t.html', {'x': user_val})",
             "output = render_to_string('t.html', {'x': escape(user_val)})"),
            ("output = out.write('<span>' + user_val + '</span>')",
             "output = out.write('<span>' + escape(user_val) + '</span>')"),
            ("output = mark_safe('<em>' + user_val + '</em>')",
             "output = mark_safe(escape('<em>' + user_val + '</em>'))"),
            ("output = HttpResponse(user_val)",
             "output = HttpResponse(escape(user_val))"),
            ("output = ctx.render(user_val)",
             "output = ctx.render(escape(user_val))"),
        ],
    },
    "CWE-22": {
        "imports": (
            "import os\n"
            "import shlex\n"
            "import zipfile\n"
            "import shutil\n"
            "from django.http import HttpResponse\n"
            "from pathlib import Path\n"
        ),
        "sources": [
            "user_val = request.GET.get('file', '')",
            "user_val = request.args.get('path', '')",
            "user_val = filename",
            "user_val = request.POST.get('name', '')",
            "user_val = user_path",
            "user_val = req.params.get('doc', '')",
            "user_val = os.environ.get('F', '')",
            "user_val = args.file",
        ],
        "pairs": [
            ("output = open(user_val, 'rb').read()",
             "output = open(os.path.join(BASE, os.path.basename(user_val)), 'rb').read()"),
            ("output = os.path.join(BASE, user_val)",
             "output = os.path.realpath(os.path.join(BASE, user_val))"),
            ("output = send_file(user_val)",
             "output = send_file(os.path.basename(user_val))"),
            ("output = os.system('cat ' + user_val)",
             "output = os.system('cat ' + shlex.quote(user_val))"),
            ("output = zipfile.ZipFile(user_val).extractall()",
             "output = zipfile.ZipFile(os.path.basename(user_val)).extractall()"),
            ("output = shutil.copy(user_val, DEST)",
             "output = shutil.copy(os.path.basename(user_val), DEST)"),
            ("output = open(BASE + user_val, 'r')",
             "output = open(os.path.realpath(os.path.join(BASE, user_val)), 'r')"),
            ("output = os.remove(user_val)",
             "output = os.remove(os.path.basename(user_val))"),
            ("output = send_from_directory(BASE, user_val)",
             "output = send_from_directory(BASE, os.path.basename(user_val))"),
            ("output = os.listdir(user_val)",
             "output = os.listdir(os.path.realpath(os.path.join(BASE, user_val)))"),
            ("output = open(user_val)",
             "output = open(os.path.basename(user_val))"),
            ("output = Path(user_val).read_text()",
             "output = Path(os.path.basename(user_val)).read_text()"),
        ],
    },
    "CWE-601": {
        "imports": (
            "from django.shortcuts import redirect\n"
            "from django.http import HttpResponseRedirect\n"
            "from django.utils.http import url_has_allowed_host_and_scheme\n"
            "from fastapi.responses import RedirectResponse\n"
            "from urllib.parse import urlparse\n"
        ),
        "sources": [
            "user_val = request.GET.get('next', '/')",
            "user_val = request.args.get('url', '/')",
            "user_val = redirect_target",
            "user_val = request.POST.get('return_to', '/')",
            "user_val = next_url",
            "user_val = req.query.get('dest', '/')",
            "user_val = params.get('goto', '/')",
            "user_val = url_param",
        ],
        "pairs": [
            ("output = redirect(user_val)",
             "output = redirect('/') if not url_has_allowed_host_and_scheme(user_val, allowed_hosts={request.get_host()}) else redirect(user_val)"),
            ("output = HttpResponseRedirect(user_val)",
             "output = HttpResponseRedirect('/') if not _safe_url(user_val) else HttpResponseRedirect(user_val)"),
            ("output = RedirectResponse(url=user_val)",
             "output = RedirectResponse(url='/') if not _ok_host(user_val) else RedirectResponse(url=user_val)"),
            ("output = response.headers['Location'] = user_val",
             "output = response.headers['Location'] = '/' if not _host_ok(user_val) else user_val"),
            ("output = redirect(target)",
             "output = redirect('/') if not is_safe(target) else redirect(target)"),
            ("output = HttpResponseRedirect(next_url)",
             "output = HttpResponseRedirect('/') if not allowed(next_url) else HttpResponseRedirect(next_url)"),
            ("output = RedirectResponse(user_val)",
             "output = RedirectResponse(url='/dashboard') if not same_origin(user_val) else RedirectResponse(url=user_val)"),
            ("output = response.headers['Location'] = dest",
             "output = response.headers['Location'] = '/home' if not safe_host(dest) else dest"),
            ("output = redirect(user_val)",
             "output = redirect('/') if not ok_host(user_val) else redirect(user_val)"),
            ("output = location = user_val",
             "output = location = '/welcome' if not valid_host(user_val) else user_val"),
            ("output = RedirectResponse(url=return_to)",
             "output = RedirectResponse(url='/') if not check_host(return_to) else RedirectResponse(url=return_to)"),
            ("output = redirect(url_param)",
             "output = redirect('/') if not is_internal(url_param) else redirect(url_param)"),
        ],
    },
    "CWE-94": {
        "imports": (
            "import os\n"
            "import shlex\n"
            "import ast as ast_mod\n"
            "import json\n"
            "import pickle\n"
            "import yaml\n"
            "import subprocess\n"
            "import importlib\n"
        ),
        "sources": [
            "user_val = request.GET.get('cmd', '')",
            "user_val = request.args.get('expr', '')",
            "user_val = code_input",
            "user_val = request.POST.get('data', '')",
            "user_val = user_code",
            "user_val = req.json.get('src', '')",
            "user_val = os.environ.get('C', '')",
            "user_val = argv[1] if len(argv) > 1 else ''",
        ],
        "pairs": [
            ("output = eval(user_val)",
             "output = ast_mod.literal_eval(user_val)"),
            ("output = exec(user_val)",
             "output = ast_mod.parse(user_val)"),
            ("output = subprocess.run(user_val, shell=True)",
             "output = subprocess.run(shlex.split(user_val))"),
            ("output = os.system(user_val)",
             "output = os.system(shlex.quote(user_val))"),
            ("output = pickle.loads(user_val.encode())",
             "output = json.loads(user_val)"),
            ("output = yaml.load(user_val)",
             "output = yaml.safe_load(user_val)"),
            ("output = subprocess.call(user_val, shell=True)",
             "output = subprocess.call(shlex.split(user_val))"),
            ("output = __import__(user_val)",
             "output = importlib.import_module('safe')"),
            ("output = exec(open(user_val).read())",
             "output = ast_mod.parse(open(user_val).read())"),
            ("output = os.popen(user_val).read()",
             "output = os.popen(shlex.quote(user_val)).read()"),
            ("output = subprocess.Popen(user_val, shell=True)",
             "output = subprocess.Popen(shlex.split(user_val))"),
            ("output = compile(user_val, '<s>', 'exec')",
             "output = compile(user_val, '<s>', 'eval')"),
        ],
    },
}


def _build_variant_modules(idx: int, spec: dict, source: str, vuln_stmt: str, safe_stmt: str):
    """Return (vulnerable_source, patched_source) for one generated sample.

    Both share the same function name ``handler_<idx>`` so diff_from_source()
    treats them as a modification and yields the vulnerable-side tokens.
    """
    name = f"handler_{idx}"
    header = spec["imports"] + f"\n\ndef {name}(request):\n"
    vuln = header + f"    {source}\n    {vuln_stmt}\n    return output\n"
    safe = header + f"    {source}\n    {safe_stmt}\n    return output\n"
    return vuln, safe


def iter_synthetic_variants() -> list[tuple[str, str, str, str]]:
    """Yield (cwe_id, vulnerable_source, patched_source, variant_tag) tuples.

    Deterministic order: outer loop over CWE specs (stable dict order), then
    sources, then (vulnerable, patched) pairs. No randomness.
    """
    out: list[tuple[str, str, str, str]] = []
    idx = 0
    for cwe_id, spec in _SYNTH_SPECS.items():
        for source in spec["sources"]:
            for vuln_stmt, safe_stmt in spec["pairs"]:
                vuln, safe = _build_variant_modules(idx, spec, source, vuln_stmt, safe_stmt)
                out.append((cwe_id, vuln, safe, f"gen_{cwe_id}_{idx}"))
                idx += 1
    return out


def generate_synthetic_samples() -> list[dict[str, Any]]:
    """
    Generate all synthetic records in-memory.

    Combines the hand-crafted _TEMPLATES with the deterministically generated
    variant library (iter_synthetic_variants). Every record is produced by
    diff_from_source() so training tokens are code-derived (def:/arg:/call:/
    sink:/ret:/@decorator/meta:) -- identical to syrth_scan.py inference output.
    No temporary files are created. Errors are reported but do not halt.
    """
    samples: list[dict[str, Any]] = []
    errors: list[str] = []

    for cwe_id, vuln_src, patched_src, variant in _TEMPLATES:
        try:
            record = _make_record(cwe_id, vuln_src, patched_src, variant)
            samples.append(record)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"  [{variant}] {exc}")

    for cwe_id, vuln_src, patched_src, variant in iter_synthetic_variants():
        try:
            record = _make_record(cwe_id, vuln_src, patched_src, variant)
            samples.append(record)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"  [{variant}] {exc}")

    if errors:
        sys.stderr.write(
            f"[SYRTH harvester] {len(errors)} template error(s):\n"
            + "\n".join(errors) + "\n"
        )

    n_templates = len(_TEMPLATES)
    n_variants = len(iter_synthetic_variants())
    sys.stderr.write(
        f"[SYRTH harvester] Synthetic: {len(samples)} records "
        f"({n_templates} handcrafted + {n_variants} generated).\n"
    )
    return samples


# ---------------------------------------------------------------------------
# OSV bulk feed
# ---------------------------------------------------------------------------

_OSV_PIP_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

_TARGET_PKGS = re.compile(
    r"(django|fastapi|starlette|flask|tornado|aiohttp|djangorestframework|"
    r"bottle|pyramid|cherrypy|falcon|quart|sanic|web2py|pylons|turbogears|"
    r"connexion|flask-restful|flask-jwt|flask-cors|graphene|strawberry|"
    r"werkzeug|uvicorn|gunicorn|mod-wsgi|"
    r"httpx|requests|urllib3|h11|h2|wsproto|"
    r"channels|daphne|asgiref|cors|"
    r"fastapi-utils|starlette-wtf|uvloop|"
    r"apistar|responder|hug|molten|sapphire|"
    r"django-cors|django-oauth|django-allauth|django-filter|"
    r"flask-login|flask-admin|flask-sqlalchemy|flask-migrate|"
    r"bcrypt|argon2|passlib|itsdangerous|hashids|"
    r"python-jose|python-jwt|jose|jwt|pyjwt|"
    r"oauthlib|requests-oauthlib|authlib|social-auth|"
    r"certifi|cryptography|pyopenssl|idna|)",
    re.IGNORECASE,
)

_CWE_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["sql injection", "sqli", "raw query", "cursor.execute"], "CWE-89"),
    (["xss", "cross-site scripting", "html injection", "mark_safe", "autoescape"], "CWE-79"),
    (["path traversal", "directory traversal", "zip slip", "../", "filename injection"], "CWE-22"),
    (["open redirect", "unvalidated redirect", "relaystate"], "CWE-601"),
    (["remote code execution", "rce", "code injection", "eval(", "exec(",
      "pickle", "yaml.load", "deserialization", "shell=true", "ssti",
      "template injection"], "CWE-94"),
]


def _infer_cwe_from_text(text: str) -> str | None:
    lower = text.lower()
    for keywords, cwe_id in _CWE_KEYWORD_MAP:
        if any(kw in lower for kw in keywords):
            return cwe_id
    return None


def _tokenise_description(description: str, cwe_id: str) -> list[str]:
    # NOTE: deliberately does NOT emit a "cwe:<id>" token. Including the
    # ground-truth CWE as a feature would leak the label and let the model
    # "cheat". The class is the prediction target, never an input.
    tokens: list[str] = []
    for frag in re.findall(r"`([^`]{1,80})`", description)[:10]:
        tokens.append(f"code:{normalise_token(frag)}")
    for sink in SINK_REGISTRY:
        if sink.lower() in description.lower():
            tokens.append(f"sink:{sink}")
    for sev in ("critical", "high", "moderate", "low"):
        if sev in description.lower():
            tokens.append(f"severity:{sev}")
            break
    for fw in ("django", "fastapi", "flask", "starlette", "drf"):
        if fw in description.lower():
            tokens.append(f"framework:{fw}")
    return tokens or ["no_code_context"]


def _tokens_from_advisory_code(description: str) -> list[str]:
    """Extract inference-aligned tokens from python fenced code in an advisory.

    The code is run through collect.py's AST extractor so training tokens use
    exactly the same vocabulary/format as syrth_scan.py produces at inference
    time (def:/arg:/sink:/call:/ret:/@decorator/meta:no_auth). Returns [] when
    no parseable python code is present.
    """
    try:
        from collect import extract_traces_from_source
    except Exception:
        return []
    out: list[str] = []
    for block in re.findall(r"```(?:python|py)?\s*(.*?)```", description, re.DOTALL):
        try:
            ft = extract_traces_from_source(block, label="<advisory>")
        except Exception:
            continue
        for func in ft.functions:
            seq = func.to_token_sequence()
            if seq:
                out.extend(seq)
    seen: set[str] = set()
    deduped: list[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def _build_advisory_tokens(description: str, severity: str, cwe_id: str) -> list[str]:
    """Prefer code-derived (inference-aligned) tokens; fall back to text tokens."""
    code_tokens = _tokens_from_advisory_code(description)
    if code_tokens:
        # Keep only AST-derived tokens (def:/arg:/sink:/call:/ret:/@/meta:)
        # Discard code: text tokens — they don't match syrth_scan.py inference vocabulary
        ast_prefixes = ("def:", "arg:", "sink:", "call:", "ret:", "@", "meta:", "flow:")
        ast_tokens = [t for t in code_tokens if t.startswith(ast_prefixes)]
        if len(ast_tokens) >= 3:
            if isinstance(severity, dict):
                severity = severity.get("type", "")
            elif isinstance(severity, list):
                severity = severity[0] if severity else ""
            sev = str(severity or "").lower()
            if sev in ("critical", "high", "moderate", "low"):
                ast_tokens = ast_tokens + [f"severity:{sev}"]
            return ast_tokens
    return _tokenise_description(description, cwe_id)


def fetch_osv_records(max_entries: int = 10000) -> list[dict[str, Any]]:
    """
    Download the OSV PyPI bulk ZIP (~50MB) and extract matching records.
    No auth token required. Returns [] on any network error.
    """
    if not _REQUESTS_OK:
        sys.stderr.write("[SYRTH harvester] requests not installed — skipping OSV.\n")
        return []

    sys.stderr.write(f"[SYRTH harvester] Downloading OSV PyPI feed from {_OSV_PIP_ZIP} ...\n")
    try:
        resp = requests.get(_OSV_PIP_ZIP, timeout=120, stream=True)
        resp.raise_for_status()
        raw = resp.content
    except requests.RequestException as exc:
        sys.stderr.write(f"[SYRTH harvester] OSV download failed: {exc}\n")
        return []

    records: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            sys.stderr.write(
                f"[SYRTH harvester] OSV ZIP: {len(names)} entries, scanning...\n"
            )
            for name in names[:max_entries]:
                try:
                    osv = json.loads(zf.read(name))
                except json.JSONDecodeError:
                    continue

                # Package filter
                affected = osv.get("affected", [])
                pkgs = [a.get("package", {}).get("name", "") for a in affected]
                if not any(_TARGET_PKGS.search(p) for p in pkgs):
                    continue

                # CWE resolution
                cwe_id: str | None = None
                for raw_cwe in osv.get("database_specific", {}).get("cwe_ids", []):
                    cwe_id = resolve_cwe(raw_cwe)
                    if cwe_id:
                        break
                if cwe_id is None:
                    text = osv.get("summary", "") + " " + osv.get("details", "")
                    cwe_id = _infer_cwe_from_text(text)
                if cwe_id is None:
                    continue

                description = osv.get("summary", "") + "\n" + osv.get("details", "")
                tokens = _build_advisory_tokens(description, osv.get("severity", ""), cwe_id)

                records.append({
                    "source": "osv",
                    "osv_id": osv.get("id", ""),
                    "packages": pkgs,
                    "cwe_id": cwe_id,
                    "cwe_name": CWE_NAMES[cwe_id],
                    "label": CWE_LABELS[cwe_id],
                    "tokens": tokens,
                    "summary": osv.get("summary", ""),
                })

    except zipfile.BadZipFile as exc:
        sys.stderr.write(f"[SYRTH harvester] OSV bad zip: {exc}\n")

    sys.stderr.write(
        f"[SYRTH harvester] OSV: {len(records)} usable records extracted.\n"
    )
    return records


# ---------------------------------------------------------------------------
# GitHub Advisory API - Enhanced
# ---------------------------------------------------------------------------

_GQL_QUERY = """
query($cursor: String, $ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(
    first: 100
    after: $cursor
    ecosystem: $ecosystem
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        description
        cwes(first: 10) { nodes { cweId name } }
        severity
        publishedAt
        updatedAt
        withdrawnAt
        identifiers {
          type
          value
        }
        references {
          url
        }
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

# Additional query for historical advisories (by severity)
_GQL_QUERY_BY_SEVERITY = """
query($cursor: String, $ecosystem: SecurityAdvisoryEcosystem!, $severity: SecurityAdvisorySeverity!) {
  securityVulnerabilities(
    first: 100
    after: $cursor
    ecosystem: $ecosystem
    severity: $severity
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        description
        cwes(first: 10) { nodes { cweId name } }
        severity
        publishedAt
        updatedAt
        withdrawnAt
        identifiers {
          type
          value
        }
        references {
          url
        }
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

_GH_API = "https://api.github.com/graphql"


def fetch_gh_advisories(
    token: str,
    max_pages: int = 50,
    severity_filter: str | None = None,
    include_all_packages: bool = True
) -> list[dict[str, Any]]:
    """Fetch advisories from GitHub Advisory Database.
    
    Args:
        token: GitHub API token
        max_pages: Maximum pages to fetch (100 records per page, default 50 = 5000 records)
        severity_filter: Filter by severity (CRITICAL, HIGH, MODERATE, LOW) or None for all
        include_all_packages: If True, fetch all Python packages; if False, only Django/FastAPI
    """
    if not _REQUESTS_OK:
        sys.stderr.write("[SYRTH harvester] requests not installed — skipping GitHub.\n")
        return []

    headers = {"Authorization": f"bearer {token}", "Content-Type": "application/json"}
    all_nodes: list[dict[str, Any]] = []
    
    # Choose query based on severity filter
    query = _GQL_QUERY_BY_SEVERITY if severity_filter else _GQL_QUERY
    variables: dict[str, Any] = {"cursor": None, "ecosystem": "PIP"}
    if severity_filter:
        variables["severity"] = severity_filter

    cursor: str | None = None
    pages_fetched = 0
    
    sys.stderr.write(
        f"[SYRTH harvester] Fetching GitHub advisories (max {max_pages} pages, "
        f"severity: {severity_filter or 'ALL'}, all_pkgs: {include_all_packages})...\n"
    )

    for page_num in range(max_pages):
        variables["cursor"] = cursor
        
        # Retry logic with exponential backoff
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.post(
                    _GH_API,
                    json={"query": query, "variables": variables},
                    headers=headers,
                    timeout=30,
                )
                
                # Handle rate limiting
                if resp.status_code == 403:
                    reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
                    if reset_time > 0:
                        wait_time = max(1, reset_time - int(time.time()))
                        sys.stderr.write(
                            f"[SYRTH harvester] Rate limited. Waiting {wait_time}s...\n"
                        )
                        time.sleep(min(wait_time, 60))  # Max wait 60s
                        continue
                
                resp.raise_for_status()
                break
                
            except requests.Timeout:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    sys.stderr.write(
                        f"[SYRTH harvester] Timeout, retrying in {wait}s...\n"
                    )
                    time.sleep(wait)
                else:
                    sys.stderr.write(
                        f"[SYRTH harvester] Failed after {max_retries} attempts.\n"
                    )
                    return all_nodes
                    
            except requests.RequestException as exc:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    sys.stderr.write(
                        f"[SYRTH harvester] Request error: {exc}, retrying in {wait}s...\n"
                    )
                    time.sleep(wait)
                else:
                    sys.stderr.write(
                        f"[SYRTH harvester] GitHub API error after retries: {exc}\n"
                    )
                    return all_nodes

        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"[SYRTH harvester] Invalid JSON response: {exc}\n")
            continue

        if "errors" in data:
            error_msg = data["errors"][0].get("message", "Unknown GraphQL error")
            sys.stderr.write(f"[SYRTH harvester] GraphQL error: {error_msg}\n")
            # Continue with partial data if available
            if "data" not in data:
                break

        # Check for valid data structure
        if "data" not in data or not data["data"]:
            sys.stderr.write("[SYRTH harvester] Empty response from GitHub API.\n")
            break
            
        vuln_data = data["data"].get("securityVulnerabilities", {})
        nodes = vuln_data.get("nodes", [])
        
        if not nodes:
            sys.stderr.write(f"[SYRTH harvester] No more advisories found at page {page_num + 1}.\n")
            break

        # Filter nodes
        for node in nodes:
            package_name = node.get("package", {}).get("name", "")
            
            # Skip if already withdrawn
            advisory = node.get("advisory", {})
            if advisory.get("withdrawnAt"):
                continue
            
            # Apply package filter
            if include_all_packages:
                # Accept all Python packages
                all_nodes.append(node)
            else:
                # Only accept Django/FastAPI packages
                if _TARGET_PKGS.search(package_name):
                    all_nodes.append(node)

        pages_fetched += 1
        
        # Progress report every 10 pages
        if (page_num + 1) % 10 == 0:
            sys.stderr.write(
                f"[SYRTH harvester] Progress: {pages_fetched} pages, "
                f"{len(all_nodes)} advisories fetched...\n"
            )

        # Pagination
        page_info = vuln_data.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            sys.stderr.write(
                f"[SYRTH harvester] Reached end of results at page {page_num + 1}.\n"
            )
            break
            
        cursor = page_info.get("endCursor")
        if not cursor:
            break
            
        # Respect rate limits with dynamic delay
        # GitHub allows 5000 points/hour for GraphQL
        # Each request costs at least 1 point, complex queries cost more
        time.sleep(0.5)  # Conservative: ~7200 requests/hour max

    sys.stderr.write(
        f"[SYRTH harvester] GitHub: {len(all_nodes)} advisory nodes fetched "
        f"({pages_fetched} pages).\n"
    )
    return all_nodes


def _gh_node_to_record(node: dict[str, Any]) -> dict[str, Any] | None:
    """Convert GitHub advisory node to SYRTH record format.
    
    Extracts comprehensive metadata including:
    - CVE/CWE identifiers
    - Vulnerable and patched versions
    - External references
    - All available CWE mappings
    """
    advisory = node.get("advisory", {})
    package_info = node.get("package", {})
    
    # Resolve CWE with multiple fallbacks
    cwe_id: str | None = None
    cwe_nodes = advisory.get("cwes", {}).get("nodes", [])
    
    # Try each CWE in order
    for entry in cwe_nodes:
        cwe_id = resolve_cwe(entry.get("cweId", ""))
        if cwe_id:
            break
    
    # Fallback to text inference
    if cwe_id is None:
        description_text = (
            advisory.get("summary", "") + " " + 
            advisory.get("description", "")
        )
        cwe_id = _infer_cwe_from_text(description_text)
    
    if cwe_id is None:
        return None

    # Extract CVE and other identifiers - ensure lists are never None
    identifiers = advisory.get("identifiers") or []
    cve_ids = [i.get("value") for i in identifiers if i.get("type") == "CVE"]
    ghsa_id = advisory.get("ghsaId", "")
    
    # Get package details
    package_name = package_info.get("name", "")
    ecosystem = package_info.get("ecosystem", "PIP")
    
    # Version information - handle None values properly
    vuln_range = node.get("vulnerableVersionRange", "") or ""
    first_patched_obj = node.get("firstPatchedVersion") or {}
    first_patched = first_patched_obj.get("identifier", "") if first_patched_obj else ""
    
    # Build rich description
    description_parts = [
        advisory.get("summary", ""),
        advisory.get("description", ""),
    ]
    
    # Add CVE info if available
    if cve_ids:
        description_parts.append(f"CVE: {', '.join(cve_ids)}")
    
    # Add version info
    if vuln_range:
        description_parts.append(f"Affected: {vuln_range}")
    if first_patched:
        description_parts.append(f"Patched in: {first_patched}")
    
    # Add references for context - ensure lists are never None
    refs = advisory.get("references") or []
    if refs:
        ref_urls = [r.get("url", "") for r in refs[:3] if r.get("url")]  # First 3 refs
        if ref_urls:
            description_parts.append(f"References: {', '.join(ref_urls)}")
    
    full_description = "\n".join(filter(None, description_parts))
    
    # Ensure cwe_nodes is never None
    all_cwe_list = [e.get("cweId", "") for e in (cwe_nodes or []) if e.get("cweId")]
    
    return {
        "source": "github_advisory",
        "ghsa_id": ghsa_id,
        "cve_ids": cve_ids,
        "package": package_name,
        "ecosystem": ecosystem,
        "cwe_id": cwe_id,
        "cwe_name": CWE_NAMES.get(cwe_id, "Unknown"),
        "label": CWE_LABELS.get(cwe_id, -1),
        "severity": advisory.get("severity", "UNKNOWN"),
        "published_at": advisory.get("publishedAt", ""),
        "updated_at": advisory.get("updatedAt", ""),
        "vulnerable_versions": vuln_range,
        "first_patched_version": first_patched,
        "tokens": _build_advisory_tokens(full_description, advisory.get("severity", ""), cwe_id),
        "summary": advisory.get("summary", ""),
        "description": advisory.get("description", ""),
        "references": [r.get("url", "") for r in refs if r.get("url")],
        "all_cwes": all_cwe_list,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_dataset(
    gh_token: str | None = None,
    output_path: str = "_dataset.json",
    use_synthetic: bool = True,
    use_osv: bool = False,
    use_gh: bool = False,
    gh_max_pages: int = 50,
    gh_severity: str | None = None,
    gh_all_packages: bool = True,
    balance_strategy: str = "none",  # "none", "min", "upsample", "threshold"
    min_per_class: int = 5,
    max_per_class: int = 1000,
) -> None:
    """Build dataset from multiple sources.
    
    Args:
        gh_token: GitHub API token for advisory access
        output_path: Path to save the dataset
        use_synthetic: Include synthetic vulnerability templates
        use_osv: Fetch from OSV database
        use_gh: Fetch from GitHub Advisory Database
        gh_max_pages: Max pages to fetch from GitHub (100 per page)
        gh_severity: Filter by severity (CRITICAL, HIGH, MODERATE, LOW, or None)
        gh_all_packages: Fetch all Python packages (not just Django/FastAPI)
        balance_strategy: "none"=keep all, "min"=downsample to min, 
                         "upsample"=replicate small classes, "threshold"=drop classes below min
        min_per_class: Minimum samples per class (for threshold strategy)
        max_per_class: Maximum samples per class (cap large classes)
    """
    records: list[dict[str, Any]] = []

    if use_synthetic:
        records.extend(generate_synthetic_samples())

    if use_osv:
        records.extend(fetch_osv_records())

    if use_gh:
        if gh_token:
            for node in fetch_gh_advisories(
                gh_token,
                max_pages=gh_max_pages,
                severity_filter=gh_severity,
                include_all_packages=gh_all_packages,
            ):
                rec = _gh_node_to_record(node)
                if rec:
                    records.append(rec)
        else:
            sys.stderr.write(
                "[SYRTH harvester] --gh requested but GH_TOKEN not set.\n"
            )

    # Drop records with empty token lists
    before = len(records)
    records = [r for r in records if r.get("tokens")]
    if (dropped := before - len(records)):
        sys.stderr.write(
            f"[SYRTH harvester] Dropped {dropped} empty-token records.\n"
        )

    # Build label groups for balancing
    label_groups: dict[int, list[dict[str, Any]]] = {}
    for r in records:
        label = r.get("label", -1)
        if label not in label_groups:
            label_groups[label] = []
        label_groups[label].append(r)

    # Balance dataset based on strategy
    if balance_strategy == "none":
        # Keep all records, just report distribution
        sys.stderr.write(
            f"[SYRTH harvester] No balancing - keeping all {len(records)} records\n"
        )
        
    elif balance_strategy == "min":
        # Downsample all classes to minimum class count (original behavior)
        min_count = min(len(group) for group in label_groups.values())
        balanced_records: list[dict[str, Any]] = []
        for label, group in label_groups.items():
            random.shuffle(group)
            kept = group[:min_count]
            dropped = len(group) - min_count
            cwe_id = None
            for k, v in CWE_LABELS.items():
                if v == label:
                    cwe_id = k
                    break
            cwe_name = CWE_NAMES.get(cwe_id, f"Class{label}") if cwe_id else f"Class{label}"
            balanced_records.extend(kept)
            if dropped > 0:
                sys.stderr.write(
                    f"[SYRTH harvester] Balanced {cwe_name}: kept {min_count}, dropped {dropped}\n"
                )
        records = balanced_records
        sys.stderr.write(
            f"[SYRTH harvester] Dataset balanced: {len(records)} total records "
            f"({len(label_groups)} classes @ {min_count} each)\n"
        )
        
    elif balance_strategy == "upsample":
        # Upsample smaller classes to match the largest class
        max_count = min(max(len(group) for group in label_groups.values()), max_per_class)
        balanced_records = []
        for label, group in label_groups.items():
            # If class has fewer samples, replicate them randomly
            current_count = len(group)
            if current_count < max_count:
                # Replicate with random selection
                needed = max_count - current_count
                replicated = [random.choice(group) for _ in range(needed)]
                group = group + replicated
                sys.stderr.write(
                    f"[SYRTH harvester] Upsampled class {label}: {current_count} -> {max_count}\n"
                )
            # Cap at max_per_class
            group = group[:max_per_class]
            balanced_records.extend(group)
        records = balanced_records
        sys.stderr.write(
            f"[SYRTH harvester] Dataset upsampled: {len(records)} total records\n"
        )
        
    elif balance_strategy == "threshold":
        # Drop classes with fewer than min_per_class samples, cap others at max
        balanced_records = []
        dropped_classes = []
        for label, group in label_groups.items():
            if len(group) < min_per_class:
                dropped_classes.append((label, len(group)))
                continue
            # Cap at max_per_class
            kept = group[:max_per_class]
            balanced_records.extend(kept)
            if len(group) > max_per_class:
                sys.stderr.write(
                    f"[SYRTH harvester] Capped class {label}: {len(group)} -> {max_per_class}\n"
                )
        records = balanced_records
        if dropped_classes:
            sys.stderr.write(
                f"[SYRTH harvester] Dropped {len(dropped_classes)} classes below threshold {min_per_class}\n"
            )
        sys.stderr.write(
            f"[SYRTH harvester] Dataset threshold-balanced: {len(records)} total records\n"
        )
    
    # Recompute label_groups after balancing for statistics
    label_groups = {}
    for r in records:
        label = r.get("label", -1)
        if label not in label_groups:
            label_groups[label] = []
        label_groups[label].append(r)

    class_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for r in records:
        class_counts[r["cwe_name"]] = class_counts.get(r["cwe_name"], 0) + 1
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1

    dataset = {
        "syrth_version": "1.0.0",
        "num_classes": len(CWE_LABELS),
        "class_map": {str(v): k for k, v in CWE_LABELS.items()},
        "cwe_names": CWE_NAMES,
        "class_distribution": class_counts,
        "source_distribution": source_counts,
        "total_records": len(records),
        "records": records,
    }

    Path(output_path).write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    sys.stderr.write(
        f"[SYRTH harvester] ✓  Saved → {output_path}\n"
        f"  Total    : {len(records)} records\n"
        f"  Sources  : {source_counts}\n"
        f"  Classes  : {class_counts}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="harvester.py",
        description=(
            "SYRTH: Scan Your Risk Trace History — Dataset builder\n\n"
            "Always includes 82 synthetic templates (zero network).\n"
            "Add --osv to pull the OSV PyPI bulk feed (no token, ~few thousand records).\n"
            "Add --gh with GH_TOKEN set to pull GitHub Advisories (up to 5000 records).\n"
            "\n"
            "Balance strategies:\n"
            "  none      - Keep all data (default)\n"
            "  min       - Downsample all classes to minimum count (aggressive balancing)\n"
            "  upsample  - Replicate small classes to match largest class\n"
            "  threshold - Drop classes below min threshold, cap at max\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", "-o", default="_dataset.json", metavar="PATH")
    parser.add_argument("--osv", action="store_true",
                        help="Download OSV PyPI bulk feed (~50MB ZIP, no auth needed)")
    parser.add_argument("--gh", action="store_true",
                        help="Pull GitHub Advisory API (needs GH_TOKEN env var)")
    parser.add_argument("--gh-max-pages", type=int, default=50, metavar="N",
                        help="Max pages to fetch from GitHub (100 per page, default: 50 = 5000 records)")
    parser.add_argument("--gh-severity", choices=["CRITICAL", "HIGH", "MODERATE", "LOW"],
                        default=None, metavar="SEV",
                        help="Filter GitHub advisories by severity")
    parser.add_argument("--gh-filtered", action="store_true",
                        help="Only fetch Django/FastAPI packages (default: all Python packages)")
    parser.add_argument("--no-synthetic", action="store_true",
                        help="Skip built-in synthetic templates")
    parser.add_argument("--balance", choices=["none", "min", "upsample", "threshold"],
                        default="none", metavar="STRATEGY",
                        help="Dataset balancing strategy (default: none = keep all data)")
    parser.add_argument("--min-per-class", type=int, default=5, metavar="N",
                        help="Minimum samples per class for threshold strategy (default: 5)")
    parser.add_argument("--max-per-class", type=int, default=1000, metavar="N",
                        help="Maximum samples per class (default: 1000)")
    args = parser.parse_args()

    build_dataset(
        gh_token=os.environ.get("GH_TOKEN") if args.gh else None,
        output_path=args.output,
        use_synthetic=not args.no_synthetic,
        use_osv=args.osv,
        use_gh=args.gh,
        gh_max_pages=args.gh_max_pages,
        gh_severity=args.gh_severity,
        gh_all_packages=not args.gh_filtered,
        balance_strategy=args.balance,
        min_per_class=args.min_per_class,
        max_per_class=args.max_per_class,
    )


if __name__ == "__main__":
    main()