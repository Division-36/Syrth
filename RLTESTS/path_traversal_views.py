"""
Real-world Path Traversal patterns (CWE-22).
Test file for SYRTH vulnerability scanner.

Contains:
- 5 vulnerable functions (user input in file paths)
- 3 safe functions (validated paths)
"""
import os
from pathlib import Path
from django.http import HttpResponse, FileResponse


UPLOAD_DIR = '/var/uploads'
STATIC_DIR = '/var/static'


# ── VULNERABLE ──────────────────────────────────────────────────

def download_file(request):
    filename = request.GET.get('file')
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, 'rb') as f:
        return HttpResponse(f.read(), content_type='application/octet-stream')


def read_template(request):
    template_name = request.GET.get('tpl', 'default')
    path = os.path.join(STATIC_DIR, 'templates', template_name)
    with open(path, 'r') as f:
        return HttpResponse(f.read())


def delete_upload(request):
    filename = request.POST.get('filename')
    target = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(target):
        os.remove(target)
        return HttpResponse("Deleted")
    return HttpResponse("Not found")


def view_log(request):
    log_name = request.GET.get('log')
    log_path = '/var/logs/' + log_name
    with open(log_path, 'r') as f:
        lines = f.readlines()
    return HttpResponse("".join(lines))


def include_user_content(request):
    page = request.GET.get('page', 'index')
    content_path = os.path.join('/var/content', page + '.html')
    with open(content_path, 'r') as f:
        return HttpResponse(f.read(), content_type='text/html')


# ── SAFE ────────────────────────────────────────────────────────

def safe_download(request):
    filename = request.GET.get('file')
    safe_dir = Path(UPLOAD_DIR).resolve()
    filepath = (safe_dir / filename).resolve()
    if not str(filepath).startswith(str(safe_dir)):
        return HttpResponse("Forbidden", status=403)
    with open(filepath, 'rb') as f:
        return HttpResponse(f.read())


def safe_read_template(request):
    template_name = request.GET.get('tpl', 'default')
    allowed = ['home', 'about', 'contact']
    if template_name not in allowed:
        return HttpResponse("Forbidden", status=403)
    path = os.path.join(STATIC_DIR, 'templates', template_name + '.html')
    with open(path, 'r') as f:
        return HttpResponse(f.read())


def safe_view_log(request):
    import re
    log_name = request.GET.get('log')
    if not re.match(r'^[a-z0-9_]+\.log$', log_name):
        return HttpResponse("Invalid log name", status=400)
    log_path = os.path.join('/var/logs', log_name)
    with open(log_path, 'r') as f:
        return HttpResponse(f.read())
