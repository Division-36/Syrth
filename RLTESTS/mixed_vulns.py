"""
Mixed vulnerability patterns — multiple CWE types in one file.
Test file for SYRTH multi-class detection.
"""
import os
import sqlite3
from django.http import HttpResponse, HttpResponseRedirect


# ── SQLi ────────────────────────────────────────────────────────

def user_search(request):
    q = request.GET.get('q')
    conn = sqlite3.connect('db.sqlite3')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + q + "'")
    return HttpResponse(cur.fetchall())


# ── XSS ─────────────────────────────────────────────────────────

def display_message(request):
    msg = request.GET.get('msg')
    return HttpResponse(f"<div class='alert'>{msg}</div>")


# ── PathTraversal ───────────────────────────────────────────────

def read_file(request):
    name = request.GET.get('name')
    with open('/var/data/' + name) as f:
        return HttpResponse(f.read())


# ── OpenRedirect ────────────────────────────────────────────────

def redirect_after_login(request):
    url = request.GET.get('next')
    return HttpResponseRedirect(url)


# ── RCE ─────────────────────────────────────────────────────────

def run_user_code(request):
    code = request.POST.get('code')
    exec(code)
    return HttpResponse("Executed")
