"""
Real-world Open Redirect patterns (CWE-601).
Test file for SYRTH vulnerability scanner.

Contains:
- 5 vulnerable functions (user-controlled redirects)
- 3 safe functions (validated redirects)
"""
from django.http import HttpResponse, HttpResponseRedirect
from urllib.parse import urlparse


# ── VULNERABLE ──────────────────────────────────────────────────

def login_redirect(request):
    next_url = request.GET.get('next', '/')
    return HttpResponseRedirect(next_url)


def oauth_callback(request):
    redirect_uri = request.POST.get('redirect_uri')
    return HttpResponseRedirect(redirect_uri)


def after_delete(request):
    back = request.POST.get('return_to', '/')
    return HttpResponseRedirect(back)


def language_switch(request):
    lang = request.GET.get('lang')
    target = request.GET.get('target', '/')
    return HttpResponseRedirect(target)


def payment_success(request):
    continue_url = request.GET.get('continue')
    return HttpResponseRedirect(continue_url)


# ── SAFE ────────────────────────────────────────────────────────

def safe_login_redirect(request):
    next_url = request.GET.get('next', '/')
    parsed = urlparse(next_url)
    if parsed.netloc and parsed.netloc != request.get_host():
        next_url = '/'
    return HttpResponseRedirect(next_url)


def safe_oauth_callback(request):
    redirect_uri = request.POST.get('redirect_uri')
    allowed_domains = ['myapp.com', 'auth.myapp.com']
    parsed = urlparse(redirect_uri)
    if parsed.netloc not in allowed_domains:
        return HttpResponse("Invalid redirect", status=400)
    return HttpResponseRedirect(redirect_uri)


def safe_after_delete(request):
    back = request.POST.get('return_to', '/')
    parsed = urlparse(back)
    if parsed.scheme or parsed.netloc:
        return HttpResponseRedirect('/')
    return HttpResponseRedirect(back)
