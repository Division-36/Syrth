"""
Real-world Cross-Site Scripting patterns (CWE-79).
Test file for SYRTH vulnerability scanner.

Contains:
- 5 vulnerable functions (user input rendered as HTML)
- 3 safe functions (escaped output)
"""
from django.http import HttpResponse
from django.shortcuts import render
from markupsafe import escape


# ── VULNERABLE ──────────────────────────────────────────────────

def greet_user(request):
    name = request.GET.get('name', 'World')
    return HttpResponse("<h1>Hello, " + name + "!</h1>")


def user_profile(request):
    bio = request.POST.get('bio', '')
    username = request.user.username
    html = f"""
    <div class="profile">
        <h2>{username}</h2>
        <p>{bio}</p>
    </div>
    """
    return HttpResponse(html)


def search_results(request):
    query = request.GET.get('q', '')
    return HttpResponse(f"""
        <h2>Search results for: {query}</h2>
        <ul>
            <li>No results found</li>
        </ul>
    """)


def comment_display(request):
    comment = request.POST.get('comment', '')
    author = request.POST.get('author', 'Anonymous')
    return HttpResponse(f"""
        <div class="comment">
            <strong>{author}</strong>
            <p>{comment}</p>
        </div>
    """)


def error_page(request):
    message = request.GET.get('msg', 'Something went wrong')
    return HttpResponse(f"<div class='error'>{message}</div>")


# ── SAFE ────────────────────────────────────────────────────────

def safe_greet(request):
    name = request.GET.get('name', 'World')
    return HttpResponse(f"<h1>Hello, {escape(name)}!</h1>")


def safe_profile(request):
    bio = request.POST.get('bio', '')
    return render(request, 'profile.html', {'bio': bio})


def safe_comment(request):
    comment = request.POST.get('comment', '')
    from django.utils.html import format_html
    return HttpResponse(format_html("<p>{}</p>", comment))
