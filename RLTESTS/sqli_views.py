"""
Real-world SQL Injection patterns (CWE-89).
Test file for SYRTH vulnerability scanner.

Contains:
- 5 vulnerable functions (raw SQL with user input)
- 3 safe functions (parameterized queries, ORM)
"""
import sqlite3
import django
from django.db import connection
from sqlalchemy import text


# ── VULNERABLE ──────────────────────────────────────────────────

def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM auth_user WHERE username='" + username
        + "' AND password='" + password + "'"
    )
    user = cursor.fetchone()
    return user


def search_users(request):
    query = request.GET.get('q', '')
    conn = sqlite3.connect('db.sqlite3')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name LIKE '%" + query + "%'")
    results = cur.fetchall()
    return results


def get_order(request):
    order_id = request.GET.get('id')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM orders WHERE id = %s" % order_id)
        return cursor.fetchone()


def filter_products(request):
    category = request.POST.get('category')
    min_price = request.POST.get('min_price', '0')
    sql = "SELECT * FROM products WHERE category = '%s' AND price > %s" % (category, min_price)
    cursor = connection.cursor()
    cursor.execute(sql)
    return cursor.fetchall()


def admin_report(request):
    date_range = request.GET.get('range', '30')
    query = (
        "SELECT COUNT(*), SUM(total) FROM orders "
        "WHERE created_at > NOW() - INTERVAL '%s days'" % date_range
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchone()


# ── SAFE ────────────────────────────────────────────────────────

def safe_login(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM auth_user WHERE username=? AND password=?",
        (username, password),
    )
    return cursor.fetchone()


def safe_search(request):
    query = request.GET.get('q', '')
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM users WHERE name LIKE %s",
            ['%' + query + '%'],
        )
        return cursor.fetchall()


def safe_get_order(request):
    order_id = request.GET.get('id')
    from django.db.models import Q
    return connection.cursor().execute(
        "SELECT * FROM orders WHERE id = %s", [order_id]
    ).fetchone()
