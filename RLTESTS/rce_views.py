"""
Real-world Remote Code Execution patterns (CWE-94).
Test file for SYRTH vulnerability scanner.

Contains:
- 5 vulnerable functions (user input evaluated as code)
- 3 safe functions (restricted execution)
"""
import os
import subprocess
import pickle
import yaml
from django.http import HttpResponse


# ── VULNERABLE ──────────────────────────────────────────────────

def evaluate_expression(request):
    expr = request.POST.get('expr', '')
    result = eval(expr)
    return result


def run_command(request):
    cmd = request.POST.get('command', '')
    output = os.popen(cmd).read()
    return output


def process_upload(request):
    data = request.FILES['file'].read()
    obj = pickle.loads(data)
    return obj


def load_config(request):
    config_data = request.POST.get('config', '')
    config = yaml.load(config_data)
    return config


def dynamic_import(request):
    module_name = request.GET.get('module', 'json')
    func_name = request.GET.get('func', 'dumps')
    mod = __import__(module_name)
    func = getattr(mod, func_name)
    result = func({"user": "test"})
    return result


# ── SAFE ────────────────────────────────────────────────────────

def safe_evaluate(request):
    import ast
    expr = request.POST.get('expr', '')
    tree = ast.parse(expr, mode='eval')
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Import, ast.ImportFrom)):
            return "Expression not allowed"
    result = eval(compile(tree, '<expr>', 'eval'))
    return result


def safe_run_command(request):
    import shlex
    cmd = request.POST.get('command', '')
    allowed = ['ls', 'pwd', 'date', 'whoami']
    parts = shlex.split(cmd)
    if parts[0] not in allowed:
        return "Command not allowed"
    result = subprocess.run(parts, capture_output=True, text=True)
    return result.stdout


def safe_load_config(request):
    config_data = request.POST.get('config', '')
    config = yaml.safe_load(config_data)
    return config
