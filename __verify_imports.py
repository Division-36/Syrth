import importlib
mods = ["torch", "numpy", "sklearn", "joblib", "matplotlib", "seaborn", "psutil", "requests"]
for m in mods:
    try:
        importlib.import_module(m)
        print("OK", m)
    except Exception as e:
        print("MISSING", m, type(e).__name__)
