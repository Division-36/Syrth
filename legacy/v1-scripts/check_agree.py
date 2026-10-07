"""Quick dev (torch) vs fast (C) agreement check on held-out real data."""
import json
import sys
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import syrth_scan as S  # noqa: E402


def main():
    data = json.load(open("testingMassiveDataset.json", encoding="utf-8"))
    recs = data["records"] if "records" in data else data
    recs = recs[:80]

    bundle = S._load_joblib_bundle("syrth_model.joblib")
    lib = S._build_fast_engine("syrth_engine.h")

    dev_ok = fast_ok = agree = 0
    for r in recs:
        toks = r["tokens"]
        dev_res = S._dev_predict(toks, bundle)
        dev_top = dev_res[0][0]
        dev_ok += 1
        fast_res = S._fast_predict(toks, lib)
        fast_top = fast_res[0][0]
        fast_ok += 1
        if fast_top == dev_top:
            agree += 1

    print(f"dev predictions: {dev_ok}")
    print(f"fast predictions: {fast_ok}")
    if fast_ok:
        print(f"dev/fast agreement: {agree / fast_ok * 100:.1f}%")


if __name__ == "__main__":
    main()
