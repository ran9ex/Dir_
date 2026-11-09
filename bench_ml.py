"""
Run on YOUR machine after:  pip install sentence-transformers transformers torch
    python bench_ml.py            # per-signal table, thresholds chosen on val.jsonl, result on TEST, demo scenarios
    python bench_ml.py --zs       # also test the slow zero-shot model (~7 s per message on CPU; off by default)
    python bench_ml.py --save     # also writes ml_thresholds.json (the app and the gateway pick it up automatically)

Honest protocol
  - thresholds are chosen on val.jsonl (generated, unseen by the kNN bank, the zero-shot model and, by construction, the classifier's
    training rows) with at most 1% false alarms on its benign rows; the choice never looks at TEST;
  - TEST (29 attacks, 36 benign, hand-written) is then reported once with those thresholds;
  - the sample is small: say "on our test set of 29 attacks and 36 normal requests", never "accuracy".
"""
import json
import os
import statistics
import sys
import time

import attacks
import demo_data
import eval_data as ed
from hybrid import scan_hybrid
from ml_layer import MLConfig, MLLayer
from normalize import normalize

SIGNALS = ("knn", "zs", "clf")


def build(factories=None):
    clf = "dir_attack_clf" if os.path.isdir("dir_attack_clf") else ""
    ml = MLLayer(MLConfig(use_ner=False, clf_path=clf, use_zero_shot="--zs" in sys.argv),
                 attack_bank=[normalize(a["text"]).text for a in ed.DEV_ATTACKS],
                 normal_bank=[normalize(t).text for t in ed.DEV_BENIGN], factories=factories)
    print("loading models (first run downloads them)...")
    print(ml.load_all())
    return ml


def scores(ml, texts, label):
    out, t0 = [], time.time()
    for i, t in enumerate(texts, 1):
        out.append(raw(ml, t))
        if i % 10 == 0 or i == len(texts):
            print(f"  {label}: {i}/{len(texts)}  ({time.time() - t0:.0f}s)", flush=True)
    return out


def raw(ml, text):
    s = ml.attack_signals(normalize(text).text)
    knn = s.knn_attack if (s.knn_attack - s.knn_normal) >= ml.config.knn_margin else 0.0
    return {"knn": knn, "zs": s.zero_shot, "clf": s.clf_prob}


def pick(vals_att, vals_ben, max_fp=0.01):
    """Lowest threshold whose false-alarm rate on benign is <= max_fp."""
    cands = sorted(set(round(v, 3) for v in vals_att + vals_ben) | {1.01})
    for th in cands:
        fp = sum(v >= th for v in vals_ben) / max(1, len(vals_ben))
        if fp <= max_fp:
            return th
    return 1.01


def load_val():
    rows = [json.loads(l) for l in open("val.jsonl", encoding="utf-8")]
    return [r["text"] for r in rows if r["label"] == 1], [r["text"] for r in rows if r["label"] == 0]


def main(ml=None):
    ml = ml or build()
    active = [k for k, part in (("knn", "embed"), ("zs", "zero_shot"), ("clf", "clf")) if ml.status.get(part) == "ready"]
    if not active:
        print("\nNo model is ready. Install the libraries first and read the status line above.")
        return
    va, vb = load_val()
    RA, RB = scores(ml, va, "val attacks"), scores(ml, vb, "val normal")
    th = {k: pick([r[k] for r in RA], [r[k] for r in RB]) for k in active}
    print(f"\nthresholds chosen on val ({len(va)} attacks / {len(vb)} normal, max 1% false alarms): {th}")

    A, B = ed.TEST_ATTACKS, ed.TEST_BENIGN
    TA, TB = scores(ml, [a["text"] for a in A], "TEST attacks"), scores(ml, B, "TEST normal")
    print(f"\nTEST: {len(A)} attacks, {len(B)} normal requests")
    print(f"{'signal':8s} {'threshold':>9s} {'detected':>10s} {'false alarms':>14s}")
    for k in active:
        print(f"{k:8s} {th[k]:>9} {sum(r[k] >= th[k] for r in TA):>6d}/{len(A):<4d} {sum(r[k] >= th[k] for r in TB):>9d}/{len(B)}")
    rules_d = sum(attacks.scan(a["text"], a["src"]).verdict != "allow" for a in A)
    rules_f = sum(attacks.scan(t).verdict != "allow" for t in B)
    any_d = sum(any(r[k] >= th[k] for k in active) for r in TA)
    any_f = sum(any(r[k] >= th[k] for k in active) for r in TB)
    print(f"{'rules':8s} {'-':>9s} {rules_d:>6d}/{len(A):<4d} {rules_f:>9d}/{len(B)}")
    print(f"{'ML any':8s} {'-':>9s} {any_d:>6d}/{len(A):<4d} {any_f:>9d}/{len(B)}   (flag only; ML never blocks alone)")
    hy_d = sum((attacks.scan(a["text"], a["src"]).verdict != "allow") or any(r[k] >= th[k] for k in active) for a, r in zip(A, TA))
    hy_f = sum((attacks.scan(t).verdict != "allow") or any(r[k] >= th[k] for k in active) for t, r in zip(B, TB))
    print(f"{'hybrid':8s} {'-':>9s} {hy_d:>6d}/{len(A):<4d} {hy_f:>9d}/{len(B)}")

    print("\nnormal requests flagged by a signal on TEST:")
    for t, r in zip(B, TB):
        hit = [k for k in active if r[k] >= th[k]]
        if hit:
            print(" ", hit, t[:80].replace("\n", " "))
    print("\nTEST attacks missed by every signal and by the rules:")
    for a, r in zip(A, TA):
        if attacks.scan(a["text"], a["src"]).verdict == "allow" and not any(r[k] >= th[k] for k in active):
            print(" ", a["text"][:80].replace("\n", " "))

    print("\ndemo scenarios (should be: 1 clean, 2 blocked/quarantined, 3 blocked, 4 clean):")
    ml.config.knn_attack_sim, ml.config.zs_threshold, ml.config.clf_threshold = th.get("knn", 1.01), th.get("zs", 1.01), th.get("clf", 1.01)
    for s in demo_data.build_scenarios():
        r = scan_hybrid(s["user_text"], "user", ml)
        raws = raw(ml, s["user_text"])
        print(f"  {s['key']:12s} verdict={r.verdict:6s} raw={ {k: round(v, 2) for k, v in raws.items()} }")

    lat = []
    for a in A[:15]:
        t0 = time.perf_counter()
        scan_hybrid(a["text"], a["src"], ml)
        lat.append((time.perf_counter() - t0) * 1000)
    print(f"\nlatency per message (warm, CPU): median {statistics.median(lat):.0f} ms, max {max(lat):.0f} ms")

    if "--save" in sys.argv:
        json.dump({"knn_attack_sim": th.get("knn", 1.01), "zs_threshold": th.get("zs", 1.01), "clf_threshold": th.get("clf", 1.01)},
                  open("ml_thresholds.json", "w"), indent=1)
        print("saved ml_thresholds.json")
    print("\nCopy the TEST table into the demo as 'on our test set', with the sample size.")


if __name__ == "__main__":
    main()