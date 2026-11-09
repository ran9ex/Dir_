"""
Evaluation harness: Dir' against a naive baseline.

Baseline = what a typical English-only keyword filter does (substring match on raw text).
Run:  python evaluate.py
"""
from __future__ import annotations

import random
import re

import attacks
import eval_data as ed
import synthetic as syn
from detectors import detect

_BASELINE_PHRASES = [
    "ignore previous instructions", "ignore all previous instructions", "ignore the previous instructions",
    "disregard previous", "system prompt", "you are now", "jailbreak", "developer mode", "do anything now",
]


def baseline_attack(text: str) -> str:
    low = text.lower()
    return "flag" if any(p in low for p in _BASELINE_PHRASES) else "allow"


def dir_attack(text: str, src: str = "user") -> str:
    return attacks.scan(text, source=src).verdict


def _rate(items, fn):
    """items: list of (text, src). Returns (detected_or_flagged, blocked, total)."""
    flagged = blocked = 0
    for text, src in items:
        v = fn(text, src)
        flagged += v in ("flag", "block")
        blocked += v == "block"
    return flagged, blocked, len(items)


def evaluate_attacks(attack_items, benign_texts, hard_negatives=()):
    atk = [(a["text"], a["src"]) for a in attack_items]
    ben = [(t, "user") for t in benign_texts]
    hard = [(t, "user") for t in hard_negatives]
    out = {"attack_total": len(atk), "benign_total": len(ben), "hard_total": len(hard), "by_cat": {}, "systems": {}}
    for name, fn in (("baseline", lambda t, s: baseline_attack(t)), ("dir", dir_attack)):
        f, b, n = _rate(atk, fn)
        bf, bb, bn = _rate(ben, fn)
        hf, hb, hn = _rate(hard, fn) if hard else (0, 0, 0)
        out["systems"][name] = {
            "detected": f, "blocked": b, "detect_rate": f / n if n else 0.0, "block_rate": b / n if n else 0.0,
            "benign_flagged": bf, "benign_blocked": bb, "fpr_flag": bf / bn if bn else 0.0, "fpr_block": bb / bn if bn else 0.0,
            "hard_flagged": hf, "hard_blocked": hb,
        }
    cats = sorted({a["cat"] for a in attack_items})
    for c in cats:
        items = [(a["text"], a["src"]) for a in attack_items if a["cat"] == c]
        out["by_cat"][c] = {
            "n": len(items),
            "baseline": _rate(items, lambda t, s: baseline_attack(t))[0],
            "dir": _rate(items, dir_attack)[0],
        }
    return out


def misses(attack_items, benign_texts):
    """What Dir' got wrong (for tuning on DEV only)."""
    fn = [a for a in attack_items if dir_attack(a["text"], a["src"]) == "allow"]
    fp = [t for t in benign_texts if dir_attack(t) != "allow"]
    return fn, fp


def evaluate_obfuscation(attack_items, seed=7):
    """Same attacks, rewritten with evasion tricks. Only user-visible text attacks (not already-encoded ones)."""
    rng = random.Random(seed)
    base = [a for a in attack_items if a["cat"] in ("override", "jailbreak", "extraction", "bulk", "exfil")]
    res = {}
    for mode in ed.OBFUSCATION_MODES:
        variants = [(ed.obfuscate(a["text"], mode, rng), a["src"]) for a in base]
        b = _rate(variants, lambda t, s: baseline_attack(t))[0]
        d = _rate(variants, dir_attack)[0]
        res[mode] = {"n": len(variants), "baseline": b, "dir": d}
    # reference: the un-obfuscated versions
    plain = [(a["text"], a["src"]) for a in base]
    res["(without obfuscation)"] = {"n": len(plain), "baseline": _rate(plain, lambda t, s: baseline_attack(t))[0],
                                     "dir": _rate(plain, dir_attack)[0]}
    return res


# ---------------------------------------------------------------- PII evaluation
_BASE_ID = re.compile(r"\b[12]\d{9}\b")
_BASE_IBAN = re.compile(r"\bSA\d{22}\b")
_BASE_PHONE = re.compile(r"(?:\+?966|0)?5\d{8}")


def evaluate_pii(n_each=200, seed=2024):
    """
    Controlled synthetic benchmark: random fake IDs / IBANs / phones, each written plainly or with an evasion.
    Metric: was the exact value (as typed) found as the right type? Baseline = plain regex.
    """
    rng = random.Random(seed)
    modes = ["plain", "arabic_digits", "zero_width", "spaced"]
    kinds = {
        "SA_NATIONAL_ID": (lambda: syn.make_national_id(rng), _BASE_ID),
        "SA_IBAN": (lambda: syn.make_iban(rng), _BASE_IBAN),
        "SA_PHONE": (lambda: syn.make_phone(rng), _BASE_PHONE),
    }
    results = {}
    for kind, (gen, base_rx) in kinds.items():
        for mode in modes:
            if kind == "SA_IBAN" and mode in ("arabic_digits", "spaced"):
                # IBAN keeps the Latin 'SA' prefix; spacing every character is not a realistic way to type it
                pass
            hit_dir = hit_base = 0
            for _ in range(n_each):
                v = gen()
                if mode == "plain":
                    typed = v
                elif mode == "arabic_digits":
                    typed = syn.to_arabic_indic(v)
                elif mode == "zero_width":
                    typed = syn.with_zero_width(v, rng)
                else:
                    typed = syn.spaced(v) if kind != "SA_IBAN" else " ".join(v[i:i + 4] for i in range(0, len(v), 4))
                text = f"رقم المرجع الخاص بالعميل هو {typed} شكراً"
                found = [f for f in detect(text) if f.type == kind and f.text.strip("​") == typed.strip("​")]
                hit_dir += bool(found)
                hit_base += bool(base_rx.search(text))
            results[(kind, mode)] = {"n": n_each, "dir": hit_dir, "baseline": hit_base}
    return results


def false_positive_pii(n=2000, seed=5):
    """Random 10-digit numbers starting with 1 or 2 (order numbers etc.) that are NOT IDs."""
    rng = random.Random(seed)
    fp = 0
    for _ in range(n):
        num = rng.choice("12") + "".join(rng.choice("0123456789") for _ in range(9))
        text = f"رقم الطلب {num}"
        fp += any(f.type in ("SA_NATIONAL_ID", "SA_IQAMA") for f in detect(text))
    return {"n": n, "false_positives": fp}


if __name__ == "__main__":
    print("== DEV (rules were tuned on this) ==")
    r = evaluate_attacks(ed.DEV_ATTACKS, ed.DEV_BENIGN, ed.DEV_HARD_NEGATIVES)
    for k, v in r["systems"].items():
        print(k, {a: (round(b, 3) if isinstance(b, float) else b) for a, b in v.items()})
    for c, v in r["by_cat"].items():
        print(f"  {c:14s} n={v['n']:2d} baseline={v['baseline']:2d} dir={v['dir']:2d}")
    fn, fp = misses(ed.DEV_ATTACKS, ed.DEV_BENIGN)
    print("\nDEV missed attacks:")
    for a in fn:
        print("  -", a["cat"], a["text"][:80].replace("\n", " "))
    print("DEV false positives:")
    for t in fp:
        print("  -", t)
    print("\nobfuscation:")
    for m, v in evaluate_obfuscation(ed.DEV_ATTACKS).items():
        print(f"  {m:24s} n={v['n']} baseline={v['baseline']} dir={v['dir']}")
