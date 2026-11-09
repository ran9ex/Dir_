"""
Synthetic (fake) Saudi-style personal data for tests and the demo.

Everything here is generated randomly with valid checksums so detectors can be
tested without ever touching real people's data. A randomly generated number
could, by pure chance, coincide with a real one; never treat these as real.
"""
from __future__ import annotations

import random

FIRST_NAMES = ["محمد", "أحمد", "عبدالله", "فهد", "سلمان", "خالد", "عمر", "ناصر", "تركي", "سعود",
               "نورة", "سارة", "ريم", "لمى", "هند", "منال", "العنود", "جود"]
FAMILY_NAMES = ["العتيبي", "القحطاني", "الدوسري", "الغامدي", "الحربي", "الشمري", "الزهراني",
                "المطيري", "السبيعي", "البقمي"]

_ARABIC_INDIC = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")


def luhn_check_digit(payload: str) -> str:
    """Check digit that makes payload+digit pass the Luhn test."""
    total = 0
    for i, ch in enumerate(reversed(payload)):
        d = int(ch)
        if i % 2 == 0:       # rightmost payload digit is doubled (check digit comes after it)
            d *= 2
            d = d - 9 if d > 9 else d
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    if not number.isdigit() or len(number) < 2:
        return False
    return luhn_check_digit(number[:-1]) == number[-1]


def make_national_id(rng: random.Random, iqama: bool = False) -> str:
    body = ("2" if iqama else "1") + "".join(rng.choice("0123456789") for _ in range(8))
    return body + luhn_check_digit(body)


def iban_check_digits(bban: str, country: str = "SA") -> str:
    def conv(s: str) -> str:
        return "".join(str(int(c, 36)) for c in s)
    n = int(conv(bban + country) + "00")
    return f"{98 - n % 97:02d}"


def iban_valid(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) != 24 or not s.startswith("SA") or not s[2:].isalnum():
        return False
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def make_iban(rng: random.Random) -> str:
    bban = rng.choice(["80", "10", "20", "45", "55"]) + "".join(rng.choice("0123456789") for _ in range(18))
    return "SA" + iban_check_digits(bban) + bban


def make_phone(rng: random.Random) -> str:
    return "05" + rng.choice("0123456789") + "".join(rng.choice("0123456789") for _ in range(7))


def make_card(rng: random.Random) -> str:
    body = rng.choice("45") + "".join(rng.choice("0123456789") for _ in range(14))
    return body + luhn_check_digit(body)


def make_name(rng: random.Random) -> str:
    return f"{rng.choice(FIRST_NAMES)} {rng.choice(FAMILY_NAMES)}"


def make_email(rng: random.Random) -> str:
    return f"user{rng.randint(100, 999)}@example.com"


# ---- evasion transforms (what a careless or adversarial user might type) ----

def to_arabic_indic(s: str) -> str:
    return s.translate(_ARABIC_INDIC)


def with_zero_width(s: str, rng: random.Random) -> str:
    out = []
    for ch in s:
        out.append(ch)
        if ch.isalnum() and rng.random() < 0.35:
            out.append("​")
    return "".join(out)


def spaced(s: str) -> str:
    return " ".join(s)


def dashed(s: str, group: int = 4) -> str:
    return "-".join(s[i:i + group] for i in range(0, len(s), group))
