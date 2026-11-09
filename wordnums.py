"""
Dir' (درع): numbers spelled out in words.

"رقم هويتي واحد صفر ثمانية ثلاثة ..." carries the same secret as "1083...", and a regex over digits never sees it.
This is deterministic (no model needed): find runs of consecutive digit words, turn them into digits,
and run the same checksums as for typed numbers.

Limits (say them in the demo): only single digit words ("واحد اثنين ثلاثة"), not "مئة وخمسة وعشرون";
a run must be long enough (7 words, or 4 right after words like "هويتي"/"جوالي") to avoid masking counting.
"""
from __future__ import annotations

import re

from normalize import normalize

_DIGITS = {
    "صفر": 0, "زيرو": 0, "واحد": 1, "واحده": 1, "وحده": 1, "اثنين": 2, "اثنان": 2, "اثنتين": 2, "ثنتين": 2, "اثنتان": 2,
    "ثلاثه": 3, "ثلاث": 3, "تلاته": 3, "اربعه": 4, "اربع": 4, "خمسه": 5, "خمس": 5, "ستة": 6, "سته": 6, "ست": 6,
    "سبعه": 7, "سبع": 7, "ثمانيه": 8, "ثماني": 8, "ثمان": 8, "تسعه": 9, "تسع": 9,
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
}
_TOKEN = re.compile(r"[A-Za-zء-ي]+")
_GAP = re.compile(r"[ \t,،\-–.]*")
_CONTEXT = re.compile(r"(هوي[هة]|اقام[هة]|جوال|هاتف|رقم|ايبان|حساب|id|phone|mobile|iban)", re.I)
MIN_PLAIN, MIN_WITH_CONTEXT = 7, 4


def _digit(tok: str):
    tok = tok.replace("ة", "ه")      # normalize.py does not fold teh marbuta
    if tok in _DIGITS:
        return _DIGITS[tok]
    if tok.startswith("و") and tok[1:] in _DIGITS:       # "وخمسة"
        return _DIGITS[tok[1:]]
    return None


def find_number_words(text: str) -> list:
    """Return [(start, end, digits)] in coordinates of the ORIGINAL text."""
    norm = normalize(text)
    t = norm.text.lower()
    toks = [(m.start(), m.end(), _digit(m.group())) for m in _TOKEN.finditer(t)]
    out, i = [], 0
    while i < len(toks):
        if toks[i][2] is None:
            i += 1
            continue
        j = i
        while j + 1 < len(toks) and toks[j + 1][2] is not None and _GAP.fullmatch(t[toks[j][1]:toks[j + 1][0]]):
            j += 1
        n = j - i + 1
        near = bool(_CONTEXT.search(t[max(0, toks[i][0] - 25):toks[i][0]]))
        if n >= (MIN_WITH_CONTEXT if near else MIN_PLAIN):
            s, e = norm.span_to_original(toks[i][0], toks[j][1])
            out.append((s, e, "".join(str(toks[k][2]) for k in range(i, j + 1))))
        i = j + 1
    return out
