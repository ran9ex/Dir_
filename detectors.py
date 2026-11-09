"""
Dir' (درع) - Step 3: sensitive-data detectors for Saudi-style identifiers.

All detection runs on NORMALIZED text (see normalize.py) and every finding is
reported in coordinates of the ORIGINAL text, so masking replaces exactly what
the user typed.

What is detected
  - National ID / Iqama : 10 digits, starts with 1 / 2, Luhn checksum
  - IBAN (SA)           : SA + 22 digits, ISO 7064 mod-97 checksum
  - Mobile phone        : 05XXXXXXXX, +9665XXXXXXXX, 009665XXXXXXXX
  - Payment card        : 16 digits, Luhn
  - Email
  - Person names        : HEURISTIC (trigger words such as "العميل", plus a small first/family-name list)
  - Health context      : keyword FLAG only (raises risk, is not masked)

Known limits (say them out loud in the demo, do not hide them)
  - Names are heuristic. A name with no trigger word and not in the small lists is missed.
  - A 10-digit number starting with 1 or 2 passes Luhn about 1 time in 10 by chance.
  - Numbers written as single digit words ("واحد صفر ثمانية") are handled (wordnums.py); "مئة وخمسة" style is not.
"""
from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass

from normalize import Normalized, find_digit_runs, normalize
from synthetic import FAMILY_NAMES, FIRST_NAMES
from wordnums import find_number_words

TYPE_INFO = {
    "SA_NATIONAL_ID": {"label_ar": "الهوية الوطنية", "token": "ID", "category": "identifier", "weight": 30, "mask": True},
    "SA_IQAMA": {"label_ar": "رقم الإقامة", "token": "IQAMA", "category": "identifier", "weight": 30, "mask": True},
    "SA_IBAN": {"label_ar": "الآيبان", "token": "IBAN", "category": "financial", "weight": 25, "mask": True},
    "CARD": {"label_ar": "بطاقة بنكية", "token": "CARD", "category": "financial", "weight": 30, "mask": True},
    "SA_PHONE": {"label_ar": "رقم جوال", "token": "PHONE", "category": "contact", "weight": 10, "mask": True},
    "EMAIL": {"label_ar": "بريد إلكتروني", "token": "EMAIL", "category": "contact", "weight": 8, "mask": True},
    "PERSON": {"label_ar": "اسم شخص", "token": "PERSON", "category": "name", "weight": 8, "mask": True},
    "NUMBER_WORDS": {"label_ar": "رقم مكتوب بالحروف", "token": "NUM", "category": "identifier", "weight": 20, "mask": True},
    "HEALTH_CONTEXT": {"label_ar": "سياق صحي", "token": "HEALTH", "category": "sensitive_health", "weight": 25, "mask": False},
}

# Higher number wins when two findings overlap.
_PRIORITY = {"SA_IBAN": 8, "CARD": 7, "SA_NATIONAL_ID": 6, "SA_IQAMA": 6, "SA_PHONE": 5,
             "EMAIL": 4, "PERSON": 3, "NUMBER_WORDS": 2, "HEALTH_CONTEXT": 1}


@dataclass(frozen=True)
class Finding:
    type: str
    start: int          # span in the ORIGINAL text
    end: int
    text: str           # exactly what the user typed
    confidence: float
    mask: bool
    reason: str


# ---------------------------------------------------------------- validators

def luhn_valid(number: str) -> bool:
    if not number.isdigit() or len(number) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    s = re.sub(r"[^0-9A-Za-z]", "", iban).upper()
    if len(s) != 24 or not s.startswith("SA"):
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1
    except ValueError:
        return False


# ------------------------------------------------------------------ patterns

_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[Ss][Aa](?:[ \-]?[0-9]){22}(?![0-9])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_ID_CONTEXT_RE = re.compile(r"(هوية|هويه|اقامة|اقامه|سجل مدني|رقم وطني|national\s*id|iqama|\bid\b)", re.I)

_AR_TRIGGERS = (
    "العميل|العميلة|السيد|السيدة|المريض|المريضة|الموظف|الموظفة|الاستاذ|الاستاذة|الدكتور|الدكتورة|"
    "المدعو|المدعوة|اسمه|اسمها|الاسم|باسم|المستفيد|المراجع|الزبون|صاحب الحساب"
)
_AR_TRIGGER_RE = re.compile(r"(?<![ء-ي])(?:" + _AR_TRIGGERS + r")(?![ء-ي])")
_AR_TOKEN_RE = re.compile(r"[ \t:\-]*([ء-ي]{2,})")
_EN_NAME_RE = re.compile(
    r"\b(?:customer|client|patient|employee|mr|mrs|ms|dr|name)\.?\s*[:\-]?\s+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"
)
_STOP = set(
    "برقم رقم هويته هويتها هوية الهوية جواله جوالها الجوال جوال لديه لديها لدي الذي التي هو هي في من الي علي عن مع "
    "ايبان الايبان حسابه حسابها بريده بريدها عمره عمرها يعمل تعمل يسكن تسكن ولد ولدت مولود موجود وجواله وهويته وايبانه "
    "وبريده ورقم ورقمه رقمه رقمها طلب طلبت يريد تريد اتصل اتصلت حول بخصوص لخص لخصي بيانات ملف ملفه ملفها تم قام قامت "
    "اشتكي شكوي كان كانت يحمل تحمل ثم ايضا هذا هذه ذلك ذو ذات المرفق المرفقة المذكور المذكورة و".split()
)

_STOP |= set(normalize(
    "حضر قال سال راجع وصل غادر زار استلم دفع سدد حول اشتري باع شكر قدم رد تحدث تواصل بلغ اخبر وقع وافق رفض "
    "ارسل ارسلت ارسله حجز الغي الغت فتح اغلق سجل حصل استقبل اجاب كتب قرا ساعد انضم استقال تاخر غاب عاد جاء ذهب "
    "امس اليوم غدا صباحا مساء الان بعد قبل عند لدي لدينا ايضا فقط جدا كثيرا").text.split())

_HEALTH_AR = [
    "سكري", "ضغط الدم", "سرطان", "تشخيص", "الايدز", "فيروس نقص المناعة", "الفشل الكلوي", "غسيل الكلي",
    "اكتئاب", "ملف طبي", "السجل الطبي", "وصفة طبية", "نتيجة التحليل", "نتائج التحليل", "تحليل الدم",
    "امراض مزمنة", "حالة مرضية", "عملية جراحية", "علاج كيماوي", "الصحة النفسية",
]
_HEALTH_RE = re.compile(
    "(" + "|".join(re.escape(w) for w in _HEALTH_AR) + ")"
    r"|\b(?:diabet\w*|cancer|hiv|aids|diagnos\w*|prescription|medical record|depression|chemotherapy|dialysis)\b",
    re.I,
)

_FIRST = {normalize(x).text for x in FIRST_NAMES} | {normalize(x).text for x in (
    "الجوهرة", "الهنوف", "الزهراء", "عبدالرحمن", "عبدالعزيز", "عبدالكريم", "بدر", "فيصل", "ماجد", "راكان", "مشعل")}
_FAMILY = {normalize(x).text for x in FAMILY_NAMES}
# Adjectives/nouns that follow "العميل" etc. but are not names ("العميل التالي", "المريض المذكور").
_NOT_NAMES = set(normalize(x).text for x in (
    "التالي التالية السابق السابقة الحالي الحالية الجديد الجديدة القديم القديمة المذكور المذكورة المرفق المرفقة الموضح "
    "الاتي الاول الثاني الاخير المعني المطلوب الكريم المحترم الفاضل الموقر العزيز المشار").split())
# Present-tense verbs start with ي/ت ("يعاني", "تشتكي"); real names with those letters are whitelisted.
_YT_NAMES = {normalize(x).text for x in (
    "يوسف يزيد ياسر يحيى يعقوب يامن تركي تميم تامر توفيق تغريد ترف تالا").split()}


def _name_token_ok(tok: str, first: bool) -> bool:
    if tok in _STOP or tok in _NOT_NAMES:
        return False
    if tok in _FIRST or tok in _FAMILY:
        return True
    if tok.startswith("ال"):
        return not first          # surnames often start with "ال"; as the FIRST word it is almost always an adjective
    if len(tok) >= 4 and tok[0] in "يت" and tok not in _YT_NAMES:
        return False
    return True


# ------------------------------------------------------------------- helpers

def _orig_span(norm: Normalized, s: int, e: int):
    return norm.span_to_original(s, e)


def _classify_window(w: str, has_context: bool, strict: bool):
    """Return (type, confidence, reason) for a window of digits, or None."""
    n = len(w)
    if n == 16 and w[0] in "4569" and luhn_valid(w):
        return ("CARD", 0.9, "luhn_ok")
    if n == 14 and w.startswith("009665"):
        return ("SA_PHONE", 0.95, "intl_prefix_00966")
    if n == 12 and w.startswith("9665"):
        return ("SA_PHONE", 0.95, "intl_prefix_966")
    if n == 10:
        if w.startswith("05"):
            return ("SA_PHONE", 0.95, "mobile_prefix_05")
        if w[0] in "12":
            kind = "SA_NATIONAL_ID" if w[0] == "1" else "SA_IQAMA"
            if luhn_valid(w):
                return (kind, 1.0 if has_context else 0.9, "luhn_ok")
            if has_context and not strict:
                return (kind, 0.6, "context_checksum_failed")
    return None


def _before_context(norm: Normalized, first_orig_pos: int) -> bool:
    idx = bisect_left(norm.offsets, first_orig_pos)
    return bool(_ID_CONTEXT_RE.search(norm.text[max(0, idx - 30):idx]))


def _person_findings(norm: Normalized):
    out = []
    text = norm.text
    for m in _AR_TRIGGER_RE.finditer(text):
        pos, spans = m.end(), []
        while len(spans) < 4:
            mm = _AR_TOKEN_RE.match(text, pos)
            if not mm:
                break
            tok = mm.group(1)
            if tok in _STOP or (tok[0] in "وب" and tok[1:] in _STOP) or not _name_token_ok(tok, first=not spans):
                break
            spans.append((mm.start(1), mm.end(1)))
            pos = mm.end()
        if spans:
            s, e = _orig_span(norm, spans[0][0], spans[-1][1])
            out.append(Finding("PERSON", s, e, norm.original[s:e], 0.8 if len(spans) > 1 else 0.7, True, "trigger_word"))
    # first name + family name from the small lists
    toks = [(t.group(), t.start(), t.end()) for t in re.finditer(r"[ء-ي]+", text)]
    i = 0
    while i < len(toks) - 1:
        tok = toks[i][0]
        if tok in _FIRST:
            j = i + 1
            while j < len(toks) and toks[j][0] in _FIRST and j - i < 2 and text[toks[j - 1][2]:toks[j][1]] == " ":
                j += 1
            if j < len(toks) and toks[j][0] in _FAMILY and text[toks[j - 1][2]:toks[j][1]] == " ":
                s, e = _orig_span(norm, toks[i][1], toks[j][2])
                out.append(Finding("PERSON", s, e, norm.original[s:e], 0.7, True, "name_list"))
                i = j + 1
                continue
        i += 1
    for m in _EN_NAME_RE.finditer(text):
        s, e = _orig_span(norm, m.start(1), m.end(1))
        out.append(Finding("PERSON", s, e, norm.original[s:e], 0.7, True, "trigger_word_en"))
    return out


# ---------------------------------------------------------------------- main

def detect(text: str, strict_checksum: bool = False) -> list:
    """Return non-overlapping findings sorted by position (ORIGINAL coordinates)."""
    norm = normalize(text)
    work = list(norm.text)          # a copy where already-claimed regions are blanked
    found = []

    for m in _IBAN_RE.finditer(norm.text):
        compact = re.sub(r"[^0-9A-Za-z]", "", m.group()).upper()
        ok = iban_valid(compact)
        s, e = _orig_span(norm, m.start(), m.end())
        found.append(Finding("SA_IBAN", s, e, text[s:e], 1.0 if ok else 0.6, True,
                             "mod97_ok" if ok else "pattern_only_checksum_failed"))
        for k in range(m.start(), m.end()):
            work[k] = "\x00"

    for m in _EMAIL_RE.finditer(norm.text):
        s, e = _orig_span(norm, m.start(), m.end())
        found.append(Finding("EMAIL", s, e, text[s:e], 0.95, True, "pattern"))
        for k in range(m.start(), m.end()):
            work[k] = "\x00"

    blanked = Normalized(original=norm.original, text="".join(work), offsets=norm.offsets, stats=norm.stats)
    for run in find_digit_runs(blanked, min_digits=10):
        digits, i = run.digits, 0
        ctx = _before_context(norm, run.positions[0])
        while i < len(digits):
            hit = None
            for length in (16, 14, 12, 10):
                if i + length <= len(digits):
                    cls = _classify_window(digits[i:i + length], ctx, strict_checksum)
                    if cls:
                        hit = (length, cls)
                        break
            if not hit:
                i += 1
                continue
            length, (ftype, conf, reason) = hit
            s, e = run.positions[i], run.positions[i + length - 1] + 1
            if ftype == "SA_PHONE" and length in (12, 14) and s > 0 and text[s - 1] == "+":
                s -= 1
            found.append(Finding(ftype, s, e, text[s:e], conf, True, reason))
            i += length

    found.extend(_person_findings(norm))

    for ws, we, digits in find_number_words(text):
        cls = _classify_window(digits, _before_context(norm, ws), strict_checksum) if len(digits) in (10, 12, 14, 16) else None
        ftype, conf, reason = cls if cls else ("NUMBER_WORDS", 0.7, "digit_words")
        found.append(Finding(ftype, ws, we, text[ws:we], conf, True, reason + "+digit_words" if cls else reason))

    for m in _HEALTH_RE.finditer(norm.text):
        s, e = _orig_span(norm, m.start(), m.end())
        found.append(Finding("HEALTH_CONTEXT", s, e, text[s:e], 0.6, False, "keyword"))

    # resolve overlaps: highest priority first, then longer span
    accepted = []
    for f in sorted(found, key=lambda f: (-_PRIORITY[f.type], -(f.end - f.start), f.start)):
        if all(f.end <= a.start or f.start >= a.end for a in accepted):
            accepted.append(f)

    # swallow invisible characters touching a span, so masking leaves no hidden residue behind
    widened = []
    for f in sorted(accepted, key=lambda f: f.start):
        s, e = f.start, f.end
        prev_end = widened[-1].end if widened else 0
        while s > prev_end and unicodedata.category(text[s - 1]) == "Cf":
            s -= 1
        while e < len(text) and unicodedata.category(text[e]) == "Cf":
            e += 1
        widened.append(Finding(f.type, s, e, text[s:e], f.confidence, f.mask, f.reason))
    return widened


def count_by_type(findings) -> dict:
    out: dict = {}
    for f in findings:
        out[f.type] = out.get(f.type, 0) + 1
    return out
