"""
Dir' (درع) - Step 5: Arabic-aware prompt-injection and exfiltration detector.

Rule-based on purpose: it runs on a laptop with no GPU, it is explainable
(every verdict names the rule and shows the matching text), and it needs no
training data. It runs on NORMALIZED text, so diacritics, tatweel, hidden
characters, Arabic digits and fullwidth letters do not hide an attack.

OWASP LLM Top 10 mapping used in the output:
  LLM01 Prompt Injection | LLM02 Sensitive Information Disclosure | LLM07 System Prompt Leakage

Honest limits
  - Rules catch known phrasing families, not meaning. A creative paraphrase can slip past.
  - Quoted examples inside an explanation are demoted to "flag", never silently allowed.
  - Homoglyphs from other scripts (e.g. Cyrillic 'о' inside "ignоre") are not handled yet.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from normalize import normalize

# ---------------------------------------------------------------- building blocks
_A = r"(?<![ء-ي])"            # Arabic word start
_Z = r"(?![ء-ي])"            # Arabic word end
_NEG = r"(?<!not )(?<!n't )(?<!never )(?<!لا )(?<!لن )"

_AR_IGNORE_V = (
    _A + r"[وف]?(?:تنسي|تتجاهل|تهمل|تتخطي|تجاهل|تجاهلي|تجاهلوا|اهمل|اهملي|اهملوا|انس|انسي|انسوا|تخط|تخطي|تخطوا|تجاوز|تجاوزي|تغاضي|"
    r"الغ|الغي|الغوا|طنش|طنشي|اترك|ابطل|عطل|اوقف|تخلي\s+عن|تحرر\s+من|"
    r"لا\s+(?:تلتزم|تتبع|تطبق|تتقيد|تراعي))" + _Z
)
_EN_IGNORE_V = _NEG + r"\b(?:ignore|disregard|forget|override|bypass|skip|discard|neglect|circumvent|disable|abandon|drop)\b"
_AR_OBJ = (
    _A + r"[وبفلك]?(?:ال)?(?:تعليمات|اوامر|قواعد|ارشادات|قيود|ضوابط|سياسات|توجيهات|قوانين|برومبت|اعدادات\s+النظام)"
    r"|" + _A + r"(?:كل\s+)?ما\s+(?:سبق|قيل|كتب|قلته|ذكر)|" + _A + r"الرسائل\s+السابقة"
    r"|" + _A + r"ما\s+(?:اخبروك|اخبروكي|قالوا|اخبرت|طلبوا|امروك|برمجت)\s+به?"
    r"|" + _A + r"(?:ب?اي)\s+(?:سياسة|قاعدة|قيد|تعليمة|ضابط)"
    r"|" + _A + r"(?:ال)?تعليمات\s+(?:التي|اللي|الي)\s+(?:برمجت|دربت|اعطيت)"
    r"|" + _A + r"(?:طلب|رسالة|سؤال|امر)\s+(?:ال)?مستخدم|(?:the\s+)?user['’]?s?\s+(?:request|message|question)"
)
_EN_OBJ = (
    r"(?:everything|anything|all)\s+(?:that\s+)?(?:you\s+(?:were|have\s+been)\s+(?:told|given|taught)|i\s+said\s+before|above|before\s+this)|what\s+you\s+were\s+told|"
    r"(?:(?:all|any|your|the|these|those|my)\s+)*(?:(?:previous|prior|above|earlier|preceding|original|initial|"
    r"system|safety|security|content)\s+)+(?:instructions?|rules?|guidelines?|restrictions?|policy|policies|"
    r"directions?|prompts?|messages?|context|constraints?|filters?|guardrails?)"
    r"|(?:(?:all|any|your|the)\s+)*(?:instructions|guardrails|safeguards|system\s+prompt)"
)
_OVERRIDE_RE = re.compile(r"(?:" + _AR_IGNORE_V + r"|" + _EN_IGNORE_V + r").{0,60}?(?:" + _AR_OBJ + r"|" + _EN_OBJ + r")", re.I | re.S)

_AR_SHOW_V = (
    _A + r"(?:اعرض|اطبع|اكشف|كرر|تخبرني|تعطيني|تقول\s+لي|تكشف|تعرض|تطبع|تذكر|تظهر|تكرر|تسرد|اظهر|اعطني|اعطيني|اخبرني|قل\s+لي|قولي|اسرد|انسخ|اذكر|وريني|ابي\s+اشوف|"
    r"ابغي\s+اشوف|ما\s+(?:هي|هو)|ماهي|وش|ايش|اكتب)" + _Z
)
_EN_SHOW_V = r"\b(?:show|print|reveal|repeat|output|display|tell\s+me|give\s+me|dump|leak|recite|copy|write\s+out|share)\b"
_AR_SYS_OBJ = (
    r"(?:تعليماتك|تعليمات\s+النظام|تعليمات\s+المطور|رسال(?:ة|ات)\s+النظام|البرومبت\s+(?:الاصلي|الاولي|الخاص\s+بك|السري|المخفي|الاساسي)|"
    r"برومبتك|التعليمات\s+(?:الاصلية|الاولية|السرية|المخفية|الداخلية)|توجيهات\s+النظام|اعدادات\s+النظام|"
    r"(?:كل\s+)?ما\s+(?:كتب|قيل|ذكر)\s+قبل\s+(?:هذه|هذي)\s+الرسالة|ما\s+قبل\s+هذه\s+الرسالة|"
    r"(?:ال)?تعليمات\s+(?:اللي|التي|الي)\s+(?:اعطيت|اعطاك|اعطتك|معطينك|معطيك|اعطوك)"
    r"|(?:ال)?قواعد\s+(?:اللي|التي|الي)\s+(?:تمشي|تعمل|تتبع|تلتزم|تسير)\s+عليها)"
)
_EN_SYS_OBJ = (
    r"(?:system\s*(?:prompt|message|instructions?)|(?:initial|original|hidden|secret|internal)\s+(?:prompt|instructions?)|"
    r"your\s+(?:system\s+)?(?:prompt|instructions|rules)|everything\s+above|text\s+above|words\s+above)"
)
_EXTRACT_RE = re.compile(r"(?:" + _AR_SHOW_V + r"|" + _EN_SHOW_V + r"|\bwhat\s+(?:is|are)\s+(?=your\b)).{0,30}?(?:" + _AR_SYS_OBJ + r"|" + _EN_SYS_OBJ + r")", re.I | re.S)

_JAIL_STRONG_RE = re.compile(
    r"developer\s+mode|jailbreak|do\s+anything\s+now|" + _A + r"وضع\s+(?:ال)?مطور" , re.I)
_DAN_RE = re.compile(r"\bDAN\b")
_ROLE_RE = re.compile(
    _A + r"(?:من\s+(?:ال)?ان\s+(?:انت|ستكون|تصرف)|انت\s+(?:ال)?ان|تصرف\s+(?:ك|كانك|كما\s+لو|وكانك)|اعتبر\s+نفسك|"
    r"العب\s+دور|تخيل\s+انك|تظاهر\s+(?:ب|انك)|تقمص)|you\s+are\s+now|from\s+now\s+on\s+you|"
    r"pretend\s+(?:to\s+be|you|that)|act\s+as\s+(?:if|an?\s+unrestricted)|role[- ]?play\s+as|imagine\s+you\s+are", re.I)
_RESTRICT_RE = re.compile(
    _A + r"(?:بدون|بلا|دون|من\s+غير|لا\s+يوجد|ما\s+عندك)\s+(?:اي\s+)?(?:قيود|رقابة|فلاتر|حدود|قواعد|ضوابط|اخلاق|رقيب)"
    r"|no\s+(?:restrictions|filters|limits|rules|guardrails|ethic\w*)"
    r"|without\s+(?:any\s+)?(?:restrictions|filters|limits|rules|guardrails|censorship)"
    r"|unrestricted|uncensored|unfiltered", re.I)

_SEND_V = re.compile(
    _A + r"[وف]?(?:ارسل|ارسلي|ارسلها|ابعث|ابعثها|اضف|ضمن|ادرج|الحق|ارفق|انسخ|سرب|وجه|حول|اعد\s+توجيه|ضع|حط|احط|ادخل|اكتب)" + _Z +
    r"|\b(?:send|post|upload|forward|email|append|include|embed|encode|exfiltrate|leak|transmit|submit|fetch|insert|add)\b", re.I)
_DATA_OBJ = re.compile(
    _A + r"(?:ال)?(?:بيانات|هويات|هوية|ارقام|معلومات|ايبان|ايبانات|جوالات|كلمات\s+المرور|اسرار|مفاتيح|مفتاح|توكن|محادثة|"
    r"رسائل|سجلات|حسابات|تفاصيل|ملف|محتوي)"
    r"|\b(?:data|ids?|identifiers|numbers|information|details|credentials|passwords?|secrets?|api[- ]?keys?|tokens?|"
    r"conversation|chat|history|content|contents|records|ssn|iban|ibans|names)\b", re.I)
_URL_RE = re.compile(r"https?://|www\.|ftp://|\b[a-z0-9\-]+\.(?:com|net|org|io|xyz|ru|cn|tk|ml|site|top|example)\b", re.I)
_SENT_SPLIT = re.compile(r"[\n!?؟]|\.\s")

_BULK_RE = re.compile(
    r"(?:" + _A + r"(?:اطبع|اعرض|اكشف|اسرد|اعطني|اعطيني|اظهر|اخرج|صدر)" + _Z +
    r"|\b(?:list|print|dump|show|output|export|display|give\s+me|extract)\b)"
    r"\s+(?:لي\s+)?(?:قائمة\s+(?:كاملة\s+)?)?(?:ب)?(?:كل|جميع|all|every|the\s+full|full|entire|complete)\s+.{0,30}?"
    r"(?:" + _A + r"(?:ال)?(?:هويات|ارقام\s+(?:ال)?(?:هوية|وطنية|جوالات)|ايبانات|ايبان|جوالات|بيانات\s+(?:ال)?(?:عملاء|شخصية|موظفين)|"
    r"معلومات\s+(?:ال)?عملاء|سجلات|كلمات\s+المرور|اسرار|ارقام\s+الوطنية|الارقام\s+الوطنية)"
    r"|\b(?:ids|ibans?|phone\s+numbers|customer\s+(?:data|records|names?)|personal\s+(?:data|information)|"
    r"credentials|passwords|secrets|ssn)\b)", re.I | re.S)

_IMG_EXFIL_RE = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*\)|<img[^>]+src\s*=\s*[\"']?https?://[^\s\"'>]*\?", re.I)

_IMPERSONATE_RE = re.compile(
    r"<\|(?:im_start|im_end|system|assistant|endoftext)\|>|\[/?(?:system|inst|sys)\]|<<\s*/?sys\s*>>"
    r"|^\s*#{1,4}\s*(?:system|instruction|new\s+instructions?)\b|^\s*(?:system|assistant)\s*:"
    r"|(?:رسالة|تحديث|تنبيه|امر|توجيه)\s+(?:عاجل(?:ة)?\s+)?(?:من|صادر\s+من)\s+(?:ال)?(?:نظام|مطور|مطورين|مسؤول\s+النظام|ادمن|ادارة)"
    r"|^\s*(?:النظام|المطور)\s*:", re.I | re.M)

_AI_KIND = (r"(?:نموذج(?:\s+(?:ال)?لغوي)?|ذكاء\s+(?:ال)?اصطناعي|مساعد\s+(?:ال)?(?:ذكي|افتراضي)|بوت|روبوت\s+دردشة|ai|llm|chatbot|language\s+model)")
_INDIRECT_RE = re.compile(
    r"(?:اذا|ان|لو)\s+كنت\s+(?:انت\s+)?" + _AI_KIND +
    r"|(?:عزيزي|الي|ملاحظة\s+(?:الي|ل)|تنبيه\s+(?:الي|ل))\s+(?:ال)?" + _AI_KIND +
    r"|(?:الي|الى)\s+كل\s+(?:ال)?" + _AI_KIND + r"\s+(?:يقرا|يقرأ|يعالج|يلخص|يحلل|يري|يشاهد)"
    r"|(?:ملاحظة|تنبيه|رسالة|تعليمات)\s+(?:الي|الى|ل|لل)\s*(?:ال)?(?:مساعد|نموذج|ذكاء|بوت|روبوت)"
    r"|(?:note|message|attention|instruction)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|llm|model|chatbot)"
    r"|if\s+you\s+are\s+an?\s+(?:ai|llm|assistant|language\s+model|chatbot)"
    r"|(?:ai|assistant|llm)\s*[:,]\s*(?:ignore|you\s+must|please\s+(?:ignore|send))"
    r"|تعليمات\s+مخفية|hidden\s+instructions?", re.I)

_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

_QUOTED_RE = re.compile(r"[\"'«“‘`](.{4,200}?)[\"'»”’`]")
_DISCUSS_RE = re.compile(r"(?:اشرح|شرح|ما\s+هو|ما\s+هي|مثال|مثل\s+عبارة|يعني|explain|example|what\s+is|how\s+do(?:es)?|هجوم|ثغرة|attack)", re.I)

_SQUEEZE_RE = re.compile(r"[\s._\-*·|/\\'\"`~,]+")
_OBF_OVERRIDE_RE = re.compile(
    r"(?:تجاهل|اهمل|تجاوز|تخط|انس|الغ|طنش|لاتلتزم|لاتتبع|ignore|disregard|override|bypass|forget)(?:.{0,25})"
    r"(?:التعليمات|الاوامر|القواعد|الارشادات|الضوابط|القيود|السياسات|التوجيهات|ماقيل|ماسبق|تعليمات|instructions|rules|systemprompt|guidelines)")
_OBF_EXTRACT_RE = re.compile(
    r"(?:اعرض|اطبع|اكشف|reveal|print|show|repeat)(?:.{0,10})"
    r"(?:تعليماتالنظام|البرومبتالاصلي|رسالةالنظام|systemprompt|systemmessage)")

_SPACED_RUN_RE = re.compile(r"(?<!\w)(?:[^\W\d_] ){2,}[^\W\d_](?!\w)")
_SYMBOL_SPLIT_RE = re.compile(r"[^\W\d_][._\-*|/'\"`~,][^\W\d_][._\-*|/'\"`~,][^\W\d_]")


def _despace(s: str) -> str:
    """'ا ل ت ع ل ي م ا ت' -> 'التعليمات' (only runs of 3+ single letters)."""
    return _SPACED_RUN_RE.sub(lambda m: m.group().replace(" ", ""), s)


_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
_ZW = set("​‌‍⁠﻿")
_BIDI_OVERRIDE = set("‪‫‬‭‮⁦⁧⁨⁩")


@dataclass(frozen=True)
class AttackFinding:
    rule_id: str
    family_ar: str
    owasp: str
    weight: int
    evidence: str
    start: int = -1          # span in ORIGINAL text, or -1 when not applicable
    end: int = -1
    note: str = ""


@dataclass
class AttackResult:
    score: int = 0
    verdict: str = "allow"           # allow | flag | block
    findings: list = field(default_factory=list)
    hidden_text: str = ""            # message smuggled in invisible Unicode tag characters
    owasp: list = field(default_factory=list)


# ------------------------------------------------------------------- scanning

def _snip(s: str, limit: int = 90) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[:limit] + "…"


def decode_tag_characters(text: str) -> str:
    return "".join(chr(ord(c) - _TAG_LO) for c in text
                   if _TAG_LO <= ord(c) <= _TAG_HI and 32 <= ord(c) - _TAG_LO < 127)


def _demoted(norm_text: str, s: int, e: int) -> bool:
    """A match inside quotation marks, in a sentence that explains/discusses attacks."""
    if not _DISCUSS_RE.search(norm_text):
        return False
    return any(q.start(1) <= s and e <= q.end(1) for q in _QUOTED_RE.finditer(norm_text))


_URL_HOST_RE = re.compile(r"https?://([^/\s?#:]+)", re.I)


def _only_trusted_urls(sentence: str, trusted) -> bool:
    hosts = _URL_HOST_RE.findall(sentence)
    if not trusted or not hosts:
        return False
    if re.search(r"(?<![a-z0-9/.])www\.", sentence, re.I):
        return False
    ok = tuple(t.lower().lstrip(".") for t in trusted)
    return all(any(h.lower() == t or h.lower().endswith("." + t) for t in ok) for h in hosts)


def score_findings(findings, source: str = "user") -> tuple:
    """Single place for the scoring rule: strongest finding + 35% of the rest. Returns (score, verdict)."""
    fs = sorted(findings, key=lambda f: -f.weight)
    score = 0
    if fs:
        score = int(min(100, fs[0].weight + 0.35 * sum(f.weight for f in fs[1:])))
    block_th = 50 if source == "document" else 60
    verdict = "block" if score >= block_th else "flag" if score >= 30 else "allow"
    return score, verdict


def scan(text: str, source: str = "user", _depth: int = 0, trusted_domains=()) -> AttackResult:
    norm = normalize(text)
    n = norm.text
    found: dict = {}     # rule_id -> AttackFinding (one per rule)

    def run_rules(n, mapped):
        def add(rule_id, family, owasp, weight, s_norm, e_norm, note="", demotable=False):
            if rule_id in found:
                return
            if mapped:
                s, e = norm.span_to_original(s_norm, e_norm)
                ev = _snip(text[s:e])
            else:
                s = e = -1
                ev = _snip(n[s_norm:e_norm])
                note = note or "كُشف بعد دمج الحروف المفصولة بمسافات"
            w = weight
            if demotable and _demoted(n, s_norm, e_norm):
                w, note = min(weight, 35), "ورد كمثال داخل شرح، خُفِّضت الخطورة"
            found[rule_id] = AttackFinding(rule_id, family, owasp, w, ev, s, e, note)

        if m := _OVERRIDE_RE.search(n):
            add("instruction_override", "تجاوز التعليمات السابقة", "LLM01", 60, m.start(), m.end(), demotable=True)
        if m := _EXTRACT_RE.search(n):
            add("prompt_extraction", "استخراج تعليمات النظام", "LLM07", 60, m.start(), m.end(), demotable=True)

        m = _JAIL_STRONG_RE.search(n) or _DAN_RE.search(n)
        if m:
            add("jailbreak", "كسر القيود / تقمص دور", "LLM01", 45, m.start(), m.end(), demotable=True)
        else:
            r1, r2 = _ROLE_RE.search(n), _RESTRICT_RE.search(n)
            if r1 and r2 and abs(r1.start() - r2.start()) <= 200:
                add("jailbreak", "كسر القيود / تقمص دور", "LLM01", 45,
                    min(r1.start(), r2.start()), max(r1.end(), r2.end()), demotable=True)

        pos = 0
        for sent in _SENT_SPLIT.split(n):
            idx = n.find(sent, pos) if sent else pos
            pos = idx + len(sent)
            if sent and _SEND_V.search(sent) and _DATA_OBJ.search(sent) and _URL_RE.search(sent) and not _only_trusted_urls(sent, trusted_domains):
                add("exfil_instruction", "أمر بإرسال البيانات إلى جهة خارجية", "LLM02", 65, idx, idx + len(sent))
                break

        if m := _BULK_RE.search(n):
            add("bulk_data_dump", "طلب تفريغ جماعي للبيانات", "LLM02", 40, m.start(), m.end(), demotable=True)
        if m := _IMG_EXFIL_RE.search(n):
            add("markdown_exfil_link", "رابط/صورة قد تسرّب البيانات عند العرض", "LLM02", 35, m.start(), m.end())
        if m := _IMPERSONATE_RE.search(n):
            add("system_impersonation", "انتحال رسالة نظام/مطور", "LLM01", 40, m.start(), m.end())
        if m := _INDIRECT_RE.search(n):
            add("indirect_marker", "نص موجّه للنموذج داخل محتوى", "LLM01", 50, m.start(), m.end())

    run_rules(n, True)
    d = _despace(n)
    if d != n:
        run_rules(d, False)

    # obfuscated variants: spaces/dots between letters
    squeezed = _SQUEEZE_RE.sub("", n).lower()
    spaced_obf = bool(_SPACED_RUN_RE.search(n) or _SYMBOL_SPLIT_RE.search(n))
    if spaced_obf and "instruction_override" not in found and _OBF_OVERRIDE_RE.search(squeezed):
        found["obfuscated_override"] = AttackFinding(
            "obfuscated_override", "تجاوز التعليمات (مموّه بمسافات/رموز)", "LLM01", 55, "(نمط مموّه)", note="كُشف بعد حذف الفواصل")
    if spaced_obf and "prompt_extraction" not in found and _OBF_EXTRACT_RE.search(squeezed):
        found["obfuscated_extraction"] = AttackFinding(
            "obfuscated_extraction", "استخراج تعليمات النظام (مموّه)", "LLM07", 55, "(نمط مموّه)", note="كُشف بعد حذف الفواصل")

    # hidden characters
    hidden = decode_tag_characters(text)
    if any(_TAG_LO <= ord(c) <= _TAG_HI for c in text):
        found["hidden_tag_chars"] = AttackFinding(
            "hidden_tag_chars", "نص مخفي بحروف Unicode غير مرئية", "LLM01", 60,
            _snip(hidden) if hidden else "(حروف وسوم غير مرئية)", note="لا يظهر هذا النص للقارئ البشري")
        if hidden and _depth == 0:
            for f in scan(hidden, source, _depth + 1, trusted_domains).findings:
                found.setdefault("hidden:" + f.rule_id, AttackFinding(
                    "hidden:" + f.rule_id, f.family_ar + " (داخل النص المخفي)", f.owasp, f.weight, f.evidence, note=f.note))
    if sum(1 for c in text if c in _ZW) >= 5:
        found["hidden_zero_width"] = AttackFinding(
            "hidden_zero_width", "عدد غير معتاد من الحروف غير المرئية", "LLM01", 30, "(حروف zero-width)")
    if any(c in _BIDI_OVERRIDE for c in text):
        found["bidi_override"] = AttackFinding(
            "bidi_override", "تحكم في اتجاه النص قد يخفي محتوى", "LLM01", 35, "(رموز اتجاه النص)")

    # encoded payloads
    if _depth == 0:
        for blob in _B64_RE.findall(text):
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
            except Exception:
                continue
            if raw and sum(c.isprintable() for c in raw) / len(raw) > 0.9:
                inner = scan(raw, source, _depth + 1, trusted_domains)
                if inner.verdict != "allow":
                    found["encoded_payload"] = AttackFinding(
                        "encoded_payload", "أمر مشفّر (Base64) يحمل هجوماً", "LLM01", 65, _snip(raw), note="فُكّ التشفير تلقائياً")
                    break

    findings = sorted(found.values(), key=lambda f: -f.weight)
    score, verdict = score_findings(findings, source)
    owasp = sorted({f.owasp for f in findings})
    return AttackResult(score=score, verdict=verdict, findings=findings, hidden_text=hidden, owasp=owasp)
