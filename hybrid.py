"""
Dir' (درع): rules + ML fusion for attack detection.

Rule of the house: the model can only ADD evidence. Weights below feed the same scoring formula as the rules
(attacks.score_findings), so:
  - one ML signal alone     -> weight 40  -> "flag" (the request is allowed, but masked and logged)
  - both ML signals agree   -> weight 50  -> "flag" for a user message, "block" (quarantine) for a document
  - ML + a rule agree       -> the combined score crosses the block threshold
ML alone never blocks a user message.
"""
from __future__ import annotations

import attacks
from attacks import AttackFinding, AttackResult
from normalize import normalize

W_ONE, W_BOTH = 40, 50


def scan_hybrid(text: str, source: str = "user", ml=None, trusted_domains=()) -> AttackResult:
    res = attacks.scan(text, source, trusted_domains=trusted_domains)
    if ml is None or not getattr(ml, "ready", False):
        return res
    sig = ml.attack_signals(normalize(text).text)
    if sig.hits == 0:
        return res
    detail = []
    if sig.knn_hit:
        detail.append(f"تشابه {sig.knn_attack:.2f} مع هجوم معروف")
    if sig.zs_hit:
        detail.append(f"تصنيف النية {sig.zero_shot:.2f}")
    if sig.clf_hit:
        detail.append(f"المصنّف العربي المدرَّب {sig.clf_prob:.2f}")
    weight = W_BOTH if sig.hits >= 2 else W_ONE
    finding = AttackFinding(
        "ml_semantic", "نية تلاعب (كشف دلالي بالنموذج)", "LLM01", weight, "؛ ".join(detail),
        note="إشارة نموذج: لا تحجب وحدها" if sig.hits == 1 else "اتفقت إشارتان من النموذج")
    findings = res.findings + [finding]
    score, verdict = attacks.score_findings(findings, source)
    if res.verdict == "allow" and verdict == "block" and sig.hits == 1:
        verdict = "flag"          # defensive: a single ML signal must never turn a clean text into a block
    findings.sort(key=lambda f: -f.weight)
    return AttackResult(score=score, verdict=verdict, findings=findings, hidden_text=res.hidden_text,
                        owasp=sorted({f.owasp for f in findings}))


def ml_person_findings(text: str, ml, existing) -> list:
    """Extra PERSON findings from NER, skipping spans already covered by another finding."""
    from detectors import Finding
    if ml is None or not getattr(ml, "ready", False):
        return []
    out = []
    for s, e, score in ml.person_spans(text):
        if all(e <= f.start or s >= f.end for f in existing):
            out.append(Finding("PERSON", s, e, text[s:e], round(score, 2), True, "ner_model"))
    return out
