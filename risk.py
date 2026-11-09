"""
Dir' (درع) - Step 7a: a transparent risk score (0-100).

The formula is deliberately simple so a judge can audit it on a slide:

  inherent  = sum over data types of  weight * (1 + 0.25 * (min(count, 5) - 1))
            + 15 if an identifier/financial item appears together with health context
            +  5 if an identifier/financial item appears together with a person's name
            + 0.4 * attack_score                      (prompt-injection signal, 0-100)
            + 10 if any sensitive data is headed to an external model
  residual  = same formula after controls: masked items count 10%, a blocked attack counts 0.
  health context weighs 25 only when tied to an identifiable person; with no identity it weighs 5,
  and once every identifier/name is masked it keeps 20% of its weight.

If the request is stopped at the gateway (sent=False) the residual is 0.
Both are capped at 100. Levels: <25 low, <50 medium, <75 high, otherwise critical.
These weights are engineering judgement for a prototype, not a regulatory standard.
"""
from __future__ import annotations

from detectors import TYPE_INFO

_MASKED_FACTOR = 0.10
_HEALTH_UNLINKED = 5.0      # health words with no identifiable person (e.g. a general question)
_HEALTH_LINK_BROKEN = 0.2   # health words whose person was pseudonymized: 20% of the weight remains

LEVELS = [(25, "low", "منخفض"), (50, "medium", "متوسط"), (75, "high", "مرتفع"), (101, "critical", "حرج")]


def level_of(score: float):
    for limit, key, label_ar in LEVELS:
        if score < limit:
            return key, label_ar
    return "critical", "حرج"


_IDENTITY = {"identifier", "financial", "name"}


def _identity_state(findings):
    ident = [f for f in findings if TYPE_INFO[f.type]["category"] in _IDENTITY]
    return bool(ident), all(f.mask for f in ident)


def _type_points(findings, apply_controls: bool):
    has_identity, identity_all_masked = _identity_state(findings)
    by_type: dict = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)
    comps = []
    for t, items in by_type.items():
        n = min(len(items), 5)
        pts = TYPE_INFO[t]["weight"] * (1 + 0.25 * (n - 1))
        if TYPE_INFO[t]["category"] == "sensitive_health":
            # health information is dangerous only when it can be tied to a person
            if not has_identity:
                pts = _HEALTH_UNLINKED
            elif apply_controls and identity_all_masked:
                pts *= _HEALTH_LINK_BROKEN
        elif apply_controls:
            masked = sum(1 for f in items if f.mask)
            share_masked = masked / len(items)
            pts *= (1 - share_masked) + share_masked * _MASKED_FACTOR
        comps.append({"type": t, "label_ar": TYPE_INFO[t]["label_ar"], "count": len(items), "points": round(pts, 1)})
    return comps


def _combo_bonus(findings, apply_controls: bool) -> float:
    def alive(f):
        return (not f.mask) if apply_controls else True
    cats = {TYPE_INFO[f.type]["category"] for f in findings if alive(f)}
    bonus = 0.0
    if ({"identifier", "financial"} & cats) and "sensitive_health" in cats:
        bonus += 15
    if ({"identifier", "financial"} & cats) and "name" in cats:
        bonus += 5
    return bonus


def assess(findings, attack_score: int = 0, attack_blocked: bool = False, external: bool = True, sent: bool = True) -> dict:
    inherent_comps = _type_points(findings, apply_controls=False)
    residual_comps = _type_points(findings, apply_controls=True)

    attack_pts = 0.4 * attack_score
    inherent = sum(c["points"] for c in inherent_comps) + _combo_bonus(findings, False) + attack_pts
    if external and findings:
        inherent += 10
    residual = sum(c["points"] for c in residual_comps) + _combo_bonus(findings, True)
    residual += 0 if attack_blocked else attack_pts
    has_identity, identity_all_masked = _identity_state(findings)
    health_linked = any(TYPE_INFO[f.type]["category"] == "sensitive_health" for f in findings) and has_identity and not identity_all_masked
    still_exposed = any(not f.mask and TYPE_INFO[f.type]["category"] != "sensitive_health" for f in findings) or health_linked
    if external and still_exposed:
        residual += 10

    if not sent:          # request stopped at the gateway: nothing reached the model
        residual = 0.0
    inherent, residual = min(100.0, round(inherent, 1)), min(100.0, round(residual, 1))
    ik, il = level_of(inherent)
    rk, rl = level_of(residual)
    return {
        "inherent": inherent, "inherent_level": ik, "inherent_level_ar": il,
        "residual": residual, "residual_level": rk, "residual_level_ar": rl,
        "components": inherent_comps, "attack_points": round(attack_pts, 1),
    }
