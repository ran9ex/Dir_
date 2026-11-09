import random

import synthetic as syn
from detectors import detect
from risk import assess, level_of
from vault import Vault

RNG = random.Random(99)


def test_mask_and_rehydrate_roundtrip():
    cid, ph = syn.make_national_id(RNG), syn.make_phone(RNG)
    text = f"العميل أحمد العتيبي هويته {cid} وجواله {ph}"
    v = Vault()
    masked, used = v.mask(text, detect(text))
    assert cid not in masked and ph not in masked and "أحمد" not in masked
    assert "[ID_1]" in masked and "[PHONE_1]" in masked and "[PERSON_1]" in masked
    restored, n = v.rehydrate("الرد: [PERSON_1] رقمه [ID_1] جواله [PHONE_1]")
    assert restored == f"الرد: أحمد العتيبي رقمه {cid} جواله {ph}" and n == 3


def test_same_value_different_notation_same_token():
    cid = syn.make_national_id(RNG)
    text = f"{cid} ثم {syn.to_arabic_indic(cid)}"
    v = Vault()
    masked, used = v.mask(text, detect(text))
    assert masked.count("[ID_1]") == 2 and "[ID_2]" not in masked


def test_phone_formats_share_token():
    v = Vault()
    t1 = v.tokenize("SA_PHONE", "0551234567")
    t2 = v.tokenize("SA_PHONE", "+966551234567")
    assert t1 == t2


def test_health_context_not_masked():
    text = "المريض يعاني من السكري"
    v = Vault()
    masked, used = v.mask(text, detect(text))
    assert "السكري" in masked and all(t != "HEALTH_CONTEXT" for _, t in used)


def test_ttl_expiry():
    now = [1000.0]
    v = Vault(ttl_seconds=60, clock=lambda: now[0])
    tok = v.tokenize("SA_PHONE", "0551234567")
    assert v.rehydrate(f"x {tok}")[0] == "x 0551234567"
    now[0] += 61
    out, n = v.rehydrate(f"x {tok}")
    assert out == f"x {tok}" and n == 0 and len(v) == 0


def test_unknown_token_left_alone_and_model_formatting_tolerated():
    v = Vault()
    tok = v.tokenize("SA_NATIONAL_ID", "1083456789")
    assert v.rehydrate("[ID_9]")[0] == "[ID_9]"
    assert v.rehydrate("[id_1]")[0] == "1083456789"       # lowercase from the model
    assert v.rehydrate("[ ID_1 ]")[0] == "1083456789"     # stray spaces


def test_risk_levels_and_controls_reduce_residual():
    text = f"العميل أحمد العتيبي هويته {syn.make_national_id(RNG)} جواله {syn.make_phone(RNG)}"
    r = assess(detect(text))
    assert r["inherent"] > r["residual"]
    assert r["residual"] < 25
    assert level_of(0)[0] == "low" and level_of(30)[0] == "medium" and level_of(60)[0] == "high" and level_of(90)[0] == "critical"


def test_health_plus_identifier_raises_risk_and_stays_after_masking():
    base = f"هويته {syn.make_national_id(RNG)}"
    r1 = assess(detect(base))
    r2 = assess(detect(base + " ويعاني من السرطان"))
    assert r2["inherent"] > r1["inherent"]
    assert r2["residual"] > r1["residual"]        # health context is not masked


def test_attack_blocked_removes_attack_component_from_residual():
    f = detect(f"هويته {syn.make_national_id(RNG)}")
    blocked = assess(f, attack_score=80, attack_blocked=True)
    open_ = assess(f, attack_score=80, attack_blocked=False)
    assert blocked["residual"] < open_["residual"]
    assert blocked["inherent"] == open_["inherent"]


def test_no_findings_zero_risk():
    r = assess([])
    assert r["inherent"] == 0 and r["residual"] == 0


def test_general_health_question_is_low_risk():
    r = assess(detect("اشرح لي أعراض السكري وكيف أتعايش معه"))
    assert r["inherent"] < 25 and r["residual"] < 25


def test_health_note_about_a_masked_person_drops_to_low_residual():
    text = f"العميل أحمد العتيبي هويته {syn.make_national_id(RNG)} يعاني من السكري"
    r = assess(detect(text))
    assert r["inherent_level"] == "critical" and r["residual_level"] == "low"


def test_health_note_about_an_unmasked_person_stays_high():
    from detectors import Finding
    ident = Finding("SA_NATIONAL_ID", 0, 10, "x", 1.0, False, "t")      # pretend masking was off
    health = Finding("HEALTH_CONTEXT", 11, 16, "السكري", 0.6, False, "keyword")
    assert assess([ident, health])["residual"] > 50
