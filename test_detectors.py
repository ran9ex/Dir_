import random

import pytest

import synthetic as syn
from detectors import count_by_type, detect, iban_valid, luhn_valid

RNG = random.Random(1234)


def types(findings):
    return [f.type for f in findings]


def test_generator_and_validator_agree():
    # Two independent implementations (generator in synthetic.py, validator in detectors.py).
    for _ in range(200):
        assert luhn_valid(syn.make_national_id(RNG))
        assert luhn_valid(syn.make_national_id(RNG, iqama=True))
        assert luhn_valid(syn.make_card(RNG))
        assert iban_valid(syn.make_iban(RNG))
    assert not iban_valid("SA0000000000000000000000")


def test_known_iban_example_from_public_spec():
    # Widely published example IBAN for Saudi Arabia (not a real account).
    assert iban_valid("SA03 8000 0000 6080 1016 7519")


def test_national_id_and_iqama_detected():
    cid, iq = syn.make_national_id(RNG), syn.make_national_id(RNG, iqama=True)
    f = detect(f"هويتي {cid} وإقامة زميلي {iq}")
    assert types(f) == ["SA_NATIONAL_ID", "SA_IQAMA"]
    assert f[0].text == cid and f[1].text == iq


def test_invalid_checksum_not_flagged_without_context():
    cid = syn.make_national_id(RNG)
    bad = cid[:-1] + str((int(cid[-1]) + 1) % 10)
    assert detect(f"رقم الطلب {bad}") == []


def test_invalid_checksum_flagged_with_context_unless_strict():
    cid = syn.make_national_id(RNG)
    bad = cid[:-1] + str((int(cid[-1]) + 1) % 10)
    assert types(detect(f"رقم الهوية {bad}")) == ["SA_NATIONAL_ID"]
    assert detect(f"رقم الهوية {bad}", strict_checksum=True) == []


def test_phone_formats():
    cases = ["0551234567", "+966551234567", "00966551234567", "966551234567"]
    for p in cases:
        f = detect(f"اتصل على {p} غدا")
        assert types(f) == ["SA_PHONE"], p
        assert f[0].text == p


def test_iban_with_spaces():
    iban = syn.make_iban(RNG)
    spaced = " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))
    f = detect(f"حسابي {spaced}")
    assert types(f) == ["SA_IBAN"] and f[0].text == spaced and f[0].confidence == 1.0


def test_card_and_email():
    card, mail = syn.make_card(RNG), "someone@example.com"
    f = detect(f"البطاقة {card} والبريد {mail}")
    assert sorted(types(f)) == ["CARD", "EMAIL"]


# ---- the evasions that make plain regex fail

def test_arabic_indic_digits():
    cid = syn.make_national_id(RNG)
    f = detect("الهوية " + syn.to_arabic_indic(cid))
    assert types(f) == ["SA_NATIONAL_ID"]


def test_zero_width_inside_number():
    cid = syn.make_national_id(RNG)
    hidden = syn.with_zero_width(cid, random.Random(5))
    assert "​" in hidden
    f = detect("id " + hidden)
    assert types(f) == ["SA_NATIONAL_ID"]
    assert f[0].text == hidden


def test_spaced_and_dashed_numbers():
    cid, ph = syn.make_national_id(RNG), syn.make_phone(RNG)
    assert types(detect(syn.spaced(cid))) == ["SA_NATIONAL_ID"]
    assert types(detect(syn.dashed(cid, 3))) == ["SA_NATIONAL_ID"]
    assert types(detect(syn.spaced(ph))) == ["SA_PHONE"]


def test_two_numbers_separated_by_single_space_are_split():
    cid, ph = syn.make_national_id(RNG), syn.make_phone(RNG)
    f = detect(f"{cid} {ph}")
    assert types(f) == ["SA_NATIONAL_ID", "SA_PHONE"]
    assert f[0].text == cid and f[1].text == ph


def test_iban_digits_not_double_reported():
    iban = syn.make_iban(RNG)
    assert types(detect(iban)) == ["SA_IBAN"]


# ---- names (heuristic)

def test_name_after_trigger_word():
    f = detect("لخص لي ملف العميل أحمد بن محمد العتيبي برقم هوية")
    assert types(f) == ["PERSON"]
    assert f[0].text == "أحمد بن محمد العتيبي"


def test_name_stops_at_stop_word():
    f = detect("العميل سارة برقم 5")
    assert [x.text for x in f if x.type == "PERSON"] == ["سارة"]


def test_name_from_name_list_without_trigger():
    f = detect("اتصلت نورة القحطاني بالدعم")
    assert [x.text for x in f if x.type == "PERSON"] == ["نورة القحطاني"]


def test_english_name_trigger():
    f = detect("customer John Smith called yesterday")
    assert [x.text for x in f if x.type == "PERSON"] == ["John Smith"]


def test_unknown_name_without_trigger_is_missed_known_limit():
    # Documented limitation: not in the list and no trigger word.
    assert [x for x in detect("تحدثت مع بدر الفيفي") if x.type == "PERSON"] == []


# ---- health flag

def test_health_context_flagged_not_masked():
    f = detect("المريض يعاني من السكري وارتفاع ضغط الدم")
    health = [x for x in f if x.type == "HEALTH_CONTEXT"]
    assert len(health) == 2 and not any(x.mask for x in health)


# ---- false positives

def test_plain_text_and_small_numbers_clean():
    assert detect("اجتماع الساعة 10 صباحا في الطابق 3، ميزانية 25000 ريال") == []


def test_counts():
    cid = syn.make_national_id(RNG)
    assert count_by_type(detect(f"{cid} {syn.make_phone(RNG)} {syn.make_phone(RNG)}")) == {
        "SA_NATIONAL_ID": 1, "SA_PHONE": 2}


@pytest.mark.parametrize("seed", range(20))
def test_randomized_roundtrip(seed):
    """Random mix of entities with random evasions: every entity must be found at its exact span."""
    rng = random.Random(seed)
    cid, ph, iban = syn.make_national_id(rng), syn.make_phone(rng), syn.make_iban(rng)
    pieces = []
    for kind, val in (("id", cid), ("ph", ph), ("ib", iban)):
        mode = rng.choice(["plain", "indic", "zw", "spaced"])
        if mode == "indic" and kind != "ib":
            val2 = syn.to_arabic_indic(val)
        elif mode == "zw":
            val2 = syn.with_zero_width(val, rng)
        elif mode == "spaced" and kind != "ib":
            val2 = syn.spaced(val)
        else:
            val2 = val
        pieces.append((kind, val2))
    text = " ثم ".join(f"{k}: {v}" for k, v in pieces)
    got = {f.type: f.text for f in detect(text)}
    assert got.get("SA_NATIONAL_ID") == pieces[0][1]
    assert got.get("SA_PHONE") == pieces[1][1]
    assert got.get("SA_IBAN") == pieces[2][1]


# ---- names: words after a trigger that are NOT names (found by looking at the demo screenshot)
@pytest.mark.parametrize("text", [
    "لخص لي ملف العميل التالي واكتب له رسالة",
    "ملاحظة: العميل يعاني من ارتفاع الضغط",
    "المريض المذكور في الملف المرفق",
    "الموظف الجديد سيبدأ غداً",
    "العميل تشتكي من التأخير",
])
def test_adjectives_and_verbs_after_trigger_are_not_names(text):
    assert [f for f in detect(text) if f.type == "PERSON"] == []


@pytest.mark.parametrize("text,name", [
    ("العميل هند السبيعي هويته", "هند السبيعي"),
    ("المريض يوسف الغامدي يعاني", "يوسف الغامدي"),
    ("العميل تركي الحربي طلب", "تركي الحربي"),
    ("الموظف بدر الفيفي حضر", "بدر الفيفي"),
    ("العميل عبدالله بن سعد الشمري", "عبدالله بن سعد الشمري"),
])
def test_real_names_after_trigger_still_found(text, name):
    assert [f.text for f in detect(text) if f.type == "PERSON"] == [name]
