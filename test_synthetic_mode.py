import random

import demo_data
import synthetic as syn
from detectors import detect, iban_valid, luhn_valid
from gateway import Gateway, GatewayConfig, guard_output
from llm import CANARY, DEFAULT_SYSTEM_PROMPT, SimulatedLLM
from vault import Vault

C = demo_data.customers(4, 11)
A = C[0]


class Echo:
    def __init__(self):
        self.seen = None

    def complete(self, messages):
        self.seen = messages
        return "تم تسجيل الطلب: " + messages[-1]["content"]


def synth_vault():
    return Vault(mode="synthetic", rng=random.Random(7))


def test_fakes_are_format_valid_and_different_from_the_real_values():
    v = synth_vault()
    fid, fib = v.tokenize("SA_NATIONAL_ID", A["id"]), v.tokenize("SA_IBAN", A["iban"])
    fph, fcard = v.tokenize("SA_PHONE", A["phone"]), v.tokenize("CARD", syn.make_card(random.Random(1)))
    assert fid != A["id"] and fib != A["iban"] and fph != A["phone"]
    assert len(fid) == 10 and fid[0] == A["id"][0] and luhn_valid(fid)
    assert iban_valid(fib) and fib[4:6] == A["iban"][4:6]
    assert fph.startswith("05") and len(fph) == 10
    assert luhn_valid(fcard)
    assert {f.type for f in detect(f"{fid} {fib} {fph}")} == {"SA_NATIONAL_ID", "SA_IBAN", "SA_PHONE"}


def test_iqama_keeps_its_leading_digit_and_phone_keeps_international_style():
    v = synth_vault()
    iq = syn.make_national_id(random.Random(3), iqama=True)
    assert v.tokenize("SA_IQAMA", iq).startswith("2")
    assert v.tokenize("SA_PHONE", "+966551234567").startswith("+9665")
    assert v.tokenize("SA_PHONE", "00966551234568").startswith("009665")


def test_same_real_value_same_fake_different_values_different_fakes():
    v = synth_vault()
    assert v.tokenize("SA_NATIONAL_ID", A["id"]) == v.tokenize("SA_NATIONAL_ID", syn.to_arabic_indic(A["id"]))
    assert v.tokenize("SA_NATIONAL_ID", A["id"]) != v.tokenize("SA_NATIONAL_ID", C[1]["id"])


def test_names_stay_tokens_in_synthetic_mode():
    v = synth_vault()
    assert v.tokenize("PERSON", "أحمد العتيبي") == "[PERSON_1]"


def test_restore_even_when_the_model_reformats_the_fake():
    v = synth_vault()
    fid = v.tokenize("SA_NATIONAL_ID", A["id"])
    for variant in (fid, syn.to_arabic_indic(fid), syn.spaced(fid), syn.dashed(fid, 3)):
        out, n = v.rehydrate(f"الهوية {variant} مسجلة")
        assert out == f"الهوية {A['id']} مسجلة" and n == 1, variant


def test_gateway_end_to_end_synthetic_model_never_sees_real_values():
    llm = Echo()
    gw = Gateway(llm, GatewayConfig(mask_mode="synthetic"))
    r = gw.process(f"سجّل العميل {A['name']} هويته {A['id']} جواله {A['phone']} الآيبان {A['iban']}")
    sent = llm.seen[-1]["content"]
    for raw in (A["id"], A["phone"], A["iban"], A["name"]):
        assert raw not in sent, raw
    assert "[PERSON_1]" in sent
    assert {f.type for f in detect(sent)} >= {"SA_NATIONAL_ID", "SA_IBAN", "SA_PHONE"}   # the model saw realistic data
    assert A["id"] in r.final_reply and A["iban"] in r.final_reply and A["phone"] in r.final_reply and A["name"] in r.final_reply
    assert r.output_events == []                  # the guard did not redact our own fakes


def test_guard_still_redacts_unknown_raw_pii_in_synthetic_mode():
    v = synth_vault()
    v.tokenize("SA_NATIONAL_ID", A["id"])
    stranger = C[3]["id"]
    out, ev = guard_output(f"رقم آخر {stranger}", CANARY, DEFAULT_SYSTEM_PROMPT, is_fake=v.is_fake)
    assert stranger not in out and ev


def test_synthetic_sessions_isolated():
    gw = Gateway(Echo(), GatewayConfig(mask_mode="synthetic"))
    gw.process(f"هويتي {A['id']}", session="alice")
    fake = gw.vault_for_test = None
    fake_alice = gw._vault_for("alice").tokenize("SA_NATIONAL_ID", A["id"])
    out, _ = gw._vault_for("mallory").rehydrate(f"كرر {fake_alice}")
    assert A["id"] not in out


def test_ttl_removes_fakes():
    now = [0.0]
    v = Vault(ttl_seconds=10, clock=lambda: now[0], mode="synthetic", rng=random.Random(2))
    fid = v.tokenize("SA_NATIONAL_ID", A["id"])
    now[0] = 11
    out, n = v.rehydrate(f"هوية {fid}")
    assert A["id"] not in out and n == 0 and not v._fake_index


def test_hidden_characters_are_not_restored_into_the_reply():
    v = synth_vault()
    typed = syn.with_zero_width(A["id"], random.Random(5))
    fid = v.tokenize("SA_NATIONAL_ID", typed)
    out, _ = v.rehydrate(fid)
    assert out == A["id"]


def test_simulated_llm_scenario_still_works_in_synthetic_mode():
    gw = Gateway(SimulatedLLM(), GatewayConfig(mask_mode="synthetic"))
    s = demo_data.build_scenarios()[0]
    r = gw.process(s["user_text"])
    assert A["id"] in r.final_reply and A["id"] not in r.model_input_text
    assert r.risk["residual_level"] == "low"
