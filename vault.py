"""
Dir' (درع) - Step 4: reversible pseudonymization, in two modes.

  mode="token"      -> [ID_1], [PHONE_1] ...   (simple, obvious to the model)
  mode="synthetic"  -> a FAKE but format-valid value: a Luhn-valid national ID with the same first digit,
                       a mod-97-valid Saudi IBAN with the same bank code, a 05xxxxxxxx phone, a Luhn-valid card,
                       a fake e-mail. Names stay as tokens (a split or re-ordered fake name cannot be restored reliably).

Why synthetic mode: the model (and any downstream validation in the prompt) sees realistic data, so answers keep
their quality, and the real value never leaves. The gateway swaps the real value back into the reply.

Anonymization vs pseudonymization (a point worth making to judges):
  - Anonymization cannot be reversed. Truly anonymous data is outside PDPL scope.
  - Pseudonymization CAN be reversed by whoever holds the vault, so the data is still personal data legally.
    The gain is that the external model never sees it.

Prototype limits: the vault lives in process memory and is not encrypted; a random fake could in theory equal a
real person's number (about 1 in 10^8 per value); a model that rewrites a fake into a different shape is not restored.
"""
from __future__ import annotations

import random
import re
import time
import unicodedata

import synthetic as syn
from detectors import TYPE_INFO, detect
from normalize import normalize

_TOKEN_TYPES = "ID|IQAMA|IBAN|PHONE|CARD|EMAIL|PERSON"
_TOKEN_RE = re.compile(r"\[\s*(" + _TOKEN_TYPES + r")[_\- ]?(\d+)\s*\]", re.I)
_SYNTH_TYPES = ("SA_NATIONAL_ID", "SA_IQAMA", "SA_IBAN", "SA_PHONE", "CARD", "EMAIL")


def canonical(ftype: str, value: str) -> str:
    """Same real-world value in different notations (Arabic digits, spaces...) -> same key."""
    t = normalize(value).text
    if ftype in ("SA_NATIONAL_ID", "SA_IQAMA", "CARD"):
        return re.sub(r"\D", "", t)
    if ftype == "SA_PHONE":
        d = re.sub(r"\D", "", t)
        return d[-9:]
    if ftype == "SA_IBAN":
        return re.sub(r"[^0-9A-Za-z]", "", t).upper()
    if ftype == "EMAIL":
        return t.strip().lower()
    return re.sub(r"\s+", " ", t).strip()


def _clean(value: str) -> str:
    return "".join(c for c in value if unicodedata.category(c) != "Cf")


class Vault:
    def __init__(self, ttl_seconds: int = 900, clock=time.time, mode: str = "token", rng: random.Random | None = None):
        assert mode in ("token", "synthetic")
        self.ttl, self.mode = ttl_seconds, mode
        self._clock = clock
        self._rng = rng or random.SystemRandom()
        self._by_token: dict = {}     # token or fake text -> (real_text, created_at)
        self._by_key: dict = {}       # (prefix, canonical real) -> token or fake text
        self._counters: dict = {}
        self._fake_index: dict = {}   # (ftype, canonical fake) -> fake text

    # ---------------------------------------------------------------- fake values
    def _digits(self, n: int) -> str:
        return "".join(self._rng.choice("0123456789") for _ in range(n))

    def _make_fake(self, ftype: str, real: str) -> str:
        c = canonical(ftype, real)
        for _ in range(50):
            if ftype in ("SA_NATIONAL_ID", "SA_IQAMA"):
                body = (c[0] if c[:1] in "12" else "1") + self._digits(8)
                fake = body + syn.luhn_check_digit(body)
            elif ftype == "CARD":
                body = (c[0] if c else "4") + self._digits(14)
                fake = body + syn.luhn_check_digit(body)
            elif ftype == "SA_IBAN":
                bban = (c[4:6] if len(c) == 24 else "80") + self._digits(18)
                fake = "SA" + syn.iban_check_digits(bban) + bban
            elif ftype == "SA_PHONE":
                digits = re.sub(r"\D", "", normalize(real).text)
                nine = "5" + self._digits(8)
                if digits.startswith("00966"):
                    fake = "00966" + nine
                elif digits.startswith("966"):
                    fake = ("+" if normalize(real).text.lstrip().startswith("+") else "") + "966" + nine
                else:
                    fake = "0" + nine
            elif ftype == "EMAIL":
                fake = f"user{self._digits(5)}@example.com"
            else:
                raise ValueError(ftype)
            if canonical(ftype, fake) != c and (ftype, canonical(ftype, fake)) not in self._fake_index:
                return fake
        raise RuntimeError("could not generate a distinct fake value")

    # --------------------------------------------------------------------- core
    def tokenize(self, ftype: str, value: str) -> str:
        prefix = TYPE_INFO[ftype]["token"]
        key = (prefix, canonical(ftype, value))
        if key in self._by_key and self._by_key[key] in self._by_token:
            return self._by_key[key]
        real = _clean(value)
        if self.mode == "synthetic" and ftype in _SYNTH_TYPES:
            out = self._make_fake(ftype, real)
            self._fake_index[(ftype, canonical(ftype, out))] = out
        else:
            self._counters[prefix] = self._counters.get(prefix, 0) + 1
            out = f"[{prefix}_{self._counters[prefix]}]"
        self._by_token[out] = (real, self._clock())
        self._by_key[key] = out
        return out

    def mask(self, text: str, findings: list):
        """Replace maskable findings (ORIGINAL coordinates). Returns (masked_text, [(replacement, type), ...])."""
        out, cursor, used = [], 0, []
        for f in sorted(findings, key=lambda f: f.start):
            if not f.mask:
                continue
            token = self.tokenize(f.type, f.text)
            out.append(text[cursor:f.start])
            out.append(token)
            cursor = f.end
            used.append((token, f.type))
        out.append(text[cursor:])
        return "".join(out), used

    def is_fake(self, ftype: str, text: str) -> bool:
        """True if `text` is a synthetic value this vault issued (the output guard must not redact it)."""
        return (ftype, canonical(ftype, text)) in self._fake_index

    def purge(self) -> int:
        now = self._clock()
        dead = [t for t, (_, created) in self._by_token.items() if now - created > self.ttl]
        for t in dead:
            del self._by_token[t]
        if dead:
            self._fake_index = {k: v for k, v in self._fake_index.items() if v in self._by_token}
        return len(dead)

    def rehydrate(self, text: str):
        """Put real values back. Unknown or expired tokens are left as they are. Returns (text, restored_count)."""
        self.purge()
        restored = 0

        def repl(m):
            nonlocal restored
            token = f"[{m.group(1).upper()}_{int(m.group(2))}]"
            hit = self._by_token.get(token)
            if hit is None:
                return m.group(0)
            restored += 1
            return hit[0]

        text = _TOKEN_RE.sub(repl, text)

        if self._fake_index:      # synthetic values: find them by type + canonical form, whatever notation the model used
            for f in sorted(detect(text), key=lambda f: -f.start):
                fake = self._fake_index.get((f.type, canonical(f.type, f.text)))
                if fake is None:
                    continue
                text = text[:f.start] + self._by_token[fake][0] + text[f.end:]
                restored += 1
        return text, restored

    def __len__(self) -> int:
        return len(self._by_token)
