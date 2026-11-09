"""
Dir' (درع): the gateway. One call = the whole protection pipeline.

  employee text + documents
     1. attack scan (user text and every document, on normalized text)
     2. quarantine documents that carry an attack; stop the request if the user's own text is an attack
     3. detect sensitive data, replace it with reversible tokens (vault)
     4. strip hidden characters, send ONLY the masked text to the model
     5. output guard: block exfiltration images/links, system-prompt and secret leaks, raw personal data
     6. put the real values back for the employee (rehydrate)
     7. score the risk (before / after controls) and write a privacy-safe audit event
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import attacks as atk
import risk
from audit import AuditLog
from detectors import TYPE_INFO, Finding, count_by_type, detect
from hybrid import ml_person_findings, scan_hybrid
from llm import CANARY, DEFAULT_SYSTEM_PROMPT
from normalize import normalize
from vault import Vault

_SECRET_RE = re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9\-_]{7,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}\b")
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*([^)\s]+)[^)]*\)")
_HTML_IMG_RE = re.compile(r"<img[^>]+src\s*=\s*[\"']?([^\s\"'>]+)[^>]*>", re.I)
_MD_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*(https?://[^)\s]+)[^)]*\)")
_URL_QUERY_RE = re.compile(r"https?://[^\s)\"'<>]*\?[^\s)\"'<>]*", re.I)
_HOST_RE = re.compile(r"https?://([^/\s?#:]+)", re.I)
_HIDDEN_CHARS_RE = re.compile("[\U000E0000-\U000E007F‪-‮⁦-⁩﻿]")


@dataclass
class GatewayConfig:
    ttl_seconds: int = 900
    trusted_domains: tuple = ()
    block_attacks: bool = True
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    canary: str = CANARY
    external: bool = True
    mask_mode: str = "token"      # "token" ([ID_1]) or "synthetic" (format-valid fake values)
    ml: object = None             # optional ml_layer.MLLayer; None = rules only
    lock_after: int = 3           # suspicious messages in one session before it is suspended (0 = never)


@dataclass
class DocReport:
    name: str
    attack: atk.AttackResult
    findings: list
    quarantined: bool


@dataclass
class Result:
    action: str = "allowed"                 # allowed | allowed_with_warnings | blocked | error
    message_ar: str = ""
    user_text: str = ""
    user_findings: list = field(default_factory=list)
    attack: atk.AttackResult = field(default_factory=atk.AttackResult)
    docs: list = field(default_factory=list)
    tokens: list = field(default_factory=list)        # [(token, type)]
    sanitized_hidden: int = 0
    model_messages: list = field(default_factory=list)
    raw_reply: str = ""
    final_reply: str = ""
    output_events: list = field(default_factory=list)
    risk: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    event: dict = field(default_factory=dict)
    trust: int = 100                        # session trust score, drops with every suspicious message

    @property
    def sent_to_model(self) -> bool:
        return bool(self.model_messages)

    @property
    def model_input_text(self) -> str:
        return "\n\n".join(m["content"] for m in self.model_messages if m["role"] != "system")


def _trusted(url: str, trusted) -> bool:
    m = _HOST_RE.search(url)
    if not m:
        return False
    host = m.group(1).lower()
    return any(host == t.lower().lstrip(".") or host.endswith("." + t.lower().lstrip(".")) for t in trusted)


def _host(url: str) -> str:
    m = _HOST_RE.search(url)
    return m.group(1).lower() if m else "?"


def guard_output(reply: str, canary: str, system_prompt: str, trusted=(), is_fake=None) -> tuple:
    """Return (clean_reply, events). Runs BEFORE tokens are turned back into real values."""
    events: list = []
    out = reply

    def image(m):
        url = m.group(1)
        if _trusted(url, trusted):
            return m.group(0)
        events.append({"kind": "exfil_image", "detail": _host(url)})
        return "[تم حذف صورة مشبوهة]"

    out = _MD_IMAGE_RE.sub(image, out)
    out = _HTML_IMG_RE.sub(image, out)

    def link(m):
        url = m.group(2)
        if "?" in url and not _trusted(url, trusted):
            events.append({"kind": "exfil_link", "detail": _host(url)})
            return f"{m.group(1)} [رابط محذوف]"
        return m.group(0)

    out = _MD_LINK_RE.sub(link, out)

    def bare(m):
        if _trusted(m.group(0), trusted):
            return m.group(0)
        events.append({"kind": "exfil_link", "detail": _host(m.group(0))})
        return "[رابط محذوف]"

    out = _URL_QUERY_RE.sub(bare, out)

    sp_sentences = [normalize(s).text for s in re.split(r"[.\n]", system_prompt) if len(s.strip()) >= 20]
    lines = []
    for line in out.split("\n"):
        nl = normalize(line).text
        if canary.lower() in line.lower() or any(s and s in nl for s in sp_sentences):
            events.append({"kind": "system_prompt_leak", "detail": "line"})
            lines.append("[محجوب: محتوى داخلي]")
            continue
        if _SECRET_RE.search(line):
            events.append({"kind": "secret_leak", "detail": "credential"})
            line = _SECRET_RE.sub("[محجوب]", line)
        lines.append(line)
    out = "\n".join(lines)

    raw = [f for f in detect(out) if f.mask and not (is_fake and is_fake(f.type, f.text))]
    for f in sorted(raw, key=lambda f: -f.start):
        events.append({"kind": "pii_in_output", "detail": f.type})
        out = out[:f.start] + "[محجوب]" + out[f.end:]
    return out, events


class Gateway:
    def __init__(self, llm, config: GatewayConfig | None = None, audit: AuditLog | None = None):
        self.llm = llm
        self.config = config or GatewayConfig()
        self.audit = audit if audit is not None else AuditLog()
        self._vaults: dict = {}
        self._strikes: dict = {}

    # One vault per session: a token typed or guessed by one user can never unlock another user's data.
    def _vault_for(self, session: str) -> Vault:
        v = self._vaults.get(session)
        if v is None:
            v = self._vaults[session] = Vault(ttl_seconds=self.config.ttl_seconds, mode=self.config.mask_mode)
        return v

    @property
    def vault(self) -> Vault:
        return self._vault_for("default")

    def new_session(self, session: str = "default"):
        self._vaults.pop(session, None)
        self._strikes.pop(session, None)

    def trust(self, session: str = "default") -> int:
        return max(0, 100 - 34 * self._strikes.get(session, 0))

    def _scan(self, text: str, src: str):
        return scan_hybrid(text, src, self.config.ml, self.config.trusted_domains)

    def _detect(self, text: str) -> list:
        base = detect(text)
        return sorted(base + ml_person_findings(text, self.config.ml, base), key=lambda f: f.start)

    # ------------------------------------------------------------------ public
    def process(self, user_text: str, documents=(), session: str = "default") -> Result:
        """Convenience wrapper: one employee message, optional documents as [(name, text)] or [text]."""
        docs = [d if isinstance(d, (tuple, list)) else (f"مستند {i + 1}", d) for i, d in enumerate(documents)]
        msgs = [{"role": "system", "content": self.config.system_prompt}, {"role": "user", "content": user_text}]
        return self.run(msgs, docs, session)

    def run(self, messages: list, documents=(), session: str = "default") -> Result:
        t0 = time.perf_counter()
        cfg = self.config
        vault = self._vault_for(session)
        res = Result()
        user_idx = [i for i, m in enumerate(messages) if m["role"] == "user"]
        last_user = user_idx[-1] if user_idx else None
        res.user_text = messages[last_user]["content"] if last_user is not None else ""

        if cfg.lock_after and self._strikes.get(session, 0) >= cfg.lock_after:
            res.action = "blocked"
            res.trust = self.trust(session)
            res.message_ar = "تم تعليق الجلسة بسبب تكرار محاولات مشبوهة. تواصل مع مسؤول الأمن السيبراني."
            return self._finish(res, [], 0, True, sent=False, t0=t0)

        # 1 + 2: attack scan
        per_msg_findings: dict = {}
        blocked_by: list = []
        top_score, top_attack = 0, atk.AttackResult()
        for i, m in enumerate(messages):
            if m["role"] not in ("user", "tool"):
                continue
            src = "user" if m["role"] == "user" else "document"
            r = self._scan(m["content"], src)
            if i == last_user:
                res.attack = r
            if r.score > top_score:
                top_score, top_attack = r.score, r
            if r.verdict == "block" and cfg.block_attacks:
                blocked_by.append(r)
        doc_reports = []
        for name, text in documents:
            r = self._scan(text, "document")
            q = r.verdict == "block" and cfg.block_attacks
            doc_reports.append(DocReport(name, r, self._detect(text), q))
            if r.score > top_score:
                top_score, top_attack = r.score, r
        res.docs = doc_reports

        if res.attack.verdict in ("flag", "block"):
            self._strikes[session] = self._strikes.get(session, 0) + 1
        res.trust = self.trust(session)

        # findings on the employee's own text (for display and scoring)
        for i, m in enumerate(messages):
            per_msg_findings[i] = self._detect(m["content"])
        if last_user is not None:
            res.user_findings = per_msg_findings[last_user]

        all_findings = [f for fs in per_msg_findings.values() for f in fs]
        for d in doc_reports:
            if d.quarantined:   # never leaves the organization, so treat its data as protected
                all_findings += [Finding(f.type, f.start, f.end, f.text, f.confidence, True, f.reason) for f in d.findings]
            else:
                all_findings += d.findings

        # request stopped?
        if blocked_by:
            worst = max(blocked_by, key=lambda r: r.score)
            fams = "، ".join(dict.fromkeys(f.family_ar for f in worst.findings[:3]))
            res.action = "blocked"
            res.message_ar = f"تم إيقاف الطلب: اكتشف درع محاولة هجوم ({fams}). لم يُرسل أي شيء إلى النموذج."
            return self._finish(res, all_findings, top_score, True, sent=False, t0=t0)

        # 3 + 4: mask and send
        out_messages, used_all, hidden_removed = [], [], 0
        doc_blocks = []
        for d, (name, text) in zip(doc_reports, documents):
            if d.quarantined:
                continue
            masked, used = vault.mask(text, d.findings)
            used_all += used
            clean = _HIDDEN_CHARS_RE.sub("", masked)
            hidden_removed += len(masked) - len(clean)
            doc_blocks.append(f"[بداية مستند: {name}]\n{clean}\n[نهاية المستند]")
        for i, m in enumerate(messages):
            content = m["content"]
            masked, used = vault.mask(content, per_msg_findings[i])
            used_all += used
            clean = _HIDDEN_CHARS_RE.sub("", masked)
            hidden_removed += len(masked) - len(clean)
            if i == last_user and doc_blocks:
                clean += "\n\n" + "\n\n".join(doc_blocks)
            out_messages.append({"role": m["role"], "content": clean})
        res.tokens = list(dict.fromkeys(used_all))
        res.sanitized_hidden = hidden_removed
        res.model_messages = out_messages

        # call the model
        try:
            raw = self.llm.complete(out_messages)
        except Exception as exc:    # never leak internals to the employee
            res.action = "error"
            res.message_ar = "تعذّر الاتصال بالنموذج. لم يُسرَّب أي شيء، حاول لاحقاً."
            res.model_messages = out_messages
            res.event_error = type(exc).__name__
            return self._finish(res, all_findings, top_score, False, sent=True, t0=t0)
        res.raw_reply = raw

        # 5 + 6: guard then rehydrate
        guarded, events = guard_output(raw, cfg.canary, cfg.system_prompt, cfg.trusted_domains, vault.is_fake)
        res.output_events = events
        res.final_reply, _ = vault.rehydrate(guarded)

        warn = top_attack.verdict in ("flag", "block") or any(d.quarantined for d in doc_reports) or bool(events) or hidden_removed
        res.action = "allowed_with_warnings" if warn else "allowed"
        parts = []
        if any(d.quarantined for d in doc_reports):
            parts.append("تم عزل مستند يحتوي على تعليمات خفية ولم يُرسل إلى النموذج")
        if top_attack.verdict == "flag":
            parts.append("اشتُبه بمحاولة تلاعب وسُمح بالطلب بعد الحجب")
        if events:
            parts.append(f"حجب حارس المخرجات {len(events)} عنصراً من رد النموذج")
        if hidden_removed:
            parts.append(f"أُزيلت {hidden_removed} حروف مخفية")
        res.message_ar = "؛ ".join(parts)
        return self._finish(res, all_findings, top_score, False, sent=True, t0=t0)

    # ----------------------------------------------------------------- helpers
    def _finish(self, res: Result, all_findings, attack_score, attack_blocked, sent, t0) -> Result:
        quarantined = sum(d.quarantined for d in res.docs)
        blocked_attack = attack_blocked or quarantined > 0
        res.risk = risk.assess(all_findings, attack_score=attack_score, attack_blocked=blocked_attack,
                               external=self.config.external, sent=sent)
        res.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        rules = {f.rule_id: {"rule_id": f.rule_id, "family_ar": f.family_ar, "owasp": f.owasp, "weight": f.weight}
                 for r in [res.attack] + [d.attack for d in res.docs] for f in r.findings}
        res.event = self.audit.record({
            "action": res.action,
            "data_types": count_by_type(all_findings),
            "items_masked": len(res.tokens),
            "token_names": [t for t, _ in res.tokens],
            "attack_score": attack_score,
            "attack_rules": list(rules.values()),
            "docs_total": len(res.docs),
            "docs_quarantined": quarantined,
            "output_events": res.output_events,
            "inherent": res.risk["inherent"], "inherent_level": res.risk["inherent_level"],
            "residual": res.risk["residual"], "residual_level": res.risk["residual_level"],
            "latency_ms": res.latency_ms,
            "external": self.config.external,
        })
        return res
