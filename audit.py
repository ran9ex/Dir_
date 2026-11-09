"""
Dir' (درع): audit log.

PRIVACY BY DESIGN: events never contain the user's text or any detected value.
They hold counts, data types, token names, rule ids and scores only, so the log
itself cannot become a second leak. (Tested in test_gateway.py.)
"""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, path: str | None = None):
        self.events: list = []
        self.path = path

    def record(self, event: dict) -> dict:
        ev = {"id": uuid.uuid4().hex[:12], "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
        self.events.append(ev)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return ev

    def clear(self):
        self.events.clear()

    def stats(self) -> dict:
        evs = self.events
        n = len(evs)
        types, rules, owasp, out_kinds = Counter(), Counter(), Counter(), Counter()
        for e in evs:
            types.update(e.get("data_types", {}))
            for r in e.get("attack_rules", []):
                rules[r["rule_id"]] += 1
                owasp[r["owasp"]] += 1
            for o in e.get("output_events", []):
                out_kinds[o["kind"]] += 1
        inh = [e["inherent"] for e in evs if "inherent" in e]
        res = [e["residual"] for e in evs if "residual" in e]
        return {
            "requests": n,
            "blocked": sum(1 for e in evs if e["action"] == "blocked"),
            "with_warnings": sum(1 for e in evs if e["action"] == "allowed_with_warnings"),
            "clean": sum(1 for e in evs if e["action"] == "allowed"),
            "docs_quarantined": sum(e.get("docs_quarantined", 0) for e in evs),
            "items_masked": sum(e.get("items_masked", 0) for e in evs),
            "data_types": dict(types),
            "attack_rules": dict(rules),
            "owasp": dict(owasp),
            "output_events": dict(out_kinds),
            "avg_inherent": round(sum(inh) / len(inh), 1) if inh else 0.0,
            "avg_residual": round(sum(res) / len(res), 1) if res else 0.0,
            "max_inherent": max(inh) if inh else 0.0,
            "avg_latency_ms": round(sum(e.get("latency_ms", 0) for e in evs) / n, 1) if n else 0.0,
        }
