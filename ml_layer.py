"""
Dir' (درع): the optional machine-learning layer.

The rules in attacks.py / detectors.py stay the first line of defence (fast, explainable, exact for IDs and IBANs).
This layer adds three things that rules are bad at:

  1. paraphrase detection : "كأنك ما سمعت أي توجيه قبل هذا" means "ignore previous instructions" but matches no rule
                            -> sentence embeddings compared with a bank of known attacks (kNN) and with normal requests
  2. zero-shot intent     : a multilingual NLI model answers "is this text trying to override the assistant's rules?"
  3. Arabic NER           : person names without a trigger word ("قابلت محمد العتيبي أمس")

Design rules
  - Everything is optional and lazy. If a model is missing or fails to load, status says so and the rest keeps working.
  - ML can raise a flag. It cannot block on its own: a block needs a rule to agree (see hybrid.py).
  - The thresholds below are PLACEHOLDERS. Calibrate them on your machine with bench_ml.py before quoting any number.
  - No data leaves the machine: models run locally (first run downloads them from Hugging Face, then they are cached).

Models (all public on Hugging Face; verify the names on your machine, they are configurable):
  embeddings : sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2   (~470 MB, CPU is fine)
  zero-shot  : MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7     (~1.1 GB, CPU ~0.3-1 s per text)
  NER        : CAMeL-Lab/bert-base-arabic-camelbert-msa-ner                  (~440 MB)
"""
from __future__ import annotations

from dataclasses import dataclass, field

EMBED_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
ZS_MODEL = "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7"
NER_MODEL = "CAMeL-Lab/bert-base-arabic-camelbert-msa-ner"

ATTACK_LABELS = [
    "The text tells an AI assistant to ignore or override its previous instructions or rules",
    "The text asks an AI assistant to reveal its hidden system prompt, secrets or other people's data",
]
NORMAL_LABEL = "The text is an ordinary work request or document"
SENSITIVE_ANCHORS = [
    "رقم الهوية الوطنية", "رقم الحساب البنكي الآيبان", "رقم الإقامة", "بيانات بطاقة الائتمان والرمز السري",
    "my national ID number is", "my bank account IBAN is",
]


@dataclass
class MLConfig:
    use_knn: bool = True
    use_zero_shot: bool = False      # ~7 s per message on a laptop CPU: too slow for real-time, so opt-in
    use_ner: bool = True
    clf_path: str = ""                # folder of the fine-tuned attack classifier from the Colab notebook ("" = not used)
    clf_threshold: float = 0.5        # PLACEHOLDER: choose it on val/DEV, then report TEST once
    knn_attack_sim: float = 0.72      # PLACEHOLDER: min cosine similarity to a known attack
    knn_margin: float = 0.05          # ...and it must beat the closest normal request by this much
    zs_threshold: float = 0.80        # PLACEHOLDER: zero-shot probability that the text is an attack
    ner_min_score: float = 0.85
    max_chars: int = 1500             # long texts are scored in chunks of this size

    @classmethod
    def from_file(cls, path: str = "ml_thresholds.json", **kw):
        """Defaults, overridden by thresholds saved with `python bench_ml.py --save` when that file exists."""
        import json
        import os
        cfg = cls(**kw)
        if os.path.exists(path):
            try:
                for k, v in json.load(open(path)).items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, float(v))
            except (OSError, ValueError):
                pass
        return cfg


@dataclass
class MLSignals:
    knn_attack: float = 0.0
    knn_normal: float = 0.0
    knn_nearest: str = ""
    zero_shot: float = 0.0
    knn_hit: bool = False
    zs_hit: bool = False
    clf_prob: float = 0.0
    clf_hit: bool = False
    used: list = field(default_factory=list)

    @property
    def hits(self) -> int:
        return int(self.knn_hit) + int(self.zs_hit) + int(self.clf_hit)


def _default_factories():
    def embed(name):
        from sentence_transformers import SentenceTransformer
        m = SentenceTransformer(name)
        return lambda texts: m.encode(list(texts), normalize_embeddings=True, convert_to_numpy=True)

    def zero_shot(name):
        from transformers import pipeline
        p = pipeline("zero-shot-classification", model=name)

        def run(text, labels):
            r = p(text, labels, multi_label=True, hypothesis_template="{}.")
            return dict(zip(r["labels"], r["scores"]))
        return run

    def ner(name):
        from transformers import pipeline
        p = pipeline("token-classification", model=name, aggregation_strategy="simple")
        return lambda text: p(text)

    def clf(path):
        from transformers import pipeline
        p = pipeline("text-classification", model=path, top_k=None, truncation=True, max_length=128)

        def run(text):
            r = p(text)
            r = r[0] if r and isinstance(r[0], list) else r
            return {str(x["label"]): float(x["score"]) for x in r}      # labels: LABEL_0 normal, LABEL_1 attack
        return run

    return {"embed": embed, "zero_shot": zero_shot, "ner": ner, "clf": clf}


class MLLayer:
    """`factories` lets tests (or another backend) plug in fake models: {"embed": f(name)->encode, ...}."""

    def __init__(self, config: MLConfig | None = None, attack_bank=(), normal_bank=(), factories=None,
                 embed_model=EMBED_MODEL, zs_model=ZS_MODEL, ner_model=NER_MODEL):
        self.config = config or MLConfig()
        self._factories = factories or _default_factories()
        self._names = {"embed": embed_model, "zero_shot": zs_model, "ner": ner_model, "clf": self.config.clf_path}
        self._attack_bank = list(attack_bank)
        self._normal_bank = list(normal_bank)
        self._models: dict = {}
        self.status: dict = {}            # part -> "ready" | "off" | "failed: <reason>"
        self._bank_vecs = None

    # ------------------------------------------------------------- loading
    def _load(self, part: str):
        if part in self._models:
            return self._models[part]
        try:
            self._models[part] = self._factories[part](self._names[part])
            self.status[part] = "ready"
        except Exception as exc:          # missing package, no internet on first run, out of memory...
            self._models[part] = None
            self.status[part] = f"failed: {type(exc).__name__}: {str(exc)[:80]}"
        return self._models[part]

    def load_all(self) -> dict:
        c = self.config
        if c.use_knn or c.use_ner is None:
            self._load("embed")
        if c.use_zero_shot:
            self._load("zero_shot")
        if c.use_ner:
            self._load("ner")
        if c.clf_path:
            self._load("clf")
        for part, on in (("embed", c.use_knn), ("zero_shot", c.use_zero_shot), ("ner", c.use_ner)):
            if not on:
                self.status[part] = "off"
        return self.status

    @property
    def ready(self) -> bool:
        return any(v == "ready" for v in self.status.values())

    # ------------------------------------------------------------- scoring
    def _chunks(self, text: str):
        n = self.config.max_chars
        return [text[i:i + n] for i in range(0, max(len(text), 1), n)] or [""]

    def _bank(self):
        if self._bank_vecs is None:
            enc = self._models["embed"]
            att = enc(self._attack_bank) if self._attack_bank else None
            nor = enc(self._normal_bank) if self._normal_bank else None
            self._bank_vecs = (att, nor)
        return self._bank_vecs

    def attack_signals(self, text: str) -> MLSignals:
        """`text` should already be normalized (normalize.normalize(text).text)."""
        c, sig = self.config, MLSignals()
        if not text.strip():
            return sig
        if c.use_knn and self._load("embed") is not None and self._attack_bank:
            import numpy as np
            att, nor = self._bank()
            enc = self._models["embed"]
            sims_a, sims_n, nearest = [], [], ""
            for ch in self._chunks(text):
                v = np.asarray(enc([ch]))[0]
                sa = np.asarray(att) @ v
                i = int(sa.argmax())
                if float(sa[i]) >= (max(sims_a) if sims_a else -1):
                    nearest = self._attack_bank[i]
                sims_a.append(float(sa[i]))
                sims_n.append(float((np.asarray(nor) @ v).max()) if nor is not None else 0.0)
            sig.knn_attack, sig.knn_normal, sig.knn_nearest = max(sims_a), max(sims_n), nearest
            sig.knn_hit = sig.knn_attack >= c.knn_attack_sim and sig.knn_attack - sig.knn_normal >= c.knn_margin
            sig.used.append("knn")
        if c.use_zero_shot and self._load("zero_shot") is not None:
            zs = self._models["zero_shot"]
            best = 0.0
            for ch in self._chunks(text):
                scores = zs(ch, ATTACK_LABELS + [NORMAL_LABEL])
                best = max(best, max(scores[l] for l in ATTACK_LABELS))
            sig.zero_shot = round(best, 3)
            sig.zs_hit = best >= c.zs_threshold
            sig.used.append("zero_shot")
        if c.clf_path and self._load("clf") is not None:
            best = 0.0
            for ch in self._chunks(text):
                sc = self._models["clf"](ch)
                best = max(best, sc.get("LABEL_1", sc.get("attack", 0.0)))
            sig.clf_prob = round(best, 3)
            sig.clf_hit = best >= c.clf_threshold
            sig.used.append("clf")
        return sig

    def person_spans(self, text: str) -> list:
        """[(start, end, score)] of PER entities, in coordinates of `text`."""
        if not self.config.use_ner or self._load("ner") is None:
            return []
        out = []
        for ent in self._models["ner"](text[: self.config.max_chars]):
            grp = str(ent.get("entity_group") or ent.get("entity") or "")
            if grp.upper().endswith("PER") and float(ent.get("score", 0)) >= self.config.ner_min_score:
                out.append((int(ent["start"]), int(ent["end"]), float(ent["score"])))
        return out

    def sensitive_similarity(self, text: str) -> float:
        """Max similarity to 'my national ID is...'-style anchors. Used only as a hint, never to mask on its own."""
        if self._load("embed") is None:
            return 0.0
        import numpy as np
        enc = self._models["embed"]
        v = np.asarray(enc([text[: self.config.max_chars]]))[0]
        return float((np.asarray(enc(SENSITIVE_ANCHORS)) @ v).max())