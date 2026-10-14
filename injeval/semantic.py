"""Semantic input detectors, the comparison for the regex rules.

    ClassifierDetector  an off-the-shelf prompt-injection classifier run
                        locally with transformers (default
                        protectai/deberta-v3-base-prompt-injection-v2).
                        Used as published: never tuned on this corpus, so
                        every case is unseen by it.
    EmbeddingDetector   nearest neighbour over Ollama embeddings (default
                        nomic-embed-text). The reference set is the original
                        corpus; the threshold is fixed by leave-one-out on
                        that set only, never on held-out cases.
    AnyOf               blocks when any wrapped detector blocks (layering).

All share the regex detector's interface: .name, .threshold and
.score(user, document) -> Verdict. Every detector gets the same
normalised text, so the comparison is detector against detector, not
normaliser against no normaliser.
"""

from __future__ import annotations

import math
import os
from pathlib import Path

from .corpus import case_set, load_attacks, load_benign
from .detector import InputDetector, Verdict, _normalise


class ClassifierDetector:
    """Scores the user turn and the document separately and keeps the
    higher injection probability: a classifier reading one long benign
    document can miss a single override sentence near its end."""

    def __init__(self, model: str = "protectai/deberta-v3-base-prompt-injection-v2", threshold: float = 0.5):
        from transformers import pipeline  # optional dependency, see requirements.txt

        self._clf = pipeline("text-classification", model=model, truncation=True, max_length=512)
        self.threshold = threshold
        self.name = f"classifier:{model.rsplit('/', 1)[-1]}"
        self._cache: dict[str, float] = {}

    def _p_injection(self, text: str) -> float:
        if text not in self._cache:
            out = self._clf(text)[0]
            p = out["score"] if out["label"].upper() == "INJECTION" else 1.0 - out["score"]
            self._cache[text] = p
        return self._cache[text]

    def score(self, user: str, document: str | None = None) -> Verdict:
        parts = {"user": _normalise(user)}
        if document:
            parts["document"] = _normalise(document)
        probs = {k: self._p_injection(v) for k, v in parts.items()}
        top = max(probs, key=probs.get)
        p = probs[top]
        blocked = p >= self.threshold
        return Verdict(blocked=blocked, score=round(p, 3), fired=[f"{top}:{p:.2f}"] if blocked else [])


class EmbeddingDetector:
    """score = similarity to the nearest reference attack minus similarity
    to the nearest reference benign prompt. A query identical to a
    reference case skips that case, which makes scoring the original set
    leave-one-out."""

    PREFIX = "classification: "  # nomic-embed-text task prefix

    def __init__(self, model: str = "nomic-embed-text", host: str | None = None, threshold: float | None = None):
        import requests

        self._requests = requests
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.name = f"embed:{model}"
        self._cache: dict[str, list[float]] = {}
        attacks = [a for a in load_attacks() if case_set(a.id) == "original"]
        benign = [b for b in load_benign() if case_set(b.id) == "original"]
        self._refs = [(self._text(a.user, a.document), True, a.id) for a in attacks] + [
            (self._text(b.user, b.document), False, b.id) for b in benign
        ]
        self._embed([t for t, _, _ in self._refs])
        self.threshold = threshold if threshold is not None else self._calibrate()

    @staticmethod
    def _text(user: str, document: str | None) -> str:
        return _normalise(user) + ("\n\n" + _normalise(document) if document else "")

    def _embed(self, texts: list[str]) -> None:
        todo = [t for t in dict.fromkeys(texts) if t not in self._cache]
        for i in range(0, len(todo), 32):
            batch = todo[i : i + 32]
            r = self._requests.post(
                f"{self.host}/api/embed",
                json={"model": self.model, "input": [self.PREFIX + t for t in batch]},
                timeout=300,
            )
            r.raise_for_status()
            for t, v in zip(batch, r.json()["embeddings"]):
                n = math.sqrt(sum(x * x for x in v)) or 1.0
                self._cache[t] = [x / n for x in v]

    def _margin(self, text: str) -> tuple[float, str]:
        self._embed([text])
        q = self._cache[text]
        best = {True: (-1.0, ""), False: (-1.0, "")}
        for ref_text, is_attack, ref_id in self._refs:
            if ref_text == text:
                continue
            sim = sum(a * b for a, b in zip(q, self._cache[ref_text]))
            if sim > best[is_attack][0]:
                best[is_attack] = (sim, ref_id)
        return best[True][0] - best[False][0], best[True][1]

    def _calibrate(self) -> float:
        """Leave-one-out over the reference set; keep the threshold with the
        best recall minus false-positive rate, the higher one on a tie."""
        scored = [(self._margin(t)[0], is_attack) for t, is_attack, _ in self._refs]
        n_att = sum(a for _, a in scored)
        n_ben = len(scored) - n_att
        best_t, best_j = 0.0, -1.0
        for t in sorted({round(s, 4) for s, _ in scored}, reverse=True):
            tpr = sum(s >= t and a for s, a in scored) / n_att
            fpr = sum(s >= t and not a for s, a in scored) / n_ben
            if tpr - fpr > best_j:
                best_t, best_j = t, tpr - fpr
        return best_t

    def score(self, user: str, document: str | None = None) -> Verdict:
        margin, nearest = self._margin(self._text(user, document))
        blocked = margin >= self.threshold
        return Verdict(blocked=blocked, score=round(margin, 3), fired=[f"near:{nearest}"] if blocked else [])


class AnyOf:
    """Layered input defence: block when any wrapped detector blocks.
    score counts how many detectors blocked."""

    threshold = None

    def __init__(self, *detectors):
        self.detectors = detectors
        self.name = "+".join(d.name for d in detectors)

    def score(self, user: str, document: str | None = None) -> Verdict:
        verdicts = [d.score(user, document) for d in self.detectors]
        return Verdict(
            blocked=any(v.blocked for v in verdicts),
            score=float(sum(v.blocked for v in verdicts)),
            fired=[f for v in verdicts for f in v.fired],
        )


def make_detector(spec: str, rules: str | None = None, threshold: float | None = None):
    """'regex' | 'regex:<rules.yaml>' | 'classifier' | 'embed', or several
    joined with '+' (AnyOf). --rules applies to plain 'regex'; --threshold
    only to a single detector."""
    parts = spec.split("+")
    if len(parts) > 1:
        return AnyOf(*(make_detector(p, rules) for p in parts))
    if spec == "regex":
        return InputDetector(rules_path=Path(rules) if rules else None, threshold=threshold)
    if spec.startswith("regex:"):
        return InputDetector(rules_path=Path(spec[len("regex:"):]), threshold=threshold)
    if spec == "classifier":
        return ClassifierDetector() if threshold is None else ClassifierDetector(threshold=threshold)
    if spec == "embed":
        return EmbeddingDetector(threshold=threshold)
    raise SystemExit(f"unknown detector {spec!r}")
