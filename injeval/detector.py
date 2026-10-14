"""Rule-based input detector and output filter.

The input detector scores the user turn and any retrieved document
against weighted regex rules in rules/detector_rules.yaml. A score at
or above the threshold blocks the request before it reaches the model.
This is the same shape as a phishing URL rule engine: cheap, explainable,
tunable, and measurable for false positives.

The output filter runs after the model: it blocks a response that leaks
the canary, or that calls a tool in a forbidden way. The two are kept
separate so the report can show how much each layer buys.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .app import CANARY, COMPANY_DOMAIN
from .targets import parse_tool_call

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT / "rules" / "detector_rules.yaml"


@dataclass
class Rule:
    id: str
    weight: float
    pattern: re.Pattern
    scope: str  # "user" | "document" | "any"
    description: str = ""


@dataclass
class Verdict:
    blocked: bool
    score: float
    fired: list[str] = field(default_factory=list)


def _normalise(text: str) -> str:
    """Fold the cheap evasions before matching: NFKC (fullwidth, ligatures),
    decode Unicode TAG characters back to the ASCII they smuggle, drop
    zero-width characters, collapse whitespace.

    Decoding rather than stripping matters: a stripped tag payload is
    invisible to the detector but still readable by the model."""
    text = unicodedata.normalize("NFKC", text)
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:          # TAG block carries printable ASCII
            out.append(chr(cp - 0xE0000))
        elif cp in (0xE0001, 0xE007F):        # language tag / cancel tag: drop
            continue
        elif ch in "\u200b\u200c\u200d\u2060\ufeff":  # zero-width family
            continue
        else:
            out.append(ch)
    return re.sub(r"\s+", " ", "".join(out))


class InputDetector:
    def __init__(self, rules_path: Path | None = None, threshold: float | None = None):
        with (rules_path or RULES_PATH).open(encoding="utf-8") as fh:
            spec = yaml.safe_load(fh)
        self.threshold = threshold if threshold is not None else float(spec["threshold"])
        self.rules = [
            Rule(
                id=r["id"],
                weight=float(r["weight"]),
                pattern=re.compile(r["pattern"], re.I | re.S),
                scope=r.get("scope", "any"),
                description=r.get("description", ""),
            )
            for r in spec["rules"]
        ]

    def score(self, user: str, document: str | None = None) -> Verdict:
        user_n = _normalise(user)
        doc_n = _normalise(document) if document else ""
        total = 0.0
        fired: list[str] = []
        for rule in self.rules:
            hay = {"user": user_n, "document": doc_n, "any": user_n + "\n" + doc_n}[rule.scope]
            if hay and rule.pattern.search(hay):
                total += rule.weight
                fired.append(rule.id)
        return Verdict(blocked=total >= self.threshold, score=round(total, 2), fired=fired)


class OutputFilter:
    """Blocks a model response that leaked the canary or made a forbidden
    tool call. Returns the reason, or None if the response is clean."""

    def check(self, output: str) -> str | None:
        if CANARY in output:
            return "canary_leak"
        call = parse_tool_call(output)
        if call:
            name = call.get("name")
            args = call.get("args") or {}
            if name == "delete_record":
                return "forbidden_tool:delete_record"
            if name == "send_email":
                to = str(args.get("to", ""))
                if not to.lower().endswith(COMPANY_DOMAIN):
                    return "forbidden_tool:send_email_external"
        return None
