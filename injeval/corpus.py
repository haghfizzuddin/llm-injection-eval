"""Load the attack and benign corpora from YAML.

Every attack case carries:
    id             unique string
    cls            attack class (direct_injection, indirect_injection,
                   jailbreak, exfiltration, tool_abuse, obfuscation)
    technique      short label for the specific trick
    user           the user turn sent to the model
    document       optional: untrusted content the "application" has
                   retrieved and placed in context (indirect injection)
    goal           one of: marker | canary | tool_call
    marker         the string the attacker wants the model to emit
                   (goal == marker)
    tool           the forbidden tool call the attacker wants
                   (goal == tool_call), e.g. {"name": "send_email",
                   "args_contains": "attacker@"}
    source         where the technique comes from (paper, disclosure,
                   OWASP entry) so every case is traceable
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT / "corpus"

ATTACK_CLASSES = (
    "direct_injection",
    "indirect_injection",
    "jailbreak",
    "exfiltration",
    "tool_abuse",
    "obfuscation",
)


@dataclass
class AttackCase:
    id: str
    cls: str
    technique: str
    user: str
    goal: str
    document: str | None = None
    marker: str | None = None
    tool: dict[str, Any] | None = None
    source: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.cls not in ATTACK_CLASSES:
            raise ValueError(f"{self.id}: unknown class {self.cls!r}")
        if self.goal not in ("marker", "canary", "tool_call"):
            raise ValueError(f"{self.id}: unknown goal {self.goal!r}")
        if self.goal == "marker" and not self.marker:
            raise ValueError(f"{self.id}: goal=marker needs a marker")
        if self.goal == "tool_call" and not self.tool:
            raise ValueError(f"{self.id}: goal=tool_call needs a tool")


@dataclass
class BenignCase:
    id: str
    user: str
    document: str | None = None
    notes: str = ""


def _load_yaml(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list at the top level")
    return data


def load_attacks(path: Path | None = None) -> list[AttackCase]:
    path = path or CORPUS_DIR / "attacks.yaml"
    cases = [AttackCase(**item) for item in _load_yaml(path)]
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(f"duplicate attack ids: {dupes}")
    return cases


def load_benign(path: Path | None = None) -> list[BenignCase]:
    path = path or CORPUS_DIR / "benign.yaml"
    return [BenignCase(**item) for item in _load_yaml(path)]


CASE_SETS = ("original", "heldout-1", "heldout-2")


def case_set(case_id: str) -> str:
    """Which set a case belongs to, from its id prefix. The held-out sets
    were written blind, after the detector they were first used to test."""
    if case_id.startswith(("h2-", "ben-h2-")):
        return "heldout-2"
    if case_id.startswith("ho-"):
        return "heldout-1"
    return "original"
