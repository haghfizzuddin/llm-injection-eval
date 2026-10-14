"""Run the corpus against a target and produce the report.

For every attack we always query the model (so ASR_raw is measured), then
compute what each defence layer would have done:

    ASR_raw    succeeded
    ASR_input  succeeded and the input detector did NOT block
    ASR_both   succeeded and neither the input detector nor the output
               filter blocked

Benign prompts are scored by the input detector only; the model is not
called for them.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .app import build_messages
from .corpus import ATTACK_CLASSES, AttackCase, BenignCase, load_attacks, load_benign
from .detector import InputDetector, OutputFilter
from .judge import attack_succeeded
from .targets import Target


@dataclass
class AttackResult:
    id: str
    cls: str
    technique: str
    input_blocked: bool
    input_score: float
    input_fired: list[str]
    output_blocked: str | None
    succeeded_raw: bool
    succeeded_after_input: bool
    succeeded_after_both: bool
    output: str


@dataclass
class BenignResult:
    id: str
    input_blocked: bool
    input_score: float
    input_fired: list[str]


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def run(
    target: Target,
    attacks: list[AttackCase] | None = None,
    benign: list[BenignCase] | None = None,
    detector: InputDetector | None = None,
    out_filter: OutputFilter | None = None,
    classes: set[str] | None = None,
    verbose: bool = False,
) -> dict:
    attacks = attacks or load_attacks()
    benign = benign or load_benign()
    detector = detector or InputDetector()
    out_filter = out_filter or OutputFilter()
    if classes:
        attacks = [a for a in attacks if a.cls in classes]

    started = time.time()
    attack_results: list[AttackResult] = []
    for case in attacks:
        verdict = detector.score(case.user, case.document)
        output = target.chat(build_messages(case.user, case.document))
        out_reason = out_filter.check(output)
        ok = attack_succeeded(case, output)
        res = AttackResult(
            id=case.id,
            cls=case.cls,
            technique=case.technique,
            input_blocked=verdict.blocked,
            input_score=verdict.score,
            input_fired=verdict.fired,
            output_blocked=out_reason,
            succeeded_raw=ok,
            succeeded_after_input=ok and not verdict.blocked,
            succeeded_after_both=ok and not verdict.blocked and out_reason is None,
            output=output,
        )
        attack_results.append(res)
        if verbose:
            flag = "SUCCESS" if ok else "fail   "
            print(f"[{flag}] {case.cls:18s} {case.id:28s} input={'BLOCK' if verdict.blocked else 'allow'} "
                  f"score={verdict.score:<4} out={out_reason or '-'}")

    benign_results = [
        BenignResult(b.id, v.blocked, v.score, v.fired)
        for b in benign
        for v in [detector.score(b.user, b.document)]
    ]

    per_class: dict[str, dict] = {}
    for cls in ATTACK_CLASSES:
        rows = [r for r in attack_results if r.cls == cls]
        if not rows:
            continue
        n = len(rows)
        per_class[cls] = {
            "n": n,
            "asr_raw": _rate(sum(r.succeeded_raw for r in rows), n),
            "asr_after_input": _rate(sum(r.succeeded_after_input for r in rows), n),
            "asr_after_both": _rate(sum(r.succeeded_after_both for r in rows), n),
            "input_block_rate": _rate(sum(r.input_blocked for r in rows), n),
        }

    n_att = len(attack_results)
    n_ben = len(benign_results)
    summary = {
        "target": target.name,
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1),
        "attacks": n_att,
        "benign": n_ben,
        "asr_raw": _rate(sum(r.succeeded_raw for r in attack_results), n_att),
        "asr_after_input": _rate(sum(r.succeeded_after_input for r in attack_results), n_att),
        "asr_after_both": _rate(sum(r.succeeded_after_both for r in attack_results), n_att),
        "input_detector_recall": _rate(sum(r.input_blocked for r in attack_results), n_att),
        "benign_fp_rate": _rate(sum(b.input_blocked for b in benign_results), n_ben),
        "detector_threshold": detector.threshold,
    }
    return {
        "summary": summary,
        "per_class": per_class,
        "attacks": [asdict(r) for r in attack_results],
        "benign": [asdict(b) for b in benign_results],
    }


def write_report(report: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = report["summary"]["target"].replace(":", "_").replace("/", "_")
    json_path = out_dir / f"run_{safe_target}_{stamp}.json"
    md_path = out_dir / f"run_{safe_target}_{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"# Injection eval: {s['target']}",
        "",
        f"Run {s['run_at']} in {s['duration_s']}s. {s['attacks']} attack cases, {s['benign']} benign prompts, "
        f"input detector threshold {s['detector_threshold']}.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack success, no defences | {_pct(s['asr_raw'])} |",
        f"| Attack success, input detector | {_pct(s['asr_after_input'])} |",
        f"| Attack success, input detector + output filter | {_pct(s['asr_after_both'])} |",
        f"| Input detector recall on attacks | {_pct(s['input_detector_recall'])} |",
        f"| Input detector false positives on benign | {_pct(s['benign_fp_rate'])} |",
        "",
        "## By attack class",
        "",
        "| Class | n | ASR raw | after input | after both | input block rate |",
        "|---|---|---|---|---|---|",
    ]
    for cls, row in report["per_class"].items():
        lines.append(
            f"| {cls} | {row['n']} | {_pct(row['asr_raw'])} | {_pct(row['asr_after_input'])} | "
            f"{_pct(row['asr_after_both'])} | {_pct(row['input_block_rate'])} |"
        )
    survivors = [a for a in report["attacks"] if a["succeeded_after_both"]]
    lines += ["", f"## Attacks that beat both layers ({len(survivors)})", ""]
    if not survivors:
        lines.append("None in this run.")
    for a in survivors:
        lines.append(f"- `{a['id']}` ({a['cls']} / {a['technique']}), detector score {a['input_score']}")
    fps = [b for b in report["benign"] if b["input_blocked"]]
    lines += ["", f"## Benign prompts blocked ({len(fps)})", ""]
    if not fps:
        lines.append("None.")
    for b in fps:
        lines.append(f"- `{b['id']}` score {b['input_score']} rules {', '.join(b['input_fired'])}")
    if s["target"] == "mock":
        lines += ["", "> **Mock target.** These numbers exercise the harness only and say nothing about any real model."]
    return "\n".join(lines) + "\n"
