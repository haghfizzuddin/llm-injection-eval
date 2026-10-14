"""Run the corpus against a target and produce the report.

For every attack we always query the model (so ASR_raw is measured), then
compute what each defence layer would have done:

    ASR_raw    succeeded
    ASR_input  succeeded and the input detector did NOT block
    ASR_both   succeeded and neither the input detector nor the output
               filter blocked

Benign prompts are scored by the input detector only; the model is not
called for them.

Querying and evaluating are separate steps. Because the model is queried
regardless of the detector, a saved run can be rescored with any other
detector without calling the model again (see load_outputs).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .app import build_messages
from .corpus import ATTACK_CLASSES, CASE_SETS, AttackCase, BenignCase, case_set, load_attacks, load_benign
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


def query(target: Target, attacks: list[AttackCase], verbose: bool = False) -> dict[str, str]:
    """Send every attack to the model; return {case id: output}."""
    outputs = {}
    for i, case in enumerate(attacks, 1):
        outputs[case.id] = target.chat(build_messages(case.user, case.document))
        if verbose:
            print(f"[{i}/{len(attacks)}] {case.id}", flush=True)
    return outputs


def load_outputs(paths: list[Path]) -> tuple[str, dict[str, str]]:
    """Read model outputs back from saved run JSON files (one target)."""
    target, outputs = None, {}
    for path in paths:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        name = report["summary"]["target"]
        if target not in (None, name):
            raise SystemExit(f"{path}: target {name!r} differs from {target!r}")
        target = name
        outputs.update({a["id"]: a["output"] for a in report["attacks"]})
    return target, outputs


def _metrics(rows: list[AttackResult]) -> dict:
    n = len(rows)
    return {
        "n": n,
        "asr_raw": _rate(sum(r.succeeded_raw for r in rows), n),
        "asr_after_input": _rate(sum(r.succeeded_after_input for r in rows), n),
        "asr_after_both": _rate(sum(r.succeeded_after_both for r in rows), n),
        "input_block_rate": _rate(sum(r.input_blocked for r in rows), n),
    }


def evaluate(
    target_name: str,
    outputs: dict[str, str],
    attacks: list[AttackCase],
    benign: list[BenignCase],
    detector,
    out_filter: OutputFilter | None = None,
    duration_s: float = 0.0,
    verbose: bool = False,
) -> dict:
    out_filter = out_filter or OutputFilter()
    attack_results: list[AttackResult] = []
    for case in attacks:
        if case.id not in outputs:
            continue
        output = outputs[case.id]
        verdict = detector.score(case.user, case.document)
        out_reason = out_filter.check(output)
        ok = attack_succeeded(case, output)
        attack_results.append(
            AttackResult(
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
        )
        if verbose:
            flag = "SUCCESS" if ok else "fail   "
            print(f"[{flag}] {case.cls:18s} {case.id:28s} input={'BLOCK' if verdict.blocked else 'allow'} "
                  f"score={verdict.score:<5} out={out_reason or '-'}")

    benign_results = [
        BenignResult(b.id, v.blocked, v.score, v.fired)
        for b in benign
        for v in [detector.score(b.user, b.document)]
    ]

    per_class = {
        cls: _metrics(rows)
        for cls in ATTACK_CLASSES
        if (rows := [r for r in attack_results if r.cls == cls])
    }
    per_set = {}
    for name in CASE_SETS:
        rows = [r for r in attack_results if case_set(r.id) == name]
        bens = [b for b in benign_results if case_set(b.id) == name]
        if rows or bens:
            per_set[name] = _metrics(rows) | {
                "benign": len(bens),
                "benign_fp_rate": _rate(sum(b.input_blocked for b in bens), len(bens)),
            }

    summary = {
        "target": target_name,
        "detector": getattr(detector, "name", "regex"),
        "detector_threshold": detector.threshold,
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(duration_s, 1),
        "attacks": len(attack_results),
        "benign": len(benign_results),
        "asr_raw": _metrics(attack_results)["asr_raw"],
        "asr_after_input": _metrics(attack_results)["asr_after_input"],
        "asr_after_both": _metrics(attack_results)["asr_after_both"],
        "input_detector_recall": _metrics(attack_results)["input_block_rate"],
        "benign_fp_rate": _rate(sum(b.input_blocked for b in benign_results), len(benign_results)),
    }
    return {
        "summary": summary,
        "per_class": per_class,
        "per_set": per_set,
        "attacks": [asdict(r) for r in attack_results],
        "benign": [asdict(b) for b in benign_results],
    }


def run(
    target: Target,
    attacks: list[AttackCase] | None = None,
    benign: list[BenignCase] | None = None,
    detector=None,
    out_filter: OutputFilter | None = None,
    classes: set[str] | None = None,
    verbose: bool = False,
) -> dict:
    attacks = attacks or load_attacks()
    benign = benign or load_benign()
    detector = detector or InputDetector()
    if classes:
        attacks = [a for a in attacks if a.cls in classes]
    started = time.time()
    outputs = query(target, attacks, verbose=verbose)
    return evaluate(target.name, outputs, attacks, benign, detector, out_filter,
                    duration_s=time.time() - started, verbose=verbose)


def _stamp_paths(out_dir: Path, prefix: str, target: str, ext: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    return out_dir / f"{prefix}_{safe_target}_{stamp}.{ext}"


def write_report(report: dict, out_dir: Path) -> tuple[Path, Path]:
    target = report["summary"]["target"]
    json_path = _stamp_paths(out_dir, "run", target, "json")
    md_path = json_path.with_suffix(".md")
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
        f"input detector {s['detector']} (threshold {s['detector_threshold']}).",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack success, no defences | {_pct(s['asr_raw'])} |",
        f"| Attack success, input detector | {_pct(s['asr_after_input'])} |",
        f"| Attack success, input detector + output filter | {_pct(s['asr_after_both'])} |",
        f"| Input detector recall on attacks | {_pct(s['input_detector_recall'])} |",
        f"| Input detector false positives on benign | {_pct(s['benign_fp_rate'])} |",
        "",
        "## By case set",
        "",
        "| Set | attacks | ASR raw | after input | after both | detector recall | benign | benign FP |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name, row in report.get("per_set", {}).items():
        lines.append(
            f"| {name} | {row['n']} | {_pct(row['asr_raw'])} | {_pct(row['asr_after_input'])} | "
            f"{_pct(row['asr_after_both'])} | {_pct(row['input_block_rate'])} | {row['benign']} | "
            f"{_pct(row['benign_fp_rate'])} |"
        )
    lines += [
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
        lines.append(f"- `{b['id']}` score {b['input_score']} fired {', '.join(b['input_fired'])}")
    if s["target"] == "mock":
        lines += ["", "> **Mock target.** These numbers exercise the harness only and say nothing about any real model."]
    return "\n".join(lines) + "\n"


def render_comparison(reports: list[dict]) -> str:
    """One table per case set, one row per detector, all on the same transcripts."""
    s0 = reports[0]["summary"]
    lines = [
        f"# Detector comparison: {s0['target']}",
        "",
        f"Rescored {s0['run_at']} from saved transcripts: the model outputs are fixed, only the input "
        f"detector changes. {s0['attacks']} attack cases, {s0['benign']} benign prompts.",
    ]
    for name in CASE_SETS:
        rows = [(r["summary"], r["per_set"][name]) for r in reports if name in r["per_set"]]
        if not rows:
            continue
        lines += [
            "",
            f"## {name}",
            "",
            "| Detector | threshold | attacks | ASR raw | after input | after both | detector recall | benign | benign FP |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for s, row in rows:
            thr = "n/a" if s["detector_threshold"] is None else s["detector_threshold"]
            lines.append(
                f"| {s['detector']} | {thr} | {row['n']} | {_pct(row['asr_raw'])} | {_pct(row['asr_after_input'])} | "
                f"{_pct(row['asr_after_both'])} | {_pct(row['input_block_rate'])} | {row['benign']} | "
                f"{_pct(row['benign_fp_rate'])} |"
            )
    lines += ["", "## Benign prompts blocked, by detector", ""]
    for r in reports:
        fps = [b["id"] for b in r["benign"] if b["input_blocked"]]
        lines.append(f"- **{r['summary']['detector']}** ({len(fps)}): {', '.join(f'`{i}`' for i in fps) or 'none'}")
    lines += ["", "## Attacks that beat both layers, by detector", ""]
    for r in reports:
        surv = [a["id"] for a in r["attacks"] if a["succeeded_after_both"]]
        lines.append(f"- **{r['summary']['detector']}** ({len(surv)}): {', '.join(f'`{i}`' for i in surv) or 'none'}")
    return "\n".join(lines) + "\n"


def write_comparison(reports: list[dict], out_dir: Path) -> tuple[Path, Path]:
    target = reports[0]["summary"]["target"]
    json_path = _stamp_paths(out_dir, "compare", target, "json")
    md_path = json_path.with_suffix(".md")
    json_path.write_text(json.dumps(reports, indent=2), encoding="utf-8")
    md_path.write_text(render_comparison(reports), encoding="utf-8")
    return json_path, md_path
