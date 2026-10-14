#!/usr/bin/env python3
"""One-command runner.

    python run_eval.py                       # mock target, proves the harness works
    python run_eval.py --target ollama:llama3.1
    python run_eval.py --target bedrock:anthropic.claude-3-haiku-20240307-v1:0
    python run_eval.py --target ollama:llama3.1 --classes tool_abuse,indirect_injection -v
    python run_eval.py --threshold 4.0       # sweep the detector threshold
    python run_eval.py --rules old_rules.yaml  # compare detector versions
    python run_eval.py --target ollama:llama3.1 --match 'h2-*'   # query only some cases

    # rescore saved transcripts with other input detectors, no model calls:
    python run_eval.py --rescore results/run_a.json results/run_b.json \\
        --detector regex,classifier,embed,regex+classifier

Reports land in results/ as JSON (full transcripts) and Markdown (summary).
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from injeval.corpus import ATTACK_CLASSES, load_attacks, load_benign  # noqa: E402
from injeval.runner import evaluate, load_outputs, query, write_comparison, write_report  # noqa: E402
from injeval.semantic import make_detector  # noqa: E402
from injeval.targets import make_target  # noqa: E402


def _print_summary(s: dict) -> None:
    print(f"attacks={s['attacks']} benign={s['benign']} detector={s['detector']} threshold={s['detector_threshold']}")
    print(f"ASR raw            {s['asr_raw']}")
    print(f"ASR after input    {s['asr_after_input']}")
    print(f"ASR after both     {s['asr_after_both']}")
    print(f"detector recall    {s['input_detector_recall']}")
    print(f"benign FP rate     {s['benign_fp_rate']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM injection / jailbreak / tool-abuse eval harness")
    ap.add_argument("--target", default="mock", help="mock | ollama[:model] | bedrock:<model_id>")
    ap.add_argument("--classes", help="comma-separated subset of: " + ",".join(ATTACK_CLASSES))
    ap.add_argument("--match", help="only attack ids matching this glob, e.g. 'h2-*'")
    ap.add_argument("--detector", default="regex",
                    help="regex | classifier | embed, '+' to layer them; comma-separated list with --rescore")
    ap.add_argument("--threshold", type=float, help="override the input detector threshold")
    ap.add_argument("--rules", help="detector rules YAML (default rules/detector_rules.yaml)")
    ap.add_argument("--rescore", nargs="+", metavar="RUN_JSON",
                    help="rescore saved run JSON (one target) instead of querying a model")
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    classes = set(args.classes.split(",")) if args.classes else None
    if classes and not classes <= set(ATTACK_CLASSES):
        ap.error(f"unknown classes: {sorted(classes - set(ATTACK_CLASSES))}")
    attacks = load_attacks()
    if classes:
        attacks = [a for a in attacks if a.cls in classes]
    if args.match:
        attacks = [a for a in attacks if fnmatch.fnmatch(a.id, args.match)]
    benign = load_benign()
    out_dir = Path(__file__).resolve().parent / args.out

    if args.rescore:
        target_name, outputs = load_outputs([Path(p) for p in args.rescore])
        missing = [a.id for a in attacks if a.id not in outputs]
        if missing:
            print(f"note: {len(missing)} cases have no saved output and are skipped: {', '.join(missing[:8])}...")
        reports = []
        for spec in args.detector.split(","):
            detector = make_detector(spec, rules=args.rules, threshold=args.threshold)
            report = evaluate(target_name, outputs, attacks, benign, detector, verbose=args.verbose)
            reports.append(report)
            print()
            _print_summary(report["summary"])
        json_path, md_path = write_comparison(reports, out_dir)
        print(f"\ncomparison: {md_path}\n      json: {json_path}")
        return 0

    target = make_target(args.target)
    detector = make_detector(args.detector, rules=args.rules, threshold=args.threshold)
    print(f"target={target.name} detector={detector.name} threshold={detector.threshold} "
          f"cases={len(attacks)}")

    started = time.time()
    outputs = query(target, attacks, verbose=args.verbose)
    report = evaluate(target.name, outputs, attacks, benign, detector,
                      duration_s=time.time() - started, verbose=args.verbose)
    json_path, md_path = write_report(report, out_dir)

    print()
    _print_summary(report["summary"])
    print(f"\nreport: {md_path}\n   json: {json_path}")
    if target.name == "mock":
        print("\nMock target: harness check only, not a result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
