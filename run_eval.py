#!/usr/bin/env python3
"""One-command runner.

    python run_eval.py                       # mock target, proves the harness works
    python run_eval.py --target ollama:llama3.1
    python run_eval.py --target bedrock:anthropic.claude-3-haiku-20240307-v1:0
    python run_eval.py --target ollama:llama3.1 --classes tool_abuse,indirect_injection -v
    python run_eval.py --threshold 4.0       # sweep the detector threshold
    python run_eval.py --rules old_rules.yaml  # compare detector versions

Reports land in results/ as JSON (full transcripts) and Markdown (summary).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from injeval.corpus import ATTACK_CLASSES  # noqa: E402
from injeval.detector import InputDetector  # noqa: E402
from injeval.runner import run, write_report  # noqa: E402
from injeval.targets import make_target  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM injection / jailbreak / tool-abuse eval harness")
    ap.add_argument("--target", default="mock", help="mock | ollama[:model] | bedrock:<model_id>")
    ap.add_argument("--classes", help="comma-separated subset of: " + ",".join(ATTACK_CLASSES))
    ap.add_argument("--threshold", type=float, help="override the input detector threshold")
    ap.add_argument("--rules", help="detector rules YAML (default rules/detector_rules.yaml)")
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    classes = set(args.classes.split(",")) if args.classes else None
    if classes and not classes <= set(ATTACK_CLASSES):
        ap.error(f"unknown classes: {sorted(classes - set(ATTACK_CLASSES))}")

    target = make_target(args.target)
    detector = InputDetector(rules_path=Path(args.rules) if args.rules else None, threshold=args.threshold)
    print(f"target={target.name} threshold={detector.threshold} classes={sorted(classes) if classes else 'all'}")

    report = run(target, detector=detector, classes=classes, verbose=args.verbose)
    json_path, md_path = write_report(report, Path(__file__).resolve().parent / args.out)

    s = report["summary"]
    print()
    print(f"attacks={s['attacks']} benign={s['benign']}")
    print(f"ASR raw            {s['asr_raw']}")
    print(f"ASR after input    {s['asr_after_input']}")
    print(f"ASR after both     {s['asr_after_both']}")
    print(f"detector recall    {s['input_detector_recall']}")
    print(f"benign FP rate     {s['benign_fp_rate']}")
    print(f"\nreport: {md_path}\n   json: {json_path}")
    if target.name == "mock":
        print("\nMock target: harness check only, not a result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
