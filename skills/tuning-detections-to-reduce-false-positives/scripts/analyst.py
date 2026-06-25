#!/usr/bin/env python3
"""Analyze labeled alert history to drive detection tuning.

Computes current precision/false-positive rate and ranks values of a chosen field by their
false-positive contribution, recommending allow-list filters for values with negligible
true-positive loss. Parses alert data only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

TP_LABELS = {"tp", "true_positive", "truepositive", "true", "malicious", "1"}
FP_LABELS = {"fp", "false_positive", "falsepositive", "false", "benign", "0"}


def _rows(path: str):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if path.lower().endswith(".json") or text.lstrip()[:1] in "{[":
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    else:
        for row in csv.DictReader(text.splitlines()):
            yield row


def _verdict(value: str) -> str | None:
    low = str(value).strip().lower()
    if low in TP_LABELS:
        return "tp"
    if low in FP_LABELS:
        return "fp"
    return None


def analyze(path: str, label_field: str, field: str) -> dict:
    tp = fp = 0
    per_value = defaultdict(lambda: {"tp": 0, "fp": 0})
    for row in _rows(path):
        verdict = _verdict(row.get(label_field, ""))
        if verdict is None:
            continue
        if verdict == "tp":
            tp += 1
        else:
            fp += 1
        val = str(row.get(field, "")).lower()
        per_value[val][verdict] += 1
    total = tp + fp
    precision = round(tp / total, 4) if total else 0.0
    # Rank FP contributors; recommend filters where TP loss is zero.
    contributors = sorted(
        ({"value": v, "fp": c["fp"], "tp": c["tp"]} for v, c in per_value.items() if c["fp"] > 0),
        key=lambda d: d["fp"], reverse=True)
    safe_filters = [c for c in contributors if c["tp"] == 0]
    projected_fp = fp - sum(c["fp"] for c in safe_filters)
    projected_total = tp + projected_fp
    projected_precision = round(tp / projected_total, 4) if projected_total else 0.0
    return {
        "current": {"tp": tp, "fp": fp, "precision": precision},
        "fp_contributors": contributors[:25],
        "recommended_safe_filters": [c["value"] for c in safe_filters][:25],
        "projected_precision_after_safe_filters": projected_precision,
        "true_positive_loss_from_safe_filters": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tune detections from alert history")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("alerts")
    p.add_argument("--label", required=True, help="field holding tp/fp verdict")
    p.add_argument("--field", required=True, help="field to analyze for FP sources")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.alerts, args.label, args.field), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
