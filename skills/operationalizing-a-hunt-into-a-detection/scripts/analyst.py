#!/usr/bin/env python3
"""Generate a Sigma rule from a detection spec produced by operationalizing a hunt.

Spec (JSON):
{
  "title": "Suspicious certutil download",
  "logsource": {"category": "process_creation", "product": "windows"},
  "selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-urlcache","http"]},
  "filter": {"CommandLine|contains": "internal-mirror"},
  "condition": "selection and not filter",
  "level": "high",
  "attack": ["T1218", "T1105"]
}
Emits a Sigma YAML rule. Generates text only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _yaml_block(name: str, mapping: dict, indent: int = 4) -> list[str]:
    pad = " " * indent
    lines = [f"{name}:"]
    for key, val in mapping.items():
        if isinstance(val, list):
            lines.append(f"{pad}{key}:")
            for item in val:
                lines.append(f"{pad}  - {json.dumps(item)}")
        else:
            lines.append(f"{pad}{key}: {json.dumps(val)}")
    return lines


def generate(spec: dict, out: str) -> dict:
    title = spec.get("title", "Untitled detection")
    lines = [
        f"title: {title}",
        "status: experimental",
        f"description: Generated from an operationalized hunt for {title}.",
        "logsource:",
    ]
    for k, v in spec.get("logsource", {}).items():
        lines.append(f"    {k}: {v}")
    lines.append("detection:")
    lines += ["    " + ln for ln in _yaml_block("selection", spec.get("selection", {}), 4)]
    if spec.get("filter"):
        lines += ["    " + ln for ln in _yaml_block("filter", spec["filter"], 4)]
    lines.append(f"    condition: {spec.get('condition', 'selection')}")
    lines.append("falsepositives:")
    lines.append("    - Legitimate administrative use (tune with filter)")
    lines.append(f"level: {spec.get('level', 'medium')}")
    tags = spec.get("attack", [])
    if tags:
        lines.append("tags:")
        for t in tags:
            lines.append(f"    - attack.{t.lower()}")
    text = "\n".join(lines) + "\n"
    Path(out).write_text(text, encoding="utf-8")
    return {"output": out, "title": title, "tags": tags}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Sigma rule from a hunt spec")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("generate")
    p.add_argument("--spec", required=True)
    p.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8-sig"))
    print(json.dumps(generate(spec, args.out), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
