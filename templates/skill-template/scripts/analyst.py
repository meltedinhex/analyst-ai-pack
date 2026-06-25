#!/usr/bin/env python3
"""Runnable tooling for the <skill-name> skill.

Replace this module with original code that automates the skill's workflow. Keep it
self-contained, dependency-light, and safe to run. Document every public function in
``references/api-reference.md``.

Authoring rules (see PLAN.md §5.1):
- Original code only. Do not lift or reword scripts from other skill repositories.
- Lint with ``ruff`` before committing.
- Fail safe: never execute a malware sample on the host; operate on files, logs, or
  telemetry only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def compute_hashes(filepath: str | Path) -> dict[str, str | int]:
    """Return MD5/SHA-1/SHA-256 and size for a file, for identification only."""
    data = Path(filepath).read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - identification, not security
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def analyze(target: str | Path) -> dict:
    """Entry point for the skill's core logic. Replace with real implementation."""
    target = Path(target)
    if not target.exists():
        raise FileNotFoundError(target)
    return {
        "target": str(target),
        "hashes": compute_hashes(target),
        "findings": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AnalystAIPack skill tool")
    parser.add_argument("target", help="path to the file or artifact to analyze")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    args = parser.parse_args(argv)

    result = analyze(args.target)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
