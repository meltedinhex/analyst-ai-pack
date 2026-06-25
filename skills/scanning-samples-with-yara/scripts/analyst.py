#!/usr/bin/env python3
"""Scan files and directories with YARA rules and summarize matches.

Wraps ``yara-python`` to compile a rules path and report matched rule names, tags, and string
offsets. Reads files as data; it never executes a sample.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def compile_rules(rules_path: str):
    import yara  # type: ignore
    p = Path(rules_path)
    if p.is_dir():
        filepaths = {f.stem: str(f) for f in p.rglob("*.yar")}
        filepaths.update({f.stem: str(f) for f in p.rglob("*.yara")})
        if not filepaths:
            raise FileNotFoundError(f"no .yar/.yara files under {rules_path}")
        return yara.compile(filepaths=filepaths)
    return yara.compile(filepath=str(p))


def scan_file(rules, filepath: str) -> dict:
    matches = rules.match(filepath, timeout=60)
    return {
        "file": filepath,
        "matches": [{
            "rule": m.rule,
            "tags": list(m.tags),
            "strings": [
                {"id": s.identifier, "offset": inst.offset}
                for s in m.strings for inst in s.instances
            ] if hasattr(m, "strings") else [],
        } for m in matches],
    }


def scan_path(rules_path: str, target: str, recursive: bool) -> list[dict]:
    rules = compile_rules(rules_path)
    target_p = Path(target)
    files = ([f for f in target_p.rglob("*") if f.is_file()] if recursive and target_p.is_dir()
             else [f for f in target_p.iterdir() if f.is_file()] if target_p.is_dir()
             else [target_p])
    return [scan_file(rules, str(f)) for f in files]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan with YARA")
    parser.add_argument("rules", help="rule file or directory")
    parser.add_argument("target", help="file or directory to scan")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    try:
        results = scan_path(args.rules, args.target, args.recursive)
    except ImportError:
        print("yara-python not installed: pip install yara-python", file=sys.stderr)
        return 2

    if args.summary:
        hit = [r for r in results if r["matches"]]
        print(json.dumps({
            "scanned": len(results),
            "with_matches": len(hit),
            "files": [{"file": r["file"],
                       "rules": [m["rule"] for m in r["matches"]]} for r in hit],
        }, indent=2))
    else:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
