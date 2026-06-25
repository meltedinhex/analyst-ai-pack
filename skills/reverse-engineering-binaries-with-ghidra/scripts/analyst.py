#!/usr/bin/env python3
"""Wrapper for Ghidra headless analysis.

Drives ``support/analyzeHeadless`` to import a binary, run auto-analysis, and execute an
optional post-script (e.g. one that exports functions/strings to JSON). This orchestrates
Ghidra; it does not execute the sample. Ghidra performs static analysis only.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess  # noqa: S404 - invoking the local Ghidra installation
import sys
import tempfile


def run_headless(ghidra_path: str, binary: str, post_script: str | None = None,
                 script_path: str | None = None, project_dir: str | None = None,
                 timeout: int = 1200) -> dict:
    analyze = os.path.join(ghidra_path, "support",
                           "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not os.path.isfile(analyze):
        raise FileNotFoundError(f"analyzeHeadless not found at {analyze}")
    project_dir = project_dir or tempfile.mkdtemp(prefix="ghidra_proj_")
    cmd = [analyze, project_dir, "analyst-ai-pack",
           "-import", binary, "-overwrite", "-deleteProject"]
    if post_script:
        cmd += ["-postScript", post_script]
        if script_path:
            cmd += ["-scriptPath", script_path]
    proc = subprocess.run(cmd, capture_output=True, text=True,  # noqa: S603
                          timeout=timeout, check=False)
    return {
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ghidra headless wrapper")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("headless")
    p.add_argument("--ghidra", required=True, help="Ghidra install dir")
    p.add_argument("--bin", required=True, dest="binary")
    p.add_argument("--post-script")
    p.add_argument("--script-path")
    p.add_argument("--out")
    args = parser.parse_args(argv)

    result = run_headless(args.ghidra, args.binary, args.post_script, args.script_path)
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 0 if result["returncode"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
