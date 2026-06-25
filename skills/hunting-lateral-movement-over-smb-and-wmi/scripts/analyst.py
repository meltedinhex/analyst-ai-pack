#!/usr/bin/env python3
"""Hunt lateral movement via remote service creation and remote WMI process spawns.

Parses Windows service-install (7045/4697) and process-creation telemetry (CSV or JSON-lines) and
flags PsExec-style service binaries, wmiprvse.exe-parented shells, and admin-share execution.
Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

PSEXEC_SVC = ["psexesvc", "paexec", "remcom", "csexec"]
RE_RANDOM_SVC = re.compile(r"^[a-z]{8,16}$", re.I)
REMOTE_PARENTS = ["wmiprvse.exe", "services.exe"]
REMOTE_SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe"]
ADMIN_SHARE = ["\\admin$", "\\c$\\", "\\\\127.0.0.1\\", "\\ipc$"]


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


def _get(row: dict, *keys: str) -> str:
    for k in keys:
        if row.get(k):
            return str(row[k])
    return ""


def _base(path: str) -> str:
    return path.replace("/", "\\").split("\\")[-1].lower()


def hunt(path: str) -> dict:
    svc_findings, wmi_findings = [], []
    for row in _rows(path):
        eid = _get(row, "EventID", "event_id")
        svc_name = _get(row, "ServiceName", "service_name")
        svc_image = _get(row, "ImagePath", "image_path").lower()
        if eid in ("7045", "4697") or svc_image:
            name_l = svc_name.lower()
            reasons = []
            if any(p in name_l or p in svc_image for p in PSEXEC_SVC):
                reasons.append("psexec_like_service")
            if svc_name and RE_RANDOM_SVC.match(svc_name) and any(a in svc_image
                                                                  for a in ADMIN_SHARE):
                reasons.append("random_service_from_admin_share")
            if reasons:
                svc_findings.append({"service": svc_name, "image": svc_image[:160],
                                     "reasons": reasons})
        image = _base(_get(row, "Image", "image"))
        parent = _base(_get(row, "ParentImage", "parent_image"))
        if parent in REMOTE_PARENTS and image in REMOTE_SHELLS:
            wmi_findings.append({"parent": parent, "child": image,
                                 "command_line": _get(row, "CommandLine",
                                                      "command_line")[:200]})
    return {
        "remote_service_installs": svc_findings,
        "remote_wmi_shells": wmi_findings,
        "lateral_movement_suspected": bool(svc_findings or wmi_findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt SMB/WMI lateral movement")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
