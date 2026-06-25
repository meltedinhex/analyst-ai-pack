#!/usr/bin/env python3
"""Profile an infostealer's targeted artifacts and exfiltration channel from static strings.

Extracts ASCII/UTF-16LE strings and matches them against curated lists of browser credential
stores, crypto wallets, application configs, and credential APIs, plus exfil-channel indicators
(HTTP POST, Telegram, Discord webhooks, FTP/SMTP). Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

TARGETS = {
    "browser_credentials": ["login data", "web data", "cookies", "logins.json", "key4.db",
                            "signons.sqlite", "\\user data\\", "local state"],
    "crypto_wallets": ["wallet.dat", "\\electrum\\", "\\exodus\\", "\\ethereum\\keystore",
                       "metamask", "\\monero\\", "ledger live"],
    "applications": ["filezilla\\recentservers.xml", "\\openvpn\\", "\\telegram desktop\\tdata",
                     "\\discord\\local storage", "winscp.ini", "\\pidgin\\", "anydesk"],
    "credential_api": ["cryptunprotectdata", "vaultcli", "credenumerate", "lsadump"],
}

EXFIL = {
    "telegram": [r"api\.telegram\.org", r"bot\d{6,}:[a-z0-9_-]{30,}"],
    "discord_webhook": [r"discord(?:app)?\.com/api/webhooks/"],
    "http_post": [r"https?://[^\s\"']+"],
    "ftp": [r"ftp://[^\s\"']+"],
    "smtp": [r"smtp\.[a-z0-9.-]+"],
}


def _strings(data: bytes) -> str:
    parts = [m.decode("ascii", "ignore") for m in ASCII_RE.findall(data)]
    parts += [m.decode("utf-16-le", "ignore") for m in UTF16_RE.findall(data)]
    return "\n".join(parts)


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def profile(path: str) -> dict:
    blob = _strings(Path(path).read_bytes())
    low = blob.lower()
    targets = {}
    for cat, needles in TARGETS.items():
        hits = sorted({n for n in needles if n in low})
        if hits:
            targets[cat] = hits
    exfil = {}
    for chan, patterns in EXFIL.items():
        found = set()
        for pat in patterns:
            for m in re.findall(pat, blob, re.I):
                found.add(_defang(m))
        if found:
            exfil[chan] = sorted(found)[:10]
    return {
        "targeted_artifacts": targets,
        "exfiltration_channels": exfil,
        "is_likely_infostealer": len(targets) >= 2,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile infostealer targets/exfil")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("profile")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(profile(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
