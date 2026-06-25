#!/usr/bin/env python3
"""Profile a RAT's capabilities and C2 transport from static strings.

Extracts ASCII/UTF-16LE strings and maps them to capability classes (remote shell, file ops,
surveillance, persistence, proxy, self-update) and C2 transports (HTTP, TCP, TLS, DNS, messaging).
Reads bytes statically, defangs endpoints, and executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

CAPABILITIES = {
    "remote_shell": ["cmd.exe", "/c ", "createprocess", "shell", "winexec", "system32\\cmd"],
    "file_operations": ["upload", "download", "getfile", "putfile", "createfile", "deletefile",
                        "findfirstfile"],
    "surveillance": ["screenshot", "bitblt", "getdc", "keylog", "getasynckeystate",
                     "setwindowshook", "webcam", "capgetdriverdescription", "waveinopen"],
    "persistence": ["currentversion\\run", "schtasks", "createservice", "startup"],
    "proxy_relay": ["socks", "proxy", "relay", "portforward", "reverse"],
    "self_update": ["update", "selfdelete", "rename", "newversion"],
    "credential_theft": ["cryptunprotectdata", "vault", "password", "credential"],
}

TRANSPORTS = {
    "http": ["wininet", "winhttp", "httpsendrequest", "internetopen", "user-agent"],
    "tcp_raw": ["ws2_32", "wsasocket", "connect", "recv", "send"],
    "tls": ["schannel", "ssl_", "tls", "openssl"],
    "dns": ["dnsquery", "dns_", "txt record"],
    "messaging": ["api.telegram.org", "discord", "pastebin", "steamcommunity"],
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
    caps = {c: sorted({n for n in needles if n in low})
            for c, needles in CAPABILITIES.items()}
    caps = {c: hits for c, hits in caps.items() if hits}
    transports = {t: sorted({n for n in needles if n in low})
                  for t, needles in TRANSPORTS.items()}
    transports = {t: hits for t, hits in transports.items() if hits}
    urls = sorted({_defang(u) for u in RE_URL.findall(blob)})[:50]
    return {
        "capabilities": caps,
        "c2_transports": transports,
        "c2_urls": urls,
        "capability_count": len(caps),
        "is_likely_rat": len(caps) >= 3,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile RAT C2/capabilities")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("profile")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(profile(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
