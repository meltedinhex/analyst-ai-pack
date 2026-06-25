#!/usr/bin/env python3
"""Generate CATALOG.md: a browsable index of every AnalystAIPack skill.

Scans skill frontmatter and writes a Markdown catalog grouped by subdomain, with each skill's
description, ATT&CK techniques, and a link to its SKILL.md. Run after adding or editing skills.

Usage:
    python tools/build-catalog.py          # write CATALOG.md
    python tools/build-catalog.py --check   # fail if CATALOG.md is out of date (CI)

Reuses read_frontmatter from lint-skills.py so parsing stays consistent. Stdlib only.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_PATH = os.path.join(REPO_ROOT, "CATALOG.md")

SUBDOMAIN_ORDER = ["lab-foundations", "malware-analysis", "reverse-engineering", "threat-hunting"]
SUBDOMAIN_TITLES = {
    "lab-foundations": "Lab Foundations",
    "malware-analysis": "Malware Analysis",
    "reverse-engineering": "Reverse Engineering",
    "threat-hunting": "Threat Hunting",
}


def _load_parser():
    path = os.path.join(REPO_ROOT, "tools", "lint-skills.py")
    spec = importlib.util.spec_from_file_location("lint_skills", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.read_frontmatter


read_frontmatter = _load_parser()


def _first_sentence(desc: str) -> str:
    desc = " ".join(desc.split())
    # Trim at the activation-trigger sentence to keep catalog rows concise.
    for marker in (". Activates for", ". Activates when", ". Use when", ". Use this"):
        idx = desc.find(marker)
        if idx != -1:
            return desc[:idx + 1]
    return desc


def collect() -> dict[str, list[dict]]:
    by_subdomain: dict[str, list[dict]] = defaultdict(list)
    for skill_dir in sorted(glob.glob(os.path.join(REPO_ROOT, "skills", "*"))):
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        with open(skill_md, encoding="utf-8") as fh:
            data, err = read_frontmatter(fh.read())
        if err or not data:
            print(f"warning: skipping {os.path.basename(skill_dir)}: {err}", file=sys.stderr)
            continue
        rel = os.path.relpath(skill_dir, REPO_ROOT).replace(os.sep, "/")
        by_subdomain[data.get("subdomain", "")].append({
            "name": data.get("name", os.path.basename(skill_dir)),
            "summary": _first_sentence(data.get("description", "")),
            "attack": data.get("mitre_attack", []) or [],
            "path": f"{rel}/SKILL.md",
        })
    for skills in by_subdomain.values():
        skills.sort(key=lambda s: s["name"])
    return by_subdomain


def build_catalog() -> str:
    by_subdomain = collect()
    total = sum(len(v) for v in by_subdomain.values())
    lines = [
        "# AnalystAIPack Skill Catalog",
        "",
        f"Auto-generated index of all **{total}** skills. Regenerate with "
        "`python tools/build-catalog.py`.",
        "",
        "| Subdomain | Skills |",
        "|---|---|",
    ]
    ordered = [s for s in SUBDOMAIN_ORDER if s in by_subdomain]
    ordered += [s for s in sorted(by_subdomain) if s not in SUBDOMAIN_ORDER]
    for sub in ordered:
        title = SUBDOMAIN_TITLES.get(sub, sub)
        anchor = title.lower().replace(" ", "-")
        lines.append(f"| [{title}](#{anchor}) | {len(by_subdomain[sub])} |")
    lines.append("")

    for sub in ordered:
        title = SUBDOMAIN_TITLES.get(sub, sub)
        skills = by_subdomain[sub]
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"{len(skills)} skills.")
        lines.append("")
        lines.append("| Skill | What it does | ATT&CK |")
        lines.append("|---|---|---|")
        for s in skills:
            attack = ", ".join(s["attack"]) if s["attack"] else "—"
            summary = s["summary"].replace("|", "\\|")
            lines.append(f"| [`{s['name']}`]({s['path']}) | {summary} | {attack} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build CATALOG.md")
    parser.add_argument("--check", action="store_true",
                        help="verify CATALOG.md is current without writing")
    args = parser.parse_args(argv)

    fresh = build_catalog()
    if args.check:
        if not os.path.isfile(CATALOG_PATH):
            print("CATALOG.md missing; run: python tools/build-catalog.py")
            return 1
        with open(CATALOG_PATH, encoding="utf-8") as fh:
            existing = fh.read()
        if existing != fresh:
            print("CATALOG.md is out of date; run: python tools/build-catalog.py")
            return 1
        print("CATALOG.md is current.")
        return 0

    with open(CATALOG_PATH, "w", encoding="utf-8") as fh:
        fh.write(fresh)
    count = fresh.count("| [`")
    print(f"Wrote CATALOG.md with {count} skill row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
