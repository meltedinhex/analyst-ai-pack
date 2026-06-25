#!/usr/bin/env python3
"""Regenerate index.json from the skills/ directory.

Scans every skill's SKILL.md frontmatter and writes a machine-readable catalog at the
repository root. Run after adding or editing skills.

Usage:
    python tools/build-index.py            # write index.json
    python tools/build-index.py --check    # fail if index.json is out of date (CI)

Reuses the frontmatter parser from lint-skills.py so parsing stays consistent.
Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import importlib.util
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_parser():
    """Import read_frontmatter from the sibling linter module."""
    path = os.path.join(REPO_ROOT, "tools", "lint-skills.py")
    spec = importlib.util.spec_from_file_location("lint_skills", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.read_frontmatter


read_frontmatter = _load_parser()


def collect_skills() -> list[dict]:
    skills: list[dict] = []
    for skill_dir in sorted(glob.glob(os.path.join(REPO_ROOT, "skills", "*"))):
        if not os.path.isdir(skill_dir):
            continue
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        with open(skill_md, encoding="utf-8") as fh:
            data, err = read_frontmatter(fh.read())
        if err or not data:
            print(f"warning: skipping {os.path.basename(skill_dir)}: {err}",
                  file=sys.stderr)
            continue
        rel = os.path.relpath(skill_dir, REPO_ROOT).replace(os.sep, "/")
        desc = data.get("description", "")
        if isinstance(desc, str):
            desc = " ".join(desc.split())
        skills.append({
            "name": data.get("name", os.path.basename(skill_dir)),
            "description": desc,
            "domain": data.get("domain", "cybersecurity"),
            "subdomain": data.get("subdomain", ""),
            "tags": data.get("tags", []),
            "mitre_attack": data.get("mitre_attack", []),
            "path": rel,
        })
    return skills


def build_index() -> dict:
    skills = collect_skills()
    by_subdomain: dict[str, int] = {}
    for s in skills:
        by_subdomain[s["subdomain"]] = by_subdomain.get(s["subdomain"], 0) + 1
    return {
        "name": "analyst-ai-pack",
        "version": "0.1.0",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "domain": "cybersecurity",
        "total_skills": len(skills),
        "skills_by_subdomain": dict(sorted(by_subdomain.items())),
        "skills": skills,
    }


def _serialize(index: dict) -> str:
    # generated_at is excluded from equality checks so --check ignores timestamp drift.
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def _comparable(index: dict) -> dict:
    clone = dict(index)
    clone.pop("generated_at", None)
    return clone


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build AnalystAIPack index.json")
    parser.add_argument("--check", action="store_true",
                        help="verify index.json is current without writing")
    args = parser.parse_args(argv)

    index_path = os.path.join(REPO_ROOT, "index.json")
    fresh = build_index()

    if args.check:
        if not os.path.isfile(index_path):
            print("index.json missing; run: python tools/build-index.py")
            return 1
        with open(index_path, encoding="utf-8") as fh:
            existing = json.load(fh)
        if _comparable(existing) != _comparable(fresh):
            print("index.json is out of date; run: python tools/build-index.py")
            return 1
        print(f"index.json is current ({fresh['total_skills']} skills).")
        return 0

    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(_serialize(fresh))
    print(f"Wrote index.json with {fresh['total_skills']} skill(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
