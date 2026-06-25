#!/usr/bin/env python3
"""analyst-pack: the unified command-line entry point for the AnalystAIPack skill library.

A single front door to discover and run the library's skills and maintenance tools. This is
AnalystAIPack's signature CLI — it wraps the per-skill ``scripts/analyst.py`` tools and the
repository utilities behind one consistent interface.

Commands:
    list [--subdomain S] [--tag T]   List skills (optionally filtered).
    show <skill>                     Print a skill's summary, ATT&CK IDs, and script commands.
    run  <skill> [-- ARGS...]        Run a skill's analyst.py with the given arguments.
    search <query>                   Full-text search over skill names and descriptions.
    stats                            Print library statistics (counts, coverage).
    lint                             Lint all skills (delegates to lint-skills.py).
    build                            Rebuild index.json, CATALOG.md, and the ATT&CK layer.

Examples:
    python tools/analyst-pack.py list --subdomain threat-hunting
    python tools/analyst-pack.py show hunting-lolbin-abuse-on-windows
    python tools/analyst-pack.py run identifying-cryptographic-routines-in-binaries -- scan a.bin
    python tools/analyst-pack.py search kerberos

Stdlib only. Reuses read_frontmatter from lint-skills.py for consistent parsing.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO_ROOT, "skills")
PY = sys.executable


def _load_read_frontmatter():
    path = os.path.join(REPO_ROOT, "tools", "lint-skills.py")
    spec = importlib.util.spec_from_file_location("lint_skills", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.read_frontmatter


read_frontmatter = _load_read_frontmatter()


def _skill_dirs() -> list[str]:
    return sorted(d for d in glob.glob(os.path.join(SKILLS_DIR, "*")) if os.path.isdir(d))


def _load_skill(skill_dir: str) -> dict | None:
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(skill_md):
        return None
    with open(skill_md, encoding="utf-8") as fh:
        data, err = read_frontmatter(fh.read())
    if err or not data:
        return None
    data["_dir"] = skill_dir
    data["_name"] = data.get("name", os.path.basename(skill_dir))
    return data


def _all_skills() -> list[dict]:
    out = []
    for d in _skill_dirs():
        s = _load_skill(d)
        if s:
            out.append(s)
    return out


def _summary(description: str) -> str:
    desc = " ".join(str(description).split())
    idx = desc.find(". Activates")
    return desc[:idx + 1] if idx != -1 else desc


def cmd_list(args) -> int:
    skills = _all_skills()
    if args.subdomain:
        skills = [s for s in skills if s.get("subdomain") == args.subdomain]
    if args.tag:
        skills = [s for s in skills if args.tag in (s.get("tags") or [])]
    by_sub: dict[str, list[dict]] = {}
    for s in skills:
        by_sub.setdefault(s.get("subdomain", "?"), []).append(s)
    for sub in sorted(by_sub):
        print(f"\n{sub} ({len(by_sub[sub])})")
        for s in sorted(by_sub[sub], key=lambda x: x["_name"]):
            print(f"  {s['_name']}")
    print(f"\nTotal: {len(skills)} skill(s)")
    return 0


def cmd_show(args) -> int:
    skill_dir = os.path.join(SKILLS_DIR, args.skill)
    s = _load_skill(skill_dir)
    if not s:
        print(f"Skill not found: {args.skill}", file=sys.stderr)
        return 1
    print(f"# {s['_name']}")
    print(f"subdomain: {s.get('subdomain', '')}")
    print(f"tags:      {', '.join(s.get('tags') or [])}")
    print(f"ATT&CK:    {', '.join(s.get('mitre_attack') or []) or '-'}")
    print(f"D3FEND:    {', '.join(s.get('d3fend') or []) or '-'}")
    print(f"\n{_summary(s.get('description', ''))}")
    script = os.path.join(skill_dir, "scripts", "analyst.py")
    if os.path.isfile(script):
        print("\nScript commands:")
        proc = subprocess.run([PY, script, "--help"], capture_output=True, text=True)
        print("  " + "\n  ".join(proc.stdout.strip().splitlines()))
    return 0


def cmd_run(args) -> int:
    script = os.path.join(SKILLS_DIR, args.skill, "scripts", "analyst.py")
    if not os.path.isfile(script):
        print(f"No analyst.py for skill: {args.skill}", file=sys.stderr)
        return 1
    return subprocess.run([PY, script, *args.args]).returncode


def cmd_search(args) -> int:
    q = args.query.lower()
    hits = []
    for s in _all_skills():
        haystack = (s["_name"] + " " + str(s.get("description", "")) + " "
                    + " ".join(s.get("tags") or [])).lower()
        if q in haystack:
            hits.append(s)
    for s in sorted(hits, key=lambda x: x["_name"]):
        print(f"{s['_name']}  [{s.get('subdomain', '')}]")
        print(f"    {_summary(s.get('description', ''))}")
    print(f"\n{len(hits)} match(es) for '{args.query}'")
    return 0


def cmd_stats(args) -> int:
    skills = _all_skills()
    by_sub: dict[str, int] = {}
    techniques: set[str] = set()
    scripted = 0
    for s in skills:
        by_sub[s.get("subdomain", "?")] = by_sub.get(s.get("subdomain", "?"), 0) + 1
        techniques.update(s.get("mitre_attack") or [])
        if os.path.isfile(os.path.join(s["_dir"], "scripts", "analyst.py")):
            scripted += 1
    print(f"Total skills:        {len(skills)}")
    print(f"Runnable (analyst.py): {scripted}")
    print(f"ATT&CK techniques:   {len(techniques)}")
    print("By subdomain:")
    for sub in sorted(by_sub):
        print(f"  {sub}: {by_sub[sub]}")
    return 0


def _delegate(rel_path: str, extra: list[str]) -> int:
    return subprocess.run([PY, os.path.join(REPO_ROOT, rel_path), *extra]).returncode


def cmd_lint(args) -> int:
    return _delegate("tools/lint-skills.py", ["--all"])


def cmd_build(args) -> int:
    rc = 0
    for tool in ("tools/build-index.py", "tools/build-catalog.py",
                 "tools/build-navigator-layer.py"):
        rc |= _delegate(tool, [])
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="analyst-pack",
                                     description="Unified CLI for the AnalystAIPack library")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="list skills")
    p.add_argument("--subdomain")
    p.add_argument("--tag")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="show a skill's details")
    p.add_argument("skill")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("run", help="run a skill's analyst.py")
    p.add_argument("skill")
    p.add_argument("args", nargs=argparse.REMAINDER,
                   help="arguments passed to the skill script (after --)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("search", help="search skills by text")
    p.add_argument("query")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("stats", help="library statistics")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("lint", help="lint all skills")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("build", help="rebuild index/catalog/navigator")
    p.set_defaults(func=cmd_build)

    args = parser.parse_args(argv)
    # Drop a leading "--" separator left by argparse.REMAINDER on `run`.
    if getattr(args, "args", None) and args.args and args.args[0] == "--":
        args.args = args.args[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
