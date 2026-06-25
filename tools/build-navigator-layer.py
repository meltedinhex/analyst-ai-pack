#!/usr/bin/env python3
"""Generate a MITRE ATT&CK Navigator layer from skill frontmatter.

Scans every skill's SKILL.md for `mitre_attack` techniques and writes an ATT&CK Navigator
layer (https://mitre-attack.github.io/attack-navigator/) where each technique is scored by
the number of AnalystAIPack skills that cover it. The per-technique comment lists those skills.

Usage:
    python tools/build-navigator-layer.py          # write mappings/attack-navigator-layer.json
    python tools/build-navigator-layer.py --check   # fail if the layer is out of date (CI)

Reuses read_frontmatter from lint-skills.py so parsing stays consistent. Stdlib only.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYER_PATH = os.path.join(REPO_ROOT, "mappings", "attack-navigator-layer.json")

# Pinned framework versions for reproducibility; bump when intentionally retargeting.
ATTACK_VERSION = "15"
NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"
GRADIENT = ["#f2f5fa", "#66b1ff", "#0d4a9e"]


def _load_parser():
    path = os.path.join(REPO_ROOT, "tools", "lint-skills.py")
    spec = importlib.util.spec_from_file_location("lint_skills", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.read_frontmatter


read_frontmatter = _load_parser()


def collect_technique_coverage() -> dict[str, list[str]]:
    """Return {techniqueID: [skill-name, ...]} sorted for determinism."""
    coverage: dict[str, set[str]] = defaultdict(set)
    for skill_dir in sorted(glob.glob(os.path.join(REPO_ROOT, "skills", "*"))):
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        with open(skill_md, encoding="utf-8") as fh:
            data, err = read_frontmatter(fh.read())
        if err or not data:
            print(f"warning: skipping {os.path.basename(skill_dir)}: {err}", file=sys.stderr)
            continue
        name = data.get("name", os.path.basename(skill_dir))
        for tech in data.get("mitre_attack", []) or []:
            coverage[str(tech)].add(name)
    return {tech: sorted(names) for tech, names in coverage.items()}


def build_layer() -> dict:
    coverage = collect_technique_coverage()
    max_score = max((len(v) for v in coverage.values()), default=1)
    techniques = []
    for tech in sorted(coverage):
        skills = coverage[tech]
        techniques.append({
            "techniqueID": tech,
            "score": len(skills),
            "comment": "AnalystAIPack skills: " + ", ".join(skills),
            "enabled": True,
            "metadata": [{"name": "skills", "value": str(len(skills))}],
        })
    return {
        "name": "AnalystAIPack Coverage",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": ("ATT&CK technique coverage across the AnalystAIPack skill library. "
                        "Technique score = number of skills that reference the technique."),
        "techniques": techniques,
        "gradient": {"colors": GRADIENT, "minValue": 0, "maxValue": max_score},
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _serialize(layer: dict) -> str:
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the ATT&CK Navigator layer")
    parser.add_argument("--check", action="store_true",
                        help="verify the layer is current without writing")
    args = parser.parse_args(argv)

    fresh = build_layer()
    if args.check:
        if not os.path.isfile(LAYER_PATH):
            print("attack-navigator-layer.json missing; run: python tools/build-navigator-layer.py")
            return 1
        with open(LAYER_PATH, encoding="utf-8") as fh:
            existing = json.load(fh)
        if existing != fresh:
            print("attack-navigator-layer.json is out of date; run: "
                  "python tools/build-navigator-layer.py")
            return 1
        print(f"attack-navigator-layer.json is current ({len(fresh['techniques'])} techniques).")
        return 0

    os.makedirs(os.path.dirname(LAYER_PATH), exist_ok=True)
    with open(LAYER_PATH, "w", encoding="utf-8") as fh:
        fh.write(_serialize(fresh))
    print(f"Wrote attack-navigator-layer.json with {len(fresh['techniques'])} technique(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
