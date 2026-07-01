#!/usr/bin/env python3
"""Lint AnalystAIPack SKILL.md files against the repository schema.

Checks frontmatter fields, kebab-case naming, framework-ID formats, and the required
body-section order described in CONTRIBUTING.md.

Usage:
    python tools/lint-skills.py skills/my-skill
    python tools/lint-skills.py --all

Exit code is non-zero if any skill fails linting. Stdlib only.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys

REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags", "version",
                   "author", "license"]

ALLOWED_SUBDOMAINS = {
    "lab-foundations",
    "malware-analysis",
    "reverse-engineering",
    "threat-hunting",
}

# Required body sections, in order. "Safety & Handling" is optional (sample-handling only).
REQUIRED_SECTIONS = [
    "When to Use",
    "Prerequisites",
    "Workflow",
    "Validation",
    "Pitfalls",
    "References",
]

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
D3FEND_RE = re.compile(r"^D3-[A-Z]{1,6}$")
CAR_RE = re.compile(r"^CAR-\d{4}-\d{2}-\d{3}$")
DESCRIPTION_MIN_CHARS = 50

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


if not _supports_color():
    RED = GREEN = YELLOW = RESET = ""


def _find_quote_close(segment: str, quote: str):
    """Return the index of the closing quote in ``segment`` or ``None`` if unclosed.

    Honors YAML single-quoted escaping where a literal quote is written ``''``.
    """
    i = 0
    n = len(segment)
    while i < n:
        if segment[i] == quote:
            if quote == "'" and i + 1 < n and segment[i + 1] == "'":
                i += 2  # escaped doubled quote; skip both characters
                continue
            return i
        i += 1
    return None


def _unescape_quoted(value: str, quote: str) -> str:
    return value.replace("''", "'") if quote == "'" else value


def read_frontmatter(text: str):
    """Parse the leading YAML frontmatter block into a dict.

    Minimal stdlib parser handling the patterns AnalystAIPack SKILL.md files use:
    scalars, inline ``[a, b]`` lists, block ``- item`` lists, folded ``>-`` scalars, and
    multi-line single/double-quoted scalars (continuation lines joined with a space).
    Returns ``(data, error)``; ``data`` is ``None`` when frontmatter is missing/malformed.
    """
    if not text.startswith("---"):
        return None, "missing frontmatter (file must start with '---')"
    end = text.find("\n---", 3)
    if end == -1:
        return None, "unterminated frontmatter (no closing '---')"
    block = text[3:end].strip("\n")

    data: dict = {}
    current_key: str | None = None
    list_values: list[str] = []
    in_folded = False
    folded_lines: list[str] = []
    in_quoted = False
    quote_char = ""
    quoted_parts: list[str] = []

    def flush_list():
        nonlocal current_key, list_values
        if current_key is not None and list_values:
            data[current_key] = list_values
        list_values = []

    def flush_folded():
        nonlocal current_key, folded_lines, in_folded
        if in_folded and current_key is not None and folded_lines:
            data[current_key] = " ".join(folded_lines)
        in_folded = False
        folded_lines = []

    def store_quoted():
        nonlocal current_key, quoted_parts, in_quoted, quote_char
        if current_key is not None:
            joined = " ".join(quoted_parts).strip()
            data[current_key] = _unescape_quoted(joined, quote_char)
        in_quoted = False
        quote_char = ""
        quoted_parts = []
        current_key = None

    for raw in block.split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        indented = raw.startswith(" ") or raw.startswith("\t")

        # Multi-line quoted scalar continuation: consume until the closing quote.
        if in_quoted:
            close = _find_quote_close(stripped, quote_char)
            if close is None:
                quoted_parts.append(stripped)
            else:
                quoted_parts.append(stripped[:close])
                store_quoted()
            continue

        if in_folded and stripped and not indented:
            flush_folded()
        if in_folded:
            if stripped:
                folded_lines.append(stripped)
            continue

        if stripped.startswith("- "):
            list_values.append(stripped[2:].strip().strip("'\""))
            continue

        if ":" in stripped and not indented:
            flush_list()
            key, _, value = stripped.partition(":")
            current_key = key.strip()
            value = value.strip()
            if value in (">-", ">", "|", "|-"):
                in_folded = True
                folded_lines = []
            elif value.startswith("[") and value.endswith("]"):
                items = value[1:-1].split(",")
                data[current_key] = [i.strip().strip("'\"") for i in items if i.strip()]
                current_key = None
            elif value and value[0] in "'\"":
                quote = value[0]
                rest = value[1:]
                close = _find_quote_close(rest, quote)
                if close is None:
                    # Opens a multi-line quoted scalar; continue on following lines.
                    in_quoted = True
                    quote_char = quote
                    quoted_parts = [rest]
                else:
                    data[current_key] = _unescape_quoted(rest[:close], quote)
                    current_key = None
            elif value:
                data[current_key] = value.strip("'\"")
                current_key = None
            # else: bare key, expect a block list on following lines
            continue

    flush_list()
    flush_folded()
    if in_quoted:
        store_quoted()
    return data, None


def _extract_sections(body: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"^##\s+(.+)$", body, re.MULTILINE)]


def lint_skill(skill_dir: str) -> list[str]:
    """Return a list of error strings for one skill directory (empty == valid)."""
    errors: list[str] = []
    folder = os.path.basename(os.path.normpath(skill_dir))
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"{folder}: missing SKILL.md"]

    with open(skill_md, encoding="utf-8") as fh:
        text = fh.read()

    data, err = read_frontmatter(text)
    if err:
        return [f"{folder}: {err}"]

    # Required fields present
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] in (None, "", []):
            errors.append(f"{folder}: missing required field '{field}'")

    # name matches folder and is kebab-case
    name = data.get("name", "")
    if name and not KEBAB_RE.match(str(name)):
        errors.append(f"{folder}: 'name' must be kebab-case (got '{name}')")
    if name and name != folder:
        errors.append(f"{folder}: 'name' ({name}) must match folder name ({folder})")

    # domain / subdomain
    if data.get("domain") != "cybersecurity":
        errors.append(f"{folder}: 'domain' must be 'cybersecurity'")
    subdomain = data.get("subdomain")
    if subdomain and subdomain not in ALLOWED_SUBDOMAINS:
        errors.append(
            f"{folder}: 'subdomain' '{subdomain}' not in {sorted(ALLOWED_SUBDOMAINS)}"
        )

    # description length
    desc = data.get("description", "")
    if desc and len(desc) < DESCRIPTION_MIN_CHARS:
        errors.append(
            f"{folder}: 'description' too short (<{DESCRIPTION_MIN_CHARS} chars)"
        )

    # tags is a list of 3-8
    tags = data.get("tags")
    if isinstance(tags, list):
        if not (3 <= len(tags) <= 8):
            errors.append(f"{folder}: expected 3-8 tags (got {len(tags)})")
    elif "tags" not in [e.split(":")[0] for e in errors]:
        errors.append(f"{folder}: 'tags' must be a list")

    # mitre_attack required and well-formed
    attack = data.get("mitre_attack")
    if not attack:
        errors.append(f"{folder}: missing 'mitre_attack' (at least one technique)")
    elif isinstance(attack, list):
        for tid in attack:
            if not ATTACK_RE.match(str(tid)):
                errors.append(f"{folder}: invalid ATT&CK id '{tid}'")

    # optional framework lists, validated when present
    for fld, rx, label in (("d3fend", D3FEND_RE, "D3FEND"), ("car", CAR_RE, "CAR")):
        vals = data.get(fld)
        if isinstance(vals, list):
            for v in vals:
                if not rx.match(str(v)):
                    errors.append(f"{folder}: invalid {label} id '{v}'")

    # body section presence + order
    body = text[text.find("\n---", 3) + 4:]
    found = _extract_sections(body)
    found_required = [s for s in found if s in REQUIRED_SECTIONS]
    missing = [s for s in REQUIRED_SECTIONS if s not in found]
    if missing:
        errors.append(f"{folder}: missing body sections: {', '.join(missing)}")
    else:
        order = [REQUIRED_SECTIONS.index(s) for s in found_required]
        if order != sorted(order):
            errors.append(f"{folder}: body sections out of order: {found_required}")

    # companion files
    if not os.path.isfile(os.path.join(skill_dir, "scripts", "analyst.py")):
        errors.append(f"{folder}: missing scripts/analyst.py")
    if not os.path.isfile(os.path.join(skill_dir, "references", "api-reference.md")):
        errors.append(f"{folder}: missing references/api-reference.md")
    if not os.path.isfile(os.path.join(skill_dir, "LICENSE")):
        errors.append(f"{folder}: missing LICENSE")

    return errors


def _iter_skill_dirs(root: str):
    for path in sorted(glob.glob(os.path.join(root, "skills", "*"))):
        if os.path.isdir(path):
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint AnalystAIPack skills")
    parser.add_argument("paths", nargs="*", help="skill directories to validate")
    parser.add_argument("--all", action="store_true", help="validate every skill")
    args = parser.parse_args(argv)

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if args.all:
        targets = list(_iter_skill_dirs(repo_root))
    elif args.paths:
        targets = args.paths
    else:
        parser.error("provide skill directories or --all")
        return 2

    if not targets:
        print(f"{YELLOW}No skills found to validate.{RESET}")
        return 0

    total_errors = 0
    for skill_dir in targets:
        errs = lint_skill(skill_dir)
        folder = os.path.basename(os.path.normpath(skill_dir))
        if errs:
            total_errors += len(errs)
            print(f"{RED}FAIL{RESET} {folder}")
            for e in errs:
                print(f"   - {e}")
        else:
            print(f"{GREEN}PASS{RESET} {folder}")

    print()
    if total_errors:
        print(f"{RED}{total_errors} problem(s) across {len(targets)} skill(s).{RESET}")
        return 1
    print(f"{GREEN}All {len(targets)} skill(s) valid.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
