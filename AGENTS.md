# AGENTS.md — Using AnalystAIPack as an AI agent

This repository is a **skill library** for malware analysis, reverse engineering, and threat
hunting. If you are an AI coding/security agent, read this file first: it tells you how to
find the right skill, run it safely, and chain skills into an investigation.

## What this repo is

- 118 self-contained **skills** under [`skills/`](skills/), one folder each.
- Every skill has: `SKILL.md` (the procedure), `scripts/analyst.py` (a runnable tool),
  `references/api-reference.md` (script docs + sources), and `LICENSE`.
- Machine-readable catalog: [`index.json`](index.json). Human catalog: [`CATALOG.md`](CATALOG.md).

## How to pick a skill

1. Search the catalog by intent, not just keyword:
   ```bash
   python tools/analyst-pack.py search <topic>     # e.g. "kerberos", "pe imports", "beacon"
   python tools/analyst-pack.py list --subdomain threat-hunting
   ```
2. Read the chosen `SKILL.md`. **Honor its `When to Use` and especially the `**Do not use**`
   line** — it states the boundaries of the technique. Do not apply a skill outside its scope.

## How to run a skill

Each skill's tool is a small CLI. Inspect it, then run it:

```bash
python tools/analyst-pack.py show <skill-name>           # see its subcommands
python tools/analyst-pack.py run  <skill-name> -- <args>  # run it
# or directly:
python skills/<skill-name>/scripts/analyst.py <subcommand> <args>
```

Scripts print **structured JSON**. Use that output as input to the next skill or a report.

## Safety rules (do not violate)

- **Never execute the malware sample.** Every script performs *static, read-only* analysis.
  Do not add code that runs, detonates, or connects to a sample's infrastructure.
- **Assume an isolated lab.** Skills that handle samples include a `Safety & Handling`
  section — follow it. Do not move samples out of the working directory.
- **Keep IOCs defanged** in any output you share (`hxxp://`, `1[.]2[.]3[.]4`). The scripts
  already do this; preserve it.
- **No live samples in the repo.** This project ships none; never commit one (see
  [`.gitignore`](.gitignore)).

## Chaining skills (the analyst loop)

A full investigation usually flows: **triage → static analysis → unpack/reverse → extract
config & IOCs → defang → hunt across telemetry → write a detection.** See the worked example
in [`README.md`](README.md#a-worked-example-from-sample-to-detection). Pass each script's JSON
output forward; defang before sharing.

## Framework mapping

Skill frontmatter carries `mitre_attack`, `d3fend`, and (for hunts) `car` IDs. Use these to
report coverage and to slot findings into detection engineering. The ATT&CK Navigator layer is
at [`mappings/attack-navigator-layer.json`](mappings/attack-navigator-layer.json).

## If you add or edit a skill

Keep the repo green — run before finishing:

```bash
python tools/lint-skills.py --all          # schema + body-section linter
python tools/build-index.py                # regenerate index.json
python tools/build-catalog.py              # regenerate CATALOG.md
python tools/build-navigator-layer.py      # regenerate the ATT&CK layer
python tools/smoke-test.py                 # run every analyst.py (--help + fixtures)
```

Authoring rules (originality, sourcing, safety) are in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`PLAN.md`](PLAN.md) §5.
