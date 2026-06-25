# Contributing to AnalystAIPack

Thanks for helping build AnalystAIPack. This guide covers how skills are structured, the
authoring checklist, and — most importantly — the originality rules that keep this library's
content genuinely its own.

## Originality rules (non-negotiable)

AnalystAIPack reuses an **open file format** (agentskills.io) on purpose, but its **content is
original**. To keep that true (PLAN.md §5.1):

1. **Author from primary sources only.** Do not open, read, or paraphrase any skill file
   from another skills repository while writing an AnalystAIPack skill. Work from tool docs,
   MITRE pages, specs, and research. Other skills repos may be consulted **only** to
   understand the file format, never the content.
2. **Distinct, content-accurate names.** Where an equivalent skill exists elsewhere, choose
   a different, accurate name.
3. **Cite real sources.** Every skill's `references/api-reference.md` lists the specific
   primary sources it was synthesized from (specific pages/specs/reports, not homepages).
4. **Original scripts.** All `analyst.py` code is written and tested fresh, and linted with
   `ruff`. No lifted or reworded code.
5. **Run the similarity gate.** Before marking a skill done, sanity-check that its prose
   does not closely track any single external source. High overlap → rewrite.

## Skill anatomy

```
skills/<skill-name>/
├── SKILL.md
├── scripts/analyst.py
├── references/api-reference.md
└── LICENSE
```

Start from the scaffold:

```bash
cp -r templates/skill-template skills/<skill-name>
# PowerShell: Copy-Item -Recurse templates/skill-template skills/<skill-name>
```

### SKILL.md frontmatter

| Field | Required | Notes |
|---|---|---|
| `name` | yes | kebab-case, **must equal the folder name** |
| `description` | yes | 1–3 sentences, ≥ 50 chars, ends with activation trigger |
| `domain` | yes | always `cybersecurity` |
| `subdomain` | yes | one of `lab-foundations`, `malware-analysis`, `reverse-engineering`, `threat-hunting` |
| `tags` | yes | 3–8 lowercase tags |
| `version` | yes | semver, start at `1.0.0` |
| `author` | yes | your handle |
| `license` | yes | `Apache-2.0` |
| `mitre_attack` | yes | ≥ 1 valid `Txxxx` / `Txxxx.yyy` id |
| `d3fend` | optional | `D3-XXX` ids where a countermeasure applies |
| `car` | optional | `CAR-YYYY-MM-NNN` ids for hunting/detection skills |
| `references` | optional | source list (full list also goes in `references/`) |

### SKILL.md body — required section order

1. `# Title`
2. `## When to Use` — triggers **and** an explicit *Do not use*
3. `## Prerequisites`
4. `## Safety & Handling` — **only** for sample-handling skills (omit otherwise)
5. `## Workflow` — numbered steps, real commands/code
6. `## Validation`
7. `## Pitfalls`
8. `## References`

Keep steps concrete: name the actual tools, flags, and artifacts. Avoid generic advice.

## Authoring checklist

- [ ] Folder + `SKILL.md` + `scripts/analyst.py` + `references/api-reference.md` + `LICENSE`
- [ ] Frontmatter passes the validator
- [ ] `When to Use` has an explicit *Do not use*
- [ ] `Safety & Handling` present for any sample-handling skill
- [ ] Workflow steps are concrete and runnable
- [ ] `analyst.py` runs and is original; `ruff` clean
- [ ] ATT&CK / D3FEND / CAR ids verified against current versions
- [ ] Sources cited in `references/api-reference.md`; originality self-check done
- [ ] `index.json` regenerated

## Validate and build

```bash
python tools/lint-skills.py skills/<skill-name>      # one skill
python tools/lint-skills.py --all                    # everything
python tools/build-index.py                          # regenerate index.json
python tools/build-index.py --check                  # CI: fail if index is stale
python tools/build-catalog.py                        # regenerate CATALOG.md
python tools/build-navigator-layer.py                # regenerate the ATT&CK layer
python tools/smoke-test.py                            # run every analyst.py (--help + fixtures)
ruff check skills/<skill-name>/scripts                # lint tooling
```

A pull request should pass `lint-skills.py --all`, the `--check` modes
(`build-index.py`, `build-catalog.py`, `build-navigator-layer.py`), `smoke-test.py`, and
`ruff`. These run automatically in CI (`.github/workflows/ci.yml`).

## Commit and PR

- One skill (or one coherent set) per PR.
- Describe the sources you synthesized from in the PR body.
- Confirm the originality rules were followed.
