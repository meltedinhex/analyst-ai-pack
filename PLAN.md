# AnalystAIPack — Build Plan

> An open agent-skills library for **malware analysis**, **reverse engineering**, and
> **threat hunting**. Built from scratch, synthesized from many authoritative sources —
> not copied from any single repository.

**Status:** Planning · **Format:** [agentskills.io](https://agentskills.io) `SKILL.md` standard ·
**Tooling:** knowledge + runnable Python scripts per skill · **Initial scope:** 100+ skills

---

## 1. Why "AnalystAIPack"

The name is purely descriptive: a **pack** of ready-to-load **AI** agent skills for the
security **analyst**. It states exactly what the project is and maps cleanly onto all three
pillars — you **hunt** for specimens (threat hunting), **reverse** them (reverse
engineering), and **analyze** their behavior (malware analysis). The name is plain,
searchable, and not tied to an existing security product.

- **Repo folder:** `analyst-ai-pack`
- **Suggested GitHub slug:** `analyst-ai-pack`
- **Tagline:** *Give your AI agent the instincts of a malware reverser and threat hunter.*

---

## 2. Design Principles

1. **Original, synthesized content.** Every skill is written from scratch by combining
   knowledge across multiple authoritative sources. No verbatim text, no copied scripts
   from other skill repos. Sources are credited in each skill's `references/`.
2. **Portable standard.** Adopt the agentskills.io `SKILL.md` layout so skills work in
   Claude Code, GitHub Copilot, Cursor, Codex CLI, Gemini CLI, and any compatible agent.
3. **Runnable, not just readable.** Each skill ships a tested `scripts/analyst.py` that an
   agent can actually execute, plus a `references/` doc.
4. **Defense-oriented framing.** Offensive detail exists only to enable detection,
   analysis, and response. No operational malware, no weaponization recipes.
5. **Safety-first.** Every malware-handling skill assumes an isolated lab and documents
   safe-handling steps (no detonation on host, defanged IOCs, encrypted sample storage).
6. **Framework-mapped.** Each skill maps to MITRE ATT&CK, MITRE D3FEND, and (where it
   applies) MITRE CAR analytics and ATT&CK Data Sources — chosen because they fit
   RE/MA/TH far better than compliance frameworks.
7. **Verifiable quality.** A validator enforces frontmatter; an index generator keeps the
   catalog in sync; CI runs both on every change.

---

## 3. Repository Layout

```
analyst-ai-pack/
├── README.md                  # Public landing page + catalog overview
├── PLAN.md                    # This document
├── LICENSE                    # Apache-2.0 (code) — see §9
├── CONTRIBUTING.md            # Authoring guide + skill checklist
├── CODE_OF_CONDUCT.md
├── SECURITY.md                # Responsible handling of malware artifacts
├── index.json                 # Machine-readable catalog (auto-generated)
├── taxonomy.md                # Pillars, subdomains, naming rules
├── skills/
│   └── <verb-led-kebab-name>/
│       ├── SKILL.md           # Frontmatter + procedural knowledge
│       ├── scripts/
│       │   └── analyst.py       # Runnable tooling
│       ├── references/
│       │   └── api-reference.md  # Tooling docs + cited sources
│       └── LICENSE
├── mappings/
│   ├── attack-navigator-layer.json   # ATT&CK coverage layer
│   ├── d3fend/                        # D3FEND technique mappings
│   └── car/                          # MITRE CAR analytic mappings
├── templates/
│   └── skill-template/        # Copy-to-start scaffold for new skills
└── tools/
    ├── lint-skills.py        # Frontmatter + structure validator
    ├── build-index.py         # Regenerates index.json from skills/
    └── coverage-report.py     # ATT&CK/D3FEND coverage stats
```

### SKILL.md frontmatter schema

```yaml
---
name: <kebab-case, matches folder>
description: '<1–3 sentences: what it does + when it activates>'
domain: cybersecurity
subdomain: malware-analysis | reverse-engineering | threat-hunting | lab-foundations
tags: [<5–8 lowercase tags>]
version: 1.0.0
author: <you>
license: Apache-2.0
mitre_attack: [Txxxx, ...]      # TTPs the skill addresses
d3fend: [Dx-XXX, ...]           # defensive countermeasures (where relevant)
car: [CAR-YYYY-MM-NNN, ...]     # MITRE CAR analytics (hunting skills)
references:                     # source provenance for the skill
  - <title — url>
---
```

> Note: the reference repo uses `nist_csf`; we drop it in favor of `d3fend`/`car`, which
> are materially more useful for these three pillars. `reverse-engineering` is promoted to
> a first-class subdomain (the reference repo folds RE into `malware-analysis`).

### SKILL.md body sections (required order)

1. `# Title`
2. `## When to Use` — bullet triggers + an explicit **Do not use** note
3. `## Prerequisites` — tools, versions, lab requirements
4. `## Safety & Handling` — *(malware-handling skills only)* isolation, storage, defanging
5. `## Workflow` — numbered steps with real commands/code blocks
6. `## Validation` — how to confirm the analysis/hunt succeeded
7. `## Pitfalls` — common mistakes and evasion traps
8. `## References` — pointers into `references/` and external sources

---

## 4. Domain Taxonomy

Four subdomains: three pillars plus a shared foundation.

| Subdomain | Scope |
|---|---|
| `lab-foundations` | Safe handling, lab setup, sample triage, hashing, reporting, IOC formats |
| `malware-analysis` | Static + dynamic + behavioral analysis, family/format-specific analysis |
| `reverse-engineering` | Disassembly/decompilation tooling, unpacking, deobfuscation, anti-analysis defeat, arch/language specifics |
| `threat-hunting` | Hypothesis-driven hunts, log/telemetry sources, detection engineering, TTP & infrastructure hunting |

**Naming convention:** verb-led kebab-case, e.g. `triaging-`, `analyzing-`,
`reverse-engineering-`, `unpacking-`, `deobfuscating-`, `hunting-`, `detecting-`,
`building-`, `extracting-`.

---

## 5. Sourcing Strategy (the "many different sources")

Knowledge is **synthesized and rewritten** from a wide source base. We never copy text or
code; we learn the technique and author original prose, original examples, and original
scripts. Each skill lists the specific sources it drew from in `references/`.

**Primary source categories**
- **Standards & catalogs:** MITRE ATT&CK, D3FEND, CAR, ATT&CK Data Sources, Engage; CISA
  advisories; NIST malware/IR guidance.
- **Vendor/tool documentation:** Ghidra, radare2/rizin, Binary Ninja, IDA, x64dbg,
  Volatility 3, YARA, CAPA, Sigma, Suricata, Zeek, Sysmon/ETW, Microsoft PE/COFF spec,
  Sysinternals.
- **Sample & family intelligence:** Malpedia, MalwareBazaar/abuse.ch, vx-underground,
  VirusTotal/MITRE behavior catalogs (for taxonomy, never live samples in-repo).
- **Practitioner curricula (topics/structure only):** SANS FOR610/FOR508/FOR578 outlines,
  Practical Malware Analysis & The Art of Memory Forensics (concepts, not text),
  OALabs / MalwareUnicorn / pwn.college workshop topics.
- **Threat-intel reporting (for real TTPs):** Mandiant, CrowdStrike, Unit 42, Talos,
  Microsoft MSTIC, Elastic, Secureworks, The DFIR Report.
- **Detection content (for patterns, not copied rules):** Sigma HQ, Elastic detection
  rules, Splunk Security Content, LOLBAS, GTFOBins.

**Originality guardrails**
- Write prose from understanding, not paraphrase-by-find-replace.
- All scripts authored fresh and tested; no lifted code.
- Cite every nontrivial technique source in `references/`.
- Run a similarity self-check against the reference repo's wording before publishing.

### 5.1 Enforceable authoring rules (hard requirements)

These exist because "synthesize, don't copy" is only real if execution is disciplined.
The risk is not the format — open standards are meant to be reused — it is reflexively
rewording the reference repo's content. These rules prevent that:

1. **Author from primary sources only.** Do **not** open, read, or reference any
   `SKILL.md`, `analyst.py`, or `references/` file from any third-party skills repository
   while writing an AnalystAIPack skill. Work from tool docs, MITRE pages, specs, and papers.
   Other skills repositories may be consulted **only** to understand the *file format*, never
   the content.
2. **Distinct skill names.** Where an equivalent skill exists in the reference repo, ours
   uses a different, content-accurate name (e.g. theirs
   `reverse-engineering-malware-with-ghidra` → ours `reverse-engineering-binaries-with-ghidra`).
   The §6 backlog already follows this.
3. **Mandatory source citations.** Every skill's `references/api-reference.md` lists the
   specific primary sources it synthesized from. A skill with no real citations is
   incomplete and fails review.
4. **Original scripts.** Every `analyst.py` is written and tested fresh. No code is lifted or
   reworded from another skill repo. Linted with `ruff`.
5. **Format reuse is allowed; content reuse is not.** The agentskills.io layout, frontmatter
   keys, and folder shape are an open standard and intentionally shared. Prose, examples,
   command sequences, and scripts must be original to AnalystAIPack.
6. **Similarity gate before publish.** Before a skill is marked done, run a text-similarity
   check of its `SKILL.md` against the corresponding reference-repo file (if any). High
   overlap = rewrite from primary sources, do not ship.

These rules are restated in `CONTRIBUTING.md` and enforced in review.

---

## 6. Initial Skill Catalog (target 100+)

Numbered backlog grouped by pillar. ✅ = milestone-1 seed (build first).

### 6.1 `lab-foundations` (12)
1. `setting-up-an-isolated-malware-analysis-lab` ✅
2. `handling-malware-samples-safely` ✅
3. `triaging-an-unknown-sample` ✅
4. `hashing-and-fingerprinting-files`
5. `identifying-file-types-and-formats`
6. `defanging-and-sharing-iocs`
7. `extracting-iocs-from-analysis-output`
8. `writing-a-malware-analysis-report` ✅
9. `building-a-sample-management-workflow`
10. `collecting-volatile-evidence-from-a-suspect-host`
11. `enriching-iocs-with-threat-intel-sources`
12. `scoping-an-incident-from-a-single-indicator`

### 6.2 `malware-analysis` (34)
**Static**
13. `performing-static-pe-analysis` ✅
14. `analyzing-pe-imports-and-exports` ✅
15. `measuring-section-entropy-to-detect-packing` ✅
16. `extracting-and-classifying-strings` ✅
17. `analyzing-elf-binaries-on-linux` ✅
18. `analyzing-mach-o-binaries-on-macos` ✅
19. `scanning-samples-with-yara` ✅
20. `generating-capability-reports-with-capa` ✅
21. `analyzing-authenticode-signatures` ✅
22. `analyzing-rich-header-and-compiler-artifacts` ✅

**Document / script malware**
23. `analyzing-malicious-office-macros` ✅
24. `analyzing-malicious-pdfs` ✅
25. `analyzing-malicious-lnk-files` ✅
26. `analyzing-malicious-onenote-and-html-smuggling` ✅
27. `deobfuscating-malicious-powershell` ✅
28. `deobfuscating-malicious-javascript` ✅
29. `analyzing-malicious-vbscript-and-wsf` ✅
30. `analyzing-malicious-iso-and-container-files` ✅

**Dynamic / behavioral**
31. `performing-dynamic-analysis-in-a-sandbox` ✅
32. `monitoring-process-and-file-behavior` ✅
33. `capturing-and-analyzing-malware-network-traffic` ✅
34. `analyzing-api-call-traces` ✅
35. `detecting-sandbox-evasion-behavior` ✅
36. `extracting-config-from-a-running-sample` ✅

**Memory**
37. `analyzing-malware-in-memory-with-volatility3` ✅
38. `detecting-process-injection-in-memory` ✅
39. `recovering-injected-code-and-shellcode` ✅

**Family / class**
40. `analyzing-ransomware-encryption-behavior` ✅
41. `analyzing-infostealer-credential-theft` ✅
42. `analyzing-rat-command-and-control` ✅
43. `analyzing-loaders-and-droppers` ✅
44. `analyzing-banking-trojan-webinjects` ✅
45. `dissecting-boot-and-kernel-rootkits` ✅
46. `extracting-cobalt-strike-beacon-config` ✅

### 6.3 `reverse-engineering` (32)
**Tooling**
47. `reverse-engineering-binaries-with-ghidra` ✅
48. `reverse-engineering-binaries-with-radare2-rizin` ✅
49. `reverse-engineering-binaries-with-binary-ninja` ✅
50. `debugging-malware-with-x64dbg` ✅
51. `scripting-ghidra-headless-analysis` ✅
52. `automating-analysis-with-r2pipe` ✅

**Unpacking / deobfuscation**
53. `unpacking-upx-and-common-packers` ✅
54. `manually-unpacking-packed-binaries` ✅
55. `dumping-and-rebuilding-unpacked-pe` ✅
56. `defeating-string-and-api-obfuscation` ✅
57. `resolving-dynamic-api-hashing` ✅
58. `decrypting-embedded-configuration` ✅

**Anti-analysis defeat**
59. `identifying-anti-debugging-techniques` ✅
60. `bypassing-anti-vm-and-sandbox-checks` ✅
61. `defeating-control-flow-flattening` ✅

**Architecture / format**
62. `reverse-engineering-shellcode` ✅
63. `analyzing-position-independent-code` ✅
64. `reverse-engineering-arm-binaries` ✅
65. `analyzing-windows-driver-malware` ✅

**Language-specific**
66. `analyzing-dotnet-malware-internals` ✅
67. `reverse-engineering-golang-malware` ✅
68. `reverse-engineering-rust-malware` ✅
69. `reverse-engineering-nim-and-other-exotic-binaries` ✅
70. `analyzing-android-dex-malware` ✅
71. `analyzing-compiled-python-malware` ✅

**Cryptography / protocols**
72. `identifying-cryptographic-routines-in-binaries` ✅
73. `reverse-engineering-custom-c2-protocols` ✅
74. `extracting-encryption-keys-from-binaries` ✅

**Signature output**
75. `writing-yara-rules-from-reversed-code` ✅
76. `building-config-extractors` ✅
77. `emulating-functions-with-unicorn` ✅
78. `diffing-malware-variants-bindiff` ✅

### 6.4 `threat-hunting` (30)
**Foundations**
79. `building-a-threat-hunt-hypothesis` ✅
80. `mapping-hunts-to-mitre-attack` ✅
81. `establishing-telemetry-baselines` ✅
82. `operationalizing-a-hunt-into-a-detection` ✅

**Endpoint hunts**
83. `hunting-process-injection-with-sysmon` ✅
84. `hunting-lolbin-abuse` ✅
85. `hunting-persistence-mechanisms-on-windows` ✅
86. `hunting-wmi-event-subscription-persistence` ✅
87. `hunting-scheduled-task-abuse` ✅
88. `hunting-credential-dumping-activity` ✅
89. `hunting-suspicious-powershell-execution` ✅
90. `hunting-fileless-and-in-memory-threats` ✅
91. `hunting-persistence-on-linux` ✅

**Network hunts**
92. `hunting-c2-beaconing-with-frequency-analysis` ✅
93. `hunting-dns-tunneling-and-exfiltration` ✅
94. `hunting-domain-fronting-and-cdn-abuse` ✅
95. `hunting-cobalt-strike-traffic` ✅
96. `hunting-unusual-outbound-connections` ✅

**Identity / lateral movement**
97. `hunting-lateral-movement-via-smb-and-wmi` ✅
98. `hunting-kerberoasting-and-ticket-abuse` ✅
99. `hunting-anomalous-authentication` ✅

**Detection engineering**
100. `writing-sigma-detection-rules` ✅
101. `writing-suricata-network-signatures` ✅
102. `building-zeek-analytics-for-hunting` ✅
103. `tuning-detections-to-reduce-false-positives` ✅
104. `validating-detections-with-atomic-tests` ✅

**Intel-driven hunting**
105. `hunting-from-a-threat-intel-report` ✅
106. `tracking-adversary-infrastructure` ✅
107. `pivoting-on-iocs-across-data-sources` ✅
108. `profiling-a-threat-actor-from-ttps` ✅

**Total backlog: 108 skills** (✅ seed milestone = 30 skills spanning all four subdomains).

---

## 7. Tooling & Automation

| Tool | Purpose |
|---|---|
| `tools/analyst-pack.py` | Unified CLI: list / show / run / search / stats / lint / build |
| `tools/lint-skills.py` | Enforce frontmatter fields, kebab naming, body sections, ATT&CK ID format |
| `tools/build-index.py` | Regenerate `index.json` from `skills/` |
| `tools/build-catalog.py` | Regenerate the browsable `CATALOG.md` |
| `tools/build-navigator-layer.py` | Regenerate the ATT&CK Navigator layer |
| `tools/smoke-test.py` | Run every skill's `analyst.py` (`--help` + fixtures) |
| `templates/skill-template/` | Canonical scaffold to copy when authoring |
| CI (GitHub Actions) | Run linter + index/catalog/layer drift checks + byte-compile + smoke-test on every PR |

---

## 8. Build Pipeline (milestones)

- **M0 — Scaffold (this phase):** repo skeleton, `PLAN.md`, `taxonomy.md`, template,
  validator, index builder, README skeleton, LICENSE, CONTRIBUTING, SECURITY.
- **M1 — Seed (30 ✅ skills):** prove the format end-to-end across all four subdomains;
  wire CI; publish first `index.json` and coverage layer.
- **M2 — Core coverage (to ~70):** complete static/dynamic MA + core RE tooling + endpoint
  and network hunts.
- **M3 — Full backlog (108+):** language-specific RE, family-specific MA, intel-driven
  hunting, detection-engineering set.
- **M4 — Polish:** ATT&CK Navigator layer, coverage report in README, contributor docs,
  optional `npx skills add` packaging.

---

## 9. Authoring Checklist (per skill)

- [ ] Folder + `SKILL.md` + `scripts/analyst.py` + `references/api-reference.md` + `LICENSE`
- [ ] Frontmatter passes `lint-skills.py`
- [ ] `When to Use` includes an explicit **Do not use**
- [ ] `Safety & Handling` present for any sample-handling skill
- [ ] Workflow steps are concrete (real tools, real commands), not generic advice
- [ ] `analyst.py` runs and is original; linted with `ruff`
- [ ] ATT&CK / D3FEND / CAR mappings verified against current versions
- [ ] Sources cited in `references/`; original-wording self-check done
- [ ] `index.json` regenerated

---

## 10. Licensing & Attribution

- **Code & scripts:** Apache-2.0.
- **Skill prose/docs:** CC BY 4.0 (or Apache-2.0 for single-license simplicity — decide at M0).
- **Attribution:** This project is independent and unaffiliated with Anthropic or MITRE.
  ATT&CK/D3FEND/CAR are © MITRE, used under their terms. Each skill credits the sources it
  synthesized from. No content is copied from any third-party skills repository.

---

## 11. Open Decisions (resolve at M0)

1. Single license (Apache-2.0) vs. split code/docs (Apache-2.0 + CC BY 4.0)?
2. Author/handle string for frontmatter `author:`.
3. Include an ATT&CK Navigator layer at M1 or defer to M4?
4. Final GitHub repo slug (`analyst-ai-pack` proposed).
