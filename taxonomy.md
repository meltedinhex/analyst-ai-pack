# AnalystAIPack Taxonomy

How skills are categorized and named. This is the authoritative reference for the
`subdomain` frontmatter field and for choosing skill folder names.

## Pillars and subdomains

AnalystAIPack covers three pillars plus a shared foundation. Each skill belongs to exactly
one subdomain, declared in its `SKILL.md` frontmatter.

| Subdomain | Pillar | Scope |
|---|---|---|
| `lab-foundations` | Foundation | Safe handling, lab setup, sample triage, hashing, file ID, IOC formats, reporting, evidence collection, intel enrichment |
| `malware-analysis` | Malware Analysis | Static, dynamic, behavioral, and memory analysis; document/script malware; family- and class-specific analysis |
| `reverse-engineering` | Reverse Engineering | Disassembler/decompiler/debugger tooling; unpacking; deobfuscation; anti-analysis defeat; architecture- and language-specific RE; signature/config-extractor output |
| `threat-hunting` | Threat Hunting | Hypothesis-driven hunts; endpoint/network/identity telemetry; detection engineering; intel-driven hunting and infrastructure tracking |

> `reverse-engineering` is a first-class subdomain in AnalystAIPack. Many libraries fold RE
> under malware-analysis; we separate them because the tooling, mindset, and outputs differ.

## Naming convention

- **Format:** lowercase **kebab-case**, verb-led, describing the action.
- **Folder name == frontmatter `name`.** They must match exactly.
- **Be specific and content-accurate.** The name should describe what the skill actually
  does, not a generic category.
- **Avoid name collisions with other public skill libraries.** Where an equivalent skill
  exists elsewhere, choose a distinct, accurate name (see PLAN.md §5.1).

### Preferred leading verbs

| Verb | Use for |
|---|---|
| `setting-up-`, `building-` | Constructing labs, workflows, pipelines, rules |
| `handling-`, `triaging-` | Sample intake and first-pass assessment |
| `analyzing-` | Examining a sample, format, or behavior |
| `reverse-engineering-` | Code-level binary analysis |
| `unpacking-`, `deobfuscating-`, `decrypting-` | Removing protection layers |
| `identifying-`, `detecting-` | Recognizing a technique or artifact |
| `extracting-` | Pulling config, IOCs, keys, or artifacts |
| `hunting-` | Proactive search across telemetry |
| `writing-` | Producing detections, signatures, reports |

### Examples

```
setting-up-an-isolated-malware-analysis-lab
performing-static-pe-analysis
reverse-engineering-binaries-with-ghidra
unpacking-upx-and-common-packers
hunting-c2-beaconing-with-frequency-analysis
writing-sigma-detection-rules
```

## Tags

5–8 lowercase tags per skill. Tags are free-form but should reuse established terms so the
catalog stays searchable. Common tag groups:

- **Discipline:** `malware`, `reverse-engineering`, `threat-hunting`, `forensics`, `detection-engineering`
- **Technique:** `static-analysis`, `dynamic-analysis`, `unpacking`, `deobfuscation`, `memory-forensics`, `beaconing`
- **Tooling:** `ghidra`, `radare2`, `volatility3`, `yara`, `capa`, `sigma`, `zeek`, `sysmon`, `x64dbg`
- **Artifact/format:** `pe`, `elf`, `macho`, `dotnet`, `shellcode`, `office-macro`, `pdf`, `lnk`
- **Platform:** `windows`, `linux`, `macos`, `android`

## Framework mappings

Each skill declares the frameworks it touches in frontmatter:

| Field | Framework | Applies to |
|---|---|---|
| `mitre_attack` | MITRE ATT&CK techniques (`Txxxx`) | All skills — the adversary behavior addressed |
| `d3fend` | MITRE D3FEND techniques (`Dx-XXX`) | Skills with a defensive countermeasure |
| `car` | MITRE CAR analytics (`CAR-YYYY-MM-NNN`) | Hunting/detection skills with a matching analytic |

Use only current, non-deprecated IDs. Validate against the latest published versions.
