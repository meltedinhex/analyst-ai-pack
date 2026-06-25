# Mappings

Framework mappings generated from skill frontmatter.

## `attack-navigator-layer.json`

A [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer showing
which ATT&CK techniques the AnalystAIPack skills cover. Each technique's **score** is the number
of skills that reference it, and its **comment** lists those skills.

Regenerate after adding or editing skills:

```bash
python tools/build-navigator-layer.py
```

### Viewing the layer

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Choose **Open Existing Layer → Upload from local**.
3. Select `mappings/attack-navigator-layer.json`.

Techniques are shaded by how many skills cover them (light → dark). Hover a technique to see
the contributing skills.

> ATT&CK is © The MITRE Corporation and used under its terms. The pinned `versions.attack`
> field in the layer records the ATT&CK release this layer targets.
