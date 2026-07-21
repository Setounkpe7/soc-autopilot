# Couverture ATT&CK — dérivée du code

Ces fichiers sont **générés**, jamais édités à la main :

```bash
python tools/sigma_to_dettect.py
```

- **`attack-navigator-layer.json`** — couche [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
  Pour la visualiser : ouvrir le Navigator → *Open Existing Layer* → *Upload from local* →
  sélectionner ce fichier. Les techniques détectées sont colorées, le score = criticité de la règle.
- **`dettect-techniques.yaml`** — fichier `technique-administration` pour [DeTT&CT](https://github.com/rabobank-cdc/DeTT&CT),
  à croiser avec les sources collectées pour produire une couche d'écart.

La génération est **déterministe** (aucun horodatage dynamique : on utilise la `date`
propre de chaque règle). La **CI échoue si ces fichiers sont périmés** : `git diff` sur
la couche JSON (byte-déterministe) et tests de contenu (`test_coverage.py`) sur le JSON
**et** le YAML — la couverture ne peut donc pas mentir : c'est un produit du code,
régénéré à chaque commit.

Voir aussi [`../telemetry-gap-analysis.md`](../telemetry-gap-analysis.md) pour les angles morts assumés.
