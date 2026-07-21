#!/usr/bin/env python3
"""Échoue si une règle Sigma référence un playbook qui n'existe pas.

Une détection sans réaction n'est qu'une alerte de plus dans la file : le pipeline
refuse le commit. On exclut les pipelines Sigma→Wazuh (ce ne sont pas des règles).
"""

import sys
from pathlib import Path

import yaml

playbooks = {
    yaml.safe_load(p.read_text(encoding="utf-8"))["id"]
    for p in Path("playbooks").glob("*.yml")
}

rules = [p for p in Path("detections").rglob("*.yml") if "pipelines" not in p.parts]

errors: list[str] = []
for rule_path in rules:
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    pb = rule.get("response_playbook")
    if not pb:
        errors.append(f"{rule_path}: aucun response_playbook déclaré")
    elif pb not in playbooks:
        errors.append(
            f"{rule_path}: playbook inconnu '{pb}' (connus: {sorted(playbooks)})"
        )

if errors:
    print("Liens détection→réponse cassés:")
    for e in errors:
        print("  -", e)
    sys.exit(1)

print(f"OK — {len(rules)} règles liées à un playbook valide ({sorted(playbooks)})")
