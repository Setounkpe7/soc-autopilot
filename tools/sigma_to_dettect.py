#!/usr/bin/env python3
"""Génère la couverture ATT&CK À PARTIR des tags des règles Sigma.

Deux sorties, toutes deux DÉTERMINISTES (aucun `now()` : on utilise la date propre
de chaque règle) pour permettre un contrôle de dérive en CI (`git diff --exit-code`) :
la carte de couverture ne peut donc jamais être périmée — elle est un produit du code.

  - docs/coverage/attack-navigator-layer.json  → chargeable dans ATT&CK Navigator
  - docs/coverage/dettect-techniques.yaml       → fichier technique-administration DeTT&CT
"""

import json
import re
from pathlib import Path

import yaml

# Tag de TECHNIQUE : `attack.t` suivi d'un chiffre. Exclut les tags de TACTIQUE
# numérotés (`attack.taNNNN`) qui commenceraient aussi par `attack.ta`.
TECHNIQUE_TAG = re.compile(r"^attack\.t\d")

DETECTIONS = Path("detections")
OUT_DIR = Path("docs/coverage")
LEVEL_SCORE = {"low": 2, "medium": 3, "high": 4, "critical": 5}


def collect() -> dict[str, list[dict]]:
    """technique_id -> liste de détections (déterministe : rules triées par nom)."""
    techniques: dict[str, list[dict]] = {}
    rules = sorted(p for p in DETECTIONS.rglob("*.yml") if "pipelines" not in p.parts)
    for path in rules:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        for tag in rule.get("tags", []):
            if not TECHNIQUE_TAG.match(tag):
                continue
            tid = tag.replace("attack.", "").upper()
            if "." in tid:
                base, sub = tid.split(".", 1)
                tid = f"{base}.{sub.zfill(3)}"
            techniques.setdefault(tid, []).append(
                {
                    "title": rule["title"],
                    "score": LEVEL_SCORE.get(rule.get("level"), 2),
                    "status": rule.get("status", "stable"),
                    "date": str(rule.get("date", "")),
                    "location": f"Wazuh/{path.name}",
                }
            )
    for tid in techniques:
        techniques[tid].sort(key=lambda d: d["location"])
    return techniques


def navigator_layer(techniques: dict[str, list[dict]]) -> dict:
    return {
        "name": "SOC Autopilot — Couverture de détection",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Généré depuis les tags ATT&CK des règles Sigma. NE PAS éditer à la main.",
        "sorting": 0,
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": tid,
                "score": max(d["score"] for d in dets),
                "enabled": True,
                "comment": "; ".join(f"{d['title']} ({d['status']})" for d in dets),
                "metadata": [{"name": "règle", "value": d["location"]} for d in dets],
            }
            for tid, dets in sorted(techniques.items())
        ],
        "gradient": {
            "colors": ["#ffe766", "#8ec843"],
            "minValue": 2,
            "maxValue": 5,
        },
        "legendItems": [{"label": "détecté (score = criticité)", "color": "#8ec843"}],
    }


def dettect_admin(techniques: dict[str, list[dict]]) -> dict:
    return {
        "version": 1.2,
        "file_type": "technique-administration",
        "name": "SOC Autopilot",
        "platform": ["Windows", "Linux"],
        "techniques": [
            {
                "technique_id": tid,
                "technique_name": "",
                "detection": [
                    {
                        "applicable_to": ["all"],
                        "location": [d["location"]],
                        "comment": d["title"],
                        "score_logbook": [
                            {
                                "date": d["date"],
                                "score": d["score"],
                                "comment": "Auto-généré depuis les tags Sigma",
                            }
                        ],
                    }
                    for d in dets
                ],
            }
            for tid, dets in sorted(techniques.items())
        ],
    }


def main() -> None:
    techniques = collect()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "attack-navigator-layer.json").write_text(
        json.dumps(navigator_layer(techniques), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (OUT_DIR / "dettect-techniques.yaml").write_text(
        yaml.safe_dump(dettect_admin(techniques), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"{len(techniques)} techniques couvertes : {sorted(techniques)}")


if __name__ == "__main__":
    main()
