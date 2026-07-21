"""Tests de détection : vrai positif (attaque réelle rejouée), faux positif
(activité admin légitime), et gouvernance (standards encodés dans le pipeline)."""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from sigma_eval import evaluate_rule  # noqa: E402

DETECTIONS = Path("detections")
ATTACK_FIXTURES = Path("tests/fixtures/attack")
BENIGN_FIXTURES = Path("tests/fixtures/benign")


def load_rule(name: str) -> dict:
    for p in DETECTIONS.rglob("*.yml"):
        if p.stem == name:
            return yaml.safe_load(p.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"Règle introuvable: {name}")


def load_events(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["events"]


# ─────────────────────────────────────────────────────────────
# VRAI POSITIF — la règle DOIT détecter l'attaque réelle rejouée.
# Fixture absente ⇒ SKIP explicite (télémétrie à capturer sur la VM),
# jamais de fixture fabriqué pour faire passer un test.
# ─────────────────────────────────────────────────────────────
TRUE_POSITIVES = [
    ("t1059.001_powershell_encoded_command", "t1059.001_encoded_test1.json"),
    ("t1059.001_powershell_download_cradle_scriptblock", "t1059.001_cradle_test1.json"),
    ("t1003.001_lsass_memory_access", "t1003.001_lsass_test1.json"),
]


@pytest.mark.parametrize("rule_name,fixture", TRUE_POSITIVES)
def test_true_positive(rule_name: str, fixture: str):
    path = ATTACK_FIXTURES / fixture
    if not path.exists():
        pytest.skip(
            f"Fixture d'attaque absent ({fixture}). Capture-le sur victim-win : "
            f"tools/capture_atomic.ps1 -Technique {rule_name.split('_')[0].upper()}"
        )
    rule = load_rule(rule_name)
    events = load_events(path)
    hits = [e for e in events if evaluate_rule(rule, e)]
    assert hits, (
        f"FAUX NÉGATIF — '{rule['title']}' n'a détecté aucun des {len(events)} "
        f"événements de {fixture}. La règle est aveugle à l'attaque qu'elle couvre."
    )


# ─────────────────────────────────────────────────────────────
# FAUX POSITIF — la règle NE DOIT PAS se déclencher sur du légitime.
# ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("rule_name,_", TRUE_POSITIVES)
def test_no_false_positive_on_admin_activity(rule_name: str, _):
    rule = load_rule(rule_name)
    events = load_events(BENIGN_FIXTURES / "admin_activity.json")
    hits = [e for e in events if evaluate_rule(rule, e)]
    assert not hits, (
        f"FAUX POSITIF — '{rule['title']}' s'est déclenchée sur du légitime : "
        f"{[h.get('EventData', {}).get('CommandLine') for h in hits]}. "
        f"Une règle bruyante finit désactivée : elle ne protège personne."
    )


# ─────────────────────────────────────────────────────────────
# GOUVERNANCE — standards de qualité encodés dans le pipeline.
# ─────────────────────────────────────────────────────────────
# Les pipelines Sigma→Wazuh ne sont pas des règles : on les exclut de la gouvernance.
ALL_RULES = sorted(p for p in DETECTIONS.rglob("*.yml") if "pipelines" not in p.parts)


@pytest.mark.parametrize("path", ALL_RULES, ids=lambda p: p.stem)
def test_rule_has_required_metadata(path: Path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    for field in (
        "title",
        "id",
        "description",
        "author",
        "date",
        "tags",
        "logsource",
        "detection",
        "falsepositives",
        "level",
    ):
        assert field in rule, f"{path.name}: champ obligatoire manquant '{field}'"


@pytest.mark.parametrize("path", ALL_RULES, ids=lambda p: p.stem)
def test_rule_has_attack_tag(path: Path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    techniques = [t for t in rule["tags"] if t.startswith("attack.t")]
    assert techniques, f"{path.name}: aucun tag de technique ATT&CK"


@pytest.mark.parametrize("path", ALL_RULES, ids=lambda p: p.stem)
def test_rule_declares_response_playbook(path: Path):
    """Une détection sans réaction n'est qu'une alerte de plus dans la file."""
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert rule.get(
        "response_playbook"
    ), f"{path.name}: aucun response_playbook — détection sans réaction"


def test_no_duplicate_rule_ids():
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in ALL_RULES]
    assert len(ids) == len(set(ids)), "UUID de règle dupliqué"
