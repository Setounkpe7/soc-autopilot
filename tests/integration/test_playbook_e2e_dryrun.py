"""Test e2e du pipeline moteur : alerte → decode → score → cas → isolation DRY-RUN,
avec audit trail complet. Déterministe, sans réseau (VT/TheHive/Slack désactivés,
isolation destructive interceptée par le dry-run)."""

import base64

import soc_autopilot.actions  # noqa: F401  → enregistre toutes les actions
from soc_autopilot.audit import AuditRepository
from soc_autopilot.engine.executor import Executor
from soc_autopilot.engine.loader import PlaybookStore

E2E_PB = """
id: PB-9001
name: e2e dry-run
version: "1.0"
trigger: { mitre: ["T1059.001"], severity_min: 0 }
inputs:
  host: "{{ alert.agent.name }}"
  cmdline: "{{ alert.data.win.eventdata.commandLine | default('') }}"
steps:
  - id: decode
    action: transform.b64_decode
    with: { field: "{{ inputs.cmdline }}" }
    on_error: continue
  - id: risk
    action: transform.score
    with:
      base: "{{ alert.rule.level }}"
      boosters:
        - when: "{{ steps.decode.output.found }}"
          points: 2
  - id: case
    action: thehive.create_case
    on_error: fail
    with: { title: "e2e {{ inputs.host }}" }
  - id: isolate
    action: wazuh.isolate_host
    destructive: true
    rollback: wazuh.unisolate_host
    with: { agent: "{{ inputs.host }}" }
outputs:
  case_id: "{{ steps.case.output.case_id }}"
  score: "{{ steps.risk.output }}"
"""


async def test_pb_runs_end_to_end_in_dry_run(monkeypatch, tmp_path):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.delenv("virustotal_api_key", raising=False)
    monkeypatch.delenv("thehive_api_key", raising=False)
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    (tmp_path / "pb.yml").write_text(E2E_PB)
    repo = AuditRepository("sqlite+aiosqlite:///:memory:")
    await repo.init_schema()
    store = PlaybookStore(str(tmp_path))
    pb = store.get("PB-9001")

    payload = base64.b64encode("Write-Output hi".encode("utf-16-le")).decode()
    alert = {
        "id": "e2e-1",
        "rule": {"id": "100101", "level": 8, "mitre": {"id": ["T1059.001"]}},
        "agent": {"name": "victim-win"},
        "data": {"win": {"eventdata": {"commandLine": f"powershell -enc {payload}"}}},
    }
    result = await Executor(repo).run(pb, alert)
    assert result["status"] in ("success", "partial")

    steps = await repo.get_steps(result["execution_id"])
    by = {s.step_id: s for s in steps}

    # décodage réel UTF-16LE
    assert by["decode"].status == "success"
    assert by["decode"].output["value"]["decoded"] == "Write-Output hi"
    # scoring : base 8 + booster 2 (decode.found) = 10
    assert by["risk"].output["value"] == 10
    # cas créé en mode dégradé local (pas de clé TheHive)
    assert by["case"].status == "success"
    assert by["case"].output["value"]["backend"] == "local"
    # l'isolation destructive est en DRY-RUN, jamais exécutée
    assert by["isolate"].status == "dry_run"

    await repo.close()
