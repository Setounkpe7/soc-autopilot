# Détection T1059.001 (PowerShell) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Détecter T1059.001 (download cradle PowerShell) via deux règles Sigma, converties par un pipeline Sigma→Wazuh maison, et prouvées contre les vraies alertes de la détonation Atomic Red Team dans `wazuh-alerts-*`.

**Architecture:** Deux règles Sigma (Sysmon EID 1 « processus » + PowerShell EID 4104 « contenu ») dans `detections/windows/`. Un pipeline pySigma dans `detections/pipelines/` remappe les champs Sigma vers le schéma JSON décodé de Wazuh et ajoute la condition de canal/eventID par `logsource`. Un script de validation convertit une règle puis rejoue la requête sur l'indexeur et compte les hits.

**Tech Stack:** sigma-cli 3.1.0 (backend `opensearch_lucene`), pySigma processing pipeline (YAML), OpenSearch (Wazuh indexer) via `query_string`, pytest, Python stdlib (`urllib`, `ssl`).

## Global Constraints

- Règles dans `detections/windows/` ; pipeline dans `detections/pipelines/`. Exécuter toutes les commandes **depuis la racine du repo**.
- Schéma Wazuh (confirmé sur données réelles) : champs sous `data.win.eventdata.*` en lowerCamelCase ; canal dans `data.win.system.channel` ; eventID dans `data.win.system.eventID` (valeur chaîne, ex. `"1"`, `"4104"`).
- Conversion : `sigma convert -t opensearch_lucene -p detections/pipelines/wazuh-windows.yml <règle>.yml`.
- Indexeur : `https://localhost:9200`, index `wazuh-alerts-*`, auth basic `admin` / `SecretPassword` (surchargée par `WAZUH_INDEXER_URL` / `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASS`), TLS auto-signé (vérification désactivée).
- Tests : `pytest` lancé depuis la racine ; les tests live se skippent si `localhost:9200` est injoignable.
- Git : travailler sur la branche `detection/t1059-001-powershell`. Terminer chaque message de commit par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- La validation live ne nécessite **pas** la VM (données déjà ingérées) ; elle nécessite Wazuh démarré sur l'hôte.

---

### Task 1 : Pipeline de mapping Sigma→Wazuh

**Files:**
- Create: `detections/pipelines/wazuh-windows.yml`
- Test: `tests/unit/test_sigma_pipeline.py`

**Interfaces:**
- Produces: le pipeline `detections/pipelines/wazuh-windows.yml`, consommé par toutes les tâches suivantes via `sigma convert -p`. Contrats de mapping : `Image→data.win.eventdata.image`, `OriginalFileName→data.win.eventdata.originalFileName`, `CommandLine→data.win.eventdata.commandLine`, `ScriptBlockText→data.win.eventdata.scriptBlockText`. Ajoute canal Sysmon+EID 1 pour `logsource category: process_creation`, canal PowerShell+EID 4104 pour `category: ps_script`.

- [ ] **Step 1: Écrire les tests de conversion (qui échouent)**

```python
# tests/unit/test_sigma_pipeline.py
"""Tests hors-ligne : le pipeline mappe les champs Sigma vers le schéma Wazuh."""
import subprocess
import textwrap

PIPELINE = "detections/pipelines/wazuh-windows.yml"


def _convert(rule_path):
    proc = subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "-p", PIPELINE, str(rule_path)],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout


def test_process_creation_maps_to_wazuh_fields_and_sysmon_channel(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(textwrap.dedent("""
        title: probe
        id: 11111111-1111-4111-8111-111111111111
        status: experimental
        logsource:
          category: process_creation
          product: windows
        detection:
          sel:
            CommandLine|contains: 'IEX'
          condition: sel
        level: low
    """))
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.commandLine" in out
    assert "Microsoft-Windows-Sysmon/Operational" in out
    assert "data.win.system.eventID" in out


def test_ps_script_maps_to_scriptblock_and_powershell_channel(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(textwrap.dedent("""
        title: probe
        id: 22222222-2222-4222-8222-222222222222
        status: experimental
        logsource:
          category: ps_script
          product: windows
        detection:
          sel:
            ScriptBlockText|contains: 'IEX('
          condition: sel
        level: low
    """))
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.scriptBlockText" in out
    assert "Microsoft-Windows-PowerShell/Operational" in out
```

- [ ] **Step 2: Lancer les tests pour vérifier qu'ils échouent**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py -v`
Expected: FAIL — `sigma convert` sort en erreur (fichier pipeline introuvable), `subprocess.CalledProcessError`.

- [ ] **Step 3: Écrire le pipeline**

```yaml
# detections/pipelines/wazuh-windows.yml
# Mappe les champs Sigma vers le schéma JSON décodé de Wazuh (wazuh-alerts-*)
# et ajoute la condition de canal/eventID selon le logsource de la règle.
name: wazuh-windows
priority: 100
transformations:
  - id: wazuh_field_mapping
    type: field_name_mapping
    mapping:
      Image: data.win.eventdata.image
      OriginalFileName: data.win.eventdata.originalFileName
      CommandLine: data.win.eventdata.commandLine
      ScriptBlockText: data.win.eventdata.scriptBlockText

  - id: sysmon_process_creation_channel
    type: add_condition
    conditions:
      "data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"
      "data.win.system.eventID": "1"
    rule_conditions:
      - type: logsource
        category: process_creation
        product: windows

  - id: powershell_scriptblock_channel
    type: add_condition
    conditions:
      "data.win.system.channel": "Microsoft-Windows-PowerShell/Operational"
      "data.win.system.eventID": "4104"
    rule_conditions:
      - type: logsource
        category: ps_script
        product: windows
```

- [ ] **Step 4: Lancer les tests pour vérifier qu'ils passent**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py -v`
Expected: PASS (2 tests). Si un test échoue sur le nom de canal, vérifier la casse exacte `Microsoft-Windows-Sysmon/Operational` dans le pipeline.

- [ ] **Step 5: Commit**

```bash
git add detections/pipelines/wazuh-windows.yml tests/unit/test_sigma_pipeline.py
git commit -m "feat(detection): pipeline de mapping Sigma vers le schéma Wazuh

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2 : Règle A — download cradle en ligne de commande (Sysmon EID 1)

**Files:**
- Create: `detections/windows/t1059.001_powershell_download_cradle_cmdline.yml`
- Modify: `tests/unit/test_sigma_pipeline.py` (ajouter un test pour la règle A)

**Interfaces:**
- Consumes: le pipeline de Task 1.
- Produces: la règle `t1059.001_powershell_download_cradle_cmdline.yml` (logsource `process_creation`), consommée par le test d'intégration de Task 4.

- [ ] **Step 1: Écrire le test (qui échoue)**

Ajouter à la fin de `tests/unit/test_sigma_pipeline.py` :

```python
def test_rule_a_valid_and_contains_cradle_terms():
    rule = "detections/windows/t1059.001_powershell_download_cradle_cmdline.yml"
    check = subprocess.run(["sigma", "check", rule], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.commandLine" in out
    assert "data.win.eventdata.image" in out
    for term in ["IEX", "Invoke-Expression", "DownloadString"]:
        assert term in out
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py::test_rule_a_valid_and_contains_cradle_terms -v`
Expected: FAIL — `sigma check` sort en erreur (fichier de règle introuvable).

- [ ] **Step 3: Écrire la règle A**

```yaml
# detections/windows/t1059.001_powershell_download_cradle_cmdline.yml
title: PowerShell Download Cradle via Command-Line
id: 7e1b4a30-6c2f-4a9d-9b1e-2f0a1c3d5e70
status: experimental
description: >
  Detects powershell.exe launched with an in-memory download-and-execute cradle
  (Invoke-Expression combined with a web download), a common T1059.001 execution
  pattern exercised by Atomic Red Team.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Michel-Ange Doubogan
date: 2026/07/20
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    - Image|endswith: '\powershell.exe'
    - OriginalFileName: 'PowerShell.EXE'
  selection_cradle:
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'Invoke-WebRequest'
      - 'IWR '
  condition: selection_proc and selection_cradle
falsepositives:
  - Legitimate administrative scripts that use Invoke-Expression with remote content
level: high
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py::test_rule_a_valid_and_contains_cradle_terms -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add detections/windows/t1059.001_powershell_download_cradle_cmdline.yml tests/unit/test_sigma_pipeline.py
git commit -m "feat(detection): règle T1059.001 download cradle en ligne de commande (Sysmon EID 1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3 : Règle B — download cradle dans le ScriptBlock (PowerShell EID 4104)

**Files:**
- Create: `detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml`
- Modify: `tests/unit/test_sigma_pipeline.py` (ajouter un test pour la règle B)

**Interfaces:**
- Consumes: le pipeline de Task 1.
- Produces: la règle `t1059.001_powershell_download_cradle_scriptblock.yml` (logsource `ps_script`), consommée par le test d'intégration de Task 4.

- [ ] **Step 1: Écrire le test (qui échoue)**

Ajouter à la fin de `tests/unit/test_sigma_pipeline.py` :

```python
def test_rule_b_valid_and_contains_scriptblock_terms():
    rule = "detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml"
    check = subprocess.run(["sigma", "check", rule], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    out = _convert(rule).replace("\\", "")  # neutralise l'échappement Lucene (\- \/)
    assert "data.win.eventdata.scriptBlockText" in out
    assert "Microsoft-Windows-PowerShell/Operational" in out
    for term in ["Invoke-Expression", "DownloadString", "Net.WebClient"]:
        assert term in out
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py::test_rule_b_valid_and_contains_scriptblock_terms -v`
Expected: FAIL — fichier de règle introuvable.

- [ ] **Step 3: Écrire la règle B**

```yaml
# detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml
title: PowerShell Download Cradle in ScriptBlock
id: 9c3d5f21-8a4b-4e6c-b2d1-3e5a7c9f0b12
status: experimental
description: >
  Detects a PowerShell script block (EID 4104) containing an in-memory
  download-and-execute cradle. ScriptBlock logging records the de-obfuscated
  script text, so this fires even when the code was launched via
  -EncodedCommand, where the process command line alone would be opaque.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Michel-Ange Doubogan
date: 2026/07/20
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: ps_script
  product: windows
detection:
  selection_cradle:
    ScriptBlockText|contains:
      - 'IEX('
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'Invoke-WebRequest'
      - 'Net.WebClient'
  condition: selection_cradle
falsepositives:
  - Administrative or packaging scripts that legitimately download and evaluate code
level: high
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `python -m pytest tests/unit/test_sigma_pipeline.py::test_rule_b_valid_and_contains_scriptblock_terms -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml tests/unit/test_sigma_pipeline.py
git commit -m "feat(detection): règle T1059.001 download cradle dans le ScriptBlock (PowerShell EID 4104)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4 : Validation live contre la détonation réelle

**Files:**
- Create: `tools/validate_detection.py`
- Create: `tests/integration/test_t1059_detonation_match.py`

**Interfaces:**
- Consumes: le pipeline (Task 1) et les deux règles (Task 2, Task 3).
- Produces: `tools/validate_detection.py` — CLI qui convertit une règle et interroge l'indexeur ; sort en code 0 si ≥1 hit, 1 sinon. Fonctions `convert(rule_path) -> str` et `search(query) -> dict`.

- [ ] **Step 1: Écrire le test d'intégration (qui échoue)**

```python
# tests/integration/test_t1059_detonation_match.py
"""Test live : la requête convertie matche la détonation ART réelle.
Se skippe si l'indexeur Wazuh n'est pas joignable."""
import socket
import subprocess
import sys

import pytest

RULES = [
    "detections/windows/t1059.001_powershell_download_cradle_cmdline.yml",
    "detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml",
]


def _indexer_up():
    try:
        with socket.create_connection(("localhost", 9200), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _indexer_up(), reason="Wazuh indexer injoignable")


@pytest.mark.parametrize("rule", RULES)
def test_rule_matches_real_detonation(rule):
    proc = subprocess.run(
        [sys.executable, "tools/validate_detection.py", rule],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `python -m pytest tests/integration/test_t1059_detonation_match.py -v`
Expected: FAIL — `tools/validate_detection.py` n'existe pas (returncode ≠ 0).

- [ ] **Step 3: Écrire le script de validation**

```python
# tools/validate_detection.py
#!/usr/bin/env python3
"""Convertit une règle Sigma avec le pipeline Wazuh, rejoue la requête sur
wazuh-alerts-* et rapporte le nombre de hits. Sort 0 si ≥1 hit, sinon 1.

Usage:
    python tools/validate_detection.py detections/windows/<règle>.yml

Env (défauts = labo local) :
    WAZUH_INDEXER_URL   défaut https://localhost:9200
    WAZUH_INDEXER_USER  défaut admin
    WAZUH_INDEXER_PASS  défaut SecretPassword
"""
import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from base64 import b64encode

PIPELINE = "detections/pipelines/wazuh-windows.yml"
INDEX = "wazuh-alerts-*"


def convert(rule_path: str) -> str:
    """Retourne la requête OpenSearch Lucene pour une règle Sigma."""
    proc = subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "-p", PIPELINE, rule_path],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def search(query: str) -> dict:
    url = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
    user = os.environ.get("WAZUH_INDEXER_USER", "admin")
    passwd = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
    body = json.dumps({
        "size": 3,
        "query": {"query_string": {"query": query, "analyze_wildcard": True}},
        "_source": ["timestamp", "agent.name", "rule.description",
                    "data.win.system.eventID"],
    }).encode()
    req = urllib.request.Request(
        f"{url}/{INDEX}/_search",
        data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(f"{user}:{passwd}".encode()).decode(),
        },
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.load(resp)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rule")
    args = ap.parse_args()

    query = convert(args.rule)
    print(f"[query] {query}\n")
    result = search(query)
    total = result["hits"]["total"]["value"]
    print(f"[hits] {total}")
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        eid = src.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        print(f"  {src.get('timestamp')}  EID={eid}  {src.get('rule', {}).get('description')}")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `python -m pytest tests/integration/test_t1059_detonation_match.py -v`
Expected: PASS (2 tests) — chaque règle matche ≥1 doc de la détonation.

> **Point de contrôle connu (leçon n°1 — mapping keyword/casse).** Si un test sort 0 hit, lancer manuellement `python tools/validate_detection.py <règle>` pour voir la requête, puis inspecter la casse réelle du champ :
> `curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{"size":1,"query":{"term":{"data.win.system.eventID":"4104"}},"_source":["data.win.eventdata.scriptBlockText"]}' | jq`
> Remédiation : le `analyze_wildcard: true` du script gère les champs `text` ; si le champ est `keyword` sensible à la casse et que la casse diffère, aligner les termes de la règle sur la casse observée (ex. `IEX(` vs `iex(`) — c'est exactement l'ajustement bruit/schéma décrit dans le spec.

- [ ] **Step 5: Commit**

```bash
git add tools/validate_detection.py tests/integration/test_t1059_detonation_match.py
git commit -m "test(detection): validation live des règles T1059.001 contre la détonation ART

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Vérification finale (après les 4 tâches)

Run: `python -m pytest tests/unit/test_sigma_pipeline.py tests/integration/test_t1059_detonation_match.py -v`
Expected: tous les tests PASS (offline systématiquement, live si l'indexeur tourne).

Démo entrevue reproductible :
```bash
python tools/validate_detection.py detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml
```
→ affiche la requête convertie puis les documents de la détonation qui matchent.

Contrôle bruit (spec §6.4 — la règle cible un sous-ensemble, pas tout PowerShell) :
```bash
# N = hits de la règle (cradle) ; M = total des événements PowerShell 4104. On veut N < M.
python tools/validate_detection.py detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml   # -> N
curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"data.win.system.eventID":"4104"}}}' | jq .count                                      # -> M
```
Si `N == M`, la règle est trop large (elle matche tout PowerShell) → resserrer les indicateurs de cradle.
