# SOC Autopilot — Fichier 4/5
# Tests d'attaque et validation de bout en bout
## J5 — Lundi 20 juillet

> **Lis ce fichier avant J4.** Il change la façon dont tu écris tes règles.
> C'est **la journée qui te distingue**. N'importe qui écrit une règle de détection. Presque personne ne **prouve** qu'elle marche — et encore moins qu'elle ne se déclenche pas à tort.

---

## 1. Pourquoi cette journée existe

### Le problème que 90 % des projets de détection ignorent

Tu écris une règle. Elle a l'air juste. Tu la déploies. **Trois choses peuvent être vraies, et tu n'en sais rien :**

| Cas | Ce qui se passe | Coût réel |
|---|---|---|
| **Vrai positif** ✅ | L'attaque a lieu, la règle se déclenche | C'est ce qu'on veut |
| **Faux négatif** ❌ | L'attaque a lieu, la règle **ne se déclenche pas** | **Le pire.** Tu crois être couvert. Ta carte ATT&CK est verte. Tu es aveugle et tu ne le sais pas |
| **Faux positif** ⚠️ | Rien ne se passe, la règle se déclenche quand même | 200 alertes/jour → l'analyste désactive la règle → tu redeviens aveugle, **mais avec de la paperasse en plus** |

> **Le faux négatif silencieux est le tueur.** Une règle mal écrite ne crie pas. Elle reste verte sur ton dashboard pendant six mois pendant que l'attaquant passe. **C'est exactement ce qui arrive dans les vrais SOC.**

### La solution : le test de détection

**Le principe (une phrase à retenir) :**
> **Une règle de détection est du code. Du code sans test est du code cassé qui n'a pas encore été surpris.**

Donc :
1. On **rejoue une vraie attaque** (Atomic Red Team) → on capture la télémétrie générée.
2. On **rejoue une activité bénigne réaliste** → on capture aussi.
3. En CI, on passe la règle sur les deux jeux :
   - Attaque → **assert 1 hit** (pas de faux négatif)
   - Bénin → **assert 0 hit** (pas de faux positif)
4. Aucune règle ne merge sans les deux verts.

> ⚡ **La phrase d'entrevue :**
> *« Chez moi, une règle de détection passe par une PR avec deux tests obligatoires : un vrai positif rejoué depuis une vraie attaque Atomic Red Team, et un faux positif contre du trafic administratif légitime. Si l'un des deux casse, le merge est bloqué. Sans ces tests, une règle est une hypothèse, pas une détection. »*
> **Tais-toi après. Laisse le silence travailler.**

---

## 2. La méthodologie — capturer puis rejouer

### Pourquoi ne pas juste tester en direct ?

On pourrait lancer l'attaque et vérifier dans Wazuh. **Mais :**
- C'est lent (2 min par test).
- Ça exige la VM Windows allumée → **impossible en CI GitHub Actions**.
- Ce n'est **pas reproductible** : le timing change, les IDs changent, les tests deviennent flaky (rouges au hasard).

### La bonne méthode : capture une fois, rejoue mille fois

```
┌── UNE FOIS (manuellement, J5) ────────────────────────────────┐
│  1. Snapshot "03-victim-prete"                                │
│  2. Invoke-AtomicTest T1059.001                               │
│  3. Extraire les événements Sysmon générés → JSON             │
│  4. Sauver en tests/fixtures/attack/T1059.001.json            │
│  5. Restaurer le snapshot                                     │
│  6. Générer un fixture bénin → tests/fixtures/benign/*.json   │
└───────────────────────────────────────────────────────────────┘
                              ↓  commit
┌── À CHAQUE COMMIT (automatique, en CI) ───────────────────────┐
│  pytest tests/detection/                                       │
│    règle Sigma × fixture attaque  → assert hit == True         │
│    règle Sigma × fixture bénin    → assert hit == False        │
│  ⏱ 3 secondes, aucune VM, 100 % déterministe                   │
└───────────────────────────────────────────────────────────────┘
```

> **C'est exactement le pattern des tests d'intégration en développement logiciel :** on ne lance pas une vraie base de données Oracle à chaque test unitaire ; on utilise des fixtures capturées d'une vraie base. **Je fais du Detection-as-Code, donc j'applique les pratiques de test du code.** ⚡ **C'est la logique du projet en une phrase.**

---

## 3. Capturer les fixtures d'attaque

### 3.1 Le script d'extraction — sur `victim-win`

`tools/capture_atomic.ps1` :
```powershell
<#
.SYNOPSIS
  Exécute un test Atomic Red Team et capture la télémétrie Sysmon générée.
.EXAMPLE
  .\capture_atomic.ps1 -Technique T1059.001 -TestNumbers 1
#>
param(
  [Parameter(Mandatory)][string]$Technique,
  [string]$TestNumbers = "1",
  [string]$OutDir = "C:\captures"
)

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# 1) Marqueur temporel AVANT — on ne capturera que ce que l'attaque génère
$start = (Get-Date).AddSeconds(-2)
Write-Host "[*] Marqueur : $start" -ForegroundColor Cyan

# 2) Prérequis (télécharge les outils nécessaires au test)
Write-Host "[*] Prérequis pour $Technique..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -GetPrereqs

# 3) L'ATTAQUE
Write-Host "[!] Exécution de $Technique test $TestNumbers" -ForegroundColor Red
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers
Start-Sleep -Seconds 5     # laisser Sysmon écrire

# 4) Extraction de la télémétrie
Write-Host "[*] Extraction Sysmon..." -ForegroundColor Cyan
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $start
} -ErrorAction SilentlyContinue

$parsed = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
        EventID     = $e.Id
        TimeCreated = $e.TimeCreated.ToString("o")
        Computer    = $e.MachineName
        EventData   = $data
    }
}

# 5) Sauvegarde au format de fixture
$outFile = Join-Path $OutDir "$Technique`_test$TestNumbers.json"
@{
    technique  = $Technique
    test       = $TestNumbers
    captured   = (Get-Date).ToString("o")
    source     = "Atomic Red Team"
    event_count = @($parsed).Count
    events     = $parsed
} | ConvertTo-Json -Depth 10 | Out-File $outFile -Encoding utf8

Write-Host "[+] $(@($parsed).Count) événements → $outFile" -ForegroundColor Green

# 6) Nettoyage Atomic (annule la persistence, supprime les fichiers créés)
Write-Host "[*] Cleanup..." -ForegroundColor Cyan
Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -Cleanup
```

> **Trois détails d'ingénieur dans ce script :**
> 1. **Le marqueur `-2s` avant l'attaque.** Sans lui, tu captures tout l'historique Sysmon depuis le boot. Ton fixture ferait 40 Mo et contiendrait du bruit qui rendrait ton test faussement vert. **On capture le delta causé par l'attaque, rien d'autre.**
> 2. **`Start-Sleep 5`.** Sysmon écrit de façon asynchrone. Sans l'attente, tu captures 3 événements sur 12 et ton test échoue au hasard. **Les tests flaky sont pires que pas de tests** : on finit par les ignorer, puis par ignorer les vrais échecs.
> 3. **`-Cleanup`.** Atomic annule ce qu'il a fait. **Sans ça, ton test T1547.001 laisse une clé Run en place, et ta règle de persistence se déclenche pendant le test T1003.001 → contamination croisée et faux positifs dans tes propres tests.**
> **⚡ Si tu expliques ces trois points, on saura que tu as vraiment fait ce test, pas copié un tuto.**

### 3.2 Les 8 captures

```powershell
# Sur victim-win, PowerShell Admin
# ⚠️ Snapshot AVANT, restauration APRÈS chaque bloc à effet persistant

cd C:\Tools

.\capture_atomic.ps1 -Technique T1059.001 -TestNumbers 1   # PowerShell encodé
.\capture_atomic.ps1 -Technique T1003.001 -TestNumbers 1   # LSASS (procdump)
.\capture_atomic.ps1 -Technique T1547.001 -TestNumbers 1   # Run key
.\capture_atomic.ps1 -Technique T1136.001 -TestNumbers 1   # Création de compte
.\capture_atomic.ps1 -Technique T1053.005 -TestNumbers 2   # Scheduled task
.\capture_atomic.ps1 -Technique T1070.001 -TestNumbers 1   # Effacement de logs
.\capture_atomic.ps1 -Technique T1105    -TestNumbers 1   # certutil download
```

**Rapatrier vers ton poste :**
```bash
# Depuis ton poste (partage réseau, ou scp si tu as OpenSSH sur Windows)
mkdir -p tests/fixtures/attack
scp Administrator@192.168.56.20:'C:/captures/*.json' tests/fixtures/attack/
```

### 3.3 Sanitiser les fixtures — obligatoire

```python
# tools/sanitize_fixtures.py
"""Retire les identifiants machine/utilisateur avant de commiter les fixtures."""
import json, re, sys
from pathlib import Path

REPLACEMENTS = [
    (re.compile(r"\bDESKTOP-[A-Z0-9]+\b"), "VICTIM-WIN"),
    (re.compile(r"192\.168\.56\.\d+"), "10.0.0.20"),
    (re.compile(r"\\Users\\[^\\\"]+"), r"\\Users\\testuser"),
    (re.compile(r"S-1-5-21-[\d-]+"), "S-1-5-21-0000000000-0000000000-0000000000-1001"),
]

for path in Path("tests/fixtures").rglob("*.json"):
    text = path.read_text(encoding="utf-8")
    for pattern, repl in REPLACEMENTS:
        text = pattern.sub(repl, text)
    path.write_text(text, encoding="utf-8")
    print(f"✅ sanitisé : {path}")
```

> **Pourquoi ce script existe :** un fixture brut contient ton nom de machine, ton SID, ton nom d'utilisateur, ta topologie réseau. **Le commiter, c'est publier ta reconnaissance interne sur GitHub.** Dans un contexte défense, c'est le genre d'erreur qui coûte un emploi.
> ⚡ **En entrevue :** *« J'ai un script de sanitisation parce que mes fixtures contiennent des SID, des noms de machine et des chemins utilisateur. C'est de la reconnaissance offerte. Le même réflexe que le PII scrubbing dans mes logs structurés. »* **Ce détail montre que le réflexe de confidentialité est automatique chez toi.**

---

## 4. Les fixtures bénins — la moitié qu'on oublie

**C'est ici que tu passes devant tout le monde.** Tout le monde teste que la règle attrape l'attaque. **Presque personne ne teste qu'elle n'attrape pas le reste.**

`tests/fixtures/benign/admin_activity.json` — de l'activité **réaliste** qui **ressemble** à l'attaque :

```json
{
  "description": "Activité administrative légitime — doit générer ZÉRO alerte",
  "events": [
    {
      "EventID": 1,
      "TimeCreated": "2026-07-20T09:12:03.000Z",
      "EventData": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\Inventory.ps1",
        "ParentImage": "C:\\Windows\\System32\\taskeng.exe",
        "User": "CORP\\svc_inventory",
        "_comment": "PowerShell + Bypass, mais PAS d'encodage → ne doit PAS matcher"
      }
    },
    {
      "EventID": 1,
      "TimeCreated": "2026-07-20T09:15:44.000Z",
      "EventData": {
        "Image": "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAA=",
        "ParentImage": "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
        "User": "NT AUTHORITY\\SYSTEM",
        "_comment": "PowerShell ENCODÉ — mais parent = agent de monitoring légitime. Doit être exclu par filter_legit. C'EST LE TEST QUI COMPTE."
      }
    },
    {
      "EventID": 10,
      "TimeCreated": "2026-07-20T09:20:10.000Z",
      "EventData": {
        "SourceImage": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1410",
        "_comment": "Defender scanne LSASS — comportement normal. Doit être exclu par filter_signed."
      }
    },
    {
      "EventID": 1,
      "TimeCreated": "2026-07-20T09:31:12.000Z",
      "EventData": {
        "Image": "C:\\Windows\\System32\\net.exe",
        "CommandLine": "net user /domain",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\jdupont",
        "_comment": "net user SANS /add → énumération, pas création. Ne doit pas matcher T1136.001."
      }
    }
  ]
}
```

> **⚡ Le deuxième événement est le plus important de tout ton repo.**
> C'est du **PowerShell encodé** — exactement ce que ta règle cherche — mais lancé par un agent de monitoring légitime. **Si ta règle le matche, elle est inutilisable en production**, parce que SCCM et l'agent de monitoring font ça toute la journée.
> **Ton `filter_legit` existe pour ce cas précis, et ce fixture le prouve.**
>
> **En entrevue :** *« Mon test de faux positif contient délibérément un cas qui ressemble à l'attaque. Une règle qui ne matche que le cas d'école est facile ; une règle qui distingue le PowerShell encodé de l'attaquant du PowerShell encodé de SCCM, c'est du travail d'ingénierie de détection. C'est ce fixture qui a justifié l'exclusion par ParentImage. »*

---

## 5. Le moteur de test — `tests/detection/`

### 5.1 L'évaluateur de règle Sigma

```python
# tests/detection/sigma_eval.py
"""Évaluateur Sigma minimal pour tests hors-ligne.
On n'a pas besoin d'un Elasticsearch en CI pour valider la logique d'une règle.
"""
from typing import Any


def _get(event: dict, field: str) -> Any:
    """Sysmon met les champs dans EventData. On aplatit."""
    if field in event:
        return event[field]
    return event.get("EventData", {}).get(field)


def _match_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    a = str(actual)
    exps = expected if isinstance(expected, list) else [expected]
    for e in exps:
        e = str(e)
        if modifier == "contains" and e.lower() in a.lower():
            return True
        if modifier == "endswith" and a.lower().endswith(e.lower()):
            return True
        if modifier == "startswith" and a.lower().startswith(e.lower()):
            return True
        if modifier is None and a.lower() == e.lower():
            return True
    return False


def _match_selection(event: dict, selection: Any) -> bool:
    # Une liste de dicts = OR entre les dicts
    if isinstance(selection, list):
        return any(_match_selection(event, s) for s in selection)
    # Un dict = AND entre les clés
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        modifier = modifier or None
        if not _match_value(_get(event, field), expected, modifier):
            return False
    return True


def evaluate_rule(rule: dict, event: dict) -> bool:
    """Évalue la condition Sigma. Gère les formes: 'A and B', 'A and not B', 'A or B'."""
    detection = rule["detection"]
    condition = detection["condition"].strip()

    results = {k: _match_selection(event, v)
               for k, v in detection.items() if k != "condition"}

    # Parseur de condition volontairement limité au sous-ensemble que j'utilise.
    expr = condition
    for name in sorted(results, key=len, reverse=True):
        expr = expr.replace(name, str(results[name]))
    expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")

    # Sécurisé : seuls True/False/and/or/not/parenthèses subsistent
    allowed = {"True", "False", "and", "or", "not", "(", ")"}
    tokens = expr.replace("(", " ( ").replace(")", " ) ").split()
    if not set(tokens).issubset(allowed):
        raise ValueError(f"Condition non supportée: {condition} → {expr}")
    return eval(expr)   # noqa: S307 — entrée validée par la whitelist ci-dessus
```

> **⚡ Sois prêt sur `eval`.** Quelqu'un le verra.
> *« Oui, il y a un `eval`. Il est dans le code de test, pas en production. Et l'entrée est validée par une whitelist stricte : après substitution, seuls `True`, `False`, `and`, `or`, `not` et les parenthèses peuvent subsister — tout le reste lève une exception avant d'atteindre `eval`. Le seul input est mon propre fichier de règle, versionné en Git et revu en PR. J'ai quand même mis un `# noqa` avec la justification pour que le prochain qui passe comprenne que ce n'est pas un oubli. En production, j'utiliserais le vrai backend pySigma contre un Elastic éphémère — j'ai fait ce choix pour garder la CI à 3 secondes sans service container. »*
> **Cette réponse-là — reconnaître un pattern dangereux, expliquer le contrôle compensatoire, ET donner l'alternative de production — est une réponse de senior.**
> **Défendre l'`eval` est plus impressionnant que de ne pas en avoir.** Ne le cache pas : **pointe-le toi-même.**

### 5.2 Les tests

```python
# tests/detection/test_rules.py
import json
from pathlib import Path

import pytest
import yaml

from tests.detection.sigma_eval import evaluate_rule

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
# TESTS DE VRAI POSITIF — la règle DOIT détecter l'attaque
# ─────────────────────────────────────────────────────────────
TRUE_POSITIVES = [
    ("powershell_encoded_command", "T1059.001_test1.json"),
    ("lsass_memory_access",        "T1003.001_test1.json"),
    ("registry_run_key_persistence", "T1547.001_test1.json"),
    ("local_account_creation",     "T1136.001_test1.json"),
    ("scheduled_task_creation",    "T1053.005_test2.json"),
    ("eventlog_clearing",          "T1070.001_test1.json"),
    ("ingress_tool_transfer",      "T1105_test1.json"),
]


@pytest.mark.parametrize("rule_name,fixture", TRUE_POSITIVES)
def test_true_positive(rule_name: str, fixture: str):
    """La règle doit se déclencher sur la télémétrie d'une attaque RÉELLE."""
    rule = load_rule(rule_name)
    events = load_events(ATTACK_FIXTURES / fixture)
    hits = [e for e in events if evaluate_rule(rule, e)]
    assert hits, (
        f"FAUX NÉGATIF — '{rule['title']}' n'a détecté aucun des {len(events)} "
        f"événements générés par {fixture}. La règle est aveugle à l'attaque "
        f"qu'elle prétend couvrir."
    )


# ─────────────────────────────────────────────────────────────
# TESTS DE FAUX POSITIF — la règle NE DOIT PAS se déclencher
# ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("rule_name,_", TRUE_POSITIVES)
def test_no_false_positive_on_admin_activity(rule_name: str, _):
    """Aucune règle ne doit se déclencher sur de l'activité admin légitime."""
    rule = load_rule(rule_name)
    events = load_events(BENIGN_FIXTURES / "admin_activity.json")
    hits = [e for e in events if evaluate_rule(rule, e)]
    assert not hits, (
        f"FAUX POSITIF — '{rule['title']}' s'est déclenchée sur de l'activité "
        f"légitime : {[h.get('EventData', {}).get('CommandLine') for h in hits]}. "
        f"Une règle bruyante finit désactivée : elle ne protège personne."
    )


# ─────────────────────────────────────────────────────────────
# TESTS DE QUALITÉ DES RÈGLES — la gouvernance
# ─────────────────────────────────────────────────────────────
ALL_RULES = list(DETECTIONS.rglob("*.yml"))


@pytest.mark.parametrize("path", ALL_RULES, ids=lambda p: p.stem)
def test_rule_has_required_metadata(path: Path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    for field in ("title", "id", "description", "author", "date",
                  "tags", "logsource", "detection", "falsepositives", "level"):
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
    assert rule.get("response_playbook"), \
        f"{path.name}: aucun response_playbook — détection sans réaction"


def test_no_duplicate_rule_ids():
    ids = [yaml.safe_load(p.read_text())["id"] for p in ALL_RULES]
    assert len(ids) == len(set(ids)), "UUID de règle dupliqué"
```

> **Les tests de gouvernance (`test_rule_has_required_metadata`, `test_rule_declares_response_playbook`) sont les plus révélateurs.**
> *« Ce ne sont pas des tests de fonctionnement. Ce sont des tests de **gouvernance** : ils encodent mes standards de qualité dans le pipeline plutôt que dans un document que personne ne lit. Si un collègue soumet une règle sans `falsepositives`, la CI la refuse — pas moi en revue de code, à qui il faudrait le rappeler à chaque fois. **Automatiser la revue de standards, c'est ce qui permet à une équipe de détection de tenir à l'échelle.** »*
> ⚡ **Cette réponse te fait passer de « celui qui code » à « celui qui pense l'équipe ». Pour un poste d'intégration DevOps dans un SOC, c'est exactement le profil recherché.**

### 5.3 Lancer

```bash
pytest tests/detection/ -v
```
Sortie attendue :
```
tests/detection/test_rules.py::test_true_positive[powershell_encoded_command-T1059.001_test1.json] PASSED
tests/detection/test_rules.py::test_true_positive[lsass_memory_access-T1003.001_test1.json] PASSED
...
tests/detection/test_rules.py::test_no_false_positive_on_admin_activity[powershell_encoded_command-...] PASSED
...
tests/detection/test_rules.py::test_rule_declares_response_playbook[lsass_memory_access] PASSED

======================== 29 passed in 0.42s ========================
```

> **Fais un screenshot de cette sortie. Mets-le dans le README.** Ces 0,42 seconde valent plus que 15 règles non testées.

---

## 6. Le test de bout en bout — la validation réelle

Les tests CI valident la **logique** des règles. Ils ne valident pas que **la chaîne complète fonctionne**. Ça, c'est J5 après-midi, en vrai, sur le labo.

### 6.1 Le protocole

`docs/e2e-validation.md` — documente chaque exécution, avec des chiffres.

```markdown
# Validation de bout en bout — 20 juillet 2026

## Environnement
- soc-lab : Ubuntu 22.04, Wazuh 4.9.0, k3s v1.30, soc-autopilot v0.3.0
- victim-win : Windows 11 Enterprise Eval, Sysmon 15.15 (config SwiftOnSecurity)
- Mode : DRY_RUN=false (armé), snapshot restauré avant chaque test

## Protocole (identique pour chaque technique)
1. Restaurer le snapshot "03-victim-prete"
2. `date +%s%3N` → T0
3. Exécuter l'atomic
4. Chronométrer : T1 = alerte visible dans Wazuh, T2 = cas TheHive créé,
   T3 = notification Slack
5. Vérifier l'audit trail : `GET /executions/{id}`
6. Restaurer le snapshot
```

### 6.2 Le scénario complet — la chaîne d'attaque

**Ne teste pas 7 techniques isolées. Teste UNE intrusion.** C'est ce qu'un défenseur voit vraiment.

```powershell
# ═══ SCÉNARIO : intrusion complète sur victim-win ═══
# ⚠️ Snapshot AVANT. VM isolée. Aucune de ces commandes hors du labo.

# ── Étape 1 — EXÉCUTION (T1059.001) ─────────────────────────
# L'attaquant obtient l'exécution via une macro. Il lance du PowerShell encodé.
Invoke-AtomicTest T1059.001 -TestNumbers 1
#   → Sysmon EID 1 → règle 100xxx → PB-0001
#   → décodage, extraction IOC, enrichissement gov, cas TheHive, score 8/10
#   → score < 9 → PAS d'approbation demandée, PAS d'isolation
#   ✅ La graduation fonctionne : on n'isole pas pour du PowerShell seul

Start-Sleep 30

# ── Étape 2 — PERSISTANCE (T1547.001) ───────────────────────
# Il s'installe pour survivre au reboot.
Invoke-AtomicTest T1547.001 -TestNumbers 1
#   → Sysmon EID 13 → PB-0003
#   → cas + tâche d'investigation, PAS d'isolation (persistance ≠ urgence)
#   ✅ Réponse graduée, encore

Start-Sleep 30

# ── Étape 3 — DÉCOUVERTE (T1087.001) ────────────────────────
Invoke-AtomicTest T1087.001 -TestNumbers 1
#   → énumération de comptes — pas de règle dédiée
#   ⚠️ GAP CONNU, documenté dans telemetry-gap-analysis.md
#   ✅ Je montre mon angle mort au lieu de le cacher — c'est le point le plus fort

Start-Sleep 30

# ── Étape 4 — ACCÈS AUX CREDENTIALS (T1003.001) ─────────────
# Il dump LSASS. LE moment critique.
Invoke-AtomicTest T1003.001 -TestNumbers 1
#   → Sysmon EID 10, GrantedAccess 0x1410 → règle CRITICAL → PB-0002
#   → PAS d'approbation : isolation IMMÉDIATE
#   → wazuh.isolate_host → firewall-drop sur victim-win
#   ✅ victim-win perd le réseau — VÉRIFIE-LE : ping depuis soc-lab échoue

# ── Vérification du containment ─────────────────────────────
# Depuis soc-lab :
#   ping 192.168.56.20        → timeout ✅
# Depuis victim-win (console VM) :
#   Test-NetConnection 8.8.8.8 → échec ✅

# ── Étape 5 — LE ROLLBACK ───────────────────────────────────
# curl -XPOST http://soc-autopilot:8000/executions/{id}/rollback
#   → wazuh.unisolate_host → le réseau revient
#   → audit trail : rolled_back = true
#   ✅ ping repasse

# ── Cleanup ─────────────────────────────────────────────────
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
# Puis : restaurer le snapshot
```

> **⚡ L'étape 3 est ton meilleur moment.**
> Tu introduis volontairement une technique que tu **ne détectes pas**, et tu le dis :
> *« Ici, T1087.001, découverte de comptes. Je ne la détecte pas. C'est un angle mort connu, il est dans mon analyse de lacunes avec sa remédiation — activer le script block logging PowerShell — et sa priorité. J'aurais pu l'exclure de ma démo pour que tout soit vert. Je l'ai gardée parce qu'un SOC qui ne montre que ses succès ne s'améliore jamais, et parce qu'une matrice ATT&CK toute verte est toujours un mensonge. »*
>
> **Un candidat qui montre son trou volontairement est un candidat qui a compris que la détection est un travail infini de réduction de l'angle mort, pas une case à cocher.** C'est la phrase que l'intervieweur retiendra de toi.

### 6.3 Les mesures — les chiffres de ton CV

**Chronomètre pour de vrai.** Remplis ce tableau avec **tes** valeurs :

```markdown
## Résultats mesurés — 20 juillet 2026 (5 itérations par technique)

| Technique | Attaque→Alerte Wazuh | Alerte→Cas TheHive | Total attaque→cas | Actions auto |
|---|---|---|---|---|
| T1059.001 | 4,2 s | 3,1 s | **7,3 s** | decode, IOC, intel, cas, notif |
| T1003.001 | 3,8 s | 2,4 s | **6,2 s** | cas, isolate, notif |
| T1547.001 | 5,1 s | 2,9 s | **8,0 s** | cas, tâche, notif |
| T1136.001 | 4,5 s | 2,7 s | **7,2 s** | cas, notif |

## Comparaison manuel vs automatisé (chronométré, moyenne de 3 essais manuels)

| Tâche | Manuel | Auto | Facteur |
|---|---|---|---|
| Triage complet d'une alerte PowerShell | 11 min 40 s | 7,3 s | **×96** |
| Enrichissement (5 IOC × 2 sources) | 6 min 20 s | 1,8 s | ×211 |
| Création de cas avec observables | 3 min 10 s | 2,4 s | ×79 |
| Décision de containment | 14 min | 92 s (dont 85 s d'attente humaine) | ×9 |
| Déploiement d'une règle (manuel vs pipeline) | ~28 min, non versionné | 2 min 40 s, testé, réversible | ×10 + traçabilité |

## Méthode de mesure
- **Manuel** : chronomètre, moi-même, avec les mêmes outils (Wazuh UI, VT web,
  TheHive UI), 3 essais, médiane retenue. Je connaissais déjà les alertes —
  **un vrai analyste serait donc plus lent, mes chiffres manuels sont optimistes.**
- **Auto** : `execution.duration_seconds` de l'audit trail, 5 itérations, médiane.
- **Limite honnête** : labo mono-utilisateur, pas de charge concurrente. À 300
  alertes/jour réelles, les temps augmenteraient (contention DB, rate limits API).
```

> **⚡ « Mes chiffres manuels sont optimistes » est la ligne la plus intelligente de tout ton document.**
> Tu affaiblis volontairement ton propre argument — et c'est **exactement** ce qui le rend crédible. Un candidat qui annonce « ×96 » sans nuance se fait démolir. Un candidat qui dit « ×96, et voici pourquoi ma mesure est biaisée en ma faveur » est **cru sur parole**.
> Si on te dit « ×96, ça semble énorme » → *« C'est un labo, oui. Le facteur réel serait plus bas — il y a de la contention, des rate limits, des cas ambigus qui exigent un humain de toute façon. Ce que je retiens, ce n'est pas le facteur, c'est que les 12 minutes étaient **déterministes** : aucune décision, juste du copier-coller. Tout ce qui est déterministe est automatisable. C'est ça, l'argument. »*

### 6.4 Le test de robustesse — ce que personne ne fait

```bash
# ── Test 1 : idempotence ─────────────────────────────────────
# Envoie 5 fois la même alerte
for i in {1..5}; do
  curl -s -X POST http://192.168.56.10:8000/webhook/wazuh \
    -H "X-Signature: $SIG" -H "Content-Type: application/json" \
    -d @tests/fixtures/alerts/powershell_alert.json
done
# ✅ Attendu : 1 exécution + 4 "deduplicated", 1 SEUL cas TheHive

# ── Test 2 : signature invalide ──────────────────────────────
curl -s -X POST http://192.168.56.10:8000/webhook/wazuh \
  -H "X-Signature: deadbeef" -d @tests/fixtures/alerts/powershell_alert.json
# ✅ Attendu : 401, rien exécuté, warning "webhook_bad_signature" dans les logs

# ── Test 3 : threat intel (mon service) indisponible ─────────
# Mets THREAT_INTEL_URL sur un port mort
# ✅ Attendu : timeout 5 s → on_error:continue → LE CAS EST QUAND MÊME CRÉÉ
#    status = "partial", step "intel" = failed dans l'audit trail

# ── Test 3 bis : VirusTotal rate-limité (429) ────────────────
# Épuise le quota (ou pointe VIRUSTOTAL_API_KEY sur une clé invalide),
# puis envoie une alerte avec plusieurs IOC
# ✅ Attendu : step "vt" = success MAIS worst_verdict = "unknown",
#    reason "rate_limited" par IOC → LE CAS EST QUAND MÊME CRÉÉ,
#    juste avec moins de contexte de réputation. AUCUN crash.
#    → C'est EXACTEMENT ce que le on_error:continue + la gestion du 429 garantissent.

# ── Test 3 ter : cache VirusTotal ────────────────────────────
# Envoie 2 fois la même alerte (même hash)
# ✅ Attendu : au 2e passage, le résultat VT porte "cached": true
#    → 0 requête API consommée, quota préservé

# ── Test 4 : actif protégé ───────────────────────────────────
# Alerte critique sur un agent nommé "DC-01" (dans protected_assets)
# ✅ Attendu : cas créé, MAIS step isolate = skipped, reason "protected_asset"

# ── Test 5 : timeout d'approbation ───────────────────────────
# Alerte score 9 → approbation demandée → NE RÉPONDS PAS
# ✅ Attendu : après 900 s (mets 30 s pour tester), approved=false,
#    reason "timeout_denied", AUCUNE isolation

# ── Test 6 : rollback ────────────────────────────────────────
# Isole puis POST /executions/{id}/rollback
# ✅ Attendu : unisolate exécuté, rolled_back=true, ping repasse
```

> **⚡ Les tests 3, 3bis, 4 et 5 sont les plus importants.**
> Ils ne testent pas que ça marche. Ils testent que **ça échoue bien**.
> *« La plupart des tests vérifient le chemin nominal. Les miens vérifient les chemins dégradés, parce qu'en production le chemin nominal est celui qui pose le moins de problèmes. Ce qui casse un SOC à 3 h du matin, c'est la dépendance externe qui timeout ou qui rate-limit, l'actif qu'on n'aurait pas dû toucher, et l'approbation que personne n'a vue. Mon enrichissement VirusTotal est en best-effort : quota épuisé, le cas se crée quand même. »*

---

## 7. Checklist J5

- [ ] `capture_atomic.ps1` exécuté pour les 7 techniques
- [ ] Fixtures rapatriés dans `tests/fixtures/attack/`
- [ ] `sanitize_fixtures.py` passé — **aucun SID/nom de machine réel commité**
- [ ] `tests/fixtures/benign/admin_activity.json` écrit, **avec le cas piège** (PowerShell encodé légitime)
- [ ] `pytest tests/detection/` → **tout vert**
- [ ] Au moins **une règle a échoué au premier essai et a été corrigée** — note-le, c'est une histoire à raconter
- [ ] Scénario d'intrusion complet exécuté sur le labo
- [ ] Isolation vérifiée **par ping** (pas juste par log)
- [ ] Rollback vérifié
- [ ] 6 tests de robustesse passés
- [ ] `docs/e2e-validation.md` rempli avec **tes** chiffres, méthode incluse
- [ ] Screenshot du `pytest` vert → README
- [ ] Snapshot restauré, VM propre

---

## 8. Si une règle échoue au test

**C'est une bonne nouvelle. C'est même la meilleure de la semaine.**

Le processus :
1. Regarde le fixture : quel événement **aurait dû** matcher ?
2. Regarde la règle : quel champ ne correspond pas ?
3. Corrige. Relance. Vert.
4. **Écris-le dans le README.**

**Exemple à mettre dans `docs/lessons-learned.md` :**
```markdown
## T1003.001 — la règle a d'abord échoué

Ma règle initiale cherchait `GrantedAccess: '0x1010'` en égalité stricte.
Le test de vrai positif a échoué : Atomic Red Team via procdump génère `0x1fffff`
(PROCESS_ALL_ACCESS), pas `0x1010`.

**Ce que j'avais fait :** copié une valeur d'un article de blog sans vérifier
contre la télémétrie réelle.
**Correction :** passage à `GrantedAccess|contains` avec la liste des masques
observés, et vérification que chaque masque inclut bien PROCESS_VM_READ.
**La leçon :** sans le test, cette règle serait partie en production, aurait été
verte sur ma carte ATT&CK, et n'aurait jamais détecté un dump de LSASS.
**C'est exactement le faux négatif silencieux que ces tests existent pour attraper.**
```

> **⚡ Cette histoire vaut plus que ton repo entier.**
> Le 23 juillet, quand on te demandera « raconte-moi un problème que tu as rencontré », **c'est celle-là que tu racontes.** Elle prouve :
> - que tu as vraiment fait le travail (personne n'invente ce niveau de détail),
> - que ta méthode a **attrapé une vraie erreur à toi**,
> - que tu comprends **pourquoi** le test existe, pas juste qu'il faut en avoir,
> - et que tu es capable de dire « j'avais copié sans vérifier » sans te justifier.
>
> **Prépare-la. Répète-la. C'est ton anecdote signature.**
