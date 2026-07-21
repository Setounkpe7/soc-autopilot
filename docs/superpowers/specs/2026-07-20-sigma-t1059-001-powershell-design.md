# Design — Détection T1059.001 (PowerShell) en detection-as-code sur Wazuh

- **Date :** 2026-07-20
- **Statut :** validé (brainstorming)
- **Auteur :** Michel-Ange Doubogan
- **Contexte :** premier lot de règles Sigma du projet soc-autopilot, validé de bout en bout
  contre les vraies alertes de la détonation Atomic Red Team T1059.001 déjà présentes dans
  `wazuh-alerts-*` (agent `victim-win`, canaux Sysmon EID 1/11 + PowerShell EID 4104).

## 1. Objectif

Détecter la technique **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)**
sous deux angles complémentaires, et **prouver** que les règles matchent une détonation réelle —
pas seulement qu'elles « compilent ». On démontre ainsi la boucle detection-as-code complète :
règle Sigma → conversion outillée → requête → validation sur données réelles.

## 2. Artefacts produits

```
detections/windows/
  t1059.001_powershell_download_cradle_cmdline.yml      # angle « processus » (Sysmon EID 1)
  t1059.001_powershell_download_cradle_scriptblock.yml  # angle « contenu »  (PowerShell EID 4104)
detections/pipelines/
  wazuh-windows.yml                                     # pipeline de mapping Sigma→Wazuh (réutilisable)
```

## 3. Les deux règles — logique de détection

Cible commune : le **download cradle** (télécharger-et-exécuter en mémoire), motif malveillant
classique de T1059.001, tel que détoné par Atomic Red Team.

### Règle A — process_creation (Sysmon EID 1)
- **Sélection processus** : `Image|endswith: \powershell.exe` **OU** `OriginalFileName: PowerShell.EXE`
  (le `OriginalFileName` résiste au renommage du binaire).
- **Sélection cradle** : `CommandLine|contains` l'un de : `IEX`, `Invoke-Expression`,
  `DownloadString`, `Invoke-WebRequest`, `IWR`.
- **Condition** : `selection_process AND selection_cradle`.
- **Angle** : voit le *processus* et sa ligne de commande. Aveugle si le code est passé en
  `-EncodedCommand` (d'où la règle B).

### Règle B — ps_script / ScriptBlock (PowerShell EID 4104)
- **Sélection** : `ScriptBlockText|contains` l'un de : `IEX(`, `Invoke-Expression`,
  `DownloadString`, `Invoke-WebRequest`, `Net.WebClient`.
- **Angle** : voit le *contenu* du script, **même lancé en `-EncodedCommand`** (le ScriptBlock
  logging journalise le code désobfusqué). Complémentaire de A.

### Posture faux-positifs
On exige toujours un **indicateur de téléchargement**, jamais « `IEX` seul » (trop courant en
administration légitime). Curseur bruit/couverture assumé et documenté dans le champ
`falsepositives` de chaque règle.

### Métadonnées
Chaque règle porte : `id` (UUID), `status: experimental`, `description`, `references` (lien
ATT&CK), `author`, `date`, `level: high`, et surtout les **tags** `attack.execution` +
`attack.t1059.001`. Ce tagging MITRE **comble le trou constaté** : les règles Wazuh par défaut
qui ont capté la détonation n'étaient pas taguées ATT&CK, faussant toute vue de couverture.

## 4. Pipeline de mapping Sigma→Wazuh (cœur technique)

Le pipeline `sysmon` standard de sigma-cli mappe vers les noms Sysmon/ECS, **pas** vers le schéma
JSON décodé de Wazuh. Sans mapping maison, la requête convertie ne matche rien dans `wazuh-alerts-*`.

On écrit un pipeline pySigma `detections/pipelines/wazuh-windows.yml` qui, à la conversion :

**Remappe les champs** (noms confirmés sur échantillons réels le 2026-07-20) :

| Champ Sigma        | Champ Wazuh                          |
|--------------------|--------------------------------------|
| `Image`            | `data.win.eventdata.image`           |
| `CommandLine`      | `data.win.eventdata.commandLine`     |
| `OriginalFileName` | `data.win.eventdata.originalFileName`|
| `ScriptBlockText`  | `data.win.eventdata.scriptBlockText` |

**Ajoute la condition de canal** selon le `logsource` de la règle :
- `category: process_creation` → `data.win.system.channel: Microsoft-Windows-Sysmon/Operational`
  et `data.win.system.eventID: "1"`.
- `category: ps_script` → `data.win.system.channel:
  Microsoft-Windows-PowerShell/Operational` et `data.win.system.eventID: "4104"`.

Réutilisable pour **toutes** les futures règles Windows du projet. C'est l'artefact qui rend la
detection-as-code viable sur Wazuh.

## 5. Validation (la preuve)

```
sigma convert -t opensearch_lucene -p detections/pipelines/wazuh-windows.yml <règle>.yml
```

→ requête Lucene → **rejouée sur `wazuh-alerts-*`** (via `_search`) → doit retourner les documents
de la détonation (fenêtre ~2026-07-21T02:13Z).

**Point de contrôle connu :** si la requête renvoie 0 alors que la donnée existe, c'est le piège
de mapping `keyword`/casse/wildcard (déjà rencontré : `rule.description` est `keyword`, donc
sensible à la casse et non tokenisé). On ajuste alors le pipeline (champ analysé, gestion de
casse, ou `contains` adapté). Traiter ce piège **fait partie** de la démonstration.

## 6. Définition de « fait »

Une règle est terminée quand :
1. `sigma check` la valide (YAML + schéma Sigma conformes) ;
2. la conversion via le pipeline produit une requête OpenSearch ;
3. la requête **matche ≥ 1 document réel** de la détonation ;
4. contrôle rapide : elle ne matche pas une activité PowerShell bénigne triviale.

## 7. Hors périmètre (YAGNI pour ce lot)

- Pipeline CI (lint/test des règles en pre-commit/CI) → lot suivant.
- Intégration au moteur SOAR (`soc_autopilot/engine`) et création de cas → lot suivant.
- Autres techniques ATT&CK → une fois la boucle prouvée sur T1059.001.

## 8. Résolution du point de contrôle (root cause réel + fix appliqué)

À l'exécution, la validation a renvoyé **0 hit**. Le diagnostic systématique a écarté
l'hypothèse du plan (casse) : le vrai problème est le **data-model de l'indexeur**. Le
template Wazuh par défaut mappe `data.win.eventdata.commandLine` et `scriptBlockText` en
`keyword` avec **`ignore_above` (~256)** via dynamic template. Toute valeur > 256 caractères
— donc la quasi-totalité des lignes de commande et scriptblocks PowerShell malveillants
(nos cradles font 341 à 6074 car.) — est stockée dans `_source` mais **non indexée**, donc
invisible en `contains`/wildcard. Preuves : wildcard sur `image` (court) matche (32 hits),
sur `commandLine`/`scriptBlockText` (longs) = 0 ; `doc['scriptBlockText'].size()` = 0 sur
tous les événements 4104.

Enseignement : Wazuh détecte le **contenu** au **manager (analysisd)** à l'ingestion (la
règle Wazuh 91837 a tiré là) ; l'indexeur sert au hunting, et son mapping par défaut ampute
les champs longs.

**Fix appliqué (sans toucher aux règles ni au pipeline) :** un template legacy de surcharge
`infra/wazuh/templates/wazuh-eventdata-override.json` (`order: 10` > 0) qui mappe ces deux
champs en `keyword, ignore_above: 32766`, rendant le contenu cherchable comme le champ
`image`. Mécanisme prouvé sur index test (0 → 1 hit). Il s'applique aux **nouveaux** index
quotidiens ; les données déjà ingérées restent sous l'ancien mapping. La boucle se validera
donc sur des **données fraîches** (re-détonation en session VM), pas sur l'historique.

Limite connue : `ignore_above: 32766` couvre jusqu'à ~32 Ko (limite de terme Lucene) ; un
scriptblock plus volumineux exigerait un sous-champ `text` (au prix de la tokenisation des
tirets, qui casse les wildcards de phrases comme `*Invoke-Expression*`).
