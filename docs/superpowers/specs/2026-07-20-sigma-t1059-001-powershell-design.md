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
  t1059.001_powershell_encoded_command.yml              # angle « processus » (Sysmon EID 1) — cf. §10
  t1059.001_powershell_download_cradle_scriptblock.yml  # angle « contenu »  (PowerShell EID 4104)
detections/pipelines/
  wazuh-windows.yml                                     # pipeline de mapping Sigma→Wazuh (réutilisable)
```

> Note : l'angle « processus » a été **re-scopé** du download cradle vers la **commande
> encodée** après examen de la télémétrie réelle (voir §10). Le fichier
> `t1059.001_powershell_download_cradle_cmdline.yml` a été supprimé.

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

## 9. Validation finale (résultat)

Deux découvertes à la re-détonation :
- **Les tests atomiques T1059.001 ne produisent pas de download cradle inline** : Atomic Red
  Team télécharge ses scripts comme **fichiers** (au `-GetPrereqs`) puis les exécute
  localement. Aucun `IEX/DownloadString` inline dans les logs frais. Le seul cradle réel de
  tout l'index est la **commande d'installation d'ART** de la session initiale.
- **Les règles initiales rataient ce cradle** : elles cherchaient `IEX(` (collé) alors que le
  cradle écrit `IEX (` (espace), et `Invoke-WebRequest` alors que le cradle utilise l'alias
  `IWR`. C'est le tuning que seule une validation sur données réelles révèle.

**Tuning appliqué :** les deux règles sont restructurées en **`selection_exec` ET
`selection_download`** — un alias d'exécution (`IEX`, `Invoke-Expression`) ET un mécanisme de
téléchargement (`IWR`, `Invoke-WebRequest`, `DownloadString`, `DownloadFile`, `Net.WebClient`)
dans le même événement. Plus robuste aux alias, et plus faible en faux positifs (exige les deux).

**Preuve :** après réindex des données existantes sous le mapping corrigé, la règle B matche le
cradle réel (1 hit, EID 4104). La règle A rend 0 sur ces données (le cradle était in-process
dans l'ISE, pas un processus enfant) — attendu, et illustration de la complémentarité des deux
angles.

**Test d'intégration reproductible** (`tests/integration/test_t1059_detonation_match.py`) :
plutôt que dépendre d'une détonation live, il crée un index jetable au mapping corrigé, y
indexe des **fixtures de cradle réels** (> 256 car., ce qui exerce aussi le fix `ignore_above`),
convertit chaque règle et vérifie le match. Les **deux** règles sont ainsi validées de bout en
bout, en CI, sans VM.

## 10. Re-scope piloté par la menace (détection = comportement réellement observé)

Principe appliqué : **une règle doit correspondre à un comportement que l'attaque testée produit
réellement**, jamais à de la télémétrie fabriquée pour la faire matcher.

Examen de la télémétrie **processus (EID 1)** de la détonation : aucun download cradle en ligne
de commande. Le vrai comportement au niveau processus est la **commande encodée** —
`powershell.exe -e / -E / -EncodedArguments / -EA <base64>` — abondante et classique (obfuscation,
T1059.001 + defense evasion). La règle A initiale (cradle en ligne de commande) détectait donc un
comportement **absent de la menace**.

**Décision — règle A re-scopée** vers `t1059.001_powershell_encoded_command.yml` : détecte
`powershell.exe` (ou `OriginalFileName`) + un flag de commande encodée (`-e`, `-E`, `-enc`, `-Enc`,
`-ea`, `-EA`, en formes explicites car le backend keyword est sensible à la casse et
`query_string` ne supporte pas `case_insensitive`). **Validée sur 4 événements réels** de la
détonation (réindexés sous mapping corrigé) — dont Wazuh lui-même décrit « executed a base64
encoded command ». Zéro télémétrie fabriquée.

**Décision — règle B conservée** : le download cradle ScriptBlock a matché un **vrai** cradle (la
commande d'installation d'ART), qui est du T1059.001 authentique et validé sur donnée réelle.
Download-and-execute cradle est une procédure documentée, complémentaire de la commande encodée.
Piste future : élargir la couverture 4104 au contenu réellement logué par les tests (shellcode,
Mimikatz) et généraliser la casse via un `normalizer` lowercase à l'indexation.
