# Analyse de lacunes de détection (télémétrie & couverture)

> Principe : **une matrice ATT&CK toute verte est un mensonge.** Ce document liste
> ce qu'on détecte, ce qu'on ne détecte pas, et la remédiation — dérivé de l'état
> réel du repo, pas d'une intention. La couverture machine est **générée depuis les
> tags ATT&CK des règles** par `tools/sigma_to_dettect.py` → `docs/coverage/`
> (couche ATT&CK Navigator + fichier DeTT&CT). La CI **échoue si la carte est
> périmée** (`git diff` sur `docs/coverage/`) : la couverture est un produit du code,
> jamais un PowerPoint qui datait déjà le jour de la présentation.

## Couverture actuelle (règles réellement présentes dans `detections/`)

| Technique | Règle | Source Sysmon | Statut | Validation |
|---|---|---|---|---|
| T1059.001 (PowerShell encodé) | `t1059.001_powershell_encoded_command` | EID 1 | ✅ actif | Vrai+faux positif **verts** (télémétrie réelle) |
| T1059.001 (download cradle) | `t1059.001_powershell_download_cradle_scriptblock` | EID 4104 | ✅ actif | Vrai+faux positif **verts** (télémétrie réelle) |
| T1003.001 (LSASS) | `t1003.001_lsass_memory_access` | EID 10 | ⚠️ experimental | Faux positif vert ; **vrai positif en attente de détonation réelle** |

## Lacunes connues (assumées, priorisées)

| Technique | Impact | Remédiation | Priorité |
|---|---|---|---|
| **T1003.001** — masque `GrantedAccess` non confirmé sur l'index | Faux négatif possible sur LSASS | Détonation `T1003.001` sur victim-win → capturer le fixture → valider/corriger le masque | **Haute** |
| **T1087.001** — découverte de comptes | Angle mort (aucune règle) | Règle sur `net user`/`net group` + LDAP ; script block logging | Moyenne |
| **T1547.001 / T1136.001 / T1053.005 / T1070.001 / T1105** | Angles morts (règles prévues mais non écrites) | Écrire la règle + capturer le fixture d'attaque + tester (vrai/faux positif) | Moyenne |
| **Script block logging PowerShell** — déjà activé (EID 4104 ingéré) | — | Fait ✅ — complète T1059.001 / T1027 | — |

## Méthode

- La colonne « ce que je détecte » est **dérivée des tags ATT&CK des règles Sigma**,
  jamais saisie à la main → la carte ne périme pas, elle se régénère à chaque commit.
- La colonne « ce que je vois » (sources collectées, qualité, rétention) est à croiser
  via DeTT&CT une fois les sources documentées.
- Toute règle sans `response_playbook` est refusée par la CI (`tests/detection/`), donc
  une détection sans réaction ne peut pas entrer.

## Sources collectées (état labo)

| Source | EID | Qualité | Note |
|---|---|---|---|
| Sysmon Process Creation | 1 | Élevée | ligne de cmd + parent + hash → base de T1059.001 |
| Sysmon ProcessAccess | 10 | Élevée | accès LSASS → base de T1003.001 |
| PowerShell Operational | 4104 | Élevée | script block logging **activé** → cradle T1059.001 |
| Sysmon Registry | 13 | Moyenne | filtré agressivement (config SwiftOnSecurity) |
| Sysmon CreateRemoteThread | 8 | **Absente** | **GAP** — T1055 (injection) invisible |
| DNS Client | 3006 | **Absente** | **GAP** — T1071.004 / T1568 invisibles |

## Ce que je NE couvre pas — et pourquoi (assumé)

J'ai priorisé le **chemin critique d'une intrusion** (Execution → Persistence →
Credential Access) plutôt qu'une couverture large et superficielle. Concrètement,
tactiques absentes aujourd'hui : Reconnaissance, Resource Development, Discovery
(T1087), Lateral Movement, Impact. Les règles T1547/T1136/T1053/T1070/T1105 sont
prévues (fichier 03 §4.2) mais **non écrites** : chacune exige sa règle + son fixture
d'attaque capturé + ses tests vrai/faux positif avant d'entrer. La largeur est dans la
roadmap ; je préfère peu de détections **prouvées** à beaucoup de vert non testé.
