# Spec d'exécution — Moteur SOAR (J2) + Intégrations (J3)

Date : 2026-07-21
Branche : `feat/soar-engine`
Source de design (code + rationale) : [`docs/03_Construction_Jour_par_Jour.md`](../../03_Construction_Jour_par_Jour.md) — **fait foi** pour le détail du code.
Ce document ne redéfinit pas le code ; il fige les **décisions d'exécution** prises le 21/07.

## 1. Contexte et constat

Le repo `main` ne contient à ce jour que la **détection-as-code** (J4 : 2 règles Sigma T1059.001,
pipeline Wazuh, 6 tests). Le **moteur SOAR (J2)** et les **intégrations (J3)** décrits dans le fichier 03
**n'existent pas** : `soc_autopilot/` n'est qu'un squelette de `__init__.py` vides. Or le pitch d'entrevue
([`docs/05_Prep_Entrevue_23_juillet.md`](../../05_Prep_Entrevue_23_juillet.md)) dépend à ~80 % de ce moteur
(Q1, Q2, Q7, Q8, Q9, Q10).

## 2. Objectif

Accomplir **tout ce qui était prévu**, adapté aux contraintes machine (« Voie B » : ~11,6 Go RAM,
Wazuh/Postgres en Docker sur l'hôte, pas de VM et VS Code simultanés). Ordre : **J2 → J3**, puis la suite
(CI, K8s/Terraform adaptés à l'hôte, jusqu'aux **tests d'attaque & validation** J5, incluant la règle LSASS
et la carte ATT&CK). Rien n'est abandonné ; le pitch devient vrai **par construction**.

Ce spec couvre le **premier bloc : J2 + J3**.

## 3. Séquence ordonnée par ROI-pitch (chaque étape finit sur un repo vert)

| # | Livrable | Rend vrai | Checkpoint vert | DB ? |
|---|---|---|---|---|
| 0 | venv + deps + `requirements.txt` + `soc_autopilot/config.py` (`dry_run=True`) | Q1 (défaut sûr) | `pytest` collecte, app importe | non |
| 1 | `engine/resolver.py` (SandboxedEnvironment) + `engine/schema.py` + `engine/registry.py` | **Q10** (RCE), `valid_mitre` | `test_sandbox_blocks_rce` + `test_missing_variable_raises` verts | non |
| 2 | `engine/executor.py` + `models/audit.py` + `dedup_key` | **Q8** (idempotence), dry-run, rollback | `test_executor.py` (dedup stable) vert | injectable |
| 3 | `api/routes/webhook.py` (HMAC) + `api/main.py` + `engine/loader.py` | **Q7** (`compare_digest`), fail-fast | `curl` signé → exécution en base | oui |
| 4 | 1er playbook `playbooks/PB-0001-*.yml` bout-en-bout | **Q9** (moteur/contenu) | webhook → dry-run → audit trail | oui |
| 5 | `.semgrep/no-unsafe-jinja.yml` + `.github/workflows/` (CI détection **+ engine**) | Q10 défense-en-profondeur | CI verte sur la PR | — |
| 6 | J3 : `actions/wazuh.py`, `actions/threatintel.py` (VT), `actions/thehive.py` + playbook complet | **Q2, Q4bis** (VT hash-only) | actions enregistrées, playbook complet | oui |

**Ligne de coupe « minimum vert défendable » = après #4** : Q1/Q7/Q8/Q9/Q10 démontrables.
#5–#6 rapprochent du pitch complet.

## 4. Gouvernance (CLAUDE.md — impérative)

- Jamais de push direct sur `main`. Tout via branche → PR → revue `code-review` + scan `semgrep` → merge squash quand vert.
- Découpage : **PR-A = moteur J2 (#0–#5)**, **PR-B = intégrations J3 (#6)**. Ajustable en 1 PR si le temps l'exige.
- Hooks pre-commit (ruff, detect-secrets…) verts avant chaque commit.

## 5. Garde-fous d'honnêteté (non négociables)

- `dry_run=True` par défaut : actions destructives **journalisées, pas exécutées**. On ne fabrique jamais une
  isolation réelle ni un appel VirusTotal live « pour faire joli ».
- VirusTotal : **par hash/IP/domaine uniquement, jamais d'upload de fichier** (structurel, aucun chemin d'upload).
- IP privées filtrées avant tout envoi à un tiers (confidentialité de la topologie).
- La détection reste **pilotée par la menace** (règles adossées à la télémétrie réelle).

## 6. Contraintes d'environnement (Voie B)

- Pas de `.venv` aujourd'hui → étape 0 le crée (deps du fichier 03 §2.1).
- Postgres prêt dans `infra/soc-stack/docker-compose.yml` (DB `soc_autopilot`) pour l'audit trail.
- Les tests à plus haut ROI (sandbox RCE, dedup) sont des **fonctions pures sans DB** → testables sans infra.
- `sigma` CLI présent (tests de détection inchangés).

## 7. Explicitement reporté (blocs suivants, pas ce spec)

J6 (k3s, Terraform, Helm, Cosign), carte ATT&CK dérivée du code, règle LSASS / T1003.001 + son fixture,
tests d'attaque & validation (fichier 04 / J5). Traités **après** J2+J3, dans l'arc complet.
Tant qu'ils ne sont pas faits, le pitch les décrit comme **intention**, à calibrer à voix haute en entrevue.
