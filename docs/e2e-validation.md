# Validation de bout en bout — GABARIT À REMPLIR SUR LE LABO

> Ce fichier est un **protocole + gabarit de mesure**. Les cellules « À MESURER »
> doivent être remplies avec **tes vraies valeurs** chronométrées sur le labo, mode
> armé (`DRY_RUN=false`), snapshot restauré avant chaque test. Ne pas inventer de chiffres.

## Environnement (à compléter)

- soc-lab : Ubuntu, Wazuh 4.x (Docker), soc-autopilot (moteur J2/J3 mergé)
- victim-win : Windows, Sysmon (config SwiftOnSecurity)
- Mode : `DRY_RUN=false`, snapshot `03-victim-prete` restauré avant chaque test

## Protocole (identique par technique)

1. Restaurer le snapshot.
2. `date +%s%3N` → T0.
3. Exécuter l'atomic (`Invoke-AtomicTest <T....> -TestNumbers <n>`).
4. Chronométrer : T1 = alerte visible dans Wazuh, T2 = cas TheHive créé, T3 = notif Slack.
5. Vérifier l'audit trail : `GET /executions/{id}`.
6. Restaurer le snapshot.

## Scénario d'intrusion (une intrusion, pas 7 techniques isolées)

1. **T1059.001** (exécution) → PB-0001 : décode, IOC, enrichissement, cas, score. Score < 9 ⇒ **pas d'isolation** (graduation).
2. **T1547.001** (persistance) → PB-0003 : cas + tâche, **pas d'isolation**.
3. **T1087.001** (découverte) → **GAP CONNU** (voir `telemetry-gap-analysis.md`) — à montrer, pas à cacher.
4. **T1003.001** (LSASS) → PB-0002 : **isolation immédiate**. Vérifier le containment **par ping** (pas juste par log).
5. **Rollback** : `POST /executions/{id}/rollback` → le réseau revient, `rolled_back = true`.

## Résultats mesurés (À MESURER — 5 itérations/technique, médiane)

| Technique | Attaque→Alerte | Alerte→Cas | Total | Actions auto |
|---|---|---|---|---|
| T1059.001 | À MESURER | À MESURER | À MESURER | decode, IOC, intel, cas, notif |
| T1003.001 | À MESURER | À MESURER | À MESURER | cas, isolate, notif |
| T1547.001 | À MESURER | À MESURER | À MESURER | cas, tâche, notif |

## Manuel vs automatisé (À MESURER — chronomètre, médiane de 3 essais manuels)

| Tâche | Manuel | Auto | Facteur |
|---|---|---|---|
| Triage complet d'une alerte PowerShell | À MESURER | À MESURER | — |
| Enrichissement (IOC × 2 sources) | À MESURER | À MESURER | — |
| Décision de containment | À MESURER | À MESURER | — |

**Méthode & limites (à conserver, elles crédibilisent les chiffres) :**
- Manuel : chronomètre, mêmes outils, 3 essais, médiane. *Je connaissais déjà les
  alertes → mes chiffres manuels sont **optimistes**, un vrai analyste serait plus lent.*
- Auto : `execution.duration_seconds` de l'audit trail, 5 itérations, médiane.
- Labo mono-utilisateur, pas de charge concurrente : à 300 alertes/jour, les temps
  augmenteraient (contention DB, rate limits API).

## Tests de robustesse (cocher après exécution réelle)

- [ ] **Idempotence** : 5× la même alerte → 1 exécution + 4 `deduplicated`, 1 seul cas.
- [ ] **Signature invalide** : `X-Signature: deadbeef` → 401, rien exécuté.
- [ ] **Threat intel down** : timeout → `on_error:continue` → cas **quand même** créé (`partial`).
- [ ] **VirusTotal 429** : `worst_verdict=unknown`, cas **quand même** créé, aucun crash.
- [ ] **Actif protégé** (`DC-01`) : cas créé, `isolate = skipped` (`protected_asset`).
- [ ] **Timeout d'approbation** : score 9, pas de réponse → `approved=false`, aucune isolation.
- [ ] **Rollback** : isole puis rollback → `rolled_back=true`, ping repasse.
