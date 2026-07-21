# soc-autopilot — Instructions projet

## Règle de déploiement vers `main` (IMPÉRATIF)

Toute intégration dans `main` suit **ce workflow, sans exception — jamais de push direct sur `main`** :

1. **Travailler sur une branche dédiée** (`detection/…`, `feat/…`, `fix/…`), jamais directement sur `main`.
2. **Ouvrir une Pull Request** vers `main` (`gh pr create`). Rien n'arrive sur `main` autrement que par le merge d'une PR.
3. **Revue de code de la PR avant tout merge** avec Claude Code (skill `code-review` / `/review`), complétée d'un scan sécurité `semgrep`. Chaque finding est corrigé ou justifié explicitement.
4. **Monitorer la PR via `gh`** (`gh pr checks`, `gh pr view`) jusqu'à ce que toutes les vérifications soient vertes.
5. **Merger uniquement quand tout est vert** (`gh pr merge --squash --delete-branch`), puis nettoyer la branche.

Les hooks pre-commit (ruff, detect-secrets, hadolint, checkov…) doivent passer avant chaque commit.

## Détection-as-code

- Les règles Sigma vivent dans `detections/windows/` (et `detections/linux/`) ; le pipeline de mapping Sigma→Wazuh dans `detections/pipelines/`.
- **Règles pilotées par la menace** : une règle doit correspondre à un comportement que l'attaque testée produit *réellement*, vérifié sur la télémétrie de l'index — jamais fabriquer de télémétrie pour faire matcher une règle.
- Validation : `python3 tools/validate_detection.py <règle>` (convertit via `sigma-cli` + le pipeline, rejoue sur `wazuh-alerts-*`). Tests : `python3 -m pytest tests/`.
