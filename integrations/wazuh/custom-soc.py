#!/usr/bin/env python3
"""Intégration Wazuh → SOC Autopilot.

`integratord` (Wazuh) invoque ce script à chaque alerte matchant le filtre
déclaré dans ossec.conf, avec les arguments :

    custom-soc  <alert_file>  <hmac_secret>  <hook_url>

- <alert_file>  : chemin d'un JSON contenant l'alerte Wazuh (rule.id, rule.level,
                  rule.mitre.id, agent.name, data.win.eventdata…).
- <hmac_secret> : le secret HMAC PARTAGÉ = WEBHOOK_HMAC_SECRET côté SOAR
                  (transporté via le champ <api_key> d'ossec.conf).
- <hook_url>    : URL du webhook SOAR, ex http://<hôte>:8000/webhook/wazuh

On signe le CORPS EXACT envoyé (HMAC-SHA256) et on le pousse au header
`X-Signature` — exactement ce que vérifie soc_autopilot/api/routes/webhook.py
(comparaison à temps constant). Stdlib uniquement : tourne sur le Python embarqué
de Wazuh (/var/ossec/framework/python).
"""

import hashlib
import hmac
import json
import sys
import urllib.request


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit("usage: custom-soc <alert_file> <hmac_secret> <hook_url>")
    alert_file, secret, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]

    # hook_url vient d'ossec.conf (opérateur). On refuse tout schéma non http(s) :
    # urllib supporte file://, un schéma inattendu lirait un fichier local au lieu
    # de POSTer l'alerte.
    if not hook_url.startswith(("http://", "https://")):
        sys.exit(f"custom-soc: hook_url doit être http(s), reçu: {hook_url}")

    with open(alert_file, encoding="utf-8") as fh:
        alert = json.load(fh)

    # Les octets signés doivent être IDENTIQUES aux octets envoyés, sinon la
    # vérification HMAC côté SOAR échoue (401). On sérialise une seule fois.
    body = json.dumps(alert).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        hook_url,
        data=body,
        headers={"Content-Type": "application/json", "X-Signature": signature},
        method="POST",
    )
    try:
        # hook_url = config opérateur (ossec.conf) + schéma restreint à http(s) plus haut.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as resp:
            sys.stdout.write(f"custom-soc: webhook HTTP {resp.status}\n")
    except Exception as exc:  # noqa: BLE001 — on ne bloque jamais Wazuh
        sys.stderr.write(f"custom-soc: erreur webhook: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
