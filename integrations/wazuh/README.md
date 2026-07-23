# Intégration Wazuh → SOC Autopilot

Le **chaînon manquant** : faire remonter automatiquement une alerte Wazuh vers le
webhook SOAR, signée HMAC, pour que la chaîne `détection → réponse → Slack`
se déclenche **sans injection manuelle**.

```
Attaque VM → Sysmon/agent → Wazuh (rule 100101…) → integratord → custom-soc
   → POST /webhook/wazuh (X-Signature HMAC) → PB-0001 → … → Slack #soc-alerts
```

## Fichiers

| Fichier | Rôle |
|---|---|
| `custom-soc` | Wrapper appelé par `integratord` (délègue au Python embarqué de Wazuh). |
| `custom-soc.py` | Signe le corps exact en HMAC-SHA256 et POST vers le webhook SOAR. |

> Le nom **doit** commencer par `custom-` (convention Wazuh pour les intégrations tierces).

## Contrat

`integratord` invoque : `custom-soc <alert_file> <api_key> <hook_url>`
où, via le bloc `<integration>` d'ossec.conf, `<api_key>` = **le secret HMAC partagé**
(`WEBHOOK_HMAC_SECRET` du `.env` SOAR) et `<hook_url>` = l'URL du webhook. Le script
signe exactement les octets envoyés → header `X-Signature`, vérifié par
`soc_autopilot/api/routes/webhook.py` (comparaison à temps constant).

## Bloc ossec.conf (dans `<ossec_config>`)

```xml
<integration>
  <name>custom-soc</name>
  <hook_url>http://172.17.0.1:8000/webhook/wazuh</hook_url>
  <api_key>__COLLE_ICI_LE_WEBHOOK_HMAC_SECRET__</api_key>
  <alert_format>json</alert_format>
  <rule_id>100101,100102</rule_id>   <!-- filtre : uniquement nos règles, pas tout le flux -->
</integration>
```

> ⚠️ **Réseau** : le SOAR tourne sur l'HÔTE ; depuis le conteneur manager,
> `127.0.0.1` = le conteneur, pas l'hôte. Utilise l'IP de la **passerelle hôte**
> vue du conteneur :
> ```bash
> docker exec single-node-wazuh.manager-1 ip route | awk '/default/{print $3}'
> # → mets cette IP (souvent 172.17.0.1) dans <hook_url>
> ```
> Et démarre l'API SOAR en écoute **0.0.0.0** (pas 127.0.0.1) :
> `uvicorn soc_autopilot.api.main:app --host 0.0.0.0 --port 8000`

## Déploiement (Wazuh en conteneur)

```bash
M=single-node-wazuh.manager-1
docker cp integrations/wazuh/custom-soc    $M:/var/ossec/integrations/custom-soc
docker cp integrations/wazuh/custom-soc.py $M:/var/ossec/integrations/custom-soc.py
docker exec $M chown root:wazuh /var/ossec/integrations/custom-soc /var/ossec/integrations/custom-soc.py
docker exec $M chmod 750       /var/ossec/integrations/custom-soc /var/ossec/integrations/custom-soc.py
# → ajoute le bloc <integration> ci-dessus dans /var/ossec/etc/ossec.conf
docker restart $M
# vérifie que integratord a démarré :
docker exec $M tail -f /var/ossec/logs/ossec.log | grep -i integrator
```

## Test sans attaque (bout en bout du connecteur)

Depuis le conteneur manager, simule ce qu'integratord ferait :

```bash
docker exec -it $M sh -c '
  echo "{\"rule\":{\"id\":\"100101\",\"level\":8,\"mitre\":{\"id\":[\"T1059.001\"]}},
        \"agent\":{\"name\":\"VICTIM-WIN\"},
        \"data\":{\"win\":{\"eventdata\":{\"user\":\"CORP\\\\jdoe\",\"commandLine\":\"powershell -enc AAA\"}}}}" \
    > /tmp/a.json
  /var/ossec/integrations/custom-soc /tmp/a.json "<WEBHOOK_HMAC_SECRET>" "http://172.17.0.1:8000/webhook/wazuh"
'
# attendu : "custom-soc: webhook HTTP 202"  → puis alerte dans #soc-alerts
```

## Pourquoi ce design (entrevue)

- **HMAC de bout en bout** : Wazuh signe, le SOAR vérifie ; une alerte non signée
  (ou forgée) est rejetée en 401. Le SIEM et le SOAR ne se font pas *aveuglément* confiance.
- **Filtre par `rule_id`** : on ne déverse pas *tout* le flux Wazuh dans le SOAR —
  seules les règles à réponse automatisée. On réduit le bruit et la surface.
- **Python embarqué** : zéro dépendance système, portable sur toute install Wazuh.
- **Best-effort** : une erreur du connecteur n'interrompt jamais Wazuh (`exit 1` loggé, pas de crash).
