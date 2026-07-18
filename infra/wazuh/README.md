# Wazuh — lancement (Voie B : sur l'hôte)

> Étape déferée volontairement : `docker compose up` démarre une stack Java d'~2-3 Go.
> À lancer quand tu es prêt à travailler sur le labo (session « détection »).

## 1. Récupérer la stack officielle

```bash
cd ~                      # hors du repo (ce sont des sources tierces, non versionnées ici)
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
```

## 2. Tuning RAM (spécifique Voie B, ~12 Go)

L'indexer (OpenSearch) réserve 4 Go de heap par défaut — trop pour cette machine.
Dans `docker-compose.yml`, sur le service `wazuh.indexer`, mets :

```yaml
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

> `vm.max_map_count=262144` est déjà posé sur l'hôte (`/etc/sysctl.d/99-wazuh.conf`),
> c'est l'erreur n°1 au démarrage de Wazuh — déjà réglée.

## 3. Démarrer

```bash
docker compose -f generate-indexer-certs.yml run --rm generator   # certificats TLS
docker compose up -d
docker compose logs -f wazuh.manager                              # ~3-5 min la 1re fois
```

**Vérifier :**
```bash
docker compose ps                                                 # 3 conteneurs "running"
curl -k -u admin:SecretPassword https://localhost:9200/_cluster/health | jq
```
Dashboard : **https://localhost:443** (ou `https://192.168.56.1:443` depuis la VM Windows).
`admin` / `SecretPassword` → **à changer immédiatement** (docker-compose + internal_users.yml).

## 4. Différences vs la doc (Voie B)

- Toutes les IP `192.168.56.10` de la doc → **`192.168.56.1`** (host-only de l'hôte) ou `localhost`.
- L'agent Wazuh de `victim-win` s'enregistre auprès du manager à **`192.168.56.1`**.
- Pas de snapshot VM du SIEM : reset propre = `docker compose down -v && docker compose up -d`.
