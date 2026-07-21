#!/usr/bin/env python3
"""Convertit une règle Sigma avec le pipeline Wazuh, rejoue la requête sur
wazuh-alerts-* et rapporte le nombre de hits. Sort 0 si >=1 hit, sinon 1.

Usage:
    python tools/validate_detection.py detections/windows/<règle>.yml

Env (défauts = labo local) :
    WAZUH_INDEXER_URL   défaut https://localhost:9200
    WAZUH_INDEXER_USER  défaut admin
    WAZUH_INDEXER_PASS  défaut SecretPassword
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from base64 import b64encode

PIPELINE = "detections/pipelines/wazuh-windows.yml"
INDEX = "wazuh-alerts-*"


def convert(rule_path: str) -> str:
    """Retourne la requête OpenSearch Lucene pour une règle Sigma."""
    proc = subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "-p", PIPELINE, rule_path],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def search(query: str) -> dict:
    url = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
    user = os.environ.get("WAZUH_INDEXER_USER", "admin")
    passwd = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
    body = json.dumps(
        {
            "size": 3,
            "query": {"query_string": {"query": query, "analyze_wildcard": True}},
            "_source": [
                "timestamp",
                "agent.name",
                "rule.description",
                "data.win.system.eventID",
            ],
        }
    ).encode()
    req = urllib.request.Request(
        f"{url}/{INDEX}/_search",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(f"{user}:{passwd}".encode()).decode(),
        },
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.load(resp)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rule")
    args = ap.parse_args()

    query = convert(args.rule)
    print(f"[query] {query}\n")
    result = search(query)
    total = result["hits"]["total"]["value"]
    print(f"[hits] {total}")
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        eid = src.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        print(
            f"  {src.get('timestamp')}  EID={eid}  {src.get('rule', {}).get('description')}"
        )
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
