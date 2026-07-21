"""Test d'intégration du chaînage detection-as-code : Sigma -> pipeline -> requête
OpenSearch -> match, contre une télémétrie de cradle réaliste indexée sous le
mapping corrigé (ignore_above 32766, cf. infra/wazuh/templates/wazuh-eventdata-override.json).

Chaque test crée un index jetable, y indexe un document fixture (contenu de cradle
réel, > 256 car. pour exercer le fix ignore_above), convertit la règle, exécute la
requête, puis nettoie. Se skippe si l'indexeur Wazuh n'est pas joignable.
"""

import json
import socket
import ssl
import subprocess
import urllib.request
from base64 import b64encode

import pytest

INDEXER = "https://localhost:9200"
AUTH = "Basic " + b64encode(b"admin:SecretPassword").decode()
PIPELINE = "detections/pipelines/wazuh-windows.yml"

MAPPING = {
    "mappings": {
        "properties": {
            "data": {
                "properties": {
                    "win": {
                        "properties": {
                            "system": {
                                "properties": {
                                    "channel": {"type": "keyword"},
                                    "eventID": {"type": "keyword"},
                                }
                            },
                            "eventdata": {
                                "properties": {
                                    "image": {"type": "keyword", "ignore_above": 32766},
                                    "originalFileName": {
                                        "type": "keyword",
                                        "ignore_above": 32766,
                                    },
                                    "commandLine": {
                                        "type": "keyword",
                                        "ignore_above": 32766,
                                    },
                                    "scriptBlockText": {
                                        "type": "keyword",
                                        "ignore_above": 32766,
                                    },
                                }
                            },
                        }
                    }
                }
            }
        }
    }
}

# Cradle réel observé dans la détonation (ScriptBlock, EID 4104) ; padding > 256 car.
CRADLE_SCRIPTBLOCK = (
    "Set-ExecutionPolicy Bypass -Scope Process -Force IEX (IWR "
    "'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/"
    "install-atomicredteam.ps1' -UseBasicParsing)  # " + "A" * 400
)
# Commande encodée réelle observée dans la détonation (ligne de commande, EID 1) ; > 256 car.
ENCODED_CMDLINE = (
    "powershell.exe -NoProfile -EncodedArguments "
    "PABPAGIAagBzACAAVgBlAHIAcwBpAG8AbgA9ACIAMQAuADEALgAwAC4AMQAiACAAeABtAGwAbgBzAD0AIgBo"
    + "A"
    * 400
)


def _indexer_up():
    try:
        with socket.create_connection(("localhost", 9200), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _indexer_up(), reason="Wazuh indexer injoignable")


def _req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{INDEXER}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Authorization": AUTH},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.load(resp)


def _convert(rule):
    return subprocess.run(
        ["sigma", "convert", "-t", "opensearch_lucene", "-p", PIPELINE, rule],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _count(index, query):
    body = {"query": {"query_string": {"query": query, "analyze_wildcard": True}}}
    return _req("POST", f"/{index}/_count", body)["count"]


@pytest.fixture
def temp_index():
    name = "zz-detection-fixture"
    try:
        _req("DELETE", f"/{name}")
    except Exception:
        pass
    _req("PUT", f"/{name}", MAPPING)
    yield name
    try:
        _req("DELETE", f"/{name}")
    except Exception:
        pass


def test_scriptblock_rule_matches_real_cradle(temp_index):
    doc = {
        "data": {
            "win": {
                "system": {
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "eventID": "4104",
                },
                "eventdata": {"scriptBlockText": CRADLE_SCRIPTBLOCK},
            }
        }
    }
    _req("POST", f"/{temp_index}/_doc?refresh=true", doc)
    query = _convert(
        "detections/windows/t1059.001_powershell_download_cradle_scriptblock.yml"
    )
    assert _count(temp_index, query) == 1


def test_encoded_command_rule_matches_real_telemetry(temp_index):
    doc = {
        "data": {
            "win": {
                "system": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "eventID": "1",
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": ENCODED_CMDLINE,
                },
            }
        }
    }
    _req("POST", f"/{temp_index}/_doc?refresh=true", doc)
    query = _convert("detections/windows/t1059.001_powershell_encoded_command.yml")
    assert _count(temp_index, query) == 1
