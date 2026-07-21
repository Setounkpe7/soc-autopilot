import asyncio
import re
import time

import httpx

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)")


@action("threatintel.extract_iocs")
async def extract_iocs(params: dict, ctx) -> dict:
    text = str(params.get("text", ""))
    ips = [i for i in set(IPV4.findall(text)) if not PRIVATE.match(i)]
    return {
        "ips": ips,
        "hashes": list(set(SHA256.findall(text))),
        "domains": list(set(DOMAIN.findall(text))),
        "urls": list(set(URL.findall(text))),
    }


@action("threatintel.lookup")
async def lookup(params: dict, ctx) -> dict:
    """Couche 2 — interroge mon threat-intel-api pour PRIORISER par profil sectoriel."""
    s = get_settings()
    profile = params.get("profile", "gov")  # CAE = défense/aéro → gov/ICS
    async with httpx.AsyncClient(timeout=s.threat_intel_timeout) as c:
        r = await c.get(
            f"{s.threat_intel_url}/cves",
            params={"profile": profile, "limit": 5, "kev_only": True},
        )
        r.raise_for_status()
        data = r.json()
    items = data.get("items", data if isinstance(data, list) else [])
    return {
        "profile": profile,
        "kev_count": len(items),
        "top": [
            {"cve": i.get("cve_id"), "score": i.get("sector_score")} for i in items[:5]
        ],
        "max_severity": max((i.get("sector_score", 0) for i in items), default=0),
    }


# ── Couche 1 — VirusTotal : RÉPUTATION d'un IOC concret ──────────────────
# Cache en mémoire { ioc: (verdict, timestamp) }. En prod : Redis avec TTL.
_VT_CACHE: dict[str, tuple[dict, float]] = {}
_VT_CACHE_TTL = 3600  # un verdict VT ne change pas en 1 h
_VT_SEMAPHORE = asyncio.Semaphore(4)  # respecte le plafond 4 req/min de l'API gratuite


def _vt_classify(malicious: int, suspicious: int, total: int) -> str:
    """Verdict par RATIO, jamais par compte brut. Absence ≠ innocence."""
    if total == 0:
        return "unknown"
    ratio = (malicious + suspicious) / total
    if ratio >= 0.30:
        return "malicious"
    if malicious + suspicious >= 3:
        return "suspicious"
    if total >= 5:
        return "likely_benign"  # "likely", jamais "benign" tout court
    return "unknown"


def _vt_worst(results: list[dict]) -> str:
    order = ["malicious", "suspicious", "likely_benign", "unknown", "error"]
    found = {r["verdict"] for r in results}
    return next((v for v in order if v in found), "unknown")


@action("threatintel.virustotal_lookup")
async def virustotal_lookup(params: dict, ctx) -> dict:
    """Enrichit des IOC via VirusTotal. Par hash/IP/domaine UNIQUEMENT — jamais d'upload."""
    s = get_settings()
    if not s.virustotal_api_key:
        return {"enabled": False, "reason": "no_api_key"}

    iocs = params.get("iocs", {})
    # On BORNE le nombre d'IOC pour ne pas cramer le quota sur une seule alerte
    to_check: list[tuple[str, str]] = []
    for h in iocs.get("hashes", [])[:5]:
        to_check.append(("files", h))
    for ip in iocs.get("ips", [])[:3]:
        to_check.append(("ip_addresses", ip))
    for d in iocs.get("domains", [])[:3]:
        to_check.append(("domains", d))

    results: list[dict] = []
    headers = {"x-apikey": s.virustotal_api_key}

    async with httpx.AsyncClient(
        timeout=s.virustotal_timeout, headers=headers
    ) as client:
        for endpoint, ioc in to_check:
            # Cache : on ne redemande JAMAIS le même IOC (le même malware frappe plusieurs postes)
            cached = _VT_CACHE.get(ioc)
            if cached and (time.time() - cached[1]) < _VT_CACHE_TTL:
                results.append({**cached[0], "cached": True})
                continue
            try:
                async with _VT_SEMAPHORE:  # sérialise → respecte le rate limit
                    r = await client.get(
                        f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
                    )
                if r.status_code == 404:
                    verdict = {"ioc": ioc, "verdict": "unknown", "reason": "not_found"}
                elif r.status_code == 429:
                    # Quota épuisé : on N'ÉCHOUE PAS le playbook, on note et on passe
                    verdict = {
                        "ioc": ioc,
                        "verdict": "unknown",
                        "reason": "rate_limited",
                    }
                else:
                    r.raise_for_status()
                    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
                    total = sum(stats.values())
                    verdict = {
                        "ioc": ioc,
                        "verdict": _vt_classify(mal, sus, total),
                        "malicious": mal,
                        "suspicious": sus,
                        "total_engines": total,
                        "vt_link": f"https://www.virustotal.com/gui/search/{ioc}",
                    }
                _VT_CACHE[ioc] = (verdict, time.time())
                results.append(verdict)
            except Exception as exc:  # noqa: BLE001 — best-effort, ne bloque jamais le cas
                results.append({"ioc": ioc, "verdict": "error", "reason": str(exc)})

    malicious = [r for r in results if r["verdict"] == "malicious"]
    return {
        "enabled": True,
        "checked": len(results),
        "malicious_count": len(malicious),
        "worst_verdict": _vt_worst(results),
        "results": results,
    }
