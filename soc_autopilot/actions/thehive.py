import httpx

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action


@action("thehive.create_case")
async def create_case(params: dict, ctx) -> dict:
    s = get_settings()
    if not s.thehive_api_key:
        # mode dégradé : le système marche même sans TheHive
        return {"case_id": f"LOCAL-{ctx.execution_id}", "backend": "local"}

    payload = {
        "title": params["title"],
        "description": params.get("description", ""),
        "severity": min(max(int(params.get("severity", 2)), 1), 4),
        "tlp": params.get("tlp", 2),
        "tags": params.get("mitre_tags", [])
        + [f"playbook:{ctx.playbook.id}", f"exec:{ctx.execution_id}"],
    }
    headers = {"Authorization": f"Bearer {s.thehive_api_key}"}
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(f"{s.thehive_url}/api/v1/case", json=payload, headers=headers)
        r.raise_for_status()
        case = r.json()

        for obs_type, values in (params.get("observables") or {}).items():
            for v in values:
                await c.post(
                    f"{s.thehive_url}/api/v1/case/{case['_id']}/observable",
                    json={
                        "dataType": obs_type,
                        "data": [v],
                        "tlp": 2,
                        "ioc": True,
                        "message": f"Auto — {ctx.playbook.id}",
                    },
                    headers=headers,
                )

    return {
        "case_id": case["_id"],
        "case_number": case.get("number"),
        "url": f"{s.thehive_url}/cases/{case['_id']}/details",
    }
