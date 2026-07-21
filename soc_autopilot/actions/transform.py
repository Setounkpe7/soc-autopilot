import base64
import re

from soc_autopilot.engine.registry import action


@action("transform.b64_decode")
async def b64_decode(params: dict, ctx) -> dict:
    text = str(params.get("field", ""))
    pattern = params.get(
        "pattern", r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})"
    )
    m = re.search(pattern, text, re.I)
    if not m:
        return {"decoded": None, "found": False}
    raw = base64.b64decode(m.group(1))
    # PowerShell -enc est en UTF-16LE
    decoded = raw.decode("utf-16-le", errors="replace")
    return {"decoded": decoded, "found": True}


@action("transform.score")
async def score(params: dict, ctx) -> int:
    total = int(params.get("base", 0))
    for booster in params.get("boosters", []):
        if booster.get("when") is True or booster.get("when") == "True":
            total += int(booster.get("points", 0))
    return min(total, 10)
