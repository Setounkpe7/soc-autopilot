import asyncio

import httpx

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

_PENDING: dict[str, asyncio.Future] = {}  # en prod : Redis (survit au restart du pod)


@action("slack.post")
async def post(params: dict, ctx) -> dict:
    s = get_settings()
    if not s.slack_bot_token:
        return {"posted": False, "reason": "slack_disabled"}
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {s.slack_bot_token}"},
            json={
                "channel": params.get("channel", s.slack_alert_channel),
                "text": params["text"],
            },
        )
        return {"ok": r.json().get("ok")}


@action("slack.request_approval")
async def request_approval(params: dict, ctx) -> dict:
    """Demande une approbation humaine. TIMEOUT => DENY (fail-safe)."""
    s = get_settings()
    key = f"{ctx.execution_id}:{params.get('step_id', 'approval')}"
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    _PENDING[key] = fut

    timeout = params.get("timeout_seconds", s.approval_timeout_seconds)
    text = (
        f"{params['text']}\n\n"
        f"Approuver : `curl -XPOST http://<soc-autopilot>/approvals/{key} "
        f"-d '{{\"approved\":true,\"by\":\"votre.nom\"}}'`\n"
        f"⏱ Expire dans {timeout}s — *sans réponse, l'action est REFUSÉE*."
    )

    if s.slack_bot_token:
        async with httpx.AsyncClient(timeout=10.0) as c:
            await c.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {s.slack_bot_token}"},
                json={
                    "channel": params.get("channel", s.slack_action_channel),
                    "text": text,
                },
            )

    try:
        result = await asyncio.wait_for(fut, timeout=timeout)
        return {
            "approved": bool(result.get("approved")),
            "by": result.get("by"),
            "reason": "human_decision",
        }
    except asyncio.TimeoutError:
        return {"approved": False, "by": None, "reason": "timeout_denied"}  # FAIL-SAFE
    finally:
        _PENDING.pop(key, None)


def resolve_approval(key: str, payload: dict) -> bool:
    fut = _PENDING.get(key)
    if fut and not fut.done():
        fut.set_result(payload)
        return True
    return False
