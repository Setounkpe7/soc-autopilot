import hashlib
import hmac

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request

from soc_autopilot.config import get_settings

router = APIRouter()
log = structlog.get_logger()


def verify_hmac(body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    secret = get_settings().webhook_hmac_secret.encode()
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)  # comparaison à temps constant


@router.post("/webhook/wazuh", status_code=202)
async def wazuh_webhook(
    request: Request,
    background: BackgroundTasks,
    x_signature: str | None = Header(default=None),
):
    body = await request.body()
    if not verify_hmac(body, x_signature):
        log.warning("webhook_bad_signature", ip=request.client.host)
        raise HTTPException(status_code=401, detail="Invalid signature")

    alert = await request.json()
    store = request.app.state.playbooks
    executor = request.app.state.executor

    matched = store.match(alert)
    if not matched:
        log.info("no_playbook_matched", rule_id=alert.get("rule", {}).get("id"))
        return {"matched": 0}

    for pb in matched:
        background.add_task(executor.run, pb, alert)  # 202 immédiat

    return {"matched": len(matched), "playbooks": [pb.id for pb in matched]}
