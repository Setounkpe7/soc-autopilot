from fastapi import APIRouter, HTTPException

from soc_autopilot.actions.slack import resolve_approval

router = APIRouter()


@router.post("/approvals/{key}")
async def approve(key: str, payload: dict):
    if not resolve_approval(key, payload):
        raise HTTPException(404, "Aucune approbation en attente pour cette clé")
    return {"ok": True, "key": key, "approved": payload.get("approved")}
