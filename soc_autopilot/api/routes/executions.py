from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def executions_health():
    return {"ok": True}
