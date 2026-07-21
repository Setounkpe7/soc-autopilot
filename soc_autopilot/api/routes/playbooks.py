from fastapi import APIRouter, Request

router = APIRouter()


@router.get("")
async def list_playbooks(request: Request):
    return {"playbooks": [pb.id for pb in request.app.state.playbooks.all()]}
