from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


router = APIRouter()


class ActivePolicyResponse(BaseModel):
    policy_version: str
    actions: list[str]


@router.get("/v1/policies/active", response_model=ActivePolicyResponse)
async def get_active_policy(agent_id: str = Query(...)):
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    # MVP: política padrão v1/allow
    return ActivePolicyResponse(policy_version="v1", actions=["allow"])


