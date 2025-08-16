from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from ...security.ca_service import CAService
from ...security.policy_service import PolicyService


router = APIRouter()
_ca_service = CAService()
_policy_service = PolicyService()


class EnrollRequest(BaseModel):
    device_info: dict = Field(default_factory=dict)
    attestation: Optional[dict] = None
    csr_pem: str


class EnrollResponse(BaseModel):
    agent_id: str
    certificate_pem: str
    ca_chain_pem: str


@router.post("/v1/agents/enroll", response_model=EnrollResponse)
async def enroll_agent(req: EnrollRequest):
    try:
        cert_pem, ca_pem = _ca_service.issue_certificate(req.csr_pem)
        # For MVP, agent_id derived from CN is acceptable
        agent_id = "agt-" + str(abs(hash(cert_pem)))[0:10]
        return EnrollResponse(agent_id=agent_id, certificate_pem=cert_pem, ca_chain_pem=ca_pem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Enrollment failed") from e


class HeartbeatRequest(BaseModel):
    version: str
    services: list = Field(default_factory=list)
    metrics: dict = Field(default_factory=dict)
    risk_score: float


class HeartbeatResponse(BaseModel):
    policy_version: str
    actions: list[str]


@router.post("/v1/agents/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(agent_id: str, req: HeartbeatRequest):
    try:
        # MVP: resolver baseado apenas no risk_score e contexto direto
        version, actions = _policy_service.resolve(agent_id=agent_id, risk_score=req.risk_score, context={
            "version": req.version,
            "services": req.services,
            "metrics": req.metrics,
        })
        return HeartbeatResponse(policy_version=version, actions=actions)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Heartbeat failed") from e


