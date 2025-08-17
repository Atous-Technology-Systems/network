from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field


router = APIRouter()


@dataclass
class _RelayQueues:
    agents: Dict[str, datetime] = field(default_factory=dict)
    queues: Dict[str, List[dict]] = field(default_factory=dict)
    ttl_seconds: int = 60

    def _cleanup(self) -> None:
        now = datetime.now(UTC)
        expired = [aid for aid, ts in self.agents.items() if now - ts > timedelta(seconds=self.ttl_seconds)]
        for aid in expired:
            self.agents.pop(aid, None)
            self.queues.pop(aid, None)

    def heartbeat(self, agent_id: str) -> int:
        if not agent_id:
            raise ValueError("agent_id required")
        self._cleanup()
        self.agents[agent_id] = datetime.now(UTC)
        self.queues.setdefault(agent_id, [])
        return self.ttl_seconds

    def send(self, from_id: str, to_id: str, payload: dict) -> bool:
        self._cleanup()
        if to_id not in self.agents:
            return False
        self.queues.setdefault(to_id, []).append({"from": from_id, "payload": payload, "ts": datetime.now(UTC).isoformat()})
        return True

    def poll(self, agent_id: str) -> list[dict]:
        self._cleanup()
        msgs = self.queues.get(agent_id, [])
        self.queues[agent_id] = []
        return msgs


_STORE = _RelayQueues()


class HeartbeatRequest(BaseModel):
    agent_id: str


class HeartbeatResponse(BaseModel):
    registered: bool
    expires_in: int


@router.post("/v1/relay/heartbeat", response_model=HeartbeatResponse)
async def relay_heartbeat(req: HeartbeatRequest):
    try:
        ttl = _STORE.heartbeat(req.agent_id)
        return HeartbeatResponse(registered=True, expires_in=ttl)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


class RelaySendRequest(BaseModel):
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    payload: dict | None = None

    model_config = {"populate_by_name": True}


class RelaySendResponse(BaseModel):
    enqueued: bool


@router.post("/v1/relay/send", response_model=RelaySendResponse)
async def relay_send(req: RelaySendRequest):
    if not req.from_ or not req.to:
        raise HTTPException(status_code=400, detail="from and to are required")
    enq = _STORE.send(req.from_, req.to, req.payload or {})
    return RelaySendResponse(enqueued=enq)


class RelayPollResponse(BaseModel):
    messages: list[dict]


@router.get("/v1/relay/poll", response_model=RelayPollResponse)
async def relay_poll(agent_id: str = Query(...)):
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    msgs = _STORE.poll(agent_id)
    return RelayPollResponse(messages=msgs)


