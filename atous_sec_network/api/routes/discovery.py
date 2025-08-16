from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import Dict, Set, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


router = APIRouter()


@dataclass
class _DiscoveryStore:
    ttl_default: int = 60
    by_agent: Dict[str, dict] = field(default_factory=dict)
    by_service: Dict[str, Set[str]] = field(default_factory=dict)

    def _cleanup(self) -> None:
        now = datetime.now(UTC)
        expired = [aid for aid, rec in self.by_agent.items() if now > rec.get("expires_at", now)]
        for aid in expired:
            # remove agent
            rec = self.by_agent.pop(aid, None) or {}
            for svc in rec.get("services", []):
                name = svc.get("name")
                if name and name in self.by_service:
                    self.by_service[name].discard(aid)
                    if not self.by_service[name]:
                        self.by_service.pop(name, None)

    def register(self, agent_id: str, services: List[dict], addresses: dict, ttl: int | None) -> int:
        if not agent_id:
            raise ValueError("agent_id required")
        self._cleanup()
        effective_ttl = int(ttl or self.ttl_default)
        rec = {
            "agent_id": agent_id,
            "services": services or [],
            "addresses": addresses or {"local": [], "lan": [], "wan": []},
            "expires_at": datetime.now(UTC) + timedelta(seconds=effective_ttl),
        }
        self.by_agent[agent_id] = rec
        # reindex
        for name, ids in list(self.by_service.items()):
            if agent_id in ids and not any(s.get("name") == name for s in services or []):
                ids.discard(agent_id)
                if not ids:
                    self.by_service.pop(name, None)
        for svc in services or []:
            name = svc.get("name")
            if name:
                self.by_service.setdefault(name, set()).add(agent_id)
        return effective_ttl

    def get_providers(self, service_name: str) -> List[dict]:
        self._cleanup()
        agent_ids = list(self.by_service.get(service_name, set()))
        # Order by most recent registration (expires_at later means more recent)
        agent_ids.sort(key=lambda aid: self.by_agent.get(aid, {}).get("expires_at"), reverse=True)
        return [
            {"agent_id": aid, "addresses": self.by_agent.get(aid, {}).get("addresses", {})}
            for aid in agent_ids
        ]

    def get_agent(self, agent_id: str) -> dict | None:
        self._cleanup()
        return self.by_agent.get(agent_id)


_STORE = _DiscoveryStore()


class RegisterRequest(BaseModel):
    agent_id: str
    services: list[dict] = []
    addresses: dict = {}
    ttl: int | None = None


class RegisterResponse(BaseModel):
    registered: bool
    expires_in: int


@router.post("/v1/discovery/register", response_model=RegisterResponse)
async def discovery_register(req: RegisterRequest):
    try:
        ttl = _STORE.register(req.agent_id, req.services, req.addresses, req.ttl)
        return RegisterResponse(registered=True, expires_in=ttl)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


class ProvidersResponse(BaseModel):
    providers: list[dict]


@router.get("/v1/discovery/services", response_model=ProvidersResponse)
async def discovery_services(name: str = Query(...)):
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    providers = _STORE.get_providers(name)
    return ProvidersResponse(providers=providers)


@router.get("/v1/discovery/agents/{agent_id}")
async def discovery_agent_detail(agent_id: str):
    rec = _STORE.get_agent(agent_id)
    if not rec:
        raise HTTPException(status_code=404, detail="agent not found")
    return rec


class ResolveResponse(BaseModel):
    candidates: list[str]


@router.get("/v1/discovery/resolve", response_model=ResolveResponse)
async def discovery_resolve(name: str = Query(...), pref: str = Query("local,lan,wan")):
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    providers = _STORE.get_providers(name)
    pref_order = [p.strip() for p in pref.split(",") if p.strip() in ("local", "lan", "wan")]
    if not pref_order:
        pref_order = ["local", "lan", "wan"]
    ordered: list[str] = []
    seen = set()
    for scope in pref_order:
        for p in providers:
            for addr in p.get("addresses", {}).get(scope, []) or []:
                if addr not in seen:
                    ordered.append(addr)
                    seen.add(addr)
    return ResolveResponse(candidates=ordered)


