from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Header, Depends
from pydantic import BaseModel
from pathlib import Path
import json
import psutil
import logging
import os

from .discovery import _STORE as DISCOVERY
from .relay import _STORE as RELAY


router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/v1/admin/overview")
async def admin_overview():
    """
    Obter visão geral do sistema administrativo
    
    Endpoint que fornece uma visão consolidada do estado do sistema,
    incluindo agentes de descoberta ativos, status do relay,
    políticas configuradas e métricas do servidor em tempo real.
    
    Returns:
        dict: Visão geral completa do sistema com métricas e status
        
    Raises:
        HTTPException: Se erro interno ao obter dados do sistema
    """
    # discovery snapshot
    discovery_agents = list(DISCOVERY.by_agent.values())
    # relay snapshot
    relay_active = list(RELAY.agents.keys())
    queues_sizes = {aid: len(RELAY.queues.get(aid, [])) for aid in relay_active}
    # policy default (MVP)
    policies = {"default_version": "v1"}
    # system metrics (server)
    proc = psutil.Process()
    mem_mb = round(proc.memory_info().rss / 1024 / 1024, 2)
    cpu = proc.cpu_percent()
    threads = proc.num_threads()
    return {
        "discovery": {"agents": discovery_agents, "services_index": {k: list(v) for k, v in DISCOVERY.by_service.items()}},
        "relay": {"active_agents": relay_active, "queue_sizes": queues_sizes},
        "policies": policies,
        "system_metrics": {"cpu_percent": cpu, "memory_mb": mem_mb, "threads": threads},
    }


# In-memory events (MVP)
_EVENTS: list[dict] = []
_EVENTS_MAX = 500
_EVENTS_FILE = Path("logs/admin_events.ndjson")


def _ensure_log_dir() -> None:
    try:
        _EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logger.warning("Failed to create log directory for admin events: %s", str(exc))


def _rotate_if_needed() -> None:
    try:
        if _EVENTS_FILE.exists() and _EVENTS_FILE.stat().st_size > 1_000_000:
            backup = _EVENTS_FILE.with_suffix(".ndjson.1")
            try:
                if backup.exists():
                    backup.unlink()
            except Exception:
                pass
            _EVENTS_FILE.rename(backup)
    except Exception as exc:
        logger.warning("Failed to rotate admin events log: %s", str(exc))

def _add_event(event: dict) -> None:
    try:
        _EVENTS.append(event)
        if len(_EVENTS) > _EVENTS_MAX:
            del _EVENTS[: len(_EVENTS) - _EVENTS_MAX]
        # Persist to ndjson file (append)
        _ensure_log_dir()
        _rotate_if_needed()
        with _EVENTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("Failed to persist admin event: %s", str(exc))


class AdminEvent(BaseModel):
    type: str
    payload: dict | None = None


def _admin_auth_enabled() -> bool:
    # Enable if ADMIN_AUTH_ENABLED=true or ADMIN_API_KEY is set
    enabled = os.environ.get("ADMIN_AUTH_ENABLED", "false").lower() in {"1", "true", "yes"}
    has_key = bool(os.environ.get("ADMIN_API_KEY"))
    return enabled or has_key


async def require_admin_api_key(x_admin_api_key: str | None = Header(default=None)) -> None:
    if not _admin_auth_enabled():
        return  # auth disabled (development/tests)
    expected = os.environ.get("ADMIN_API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="Admin authentication not configured")
    if not x_admin_api_key or x_admin_api_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/v1/admin/events", dependencies=[Depends(require_admin_api_key)])
async def get_events(limit: int = Query(100, ge=1, le=500)):
    """
    Obter eventos administrativos do sistema
    
    Endpoint que retorna eventos administrativos recentes do sistema,
    incluindo ações de usuários, mudanças de configuração e eventos
    de segurança. Requer autenticação via API key administrativa.
    
    Args:
        limit: Número máximo de eventos a retornar (1-500, padrão: 100)
        
    Returns:
        dict: Lista de eventos administrativos com limite especificado
        
    Raises:
        HTTPException: Se não autorizado ou erro interno
    """
    return {"events": _EVENTS[-limit:]}


@router.post("/v1/admin/events", dependencies=[Depends(require_admin_api_key)])
async def post_event(evt: AdminEvent):
    """
    Postar evento administrativo no sistema
    
    Endpoint que permite registrar eventos administrativos no sistema,
    incluindo ações de usuários, mudanças de configuração e eventos
    de auditoria. Requer autenticação via API key administrativa.
    Campos sensíveis são automaticamente redatados.
    
    Args:
        evt: Evento administrativo a ser registrado
        
    Returns:
        dict: Confirmação de registro do evento
        
    Raises:
        HTTPException: Se não autorizado, payload inválido ou evento muito grande
    """
    # Basic input limits and sanitization for production safety
    max_bytes = int(os.environ.get("MAX_ADMIN_EVENT_BYTES", "8192"))
    try:
        raw = json.dumps({"type": evt.type, "payload": evt.payload or {}})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid event payload")
    if len(raw.encode("utf-8")) > max_bytes:
        raise HTTPException(status_code=413, detail="Event too large")

    # Redact sensitive fields (shallow)
    redact_keys = {k.strip().lower() for k in os.environ.get("ADMIN_REDACT_KEYS", "password,secret,token,key").split(",") if k.strip()}
    payload = dict(evt.payload or {})
    for k in list(payload.keys()):
        if k.lower() in redact_keys:
            payload[k] = "[REDACTED]"

    _add_event({"type": evt.type[:64], "payload": payload})
    return {"ok": True}


