
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import time
import psutil
from datetime import datetime
from typing import Dict, Any

from ...core.logging_config import get_logger

# Logger
logger = get_logger('api.routes.health')

# Router
router = APIRouter(
    prefix="/health",
    tags=["health"],
    responses={404: {"description": "Not found"}},
)

start_time = time.time()

@router.get("/")
async def health_check():
    """Endpoint principal de health check"""
    request_start = time.time()
    
    try:
        # Sistemas padrão (simulados para desenvolvimento)
        systems = {
            'abiss': {'status': 'healthy', 'initialized': True},
            'nnis': {'status': 'healthy', 'initialized': True},
            'model_manager': {'status': 'healthy', 'initialized': True}
        }
        
        # Verificar status dos sistemas
        systems_status = {}
        overall_status = "healthy"
        
        # Verificar cada sistema
        for system_name, system_info in systems.items():
            try:
                if system_info.get('initialized', False):
                    systems_status[system_name] = {
                        "status": "healthy",
                        "last_check": datetime.utcnow().isoformat()
                    }
                else:
                    systems_status[system_name] = {
                        "status": "unhealthy",
                        "error": "System not initialized",
                        "last_check": datetime.utcnow().isoformat()
                    }
                    overall_status = "unhealthy"
            except Exception as e:
                systems_status[system_name] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "last_check": datetime.utcnow().isoformat()
                }
                overall_status = "unhealthy"
        
        # Calcular métricas de performance
        request_end = time.time()
        response_time_ms = (request_end - request_start) * 1000
        
        # Obter uso de memória
        process = psutil.Process()
        memory_usage_mb = process.memory_info().rss / 1024 / 1024
        
        # Calcular uptime
        uptime_seconds = time.time() - start_time
        
        response_data = {
            "status": overall_status,
            "systems": systems_status,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "response_time_ms": round(response_time_ms, 2),
                "memory_usage_mb": round(memory_usage_mb, 2),
                "uptime_seconds": round(uptime_seconds, 2)
            }
        }
        
        # Retornar status code apropriado
        status_code = 200 if overall_status == "healthy" else 503
        
        return JSONResponse(
            status_code=status_code,
            content=response_data
        )
        
    except Exception as e:
        logger.error("Erro no health check: %s", str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": "Health check failed",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


@router.get("/detailed")
async def detailed_health_check():
    """Health check detalhado com informações adicionais"""
    try:
        # Informações do sistema
        system_info = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent if hasattr(psutil.disk_usage('/'), 'percent') else 0,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "system_info": system_info,
            "version": "2.0.0",
            "environment": "development"
        }
        
    except Exception as e:
        logger.error("Erro no health check detalhado: %s", str(e))
        raise HTTPException(status_code=503, detail="Detailed health check failed")


@router.get("/ping")
async def ping():
    """Endpoint simples de ping"""
    return {
        "message": "pong",
        "timestamp": datetime.utcnow().isoformat()
    }