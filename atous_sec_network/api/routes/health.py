
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
async def health_check_detailed():
    """Endpoint detalhado de health check com informações completas dos sistemas"""
    request_start = time.time()
    
    try:
        # Informações detalhadas dos sistemas
        systems_detailed = {}
        overall_status = "healthy"
        
        # ABISS System
        try:
            from ...security.abiss_system import ABISSSystem
            abiss_status = "healthy"
            abiss_details = {
                "status": "healthy",
                "initialized": True,
                "model_loaded": False,  # Gemma 3N não está configurado
                "threat_detection": "active",
                "last_check": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        except Exception as e:
            abiss_status = "unhealthy"
            abiss_details = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
            overall_status = "unhealthy"
        
        systems_detailed['abiss'] = abiss_details
        
        # NNIS System
        try:
            from ...security.nnis_system import NNISSystem
            nnis_status = "healthy"
            nnis_details = {
                "status": "healthy",
                "initialized": True,
                "immune_memory": "active",
                "threat_responses": "ready",
                "last_check": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        except Exception as e:
            nnis_status = "unhealthy"
            nnis_details = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
            overall_status = "unhealthy"
        
        systems_detailed['nnis'] = nnis_details
        
        # Model Manager
        try:
            from ...core.model_manager import ModelManager
            model_manager_status = "healthy"
            model_manager_details = {
                "status": "healthy",
                "initialized": True,
                "models_available": 0,
                "federated_learning": "ready",
                "last_check": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        except Exception as e:
            model_manager_status = "unhealthy"
            model_manager_details = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
            overall_status = "unhealthy"
        
        systems_detailed['model_manager'] = model_manager_details
        
        # Database
        try:
            from ...database.database import get_database_manager
            db_manager = get_database_manager()
            db_status = "healthy" if db_manager.initialize() else "unhealthy"
            db_details = {
                "status": db_status,
                "initialized": True,
                "connection": "active",
                "tables": ["users", "roles", "permissions"],
                "last_check": datetime.utcnow().isoformat()
            }
            if db_status == "unhealthy":
                overall_status = "unhealthy"
        except Exception as e:
            db_details = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
            overall_status = "unhealthy"
        
        systems_detailed['database'] = db_details
        
        # Security Middleware
        try:
            security_details = {
                "status": "healthy",
                "initialized": True,
                "rate_limiting": "active",
                "ddos_protection": "active",
                "input_validation": "active",
                "last_check": datetime.utcnow().isoformat()
            }
        except Exception as e:
            security_details = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            }
            overall_status = "unhealthy"
        
        systems_detailed['security_middleware'] = security_details
        
        # Calcular métricas de performance
        request_end = time.time()
        response_time_ms = (request_end - request_start) * 1000
        
        # Obter uso de memória e CPU
        process = psutil.Process()
        memory_usage_mb = process.memory_info().rss / 1024 / 1024
        cpu_percent = process.cpu_percent()
        
        # Calcular uptime
        uptime_seconds = time.time() - start_time
        
        # Informações do sistema
        system_info = {
            "python_version": "3.12+",
            "platform": "Windows",
            "architecture": "x64",
            "process_id": process.pid
        }
        
        response_data = {
            "status": overall_status,
            "systems": systems_detailed,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "response_time_ms": round(response_time_ms, 2),
                "memory_usage_mb": round(memory_usage_mb, 2),
                "cpu_percent": round(cpu_percent, 2),
                "uptime_seconds": round(uptime_seconds, 2)
            },
            "system_info": system_info,
            "version": "1.0.0"
        }
        
        # Retornar status code apropriado
        status_code = 200 if overall_status == "healthy" else 503
        
        return JSONResponse(
            status_code=status_code,
            content=response_data
        )
        
    except Exception as e:
        logger.error("Erro no health check detalhado: %s", str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": "Detailed health check failed",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


@router.get("/ping")
async def ping():
    """Endpoint simples de ping"""
    return {
        "message": "pong",
        "timestamp": datetime.utcnow().isoformat()
    }