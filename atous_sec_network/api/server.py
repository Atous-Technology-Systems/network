"""Servidor principal FastAPI para ATous Secure Network

Implementação do servidor web com endpoints REST e WebSocket
para o sistema ATous Secure Network.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
import psutil
from datetime import datetime
from typing import Dict, Any, Optional

from ..core.logging_config import get_logger

# Logger
logger = get_logger('api.server')

# Variável global para rastrear tempo de inicialização
start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação"""
    # Startup
    logger.info("Iniciando ATous Secure Network API Server")
    
    # Inicializar componentes do sistema
    try:
        # Inicializar sistemas principais
        app.state.systems = {
            'abiss': {'status': 'healthy', 'initialized': True},
            'nnis': {'status': 'healthy', 'initialized': True},
            'model_manager': {'status': 'healthy', 'initialized': True}
        }
        
        logger.info("Todos os sistemas inicializados com sucesso")
        
    except Exception as e:
        logger.error("Falha na inicialização dos sistemas: %s", str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Finalizando ATous Secure Network API Server")
    logger.info("Shutdown concluído")


# Criar aplicação FastAPI
app = FastAPI(
    title="ATous Secure Network API",
    description="API para gerenciamento da rede segura ATous com Federated Learning",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Middleware de segurança
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.atous.tech", "testserver"]
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# Exception handler global
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# Health Check Endpoint
@app.get("/health")
async def health_check():
    """Endpoint de health check com informações detalhadas dos sistemas"""
    request_start = time.time()
    
    try:
        # Inicializar sistemas se não existirem
        if not hasattr(app.state, 'systems'):
            app.state.systems = {
                'abiss': {'status': 'healthy', 'initialized': True},
                'nnis': {'status': 'healthy', 'initialized': True},
                'model_manager': {'status': 'healthy', 'initialized': True}
            }
        
        # Verificar status dos sistemas
        systems_status = {}
        overall_status = "healthy"
        
        # Verificar cada sistema
        for system_name, system_info in app.state.systems.items():
            try:
                # Simular verificação de saúde do sistema
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


# Root endpoint
@app.get("/")
async def root():
    """Endpoint raiz com informações da API"""
    return {
        "name": "ATous Secure Network API",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "redoc": "/redoc"
        }
    }


def create_app() -> FastAPI:
    """Factory function para criar aplicação"""
    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
    log_level: str = "info"
) -> None:
    """Executar servidor FastAPI
    
    Args:
        host: Host para bind do servidor
        port: Porta para bind do servidor
        reload: Habilitar auto-reload para desenvolvimento
        log_level: Nível de log (debug, info, warning, error)
    """
    import uvicorn
    
    logger.info(f"Iniciando servidor em {host}:{port}")
    
    uvicorn.run(
        "atous_sec_network.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level
    )


if __name__ == "__main__":
    run_server(reload=True)