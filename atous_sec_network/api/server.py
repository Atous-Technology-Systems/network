"""Servidor principal FastAPI para ATous Secure Network

Implementação do servidor web com endpoints REST e WebSocket
para o sistema ATous Secure Network.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
import psutil
from datetime import datetime, UTC
from typing import Dict, Any, Optional

from ..core.logging_config import setup_logging
from ..security.abiss_system import ABISSSystem
from ..security.nnis_system import NNISSystem
from .routes import security

# Configurar logging
setup_logging()
logger = logging.getLogger(__name__)

# Instâncias globais dos sistemas de segurança
abiss_system = None
nnis_system = None

# Funções para inicialização lazy
def get_abiss_system():
    """Obtém a instância do sistema ABISS, inicializando se necessário."""
    global abiss_system
    if abiss_system is None:
        try:
            logger.info("Inicializando sistema ABISS (lazy loading)...")
            from ..security.abiss_system import ABISSSystem
            abiss_system = ABISSSystem(app.state.abiss_config)
            logger.info("Sistema ABISS inicializado com sucesso")
            app.state.systems['abiss'] = {'status': 'healthy', 'initialized': True}
        except Exception as e:
            logger.exception("Falha na inicialização do ABISS: %s", str(e))
            app.state.systems['abiss'] = {'status': 'unhealthy', 'initialized': False, 'error': str(e)}
            raise
    return abiss_system

def get_nnis_system():
    """Obtém a instância do sistema NNIS, inicializando se necessário."""
    global nnis_system
    if nnis_system is None:
        try:
            logger.info("Inicializando sistema NNIS (lazy loading)...")
            from ..security.nnis_system import NNISSystem
            nnis_system = NNISSystem(app.state.nnis_config)
            logger.info("Sistema NNIS inicializado com sucesso")
            app.state.systems['nnis'] = {'status': 'healthy', 'initialized': True}
        except Exception as e:
            logger.exception("Falha na inicialização do NNIS: %s", str(e))
            app.state.systems['nnis'] = {'status': 'unhealthy', 'initialized': False, 'error': str(e)}
            raise
    return nnis_system

# Variável global para rastrear tempo de inicialização
start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação"""
    global abiss_system, nnis_system
    
    # Startup
    logger.info("Iniciando aplicação...")
    try:
        # Configurações padrão para os sistemas
        abiss_config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "threat_threshold": 0.7,
            "learning_rate": 0.01,
            "enable_monitoring": True
        }
        
        nnis_config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "immune_cell_count": 50,
            "memory_cell_count": 100,
            "threat_threshold": 0.8
        }
        
        # Inicialização lazy dos sistemas ABISS e NNIS
        logger.info("Configurando inicialização lazy dos sistemas de segurança...")
        
        # Armazenar configurações para inicialização lazy
        app.state.abiss_config = abiss_config
        app.state.nnis_config = nnis_config
        
        # Inicializar status como 'not_initialized' para lazy loading
        abiss_status = {'status': 'not_initialized', 'initialized': False}
        nnis_status = {'status': 'not_initialized', 'initialized': False}
        
        logger.info("Sistemas configurados para inicialização lazy")
        
        # Inicializar sistemas principais
        app.state.systems = {
            'abiss': abiss_status,
            'nnis': nnis_status,
            'model_manager': {'status': 'healthy', 'initialized': True}
        }
        
        logger.info("Aplicação inicializada com sistemas ABISS e NNIS")
        
    except Exception as e:
        logger.error("Falha na inicialização da aplicação: %s", str(e))
        logger.exception("Detalhes do erro:")
        # Continuar mesmo com erro na inicialização
        abiss_system = None
        nnis_system = None
        
        # Inicializar sistemas com status de erro
        app.state.systems = {
            'abiss': {'status': 'unhealthy', 'initialized': False, 'error': str(e)},
            'nnis': {'status': 'unhealthy', 'initialized': False, 'error': str(e)},
            'model_manager': {'status': 'unhealthy', 'initialized': False, 'error': str(e)}
        }
    
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
    redoc_url="/redoc"
)

# Inicializar configurações na criação do app
app.state.abiss_config = {
    "model_name": "google/gemma-3n-2b",
    "memory_size": 1000,
    "threat_threshold": 0.7,
    "learning_rate": 0.01,
    "enable_monitoring": True
}

app.state.nnis_config = {
    "model_name": "google/gemma-3n-2b",
    "memory_size": 1000,
    "immune_cell_count": 50,
    "memory_cell_count": 100,
    "threat_threshold": 0.8
}

app.state.systems = {
    'abiss': {'status': 'not_initialized', 'initialized': False},
    'nnis': {'status': 'not_initialized', 'initialized': False},
    'model_manager': {'status': 'healthy', 'initialized': True}
}

logger.info("Aplicação FastAPI criada com configurações lazy loading")

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

# Incluir routers
app.include_router(security.router, prefix="/api/v1", tags=["security"])


# Exception handler global
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.now(UTC).isoformat()
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
                        "last_check": datetime.now(UTC).isoformat()
                    }
                else:
                    systems_status[system_name] = {
                        "status": "unhealthy",
                        "error": "System not initialized",
                        "last_check": datetime.now(UTC).isoformat()
                    }
                    overall_status = "unhealthy"
            except Exception as e:
                systems_status[system_name] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "last_check": datetime.now(UTC).isoformat()
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
            "timestamp": datetime.now(UTC).isoformat(),
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
                "timestamp": datetime.now(UTC).isoformat()
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
        "timestamp": datetime.now(UTC).isoformat(),
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
    run_server(reload=False)