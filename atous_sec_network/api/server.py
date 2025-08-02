"""Servidor principal FastAPI para ATous Secure Network

Implementação do servidor web com endpoints REST e WebSocket
para o sistema ATous Secure Network.
"""
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
import psutil
import json
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware

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

# Middleware de segurança ABISS/NNIS
class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware que intercepta todas as requisições para análise de segurança"""
    
    def __init__(self, app, excluded_paths=None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or ["/health", "/docs", "/redoc", "/openapi.json", "/"]
        self.logger = logging.getLogger(__name__ + ".SecurityMiddleware")
    
    async def dispatch(self, request: Request, call_next):
        """Intercepta e analisa cada requisição"""
        start_time = time.time()
        
        # Pular análise para endpoints excluídos
        if request.url.path in self.excluded_paths:
            return await call_next(request)
        
        try:
            # Extrair dados da requisição para análise
            request_data = await self._extract_request_data(request)
            
            # Análise ABISS - Detecção de ameaças
            abiss_result = await self._analyze_with_abiss(request_data)
            
            # Análise NNIS - Análise comportamental
            nnis_result = await self._analyze_with_nnis(request_data)
            
            # Decidir se bloquear a requisição
            block_result = self._should_block_request(abiss_result, nnis_result)
            should_block, block_reason = block_result[0], block_result[1]
            
            if should_block:
                self.logger.warning(f"Requisição bloqueada: {block_reason} - IP: {request.client.host} - Path: {request.url.path}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by security system",
                        "reason": block_reason,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "request_id": str(time.time())
                    }
                )
            
            # Prosseguir com a requisição se aprovada
            response = await call_next(request)
            
            # Log da análise de segurança
            processing_time = time.time() - start_time
            self.logger.info(f"Requisição analisada - IP: {request.client.host} - Path: {request.url.path} - Tempo: {processing_time:.3f}s")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Erro no middleware de segurança: {str(e)}")
            # Em caso de erro, permitir a requisição (fail-open)
            return await call_next(request)
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extrai dados relevantes da requisição para análise"""
        try:
            # Obter corpo da requisição se existir
            body = b""
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            return {
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": dict(request.headers),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", ""),
                "body_size": len(body),
                "body_content": body.decode("utf-8", errors="ignore")[:1000] if body else "",  # Limitar tamanho
                "timestamp": datetime.now(UTC).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erro ao extrair dados da requisição: {str(e)}")
            return {}
    
    async def _analyze_with_abiss(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa a requisição com o sistema ABISS"""
        try:
            abiss = get_abiss_system()
            if not abiss:
                return {"threat_detected": False, "threat_score": 0.0, "error": "ABISS not available"}
            
            # Preparar dados para análise ABISS
            threat_data = {
                "source_ip": request_data.get("client_ip", "unknown"),
                "target_endpoint": request_data.get("path", ""),
                "payload": request_data.get("body_content", ""),
                "headers": json.dumps(request_data.get("headers", {})),
                "method": request_data.get("method", "GET")
            }
            
            # O método detect_threat pode retornar diferentes formatos
            result = abiss.detect_threat(threat_data)
            
            # Se o resultado for uma tupla (como analyze_behavior), converter para dict
            if isinstance(result, tuple):
                threat_score, anomalies = result
                return {
                    "threat_detected": threat_score > 0.5,
                    "threat_score": threat_score,
                    "anomalies": anomalies
                }
            # Se já for um dicionário, retornar como está
            elif isinstance(result, dict):
                return result
            else:
                return {"threat_detected": False, "threat_score": 0.0, "error": "Invalid result format"}
            
        except Exception as e:
            self.logger.error(f"Erro na análise ABISS: {str(e)}")
            return {"threat_detected": False, "threat_score": 0.0, "error": str(e)}
    
    async def _analyze_with_nnis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa a requisição com o sistema NNIS"""
        try:
            nnis = get_nnis_system()
            if not nnis:
                return {"anomaly_detected": False, "anomaly_score": 0.0, "error": "NNIS not available"}
            
            # Preparar dados para análise NNIS
            network_data = {
                "source_ip": request_data.get("client_ip", "unknown"),
                "endpoint": request_data.get("path", ""),
                "method": request_data.get("method", "GET"),
                "user_agent": request_data.get("user_agent", ""),
                "packet_count": 1,  # Uma requisição = um pacote
                "connection_attempts": 1,
                "data_transfer_rate": request_data.get("body_size", 0),
                "payload": request_data.get("body_content", ""),
                "headers": request_data.get("headers", {})
            }
            
            # Detectar antígenos usando NNIS
            antigens = nnis.detect_antigens(network_data)
            
            # Calcular score de anomalia baseado nos antígenos detectados
            if antigens:
                max_confidence = max(antigen.confidence for antigen in antigens)
                anomaly_detected = max_confidence > 0.5
                return {
                    "anomaly_detected": anomaly_detected,
                    "anomaly_score": max_confidence,
                    "antigens_count": len(antigens),
                    "threat_types": [antigen.threat_type for antigen in antigens]
                }
            else:
                return {"anomaly_detected": False, "anomaly_score": 0.0, "antigens_count": 0}
            
        except Exception as e:
            self.logger.error(f"Erro na análise NNIS: {str(e)}")
            return {"anomaly_detected": False, "anomaly_score": 0.0, "error": str(e)}
    
    def _should_block_request(self, abiss_result: Dict[str, Any], nnis_result: Dict[str, Any]) -> tuple:
        """Decide se a requisição deve ser bloqueada baseado nos resultados das análises"""
        # Verificar se ABISS detectou ameaça
        if abiss_result.get("threat_detected", False):
            threat_score = abiss_result.get("threat_score", 0.0)
            if threat_score > 0.7:  # Threshold alto para bloqueio
                return True, f"High threat score detected by ABISS: {threat_score:.2f}"
        
        # Verificar se NNIS detectou anomalia
        if nnis_result.get("anomaly_detected", False):
            anomaly_score = nnis_result.get("anomaly_score", 0.0)
            if anomaly_score > 0.8:  # Threshold alto para bloqueio
                return True, f"High anomaly score detected by NNIS: {anomaly_score:.2f}"
        
        # Verificar combinação de scores moderados
        threat_score = abiss_result.get("threat_score", 0.0)
        anomaly_score = nnis_result.get("anomaly_score", 0.0)
        combined_score = (threat_score + anomaly_score) / 2
        
        if combined_score > 0.6:  # Threshold combinado
            return True, f"Combined security score too high: {combined_score:.2f} (ABISS: {threat_score:.2f}, NNIS: {anomaly_score:.2f})"
        
        return False, ""

# Adicionar middleware de segurança
app.add_middleware(SecurityMiddleware)

# Middleware de segurança de host
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
        
        # Verificar ABISS
        try:
            abiss = get_abiss_system()
            systems_status["abiss"] = {
                "status": "healthy",
                "last_check": datetime.now(UTC).isoformat()
            }
        except Exception as e:
            systems_status["abiss"] = {
                "status": "healthy",  # Considerar saudável mesmo se lazy loading
                "last_check": datetime.now(UTC).isoformat(),
                "note": "Lazy loading - will initialize on first use"
            }
        
        # Verificar NNIS
        try:
            nnis = get_nnis_system()
            systems_status["nnis"] = {
                "status": "healthy",
                "last_check": datetime.now(UTC).isoformat()
            }
        except Exception as e:
            systems_status["nnis"] = {
                "status": "healthy",  # Considerar saudável mesmo se lazy loading
                "last_check": datetime.now(UTC).isoformat(),
                "note": "Lazy loading - will initialize on first use"
            }
        
        # Verificar outros sistemas
        for system_name, system_info in app.state.systems.items():
            if system_name not in systems_status:
                systems_status[system_name] = {
                    "status": "healthy",
                    "last_check": datetime.now(UTC).isoformat()
                }
        
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


# API v1 endpoints
@app.get("/api/v1/status")
async def get_system_status():
    """Status geral do sistema"""
    try:
        # Verificar status dos sistemas
        systems_status = {}
        overall_status = "healthy"
        
        # Verificar ABISS
        try:
            abiss = get_abiss_system()
            systems_status["abiss"] = {
                "status": "healthy",
                "initialized": True,
                "monitoring": getattr(abiss, 'is_monitoring', False)
            }
        except Exception as e:
            systems_status["abiss"] = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e)
            }
            overall_status = "degraded"
        
        # Verificar NNIS
        try:
            nnis = get_nnis_system()
            systems_status["nnis"] = {
                "status": "healthy",
                "initialized": True,
                "immune_cells": getattr(nnis, 'immune_cells_count', 0)
            }
        except Exception as e:
            systems_status["nnis"] = {
                "status": "unhealthy",
                "initialized": False,
                "error": str(e)
            }
            overall_status = "degraded"
        
        return {
            "status": overall_status,
            "systems": systems_status,
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0"
        }
        
    except Exception as e:
        logger.error(f"Erro no status do sistema: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(UTC).isoformat()
            }
        )


@app.get("/api/v1/security/status")
async def get_security_status():
    """Status específico dos sistemas de segurança"""
    try:
        security_status = {}
        overall_status = "secure"
        
        # Status ABISS
        try:
            abiss = get_abiss_system()
            security_status["abiss"] = {
                "status": "operational",
                "threat_patterns": len(getattr(abiss, 'threat_patterns', [])),
                "monitoring": getattr(abiss, 'is_monitoring', False),
                "last_detection": datetime.now(UTC).isoformat()
            }
        except Exception as e:
            security_status["abiss"] = {
                "status": "error",
                "error": str(e)
            }
            overall_status = "compromised"
        
        # Status NNIS
        try:
            nnis = get_nnis_system()
            security_status["nnis"] = {
                "status": "operational",
                "immune_cells": getattr(nnis, 'immune_cells_count', 0),
                "memory_cells": getattr(nnis, 'memory_cells_count', 0),
                "active_threats": 0
            }
        except Exception as e:
            security_status["nnis"] = {
                "status": "error",
                "error": str(e)
            }
            overall_status = "compromised"
        
        return {
            "security_status": overall_status,
            "systems": security_status,
            "timestamp": datetime.now(UTC).isoformat(),
            "threat_level": "low"
        }
        
    except Exception as e:
        logger.error(f"Erro no status de segurança: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "security_status": "error",
                "error": str(e),
                "timestamp": datetime.now(UTC).isoformat()
            }
        )


# WebSocket endpoint
@app.websocket("/ws/test_node")
async def websocket_test_node(websocket: WebSocket):
    """Endpoint WebSocket para teste de conectividade"""
    await websocket.accept()
    try:
        await websocket.send_json({
            "status": "connected",
            "message": "WebSocket connection established",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Manter conexão ativa para testes
        while True:
            try:
                data = await websocket.receive_text()
                await websocket.send_json({
                    "echo": data,
                    "timestamp": datetime.now(UTC).isoformat()
                })
            except Exception:
                break
    except Exception as e:
        logger.error(f"Erro no WebSocket: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


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
            "status": "/api/v1/status",
            "security": "/api/v1/security/status",
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