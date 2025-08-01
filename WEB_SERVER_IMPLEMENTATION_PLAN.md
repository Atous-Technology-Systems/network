# Plano de Implementação - Servidor Web e APIs

> **Data:** 2025-01-27  
> **Prioridade:** 🔴 **CRÍTICA**  
> **Estimativa:** 3-4 dias

## 📋 Problema Identificado

O sistema ATous Secure Network não possui servidor web ou APIs REST/WebSocket para operação em produção. O sistema atualmente funciona apenas como biblioteca, sem capacidade de receber requisições HTTP ou comunicação em tempo real.

## 🎯 Objetivos

1. **Implementar servidor FastAPI** com endpoints essenciais
2. **Criar APIs REST** baseadas em `api-contracts.md`
3. **Implementar WebSockets** para comunicação P2P
4. **Adicionar health checks** e métricas
5. **Configurar CORS e segurança**
6. **Implementar autenticação** e autorização

## 🛠️ Implementação

### ETAPA 1: Estrutura Base do Servidor

#### 1.1 Criar Módulo API

**Estrutura de Diretórios:**
```
atous_sec_network/
├── api/
│   ├── __init__.py
│   ├── server.py          # Servidor principal FastAPI
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── health.py      # Health checks
│   │   ├── model.py       # Model management
│   │   ├── security.py    # Security endpoints
│   │   ├── network.py     # Network management
│   │   └── metrics.py     # Prometheus metrics
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth.py        # Autenticação
│   │   ├── cors.py        # CORS configuration
│   │   └── logging.py     # Request logging
│   ├── models/
│   │   ├── __init__.py
│   │   ├── requests.py    # Pydantic request models
│   │   └── responses.py   # Pydantic response models
│   └── websockets/
│       ├── __init__.py
│       ├── manager.py     # WebSocket manager
│       └── handlers.py    # WebSocket handlers
```

#### 1.2 Servidor Principal FastAPI

**Arquivo:** `atous_sec_network/api/server.py`

```python
"""
Servidor principal FastAPI para ATous Secure Network
"""
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
import logging
from datetime import datetime
from typing import Dict, Any

from ..core.logging_config import get_logger
from .routes import health, model, security, network, metrics
from .middleware.auth import AuthMiddleware
from .middleware.logging import LoggingMiddleware
from .websockets.manager import WebSocketManager

# Logger
logger = get_logger('api.server')

# Global instances
websocket_manager = WebSocketManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação"""
    # Startup
    logger.info("Iniciando ATous Secure Network API Server")
    
    # Inicializar componentes do sistema
    try:
        from ..security.abiss_system import ABISSSystem
        from ..security.nnis_system import NNISSystem
        from ..core.model_manager_impl import ModelManagerImpl
        from ..network.p2p_recovery import P2PRecoverySystem
        
        # Inicializar sistemas
        app.state.abiss = ABISSSystem()
        app.state.nnis = NNISSystem()
        app.state.model_manager = ModelManagerImpl()
        app.state.p2p_recovery = P2PRecoverySystem()
        app.state.websocket_manager = websocket_manager
        
        logger.info("Todos os sistemas inicializados com sucesso")
        
    except Exception as e:
        logger.error("Falha na inicialização dos sistemas: %s", str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Finalizando ATous Secure Network API Server")
    
    # Cleanup
    if hasattr(app.state, 'p2p_recovery'):
        app.state.p2p_recovery.stop_monitoring()
    
    await websocket_manager.disconnect_all()
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
    allowed_hosts=["localhost", "127.0.0.1", "*.atous.tech"]
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Middleware customizado
app.add_middleware(LoggingMiddleware)
app.add_middleware(AuthMiddleware)

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

# Incluir rotas
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(model.router, prefix="/model", tags=["model"])
app.include_router(security.router, prefix="/security", tags=["security"])
app.include_router(network.router, prefix="/network", tags=["network"])
app.include_router(metrics.router, prefix="/metrics", tags=["metrics"])

# WebSocket endpoint
from .websockets.handlers import websocket_endpoint
app.add_websocket_route("/ws/{node_id}", websocket_endpoint)

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
            "metrics": "/metrics",
            "websocket": "/ws/{node_id}"
        }
    }


def create_app() -> FastAPI:
    """Factory function para criar aplicação"""
    return app


def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    log_level: str = "info"
):
    """Executa o servidor"""
    logger.info("Iniciando servidor em %s:%d", host, port)
    
    uvicorn.run(
        "atous_sec_network.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
        access_log=True
    )


if __name__ == "__main__":
    run_server(reload=True)
```

### ETAPA 2: Implementar Rotas Essenciais

#### 2.1 Health Checks

**Arquivo:** `atous_sec_network/api/routes/health.py`

```python
"""
Endpoints de health check e status do sistema
"""
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from typing import Dict, Any
import psutil
import asyncio

from ...core.logging_config import get_logger
from ..models.responses import HealthResponse, SystemStatusResponse

logger = get_logger('api.health')
router = APIRouter()


@router.get("/", response_model=HealthResponse)
async def health_check():
    """Health check básico"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version="2.0.0"
    )


@router.get("/detailed", response_model=SystemStatusResponse)
async def detailed_health_check(request):
    """Health check detalhado com status de todos os componentes"""
    try:
        # Verificar componentes do sistema
        components_status = {}
        
        # ABISS System
        try:
            abiss = request.app.state.abiss
            components_status["abiss"] = {
                "status": "healthy" if abiss else "unavailable",
                "details": "ABISS Security System operational"
            }
        except Exception as e:
            components_status["abiss"] = {
                "status": "error",
                "details": str(e)
            }
        
        # NNIS System
        try:
            nnis = request.app.state.nnis
            components_status["nnis"] = {
                "status": "healthy" if nnis else "unavailable",
                "details": "NNIS Immune System operational"
            }
        except Exception as e:
            components_status["nnis"] = {
                "status": "error",
                "details": str(e)
            }
        
        # Model Manager
        try:
            model_manager = request.app.state.model_manager
            components_status["model_manager"] = {
                "status": "healthy" if model_manager else "unavailable",
                "details": "Model Manager operational"
            }
        except Exception as e:
            components_status["model_manager"] = {
                "status": "error",
                "details": str(e)
            }
        
        # P2P Recovery
        try:
            p2p = request.app.state.p2p_recovery
            components_status["p2p_recovery"] = {
                "status": "healthy" if p2p else "unavailable",
                "details": "P2P Recovery System operational"
            }
        except Exception as e:
            components_status["p2p_recovery"] = {
                "status": "error",
                "details": str(e)
            }
        
        # System metrics
        system_metrics = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "uptime_seconds": (datetime.utcnow() - datetime.utcnow()).total_seconds()
        }
        
        # Determinar status geral
        all_healthy = all(
            comp["status"] == "healthy" 
            for comp in components_status.values()
        )
        
        overall_status = "healthy" if all_healthy else "degraded"
        
        return SystemStatusResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version="2.0.0",
            components=components_status,
            system_metrics=system_metrics
        )
        
    except Exception as e:
        logger.error("Erro no health check detalhado: %s", str(e))
        raise HTTPException(status_code=500, detail="Health check failed")


@router.get("/ready")
async def readiness_check(request):
    """Verifica se o sistema está pronto para receber tráfego"""
    try:
        # Verificar se componentes críticos estão inicializados
        required_components = ['abiss', 'nnis', 'model_manager', 'p2p_recovery']
        
        for component in required_components:
            if not hasattr(request.app.state, component):
                return {"ready": False, "reason": f"Component {component} not initialized"}
        
        return {"ready": True, "timestamp": datetime.utcnow()}
        
    except Exception as e:
        logger.error("Erro no readiness check: %s", str(e))
        return {"ready": False, "reason": str(e)}


@router.get("/live")
async def liveness_check():
    """Verifica se o processo está vivo"""
    return {"alive": True, "timestamp": datetime.utcnow()}
```

#### 2.2 Model Management API

**Arquivo:** `atous_sec_network/api/routes/model.py`

```python
"""
Endpoints para gerenciamento de modelos
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional
from datetime import datetime

from ...core.logging_config import get_logger
from ..models.requests import ModelVersionRequest, ModelUpdateRequest
from ..models.responses import ModelVersionResponse, ModelUpdateResponse

logger = get_logger('api.model')
router = APIRouter()


@router.get("/version", response_model=ModelVersionResponse)
async def get_model_version(
    node_id: str,
    current_version: int,
    model_type: str = "default",
    request: Request = None
):
    """Verifica versão mais recente do modelo"""
    try:
        logger.info("Model version check: node_id=%s, current=%d, type=%s", 
                   node_id, current_version, model_type)
        
        model_manager = request.app.state.model_manager
        
        # Simular verificação de versão (implementar lógica real)
        latest_version = 5  # Placeholder
        update_available = latest_version > current_version
        
        response = ModelVersionResponse(
            latest_version=latest_version,
            update_available=update_available,
            update_required=False,
            update_url=f"/model/diff/{current_version}/{latest_version}" if update_available else None,
            full_model_url=f"/model/full/{latest_version}",
            metadata={
                "release_date": "2025-01-15T10:30:00Z",
                "size_bytes": 12500000,
                "diff_size_bytes": 250000 if update_available else 0,
                "release_notes": "Improved anomaly detection for industrial environments"
            }
        )
        
        logger.info("Model version response: latest=%d, update_available=%s", 
                   latest_version, update_available)
        
        return response
        
    except Exception as e:
        logger.error("Erro ao verificar versão do modelo: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to check model version")


@router.get("/diff/{from_version}/{to_version}")
async def get_model_diff(
    from_version: int,
    to_version: int,
    node_id: str,
    model_type: str = "default",
    format: str = "bsdiff",
    request: Request = None
):
    """Obtém patch binário para atualização de modelo"""
    try:
        logger.info("Model diff request: %d -> %d, node_id=%s, format=%s", 
                   from_version, to_version, node_id, format)
        
        model_manager = request.app.state.model_manager
        
        # Implementar lógica de geração de diff
        # Por enquanto, retornar erro não implementado
        raise HTTPException(
            status_code=501, 
            detail="Model diff generation not implemented yet"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Erro ao gerar diff do modelo: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to generate model diff")


@router.get("/full/{version}")
async def get_full_model(
    version: int,
    node_id: str,
    model_type: str = "default",
    request: Request = None
):
    """Obtém modelo completo"""
    try:
        logger.info("Full model request: version=%d, node_id=%s, type=%s", 
                   version, node_id, model_type)
        
        model_manager = request.app.state.model_manager
        
        # Implementar lógica de download de modelo completo
        raise HTTPException(
            status_code=501, 
            detail="Full model download not implemented yet"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Erro ao obter modelo completo: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to get full model")


@router.post("/update", response_model=ModelUpdateResponse)
async def update_model(
    update_request: ModelUpdateRequest,
    request: Request = None
):
    """Inicia atualização de modelo"""
    try:
        logger.info("Model update request: node_id=%s, target_version=%d", 
                   update_request.node_id, update_request.target_version)
        
        model_manager = request.app.state.model_manager
        
        # Implementar lógica de atualização
        # Por enquanto, simular sucesso
        
        return ModelUpdateResponse(
            success=True,
            message="Model update initiated successfully",
            update_id="update_" + str(int(datetime.utcnow().timestamp())),
            estimated_completion=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error("Erro na atualização do modelo: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to update model")


@router.get("/status/{node_id}")
async def get_model_status(
    node_id: str,
    request: Request = None
):
    """Obtém status atual do modelo no nó"""
    try:
        logger.info("Model status request: node_id=%s", node_id)
        
        model_manager = request.app.state.model_manager
        
        # Implementar lógica de status
        return {
            "node_id": node_id,
            "current_version": 4,
            "status": "operational",
            "last_update": "2025-01-15T10:30:00Z",
            "next_check": "2025-01-27T12:00:00Z"
        }
        
    except Exception as e:
        logger.error("Erro ao obter status do modelo: %s", str(e))
        raise HTTPException(status_code=500, detail="Failed to get model status")
```

### ETAPA 3: WebSockets para Comunicação P2P

#### 3.1 WebSocket Manager

**Arquivo:** `atous_sec_network/api/websockets/manager.py`

```python
"""
Gerenciador de conexões WebSocket
"""
from fastapi import WebSocket
from typing import Dict, List, Set
import json
import asyncio
from datetime import datetime

from ...core.logging_config import get_logger

logger = get_logger('api.websocket')


class WebSocketManager:
    """Gerencia conexões WebSocket para comunicação P2P"""
    
    def __init__(self):
        # Conexões ativas: node_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        
        # Grupos de nós: group_name -> Set[node_id]
        self.node_groups: Dict[str, Set[str]] = {}
        
        # Estatísticas
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_received": 0
        }
    
    async def connect(self, websocket: WebSocket, node_id: str):
        """Aceita nova conexão WebSocket"""
        await websocket.accept()
        
        # Desconectar conexão anterior se existir
        if node_id in self.active_connections:
            await self.disconnect(node_id)
        
        self.active_connections[node_id] = websocket
        self.connection_stats["total_connections"] += 1
        self.connection_stats["active_connections"] = len(self.active_connections)
        
        logger.info("WebSocket connected: node_id=%s, total_active=%d", 
                   node_id, len(self.active_connections))
        
        # Notificar outros nós sobre nova conexão
        await self.broadcast_to_group(
            "network",
            {
                "type": "node_connected",
                "node_id": node_id,
                "timestamp": datetime.utcnow().isoformat()
            },
            exclude=[node_id]
        )
    
    async def disconnect(self, node_id: str):
        """Desconecta nó específico"""
        if node_id in self.active_connections:
            websocket = self.active_connections[node_id]
            
            try:
                await websocket.close()
            except Exception as e:
                logger.warning("Erro ao fechar WebSocket para %s: %s", node_id, str(e))
            
            del self.active_connections[node_id]
            self.connection_stats["active_connections"] = len(self.active_connections)
            
            # Remover de todos os grupos
            for group_nodes in self.node_groups.values():
                group_nodes.discard(node_id)
            
            logger.info("WebSocket disconnected: node_id=%s, remaining=%d", 
                       node_id, len(self.active_connections))
            
            # Notificar outros nós sobre desconexão
            await self.broadcast_to_group(
                "network",
                {
                    "type": "node_disconnected",
                    "node_id": node_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
    
    async def send_personal_message(self, message: dict, node_id: str):
        """Envia mensagem para nó específico"""
        if node_id in self.active_connections:
            websocket = self.active_connections[node_id]
            try:
                await websocket.send_text(json.dumps(message))
                self.connection_stats["messages_sent"] += 1
                logger.debug("Message sent to %s: %s", node_id, message.get("type", "unknown"))
            except Exception as e:
                logger.error("Erro ao enviar mensagem para %s: %s", node_id, str(e))
                await self.disconnect(node_id)
        else:
            logger.warning("Tentativa de enviar mensagem para nó desconectado: %s", node_id)
    
    async def broadcast_to_group(self, group_name: str, message: dict, exclude: List[str] = None):
        """Envia mensagem para todos os nós de um grupo"""
        exclude = exclude or []
        
        if group_name in self.node_groups:
            target_nodes = self.node_groups[group_name] - set(exclude)
            
            for node_id in target_nodes:
                await self.send_personal_message(message, node_id)
            
            logger.debug("Broadcast to group %s: %d nodes, message type: %s", 
                        group_name, len(target_nodes), message.get("type", "unknown"))
    
    async def broadcast_to_all(self, message: dict, exclude: List[str] = None):
        """Envia mensagem para todos os nós conectados"""
        exclude = exclude or []
        
        for node_id in self.active_connections:
            if node_id not in exclude:
                await self.send_personal_message(message, node_id)
        
        logger.debug("Broadcast to all: %d nodes, message type: %s", 
                    len(self.active_connections) - len(exclude), 
                    message.get("type", "unknown"))
    
    def add_to_group(self, node_id: str, group_name: str):
        """Adiciona nó a um grupo"""
        if group_name not in self.node_groups:
            self.node_groups[group_name] = set()
        
        self.node_groups[group_name].add(node_id)
        logger.debug("Node %s added to group %s", node_id, group_name)
    
    def remove_from_group(self, node_id: str, group_name: str):
        """Remove nó de um grupo"""
        if group_name in self.node_groups:
            self.node_groups[group_name].discard(node_id)
            logger.debug("Node %s removed from group %s", node_id, group_name)
    
    async def disconnect_all(self):
        """Desconecta todos os nós"""
        node_ids = list(self.active_connections.keys())
        
        for node_id in node_ids:
            await self.disconnect(node_id)
        
        logger.info("All WebSocket connections closed")
    
    def get_stats(self) -> dict:
        """Retorna estatísticas das conexões"""
        return {
            **self.connection_stats,
            "groups": {name: len(nodes) for name, nodes in self.node_groups.items()},
            "connected_nodes": list(self.active_connections.keys())
        }
```

### ETAPA 4: Modelos Pydantic

#### 4.1 Request Models

**Arquivo:** `atous_sec_network/api/models/requests.py`

```python
"""
Modelos Pydantic para requisições
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class ModelVersionRequest(BaseModel):
    """Requisição de verificação de versão de modelo"""
    node_id: str = Field(..., description="ID único do nó")
    current_version: int = Field(..., description="Versão atual do modelo")
    model_type: str = Field("default", description="Tipo do modelo")


class ModelUpdateRequest(BaseModel):
    """Requisição de atualização de modelo"""
    node_id: str = Field(..., description="ID único do nó")
    target_version: int = Field(..., description="Versão de destino")
    model_type: str = Field("default", description="Tipo do modelo")
    force_update: bool = Field(False, description="Forçar atualização")


class SecurityThreatRequest(BaseModel):
    """Requisição de relatório de ameaça"""
    node_id: str = Field(..., description="ID do nó que detectou a ameaça")
    threat_type: str = Field(..., description="Tipo da ameaça")
    severity: str = Field(..., description="Severidade (low, medium, high, critical)")
    details: Dict[str, Any] = Field(..., description="Detalhes da ameaça")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class NetworkJoinRequest(BaseModel):
    """Requisição para juntar-se à rede"""
    node_id: str = Field(..., description="ID único do nó")
    node_type: str = Field(..., description="Tipo do nó (sensor, gateway, server)")
    capabilities: Dict[str, Any] = Field(..., description="Capacidades do nó")
    location: Optional[Dict[str, float]] = Field(None, description="Localização geográfica")
```

#### 4.2 Response Models

**Arquivo:** `atous_sec_network/api/models/responses.py`

```python
"""
Modelos Pydantic para respostas
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class HealthResponse(BaseModel):
    """Resposta de health check básico"""
    status: str = Field(..., description="Status da aplicação")
    timestamp: datetime = Field(..., description="Timestamp da verificação")
    version: str = Field(..., description="Versão da aplicação")


class SystemStatusResponse(BaseModel):
    """Resposta de health check detalhado"""
    status: str = Field(..., description="Status geral do sistema")
    timestamp: datetime = Field(..., description="Timestamp da verificação")
    version: str = Field(..., description="Versão da aplicação")
    components: Dict[str, Dict[str, str]] = Field(..., description="Status dos componentes")
    system_metrics: Dict[str, float] = Field(..., description="Métricas do sistema")


class ModelVersionResponse(BaseModel):
    """Resposta de verificação de versão de modelo"""
    latest_version: int = Field(..., description="Versão mais recente disponível")
    update_available: bool = Field(..., description="Se há atualização disponível")
    update_required: bool = Field(..., description="Se a atualização é obrigatória")
    update_url: Optional[str] = Field(None, description="URL para download do patch")
    full_model_url: str = Field(..., description="URL para download do modelo completo")
    metadata: Dict[str, Any] = Field(..., description="Metadados da versão")


class ModelUpdateResponse(BaseModel):
    """Resposta de atualização de modelo"""
    success: bool = Field(..., description="Se a atualização foi iniciada com sucesso")
    message: str = Field(..., description="Mensagem de status")
    update_id: str = Field(..., description="ID único da atualização")
    estimated_completion: datetime = Field(..., description="Tempo estimado de conclusão")


class SecurityThreatResponse(BaseModel):
    """Resposta de relatório de ameaça"""
    threat_id: str = Field(..., description="ID único da ameaça")
    status: str = Field(..., description="Status do processamento")
    actions_taken: List[str] = Field(..., description="Ações tomadas")
    recommendations: List[str] = Field(..., description="Recomendações")


class NetworkStatusResponse(BaseModel):
    """Resposta de status da rede"""
    total_nodes: int = Field(..., description="Total de nós na rede")
    active_nodes: int = Field(..., description="Nós ativos")
    network_health: str = Field(..., description="Saúde geral da rede")
    partitions: int = Field(..., description="Número de partições detectadas")
    last_update: datetime = Field(..., description="Última atualização")
```

## 📋 Checklist de Implementação

### Fase 1: Estrutura Base
- [ ] Criar estrutura de diretórios da API
- [ ] Implementar servidor FastAPI principal
- [ ] Configurar middleware básico
- [ ] Implementar health checks

### Fase 2: APIs Essenciais
- [ ] Endpoints de modelo (version, diff, full)
- [ ] Endpoints de segurança
- [ ] Endpoints de rede
- [ ] Métricas Prometheus

### Fase 3: WebSockets
- [ ] WebSocket manager
- [ ] Handlers de mensagens
- [ ] Grupos e broadcasting
- [ ] Autenticação WebSocket

### Fase 4: Segurança
- [ ] Autenticação JWT
- [ ] Autorização baseada em roles
- [ ] Rate limiting
- [ ] CORS e HTTPS

### Fase 5: Testes
- [ ] Testes de endpoints
- [ ] Testes de WebSocket
- [ ] Testes de integração
- [ ] Testes de carga

## 🚀 Script de Inicialização

**Arquivo:** `start_server.py`

```python
#!/usr/bin/env python3
"""
Script para inicializar o servidor ATous Secure Network
"""
import os
import sys
from pathlib import Path

# Adicionar diretório do projeto ao path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from atous_sec_network.core.logging_config import setup_logging
from atous_sec_network.api.server import run_server

def main():
    # Configurar logging
    setup_logging(
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        log_dir=os.getenv('LOG_DIR', 'logs')
    )
    
    # Configurações do servidor
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 8000))
    reload = os.getenv('RELOAD', 'false').lower() == 'true'
    
    # Iniciar servidor
    run_server(
        host=host,
        port=port,
        reload=reload,
        log_level=os.getenv('UVICORN_LOG_LEVEL', 'info')
    )

if __name__ == '__main__':
    main()
```

Esta implementação fornecerá uma base sólida para o servidor web com APIs REST e WebSockets, permitindo operação em produção com monitoramento adequado.