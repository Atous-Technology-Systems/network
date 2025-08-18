"""
Rotas de LLM para ATous Secure Network

Este módulo implementa endpoints para:
- Comunicação com o modelo Gemma 3N
- Consultas inteligentes sobre o sistema
- Fine-tuning automático
- Assistente virtual da plataforma
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime, UTC
import json
import asyncio
import logging

from ...ml.llm_service import llm_service, LLMResponse, FineTuningResult
from ...core.logging_config import get_logger

logger = get_logger('api.routes.llm')

router = APIRouter(prefix="", tags=["llm"])

# Modelos Pydantic
class LLMQueryRequest(BaseModel):
    """Request para consulta ao LLM"""
    question: str = Field(..., description="Pergunta para o LLM", min_length=1, max_length=1000)
    context: Optional[Dict[str, Any]] = Field(None, description="Contexto adicional para a pergunta")
    include_system_context: bool = Field(True, description="Incluir contexto do sistema automaticamente")

class LLMQueryResponse(BaseModel):
    """Response da consulta ao LLM"""
    answer: str
    confidence: float
    sources: List[str]
    metadata: Dict[str, Any]
    timestamp: str
    processing_time: float

class FineTuningRequest(BaseModel):
    """Request para iniciar fine-tuning manual"""
    force: bool = Field(False, description="Forçar fine-tuning mesmo se já estiver em execução")

class FineTuningResponse(BaseModel):
    """Response do fine-tuning"""
    success: bool
    improvements: Dict[str, float]
    new_thresholds: Dict[str, float]
    training_loss: float
    timestamp: str
    message: str

class LLMStatusResponse(BaseModel):
    """Status do serviço LLM"""
    is_loaded: bool
    is_training: bool
    model_path: str
    metrics: Dict[str, Any]
    last_fine_tuning: Optional[str] = None

# WebSocket connections
class ConnectionManager:
    """Gerencia conexões WebSocket para LLM"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.llm_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket, connection_type: str = "general"):
        """Conecta um novo WebSocket"""
        await websocket.accept()
        if connection_type == "llm":
            self.llm_connections.append(websocket)
        else:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket conectado. Tipo: {connection_type}, Total: {len(self.active_connections) + len(self.llm_connections)}")
    
    def disconnect(self, websocket: WebSocket, connection_type: str = "general"):
        """Desconecta um WebSocket"""
        if connection_type == "llm":
            if websocket in self.llm_connections:
                self.llm_connections.remove(websocket)
        else:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket desconectado. Tipo: {connection_type}, Total: {len(self.active_connections) + len(self.llm_connections)}")
    
    async def broadcast_to_llm(self, message: Dict[str, Any]):
        """Envia mensagem para todas as conexões LLM"""
        if self.llm_connections:
            for connection in self.llm_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Erro ao enviar para WebSocket LLM: {e}")
                    # Remover conexão problemática
                    if connection in self.llm_connections:
                        self.llm_connections.remove(connection)

# Instância global do manager
connection_manager = ConnectionManager()

# Endpoints REST
@router.post("/query", response_model=LLMQueryResponse)
async def query_llm(request: LLMQueryRequest):
    """
    Consulta o LLM com uma pergunta
    
    Este endpoint permite fazer perguntas ao modelo Gemma 3N sobre:
    - Status do sistema de segurança
    - Estatísticas de usuários e ameaças
    - Configurações e otimizações
    - Assistência geral da plataforma
    """
    try:
        start_time = datetime.now(UTC)
        
        # Verificar se o modelo está pronto
        if not llm_service.is_model_ready():
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Modelo LLM não está pronto",
                    "status": llm_service.get_model_status(),
                    "message": "Aguarde o carregamento ou verifique o status do modelo"
                }
            )
        
        # Obter contexto do sistema se solicitado
        context = request.context or {}
        if request.include_system_context:
            system_context = await llm_service.get_system_context()
            context.update(system_context)
        
        # Executar consulta
        response = await llm_service.query(request.question, context)
        
        # Calcular tempo de processamento
        end_time = datetime.now(UTC)
        processing_time = (end_time - start_time).total_seconds()
        
        # Log da consulta
        logger.info(f"Consulta LLM processada: '{request.question[:50]}...' em {processing_time:.2f}s")
        
        return LLMQueryResponse(
            answer=response.answer,
            confidence=response.confidence,
            sources=response.sources,
            metadata=response.metadata,
            timestamp=response.timestamp,
            processing_time=processing_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao processar consulta LLM: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao processar consulta: {str(e)}"
        )

@router.post("/fine-tuning", response_model=FineTuningResponse)
async def start_fine_tuning(request: FineTuningRequest):
    """
    Inicia fine-tuning manual do sistema de segurança
    
    Este endpoint permite iniciar manualmente o processo de fine-tuning
    que otimiza os thresholds e parâmetros do sistema ABISS/NNIS.
    """
    try:
        # Verificar se o modelo está pronto
        if not llm_service.is_model_ready():
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Modelo LLM não está pronto",
                    "status": llm_service.get_model_status(),
                    "message": "Aguarde o carregamento ou verifique o status do modelo"
                }
            )
        
        # Verificar se já está em treinamento
        if llm_service.is_training and not request.force:
            raise HTTPException(
                status_code=409,
                detail="Fine-tuning já está em execução. Use force=true para forçar."
            )
        
        # Executar fine-tuning
        result = llm_service.perform_fine_tuning()
        
        # Broadcast para WebSockets se bem-sucedido
        if result.success:
            await connection_manager.broadcast_to_llm({
                "type": "fine_tuning_completed",
                "data": {
                    "improvements": result.improvements,
                    "new_thresholds": result.new_thresholds,
                    "timestamp": result.timestamp
                }
            })
        
        message = "Fine-tuning concluído com sucesso" if result.success else "Fine-tuning falhou"
        
        return FineTuningResponse(
            success=result.success,
            improvements=result.improvements,
            new_thresholds=result.new_thresholds,
            training_loss=result.training_loss,
            timestamp=result.timestamp,
            message=message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao iniciar fine-tuning: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao iniciar fine-tuning: {str(e)}"
        )

@router.get("/status", response_model=LLMStatusResponse)
async def get_llm_status():
    """
    Obtém status atual do serviço LLM
    
    Retorna informações sobre:
    - Status de carregamento do modelo
    - Status de treinamento
    - Métricas de performance
    - Último fine-tuning realizado
    """
    try:
        metrics = llm_service.get_metrics()
        
        return LLMStatusResponse(
            is_loaded=llm_service.is_loaded,
            is_training=llm_service.is_training,
            model_path=llm_service.model_path,
            metrics=metrics,
            last_fine_tuning=None  # TODO: Implementar tracking de último fine-tuning
        )
        
    except Exception as e:
        logger.error(f"Erro ao obter status LLM: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao obter status: {str(e)}"
        )

@router.post("/load-model")
async def load_llm_model():
    """
    Carrega o modelo LLM manualmente
    
    Este endpoint permite carregar o modelo Gemma 3N manualmente
    caso o carregamento automático tenha falhado.
    """
    try:
        if llm_service.is_loaded:
            return JSONResponse(
                content={"message": "Modelo já está carregado"},
                status_code=200
            )
        
        success = await llm_service.load_model()
        
        if success:
            return JSONResponse(
                content={"message": "Modelo carregado com sucesso"},
                status_code=200
            )
        else:
            raise HTTPException(
                status_code=500,
                detail="Falha ao carregar modelo"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao carregar modelo LLM: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao carregar modelo: {str(e)}"
        )

@router.get("/metrics")
async def get_llm_metrics():
    """
    Obtém métricas detalhadas do serviço LLM
    
    Retorna informações sobre:
    - Total de consultas processadas
    - Taxa de sucesso
    - Tempo médio de resposta
    - Tamanho do cache
    - Status do modelo
    """
    try:
        metrics = llm_service.get_metrics()
        
        return JSONResponse(content={
            "total_queries": metrics.get("total_queries", 0),
            "successful_responses": metrics.get("successful_responses", 0),
            "average_response_time": metrics.get("average_response_time", 0.0),
            "cache_size": metrics.get("cache_size", 0),
            "is_loaded": metrics.get("is_loaded", False),
            "is_training": metrics.get("is_training", False),
            "model_path": metrics.get("model_path", ""),
            "model_type": metrics.get("model_type", "unknown"),
            "tflite_available": metrics.get("tflite_available", False),
            "timestamp": datetime.now(UTC).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Erro ao obter métricas LLM: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao obter métricas: {str(e)}"
        )

@router.get("/context")
async def get_system_context():
    """
    Obtém contexto atual do sistema para o LLM
    
    Retorna informações sobre:
    - Status dos sistemas ABISS e NNIS
    - Estatísticas de usuários
    - Métricas de segurança
    - Status geral do sistema
    """
    try:
        context = await llm_service.get_system_context()
        return JSONResponse(content=context)
        
    except Exception as e:
        logger.error(f"Erro ao obter contexto do sistema: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao obter contexto: {str(e)}"
        )

@router.get("/model-status")
async def get_model_status():
    """
    Obtém status detalhado do modelo LLM
    
    Retorna informações sobre:
    - Status de carregamento (ready/degraded/unavailable)
    - Modo fallback
    - Detalhes do modelo
    - Mensagens de status
    """
    try:
        status = llm_service.get_model_status()
        return JSONResponse(content=status)
        
    except Exception as e:
        logger.error(f"Erro ao obter status do modelo: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro interno ao obter status do modelo: {str(e)}"
        )

# WebSocket endpoint para LLM
@router.websocket("/ws")
async def llm_websocket(websocket: WebSocket):
    """
    WebSocket para comunicação em tempo real com o LLM
    """
    try:
        await websocket.accept()
        
        # Enviar mensagem de boas-vindas
        await websocket.send_json({
            "type": "welcome",
            "message": "Conectado ao assistente LLM da ATous Secure Network",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Loop simples de comunicação
        while True:
            try:
                # Receber mensagem
                data = await websocket.receive_text()
                
                # Echo simples para teste
                await websocket.send_json({
                    "type": "echo",
                    "message": f"Recebido: {data}",
                    "timestamp": datetime.now(UTC).isoformat()
                })
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Erro no WebSocket LLM: {e}")
                break
                    
    except Exception as e:
        logger.error(f"Erro na conexão WebSocket LLM: {e}")

async def _handle_llm_query(websocket: WebSocket, message: Dict[str, Any]):
    """Processa consulta LLM via WebSocket"""
    try:
        question = message.get("question", "")
        context = message.get("context", {})
        
        if not question:
            await websocket.send_json({
                "type": "error",
                "message": "Pergunta é obrigatória",
                "timestamp": datetime.now(UTC).isoformat()
            })
            return
        
        # Enviar confirmação de recebimento
        await websocket.send_json({
            "type": "processing",
            "message": "Processando sua pergunta...",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Executar consulta
        response = await llm_service.query(question, context)
        
        # Enviar resposta
        await websocket.send_json({
            "type": "response",
            "data": {
                "answer": response.answer,
                "confidence": response.confidence,
                "sources": response.sources,
                "metadata": response.metadata,
                "timestamp": response.timestamp
            }
        })
        
    except Exception as e:
        logger.error(f"Erro ao processar consulta LLM via WebSocket: {e}")
        await websocket.send_json({
            "type": "error",
            "message": f"Erro ao processar consulta: {str(e)}",
            "timestamp": datetime.now(UTC).isoformat()
        })

async def _handle_fine_tuning_request(websocket: WebSocket, message: Dict[str, Any]):
    """Processa solicitação de fine-tuning via WebSocket"""
    try:
        force = message.get("force", False)
        
        # Enviar confirmação
        await websocket.send_json({
            "type": "fine_tuning_started",
            "message": "Iniciando fine-tuning...",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Executar fine-tuning
        result = llm_service.perform_fine_tuning()
        
        # Enviar resultado
        await websocket.send_json({
            "type": "fine_tuning_completed",
            "data": {
                "success": result.success,
                "improvements": result.improvements,
                "new_thresholds": result.new_thresholds,
                "training_loss": result.training_loss,
                "timestamp": result.timestamp
            }
        })
        
    except Exception as e:
        logger.error(f"Erro ao processar fine-tuning via WebSocket: {e}")
        await websocket.send_json({
            "type": "error",
            "message": f"Erro no fine-tuning: {str(e)}",
            "timestamp": datetime.now(UTC).isoformat()
        })

# Event handlers
@router.on_event("startup")
async def startup_event():
    """Evento de inicialização"""
    logger.info("Iniciando serviço LLM...")
    
    # Carregar modelo em background
    asyncio.create_task(_load_model_background())

@router.on_event("shutdown")
async def shutdown_event():
    """Evento de desligamento"""
    logger.info("Desligando serviço LLM...")
    await llm_service.shutdown()

async def _load_model_background():
    """Carrega modelo em background"""
    try:
        await asyncio.sleep(5)  # Aguardar sistema inicializar
        success = await llm_service.load_model()
        if success:
            logger.info("Modelo LLM carregado com sucesso em background")
        else:
            logger.warning("Falha ao carregar modelo LLM em background")
    except Exception as e:
        logger.error(f"Erro ao carregar modelo LLM em background: {e}")
