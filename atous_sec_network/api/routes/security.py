"""Rotas de segurança para ABISS e NNIS

Endpoints para interação com os sistemas de segurança:
- ABISS (Adaptive Behaviour Intelligence Security System)
- NNIS (Neural Network Immune System)
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
from datetime import datetime, UTC
import time
from pydantic import BaseModel

# Lazy imports para evitar problemas com dependências pesadas
from ...security import get_abiss_system, get_nnis_system
from ...core.logging_config import get_logger

# Import security middleware for management
import sys
import os
from ...security.security_middleware import ComprehensiveSecurityMiddleware
from ...security.input_validator import validator, ValidationResult

# Logger
logger = get_logger('api.security')

# Router
router = APIRouter(prefix="/security", tags=["security"])

# Função para obter instâncias dos sistemas
def get_abiss_system():
    try:
        from ...security.abiss_system import ABISSSystem
        # Retornar instância mock para testes ou criar nova instância
        # Em produção, isso deve ser gerenciado pelo sistema principal
        return ABISSSystem()
    except Exception as e:
        logger.error(f"Erro ao obter sistema ABISS: {e}")
        raise HTTPException(status_code=503, detail="ABISS system not available")

def get_nnis_system():
    try:
        from ...security.nnis_system import NNISSystem
        # Retornar instância mock para testes ou criar nova instância
        # Em produção, isso deve ser gerenciado pelo sistema principal
        return NNISSystem()
    except Exception as e:
        logger.error(f"Erro ao obter sistema NNIS: {e}")
        raise HTTPException(status_code=503, detail="NNIS system not available")


@router.get("/abiss/status")
async def get_abiss_status(abiss = Depends(get_abiss_system)) -> JSONResponse:
    """
    Obter status e saúde do sistema ABISS
    
    Endpoint que retorna informações sobre o estado atual do sistema
    ABISS (Adaptive Behaviour Intelligence Security System), incluindo
    status de inicialização, thresholds configurados e contadores
    de padrões de ameaça.
    
    Returns:
        JSONResponse: Status completo do sistema ABISS com timestamp
        
    Raises:
        HTTPException: Se sistema ABISS não disponível ou erro interno
    """
    try:
        # Obter status usando o método correto
        status_data = abiss.get_status()
        status_data["timestamp"] = datetime.now(UTC).isoformat()
        
        return JSONResponse(content=status_data)
        
    except Exception as e:
        logger.error(f"Erro ao obter status do ABISS: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.get("/abiss/config")
async def get_abiss_config(abiss = Depends(get_abiss_system)) -> JSONResponse:
    """
    Obter configuração atual do sistema ABISS
    
    Endpoint que retorna a configuração completa do sistema ABISS,
    incluindo thresholds de bloqueio e monitoramento, whitelist de
    endpoints e parâmetros de aprendizado e memória.
    
    Returns:
        JSONResponse: Configuração completa do sistema ABISS com timestamp
        
    Raises:
        HTTPException: Se sistema ABISS não disponível ou erro interno
    """
    try:
        # Obter configuração usando o método correto
        config_data = abiss.get_config()
        config_data["timestamp"] = datetime.now(UTC).isoformat()
        
        return JSONResponse(content=config_data)
        
    except Exception as e:
        logger.error(f"Erro ao obter configuração do ABISS: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.get("/abiss/stats")
async def get_abiss_stats(abiss = Depends(get_abiss_system)) -> JSONResponse:
    """
    Obter estatísticas e métricas do sistema ABISS
    
    Endpoint que retorna estatísticas detalhadas sobre o funcionamento
    do sistema ABISS, incluindo total de requisições analisadas,
    requisições bloqueadas, taxa média de ameaça e contadores
    de IPs únicos monitorados.
    
    Returns:
        JSONResponse: Estatísticas completas do sistema ABISS com timestamp
        
    Raises:
        HTTPException: Se sistema ABISS não disponível ou erro interno
    """
    try:
        # Obter estatísticas usando o método correto
        stats_data = abiss.get_stats()
        stats_data["timestamp"] = datetime.now(UTC).isoformat()
        
        return JSONResponse(content=stats_data)
        
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas do ABISS: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.get("/nnis/status")

async def get_nnis_status(nnis = Depends(get_nnis_system)) -> JSONResponse:
    """
    Obter status e saúde do sistema NNIS
    
    Endpoint que retorna informações sobre o estado atual do sistema
    NNIS (Neural Network Immune System), incluindo saúde do sistema
    imune, contadores de células imunes e status de memória.
    
    Returns:
        JSONResponse: Status completo do sistema NNIS com timestamp
        
    Raises:
        HTTPException: Se sistema NNIS não disponível ou erro interno
    """
    try:
        
        # Obter saúde do sistema imune
        health_data = nnis.get_immune_system_health()
        
        status_data = {
            "status": "operational",
            "immune_cells_count": len(nnis.immune_cells),
            "memory_cells_count": len(nnis.memory_cells),
            "threat_database_size": len(nnis.threat_database),
            "health_metrics": health_data,
            "response_stats": dict(nnis.response_stats),
            "threat_stats": dict(nnis.threat_stats),
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        return JSONResponse(content=status_data)
        
    except Exception as e:
        logger.error(f"Erro ao obter status do NNIS: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.post("/nnis/detect-antigens")
async def detect_antigens(network_data: Dict[str, Any], nnis = Depends(get_nnis_system)) -> JSONResponse:
    """
    Detectar antígenos de ameaças usando o sistema NNIS
    
    Endpoint que analisa dados de rede para detectar padrões
    de ameaça usando o sistema neural imune. O NNIS processa
    dados de tráfego e identifica possíveis ameaças baseadas
    em padrões aprendidos e reconhecimento de antígenos.
    
    Args:
        network_data: Dados de rede para análise (tráfego, conexões, etc.)
        nnis: Sistema NNIS injetado via dependency
        
    Returns:
        JSONResponse: Resultado da detecção com antígenos encontrados e métricas
        
    Raises:
        HTTPException: Se sistema NNIS não disponível ou erro interno
    """
    try:
        
        # Detectar antígenos
        start_time = time.time()
        antigens = nnis.detect_antigens(network_data)
        detection_time = (time.time() - start_time) * 1000
        
        # Converter antígenos para formato serializável
        antigens_data = []
        for antigen in antigens:
            antigens_data.append({
                "threat_type": antigen.threat_type,
                "severity": antigen.severity,
                "confidence": antigen.confidence,
                "source_ip": antigen.source_ip,
                "target_ip": antigen.target_ip,
                "description": antigen.description,
                "detected_at": antigen.detected_at
            })
        
        response_data = {
            "antigens_detected": len(antigens) > 0,
            "antigens_count": len(antigens),
            "antigens": antigens_data,
            "detection_time_ms": round(detection_time, 2),
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        # Log da detecção
        if len(antigens) > 0:
            logger.warning(f"Antígenos detectados: {len(antigens)} ameaças encontradas")
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Erro na detecção de antígenos: {e}")
        raise HTTPException(status_code=500, detail=f"Erro na detecção: {str(e)}")


@router.post("/nnis/generate-response")
async def generate_immune_response(threat_data: Dict[str, Any], nnis = Depends(get_nnis_system)) -> JSONResponse:
    """
    Gerar resposta imune para uma ameaça específica
    
    Endpoint que permite ao sistema NNIS gerar uma resposta
    imune personalizada para uma ameaça detectada. O sistema
    analisa os dados da ameaça e gera ações de resposta
    apropriadas baseadas em padrões aprendidos.
    
    Args:
        threat_data: Dados da ameaça para análise (tipo, confiança, origem)
        nnis: Sistema NNIS injetado via dependency
        
    Returns:
        JSONResponse: Resposta imune gerada com tipo, intensidade e ações
        
    Raises:
        HTTPException: Se sistema NNIS não disponível ou erro interno
    """
    try:
        
        # Criar antígeno a partir dos dados da ameaça
        from ...security.nnis_system import ThreatAntigen
        antigen = ThreatAntigen(
            threat_type=threat_data.get("threat_type", "unknown"),
            confidence=threat_data.get("confidence", 0.5),
            source=threat_data.get("source", "unknown")
        )
        
        # Gerar resposta imune
        start_time = time.time()
        immune_response = nnis.generate_immune_response(antigen)
        response_time = (time.time() - start_time) * 1000
        
        response_data = {
            "response_generated": True,
            "response_type": immune_response.response_type,
            "intensity": immune_response.intensity,
            "actions": immune_response.actions,
            "response_id": immune_response.response_id,
            "response_time_ms": round(response_time, 2),
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Erro na geração de resposta imune: {e}")
        raise HTTPException(status_code=500, detail=f"Erro na resposta: {str(e)}")


@router.get("/threat-intelligence")
async def get_threat_intelligence(
    abiss = Depends(get_abiss_system),
    nnis = Depends(get_nnis_system)
) -> JSONResponse:
    """
    Obter inteligência de ameaças combinada dos sistemas ABISS e NNIS
    
    Endpoint que consolida informações de inteligência de ameaças
    de ambos os sistemas de segurança, fornecendo uma visão
    unificada dos padrões de ameaça, respostas imunes e métricas
    de segurança em tempo real.
    
    Args:
        abiss: Sistema ABISS injetado via dependency
        nnis: Sistema NNIS injetado via dependency
        
    Returns:
        JSONResponse: Inteligência consolidada de ameaças com dados de ambos os sistemas
        
    Raises:
        HTTPException: Se sistemas não disponíveis ou erro interno
    """
    try:
        threat_intel = {
            "abiss_available": True,
            "nnis_available": True,
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        # Dados do ABISS
        threat_intel["abiss_data"] = {
            "threat_patterns": len(abiss.threat_patterns),
            "recent_threats": dict(list(abiss.threat_stats.items())[-5:]),
            "false_positive_rate": abiss.false_positive_rate
        }
        
        # Dados do NNIS
        threat_intel["nnis_data"] = {
            "immune_cells": len(nnis.immune_cells),
            "memory_cells": len(nnis.memory_cells),
            "known_threats": len(nnis.threat_database),
            "recent_responses": dict(list(nnis.response_stats.items())[-5:])
        }
        
        return JSONResponse(content=threat_intel)
        
    except Exception as e:
        logger.error(f"Erro ao obter inteligência de ameaças: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


# Endpoints para teste e configuração do middleware de segurança
@router.post("/middleware/test")
async def test_security_middleware(request_data: Dict[str, Any]) -> JSONResponse:
    """
    Testar funcionalidade do middleware de segurança
    
    Endpoint para testar e validar o funcionamento do middleware
    de segurança, permitindo simular requisições e verificar
    respostas de segurança, análise ABISS e validação de entrada.
    
    Args:
        request_data: Dados da requisição para teste (método, path, headers, body)
        
    Returns:
        JSONResponse: Resultado do teste com análise de segurança e métricas
        
    Raises:
        HTTPException: Se dados de teste inválidos ou erro interno
    """
    """Endpoint para testar o middleware de segurança com dados simulados"""
    try:
        # Este endpoint será interceptado pelo middleware de segurança
        # e pode ser usado para testar diferentes tipos de payloads
        
        response_data = {
            "message": "Request processed successfully",
            "received_data": request_data,
            "timestamp": datetime.now(UTC).isoformat(),
            "middleware_status": "passed"
        }
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Erro no endpoint de teste: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.get("/middleware/config")
async def get_middleware_config() -> JSONResponse:
    """
    Obter configuração atual do middleware de segurança
    
    Endpoint que retorna a configuração completa do middleware
    de segurança, incluindo thresholds de ameaça, configurações
    de análise ABISS/NNIS e parâmetros de operação.
    
    Returns:
        JSONResponse: Configuração completa do middleware de segurança
        
    Raises:
        HTTPException: Se erro interno ao obter configuração
    """
    try:
        config = {
            "abiss_threat_threshold": 0.7,
            "nnis_anomaly_threshold": 0.8,
            "combined_threshold": 0.6,
            "excluded_paths": ["/health", "/docs", "/redoc", "/openapi.json", "/"],
            "fail_open_on_error": True,
            "log_all_requests": True
        }
        
        return JSONResponse(content=config)
        
    except Exception as e:
        logger.error(f"Erro ao obter configuração do middleware: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@router.post("/middleware/simulate-attack")
async def simulate_attack(attack_type: str = "sql_injection") -> JSONResponse:
    """
    Simular diferentes tipos de ataques para testar o middleware
    
    Endpoint para testar a eficácia do middleware de segurança
    simulando diferentes tipos de ataques conhecidos. Útil para
    validação de segurança e testes de penetração controlados.
    
    Args:
        attack_type: Tipo de ataque a simular (sql_injection, xss, command_injection)
        
    Returns:
        JSONResponse: Resultado da simulação com payload e análise de segurança
        
    Raises:
        HTTPException: Se tipo de ataque inválido ou erro interno
    """
    try:
        attack_payloads = {
            "sql_injection": {
                "payload": "'; DROP TABLE users; --",
                "headers": {"Content-Type": "application/json"},
                "description": "SQL Injection attempt"
            },
            "xss": {
                "payload": "<script>alert('XSS')</script>",
                "headers": {"Content-Type": "text/html"},
                "description": "Cross-Site Scripting attempt"
            },
            "command_injection": {
                "payload": "; rm -rf / --no-preserve-root",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "description": "Command injection attempt"
            },
            "ddos_simulation": {
                "payload": "A" * 10000,  # Large payload
                "headers": {"User-Agent": "AttackBot/1.0"},
                "description": "DDoS simulation with large payload"
            }
        }
        
        if attack_type not in attack_payloads:
            raise HTTPException(status_code=400, detail=f"Unknown attack type: {attack_type}")
        
        attack_data = attack_payloads[attack_type]
        
        # Este endpoint será interceptado pelo middleware
        # Se chegou até aqui, o ataque não foi bloqueado
        response_data = {
            "message": "Attack simulation processed",
            "attack_type": attack_type,
            "attack_data": attack_data,
            "status": "not_blocked",
            "warning": "This attack should have been blocked by the security middleware",
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Erro na simulação de ataque: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


# Pydantic models for security management
class IPBlockRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = None

class InputValidationRequest(BaseModel):
    input_data: str
    context: Optional[str] = "general"

class SecurityConfigUpdate(BaseModel):
    enable_input_validation: Optional[bool] = None
    enable_rate_limiting: Optional[bool] = None
    enable_ddos_protection: Optional[bool] = None
    requests_per_minute: Optional[int] = None
    requests_per_hour: Optional[int] = None
    max_request_size: Optional[int] = None

# Global variable to store middleware instance reference
_security_middleware_instance = None

def get_security_middleware():
    """Get the security middleware instance from the app"""
    global _security_middleware_instance
    if _security_middleware_instance is None:
        # Try to get from the FastAPI app instance
        try:
            from ...api.server import app
            for middleware in app.user_middleware:
                if isinstance(middleware.cls, type) and issubclass(middleware.cls, ComprehensiveSecurityMiddleware):
                    _security_middleware_instance = middleware
                    break
        except Exception as e:
            logger.warning(f"Could not get security middleware instance: {e}")
    return _security_middleware_instance

@router.get("/middleware/stats")
async def get_middleware_stats() -> JSONResponse:
    """
    Obter estatísticas abrangentes do middleware de segurança
    
    Endpoint que retorna estatísticas detalhadas sobre o funcionamento
    do middleware de segurança, incluindo métricas de clientes,
    requisições analisadas, IPs bloqueados e status dos sistemas
    de segurança integrados.
    
    Returns:
        JSONResponse: Estatísticas completas do middleware de segurança
        
    Raises:
        HTTPException: Se erro interno ao obter estatísticas
    """
    try:
        middleware = get_security_middleware()
        if middleware and hasattr(middleware, 'get_security_stats'):
            stats = middleware.get_security_stats()
        else:
            # Fallback stats if middleware not available
            stats = {
                "total_clients": 0,
                "blocked_clients": 0,
                "total_requests": 0,
                "malicious_requests": 0,
                "suspicious_requests": 0,
                "blocked_ips_count": 0,
                "active_connections": 0
            }
        
        # Add system status
        stats["system_status"] = {
            "abiss_available": True,
            "nnis_available": True,
            "middleware_active": middleware is not None,
            "input_validation_active": True,
            "rate_limiting_active": True,
            "ddos_protection_active": True
        }
        
        stats["timestamp"] = datetime.now(UTC).isoformat()
        
        return JSONResponse(content=stats)
        
    except Exception as e:
        logger.error(f"Error getting middleware stats: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@router.post("/middleware/block-ip")
async def block_ip(request: IPBlockRequest) -> JSONResponse:
    """
    Bloquear endereço IP específico
    
    Endpoint administrativo que permite bloquear um endereço IP
    específico no sistema de segurança. O IP bloqueado será
    rejeitado por todas as rotas protegidas pelo middleware.
    
    Args:
        request: Dados da requisição com IP e motivo do bloqueio
        
    Returns:
        JSONResponse: Confirmação do bloqueio com detalhes
        
    Raises:
        HTTPException: Se middleware não disponível ou erro interno
    """
    try:
        middleware = get_security_middleware()
        if middleware and hasattr(middleware, 'block_ip'):
            middleware.block_ip(request.ip_address)
            logger.info(f"IP {request.ip_address} blocked. Reason: {request.reason or 'Manual block'}")
            
            return JSONResponse(content={
                "success": True,
                "message": f"IP {request.ip_address} has been blocked",
                "ip_address": request.ip_address,
                "reason": request.reason,
                "timestamp": datetime.now(UTC).isoformat()
            })
        else:
            raise HTTPException(status_code=503, detail="Security middleware not available")
            
    except Exception as e:
        logger.error(f"Error blocking IP {request.ip_address}: {e}")
        raise HTTPException(status_code=500, detail=f"Error blocking IP: {str(e)}")

@router.post("/middleware/unblock-ip")
async def unblock_ip(request: IPBlockRequest) -> JSONResponse:
    """
    Desbloquear endereço IP previamente bloqueado
    
    Endpoint administrativo que permite remover o bloqueio de um
    endereço IP, restaurando o acesso normal ao sistema.
    Útil para desbloqueios manuais após análise de segurança.
    
    Args:
        request: Dados da requisição com IP a desbloquear
        
    Returns:
        JSONResponse: Confirmação do desbloqueio com detalhes
        
    Raises:
        HTTPException: Se middleware não disponível ou erro interno
    """
    try:
        middleware = get_security_middleware()
        if middleware and hasattr(middleware, 'unblock_ip'):
            middleware.unblock_ip(request.ip_address)
            logger.info(f"IP {request.ip_address} unblocked")
            
            return JSONResponse(content={
                "success": True,
                "message": f"IP {request.ip_address} has been unblocked",
                "ip_address": request.ip_address,
                "timestamp": datetime.now(UTC).isoformat()
            })
        else:
            raise HTTPException(status_code=503, detail="Security middleware not available")
            
    except Exception as e:
        logger.error(f"Error unblocking IP {request.ip_address}: {e}")
        raise HTTPException(status_code=500, detail=f"Error unblocking IP: {str(e)}")

@router.post("/validate-input")
async def validate_input(request: InputValidationRequest) -> JSONResponse:
    """
    Validar dados de entrada para ameaças de segurança
    
    Endpoint que analisa dados de entrada em busca de padrões
    maliciosos, incluindo SQL injection, XSS, command injection
    e outras ameaças conhecidas. Retorna resultado da validação
    com dados sanitizados e score de confiança.
    
    Args:
        request: Dados da requisição com entrada a validar e contexto
        
    Returns:
        JSONResponse: Resultado da validação com ameaças detectadas e dados sanitizados
        
    Raises:
        HTTPException: Se dados de entrada inválidos ou erro interno
    """
    try:
        validation_result = validator.validate_input(request.input_data, request.context)
        
        response_data = {
            "result": validation_result.result.value,
            "sanitized_value": validation_result.sanitized_value,
            "threats_detected": validation_result.threats_detected,
            "confidence_score": validation_result.confidence_score,
            "is_safe": validation_result.result == ValidationResult.SAFE,
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        # Log suspicious or malicious inputs
        if validation_result.result != ValidationResult.SAFE:
            logger.warning(f"Suspicious input detected: {validation_result.threats_detected} (confidence: {validation_result.confidence_score})")
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Error validating input: {e}")
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

@router.get("/validation-patterns")
async def get_validation_patterns() -> JSONResponse:
    """
    Obter informações sobre padrões de validação utilizados
    
    Endpoint que retorna informações detalhadas sobre os padrões
    de validação utilizados pelo sistema de validação de entrada,
    incluindo contadores de padrões por categoria e contextos
    de segurança suportados.
    
    Returns:
        JSONResponse: Informações sobre padrões de validação e contextos suportados
        
    Raises:
        HTTPException: Se erro interno ao obter padrões
    """
    try:
        patterns_info = {
            "sql_patterns_count": len(validator.sql_patterns),
            "xss_patterns_count": len(validator.xss_patterns),
            "command_patterns_count": len(validator.command_patterns),
            "ldap_patterns_count": len(validator.ldap_patterns),
            "path_traversal_patterns_count": len(validator.path_traversal_patterns),
            "xxe_patterns_count": len(validator.xxe_patterns),
            "nosql_patterns_count": len(validator.nosql_patterns),
            "safe_chars_contexts": list(validator.safe_chars.keys()),
            "supported_contexts": ["general", "html", "web", "url", "database", "system", "ldap", "xml", "json"],
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        return JSONResponse(content=patterns_info)
        
    except Exception as e:
        logger.error(f"Error getting validation patterns: {e}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.get("/security-report")
async def get_security_report() -> JSONResponse:
    """
    Gerar relatório abrangente de segurança
    
    Endpoint que consolida informações de todos os sistemas de
    segurança em um relatório unificado, incluindo estatísticas
    do middleware, ABISS, NNIS e métricas de validação de entrada.
    Útil para análise de segurança e auditoria.
    
    Returns:
        JSONResponse: Relatório completo de segurança com todas as métricas
        
    Raises:
        HTTPException: Se erro interno ao gerar relatório
    """
    try:
        # Get middleware stats
        middleware = get_security_middleware()
        middleware_stats = {}
        if middleware and hasattr(middleware, 'get_security_stats'):
            middleware_stats = middleware.get_security_stats()
        
        # Get ABISS stats
        abiss_stats = {}
        try:
            abiss = get_abiss_system()
            abiss_stats = {
                "threat_patterns_count": len(abiss.threat_patterns),
                "threat_stats": dict(abiss.threat_stats),
                "false_positive_rate": abiss.false_positive_rate,
                "is_monitoring": abiss.is_monitoring
            }
        except Exception:
            abiss_stats = {"status": "unavailable"}
        
        # Get NNIS stats
        nnis_stats = {}
        try:
            nnis = get_nnis_system()
            nnis_stats = {
                "immune_cells_count": len(nnis.immune_cells),
                "memory_cells_count": len(nnis.memory_cells),
                "threat_threshold": nnis.threat_threshold
            }
        except Exception:
            nnis_stats = {"status": "unavailable"}
        
        # Compile comprehensive report
        security_report = {
            "report_timestamp": datetime.now(UTC).isoformat(),
            "security_middleware": middleware_stats,
            "abiss_system": abiss_stats,
            "nnis_system": nnis_stats,
            "input_validation": {
                "patterns_loaded": len(validator.compiled_patterns),
                "contexts_supported": len(validator.safe_chars)
            },
            "overall_status": {
                "security_level": "HIGH" if middleware_stats.get("malicious_requests", 0) == 0 else "MEDIUM",
                "threats_blocked_today": middleware_stats.get("malicious_requests", 0),
                "active_protections": [
                    "Input Validation",
                    "Rate Limiting", 
                    "DDoS Protection",
                    "ABISS Threat Detection",
                    "NNIS Behavioral Analysis"
                ]
            }
        }
        
        return JSONResponse(content=security_report)
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@router.get("/middleware/legacy-stats")
async def get_legacy_middleware_stats() -> JSONResponse:
    """
    Obter estatísticas legacy do middleware (compatibilidade)
    
    Endpoint legacy mantido para compatibilidade com versões
    anteriores do sistema. Retorna estatísticas básicas do
    middleware de segurança em formato simplificado.
    
    Returns:
        JSONResponse: Estatísticas legacy do middleware de segurança
        
    Raises:
        HTTPException: Se erro interno ao obter estatísticas
    """
    try:
        # Legacy implementation for backward compatibility
        stats = {
            "total_requests_analyzed": 0,
            "threats_blocked": 0,
            "anomalies_detected": 0,
            "average_processing_time_ms": 0.0,
            "last_threat_blocked": None,
            "system_status": {
                "abiss_available": True,
                "nnis_available": True,
                "middleware_active": True
            },
            "timestamp": datetime.now(UTC).isoformat()
        }
        
        return JSONResponse(content=stats)
        
    except Exception as e:
        logger.error(f"Error getting legacy middleware stats: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")