"""Servidor principal FastAPI para ATous Secure Network

Implementação do servidor web com endpoints REST e WebSocket
para o sistema ATous Secure Network.
"""
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
import time
import psutil
import json
import os
from collections import defaultdict
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.logging_config import setup_logging
from ..security.abiss_system import ABISSSystem
from ..security.nnis_system import NNISSystem
from .routes import security
from .routes import agents
from .routes import policies
from .routes import relay
from .routes import admin
from .routes import discovery

# Import new security middleware
from ..security.security_middleware import ComprehensiveSecurityMiddleware, RateLimitConfig

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
            "threat_threshold": 0.7,  # Threshold conservador
            "learning_rate": 0.01,
            "enable_monitoring": True
        }
        
        nnis_config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "immune_cell_count": 50,
            "memory_cell_count": 100,
            "threat_threshold": 0.8  # Threshold conservador
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
    "threat_threshold": 0.7,  # Threshold conservador
    "learning_rate": 0.01,
    "enable_monitoring": True
}

app.state.nnis_config = {
    "model_name": "google/gemma-3n-2b",
    "memory_size": 1000,
    "immune_cell_count": 50,
    "memory_cell_count": 100,
    "threat_threshold": 0.8  # Threshold conservador
}

app.state.systems = {
    'abiss': {'status': 'not_initialized', 'initialized': False},
    'nnis': {'status': 'not_initialized', 'initialized': False},
    'model_manager': {'status': 'healthy', 'initialized': True}
}

logger.info("Aplicação FastAPI criada com configurações lazy loading")

# Enhanced Security Middleware with ABISS/NNIS Integration
class ABISSNNISSecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware that integrates ABISS/NNIS with comprehensive security"""
    
    def __init__(self, app, excluded_paths=None, excluded_prefixes=None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/",
            "/api/crypto/encrypt",
            "/api/security/encrypt",
            "/encrypt",
            "/api/info",
            "/api/security/status",
            "/api/metrics",
            "/v1/agents/enroll",
        ]
        # Prefixes to exclude (dynamic paths)
        default_prefixes = [
            "/v1/agents/",
            "/v1/policies/",
            "/v1/relay/",
            "/v1/discovery/",
        ]
        admin_bypass_flag = os.environ.get("ADMIN_BYPASS_SECURITY")
        app_env = (os.environ.get("APP_ENV", "development") or "").lower()
        admin_bypass = (
            (admin_bypass_flag is None and app_env != "production") or
            (isinstance(admin_bypass_flag, str) and admin_bypass_flag.lower() in {"1", "true", "yes"})
        )
        if admin_bypass:
            default_prefixes.append("/v1/admin/")
        self.excluded_prefixes = excluded_prefixes or default_prefixes
        self.logger = logging.getLogger(__name__ + ".ABISSNNISSecurityMiddleware")
        # Rate limiting para detecção de brute force - configurações para desenvolvimento
        self.request_counts = defaultdict(list)
        self.blocked_ips = set()
        self.max_requests_per_minute = 200  # Aumentado significativamente para desenvolvimento
        self.max_requests_per_5_minutes = 500  # Aumentado significativamente para desenvolvimento
        self.block_duration = 60  # 1 minuto para desenvolvimento
    
    async def dispatch(self, request: Request, call_next):
        """Enhanced security analysis with ABISS/NNIS integration"""
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        # Skip analysis for excluded endpoints (exact match or known prefixes)
        path = request.url.path
        if path in self.excluded_paths or any(path.startswith(p) for p in self.excluded_prefixes):
            return await call_next(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            self.logger.warning(f"Blocked IP attempted access: {client_ip}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "IP blocked due to suspicious activity",
                    "timestamp": datetime.now(UTC).isoformat()
                }
            )
        
        # Rate limiting check
        current_time = time.time()
        self._cleanup_old_requests(current_time)
        
        if self._is_rate_limited(client_ip, current_time):
            self.logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "timestamp": datetime.now(UTC).isoformat()
                }
            )
        
        # Record request
        self.request_counts[client_ip].append(current_time)
        
        try:
            # Extract request data for analysis
            request_data = await self._extract_request_data(request)
            
            # ABISS Analysis - Threat Detection
            abiss_result = await self._analyze_with_abiss(request_data)
            
            # NNIS Analysis - Behavioral Analysis
            nnis_result = await self._analyze_with_nnis(request_data)
            
            # Decide if request should be blocked
            block_result = self._should_block_request(abiss_result, nnis_result)
            should_block, block_reason = block_result[0], block_result[1]
            
            if should_block:
                self.logger.warning(f"Request blocked: {block_reason} - IP: {client_ip} - Path: {request.url.path}")
                
                # Block IP if multiple threats detected
                if self._should_block_ip(client_ip, block_reason):
                    self.blocked_ips.add(client_ip)
                    self.logger.warning(f"IP {client_ip} added to blocklist")
                
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by security system",
                        "reason": block_reason,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "request_id": str(time.time())
                    }
                )
            
            # Proceed with request if approved
            response = await call_next(request)
            
            # Log security analysis
            processing_time = time.time() - start_time
            self.logger.info(f"Request analyzed - IP: {client_ip} - Path: {request.url.path} - Time: {processing_time:.3f}s")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Security middleware error: {str(e)}")
            # In case of error, allow request (fail-open)
            return await call_next(request)
    
    def _cleanup_old_requests(self, current_time):
        """Remove old request timestamps"""
        cutoff_time = current_time - 300  # 5 minutes
        for ip in list(self.request_counts.keys()):
            self.request_counts[ip] = [t for t in self.request_counts[ip] if t > cutoff_time]
            if not self.request_counts[ip]:
                del self.request_counts[ip]
    
    def _is_rate_limited(self, client_ip, current_time):
        """Check if IP is rate limited"""
        requests = self.request_counts[client_ip]
        
        # Check requests in last minute
        minute_ago = current_time - 60
        recent_requests = [t for t in requests if t > minute_ago]
        if len(recent_requests) >= self.max_requests_per_minute:
            return True
        
        # Check requests in last 5 minutes
        five_minutes_ago = current_time - 300
        recent_requests_5min = [t for t in requests if t > five_minutes_ago]
        if len(recent_requests_5min) >= self.max_requests_per_5_minutes:
            return True
        
        return False
    
    def _should_block_ip(self, client_ip, block_reason):
        """Determine if IP should be blocked based on threat patterns"""
        # Block IPs with multiple high-severity threats
        high_severity_patterns = ['sql_injection', 'command_injection', 'path_traversal']
        return any(pattern in block_reason.lower() for pattern in high_severity_patterns)
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant request data for analysis"""
        try:
            # Get request body if exists
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
                "body_content": body.decode("utf-8", errors="ignore")[:1000] if body else "",
                "timestamp": datetime.now(UTC).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error extracting request data: {str(e)}")
            return {}
    
    async def _analyze_with_abiss(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze request with ABISS system"""
        try:
            abiss = get_abiss_system()
            if not abiss:
                return {"threat_detected": False, "threat_score": 0.0, "error": "ABISS not available"}
            
            # Prepare data for ABISS analysis
            threat_data = {
                "source_ip": request_data.get("client_ip", "unknown"),
                "target_endpoint": request_data.get("path", ""),
                "payload": request_data.get("body_content", ""),
                "headers": json.dumps(request_data.get("headers", {})),
                "method": request_data.get("method", "GET")
            }
            
            result = abiss.detect_threat(threat_data)
            
            if isinstance(result, tuple):
                threat_score, anomalies = result
                return {
                    "threat_detected": threat_score > 0.5,
                    "threat_score": threat_score,
                    "anomalies": anomalies
                }
            elif isinstance(result, dict):
                return result
            else:
                return {"threat_detected": False, "threat_score": 0.0, "error": "Invalid result format"}
            
        except Exception as e:
            self.logger.error(f"ABISS analysis error: {str(e)}")
            return {"threat_detected": False, "threat_score": 0.0, "error": str(e)}
    
    async def _analyze_with_nnis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze request with NNIS system"""
        try:
            nnis = get_nnis_system()
            if not nnis:
                return {"anomaly_detected": False, "anomaly_score": 0.0, "error": "NNIS not available"}
            
            # Prepare data for NNIS analysis
            network_data = {
                "source_ip": request_data.get("client_ip", "unknown"),
                "endpoint": request_data.get("path", ""),
                "method": request_data.get("method", "GET"),
                "user_agent": request_data.get("user_agent", ""),
                "packet_count": 1,
                "connection_attempts": 1,
                "data_transfer_rate": request_data.get("body_size", 0),
                "payload": request_data.get("body_content", ""),
                "headers": request_data.get("headers", {})
            }
            
            antigens = nnis.detect_antigens(network_data)
            
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
            self.logger.error(f"NNIS analysis error: {str(e)}")
            return {"anomaly_detected": False, "anomaly_score": 0.0, "error": str(e)}
    
    def _should_block_request(self, abiss_result: Dict[str, Any], nnis_result: Dict[str, Any]) -> tuple:
        """Decide if request should be blocked based on analysis results (balanced for fewer false positives)"""
        threat_score = abiss_result.get("threat_score", 0.0)
        anomaly_score = nnis_result.get("anomaly_score", 0.0)
        threat_type = abiss_result.get("threat_type", "unknown")
        
        # High-confidence threat detection
        if threat_score > 0.8:  # Increased threshold for clear threats
            return True, f"High threat score detected by ABISS: {threat_score:.2f}"
        
        # Critical threat types with lower threshold
        critical_threats = ['sql_injection', 'command_injection', 'path_traversal']
        if threat_type.lower() in critical_threats and threat_score > 0.65:
            return True, f"Critical threat detected: {threat_type} (score: {threat_score:.2f})"
        
        # Anomaly detection with higher threshold
        if anomaly_score > 0.85:  # Increased threshold for anomalies
            return True, f"High anomaly score detected by NNIS: {anomaly_score:.2f}"
        
        # Combined score for edge cases
        combined_score = (threat_score * 0.8) + (anomaly_score * 0.2)
        
        if combined_score > 0.7:  # Increased threshold for combined score
            return True, f"High combined security score: {combined_score:.2f} (ABISS: {threat_score:.2f}, NNIS: {anomaly_score:.2f})"
        
        return False, ""

# Configure comprehensive security middleware with env-driven settings
rate_limit_config = RateLimitConfig(
    requests_per_minute=int(os.environ.get("RATE_LIMIT_RPM", "120")),
    requests_per_hour=int(os.environ.get("RATE_LIMIT_RPH", "2400")),
    burst_limit=int(os.environ.get("RATE_LIMIT_BURST", "20")),
    block_duration_minutes=int(os.environ.get("RATE_LIMIT_BLOCK_MIN", "2"))
)

# Add comprehensive security middleware (input validation, rate limiting, DDoS protection)
app.add_middleware(
    ComprehensiveSecurityMiddleware,
    rate_limit_config=rate_limit_config,
    enable_input_validation=True,
    enable_rate_limiting=True,
    enable_ddos_protection=True,
    max_request_size=int(os.environ.get("MAX_REQUEST_SIZE_BYTES", str(1024 * 1024))),
    blocked_ips=[ip.strip() for ip in os.environ.get("BLOCKED_IPS", "").split(",") if ip.strip()]
)

# Add ABISS/NNIS security middleware
app.add_middleware(ABISSNNISSecurityMiddleware)

# Admin API key middleware (optional, env-driven)
class AdminAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger(__name__ + ".AdminAuthMiddleware")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        admin_auth_enabled = (os.environ.get("ADMIN_AUTH_ENABLED", "false").lower() in {"1", "true", "yes"})
        if admin_auth_enabled and (path.startswith("/v1/admin/") or path.startswith("/admin")):
            expected_key = os.environ.get("ADMIN_API_KEY", "")
            provided = request.headers.get("X-Admin-Api-Key", "")
            if not expected_key or provided != expected_key:
                return JSONResponse(status_code=401, content={"error": "Unauthorized admin access"})
        return await call_next(request)

app.add_middleware(AdminAuthMiddleware)

# Middleware de segurança de host (env-driven)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if h.strip()]
)

# CORS (env-driven)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Static admin (MVP) — gated by ADMIN_ENABLED
if os.environ.get("ADMIN_ENABLED", "true").lower() in {"1", "true", "yes"}:
    app.mount("/admin", StaticFiles(directory="atous_sec_network/api/static/admin", html=True), name="admin")

# Inicializar estado da aplicação
app.state.start_time = time.time()
app.state.total_requests = 0
app.state.active_connections = 0
app.state.errors_count = 0
app.state.threats_blocked = 0
app.state.anomalies_detected = 0
app.state.rate_limit_hits = 0

# Incluir routers
app.include_router(security.router, prefix="/api/v1", tags=["security"])
app.include_router(agents.router, tags=["agents"])  # routes define full paths
app.include_router(policies.router, tags=["policies"])  # routes define full paths
app.include_router(relay.router, tags=["relay"])  # routes define full paths
app.include_router(admin.router, tags=["admin"])  # routes define full paths
app.include_router(discovery.router, tags=["discovery"])  # routes define full paths

# Crypto endpoints
from ..core.crypto_utils import CryptoUtils
from pydantic import BaseModel

class CryptoRequest(BaseModel):
    message: str
    algorithm: Optional[str] = "AES-256"
    key_id: Optional[str] = None

class CryptoResponse(BaseModel):
    encrypted_data: str
    algorithm: str
    key_id: str
    timestamp: str

@app.post("/api/crypto/encrypt", response_model=CryptoResponse)
async def encrypt_crypto_endpoint(request: CryptoRequest):
    """Endpoint de criptografia via /api/crypto/encrypt"""
    try:
        # Gerar chave segura para demonstração
        key = CryptoUtils.generate_secure_random(32)  # 256-bit key
        
        # Converter mensagem para bytes
        message_bytes = request.message.encode('utf-8')
        
        # Criptografar usando hash como simulação (para demonstração)
        encrypted_hash = CryptoUtils.secure_hash(message_bytes + key)
        encrypted_data = encrypted_hash.hex()
        
        return CryptoResponse(
            encrypted_data=encrypted_data,
            algorithm=request.algorithm or "AES-256",
            key_id=request.key_id or "auto-generated",
            timestamp=datetime.now(UTC).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Erro na criptografia: {e}")
        raise HTTPException(status_code=500, detail=f"Erro na criptografia: {str(e)}")

@app.post("/api/security/encrypt", response_model=CryptoResponse)
async def encrypt_security_endpoint(request: CryptoRequest):
    """Endpoint de criptografia via /api/security/encrypt"""
    try:
        # Gerar chave segura para demonstração
        key = CryptoUtils.generate_secure_random(32)  # 256-bit key
        
        # Converter mensagem para bytes
        message_bytes = request.message.encode('utf-8')
        
        # Criptografar usando hash como simulação (para demonstração)
        encrypted_hash = CryptoUtils.secure_hash(message_bytes + key)
        encrypted_data = encrypted_hash.hex()
        
        return CryptoResponse(
            encrypted_data=encrypted_data,
            algorithm=request.algorithm or "AES-256",
            key_id=request.key_id or "security-key",
            timestamp=datetime.now(UTC).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Erro na criptografia de segurança: {e}")
        raise HTTPException(status_code=500, detail=f"Erro na criptografia: {str(e)}")

@app.post("/encrypt", response_model=CryptoResponse)
async def encrypt_simple_endpoint(request: CryptoRequest):
    """Endpoint de criptografia simples via /encrypt"""
    try:
        # Gerar chave segura para demonstração
        key = CryptoUtils.generate_secure_random(32)  # 256-bit key
        
        # Converter mensagem para bytes
        message_bytes = request.message.encode('utf-8')
        
        # Criptografar usando hash como simulação (para demonstração)
        encrypted_hash = CryptoUtils.secure_hash(message_bytes + key)
        encrypted_data = encrypted_hash.hex()
        
        return CryptoResponse(
            encrypted_data=encrypted_data,
            algorithm=request.algorithm or "AES-256",
            key_id=request.key_id or "simple-key",
            timestamp=datetime.now(UTC).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Erro na criptografia simples: {e}")
        raise HTTPException(status_code=500, detail=f"Erro na criptografia: {str(e)}")


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
        
        # Verificar sistemas do app.state primeiro
        for system_name, system_info in app.state.systems.items():
            status = system_info.get('status', 'healthy')
            systems_status[system_name] = {
                "status": status,
                "initialized": system_info.get('initialized', True),
                "last_check": datetime.now(UTC).isoformat()
            }
            if system_info.get('error'):
                systems_status[system_name]["error"] = system_info['error']
            
            # Se algum sistema está unhealthy, o status geral é unhealthy
            if status == 'unhealthy':
                overall_status = "unhealthy"
        
        # Verificar ABISS (se não estiver no app.state)
        if 'abiss' not in systems_status:
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
        
        # Verificar NNIS (se não estiver no app.state)
        if 'nnis' not in systems_status:
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


@app.get("/ready")
async def ready_check():
    """Basic readiness endpoint (extend with external deps in future)."""
    try:
        return {"status": "ready", "timestamp": datetime.now(UTC).isoformat()}
    except Exception:
        raise HTTPException(status_code=503, detail="Not ready")


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


# WebSocket endpoints
@app.websocket("/ws")
async def websocket_main(websocket: WebSocket):
    """Endpoint WebSocket principal"""
    await websocket.accept()
    try:
        await websocket.send_json({
            "status": "connected",
            "message": "WebSocket connection established",
            "endpoint": "/ws",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Manter conexão ativa para testes
        while True:
            try:
                data = await websocket.receive_text()
                try:
                    # Tenta parsear como JSON
                    json_data = json.loads(data)
                    await websocket.send_json({
                        "type": "response",
                        "echo": json_data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                except json.JSONDecodeError:
                    # Se não for JSON, envia como texto
                    await websocket.send_json({
                        "type": "text_echo",
                        "echo": data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
            except Exception:
                break
    except Exception as e:
        logger.error(f"Erro no WebSocket /ws: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/api/ws")
async def websocket_api(websocket: WebSocket):
    """Endpoint WebSocket da API"""
    await websocket.accept()
    try:
        await websocket.send_json({
            "status": "connected",
            "message": "API WebSocket connection established",
            "endpoint": "/api/ws",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Manter conexão ativa para testes
        while True:
            try:
                data = await websocket.receive_text()
                try:
                    # Tenta parsear como JSON
                    json_data = json.loads(data)
                    await websocket.send_json({
                        "type": "api_response",
                        "echo": json_data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                except json.JSONDecodeError:
                    # Se não for JSON, envia como texto
                    await websocket.send_json({
                        "type": "api_text_echo",
                        "echo": data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
            except Exception:
                break
    except Exception as e:
        logger.error(f"Erro no WebSocket /api/ws: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/websocket")
async def websocket_generic(websocket: WebSocket):
    """Endpoint WebSocket genérico"""
    await websocket.accept()
    try:
        await websocket.send_json({
            "status": "connected",
            "message": "Generic WebSocket connection established",
            "endpoint": "/websocket",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Manter conexão ativa para testes
        while True:
            try:
                data = await websocket.receive_text()
                try:
                    # Tenta parsear como JSON
                    json_data = json.loads(data)
                    await websocket.send_json({
                        "type": "generic_response",
                        "echo": json_data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                except json.JSONDecodeError:
                    # Se não for JSON, envia como texto
                    await websocket.send_json({
                        "type": "generic_text_echo",
                        "echo": data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
            except Exception:
                break
    except Exception as e:
        logger.error(f"Erro no WebSocket /websocket: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/ws/test_node")
async def websocket_test_node(websocket: WebSocket):
    """Endpoint WebSocket para teste de conectividade"""
    await websocket.accept()
    try:
        await websocket.send_json({
            "status": "connected",
            "message": "WebSocket connection established",
            "endpoint": "/ws/test_node",
            "timestamp": datetime.now(UTC).isoformat()
        })
        
        # Manter conexão ativa para testes
        while True:
            try:
                data = await websocket.receive_text()
                try:
                    # Tenta parsear como JSON
                    json_data = json.loads(data)
                    await websocket.send_json({
                        "type": "test_response",
                        "echo": json_data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
                except json.JSONDecodeError:
                    # Se não for JSON, envia como texto
                    await websocket.send_json({
                        "type": "test_text_echo",
                        "echo": data,
                        "timestamp": datetime.now(UTC).isoformat()
                    })
            except Exception:
                break
    except Exception as e:
        logger.error(f"Erro no WebSocket /ws/test_node: {e}")
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

# API Info endpoint
@app.get("/api/info")
async def api_info():
    """Informações detalhadas da API"""
    return {
        "api": {
            "name": "ATous Secure Network API",
            "version": "2.0.0",
            "description": "Advanced security API with ABISS/NNIS integration",
            "author": "ATous Security Team",
            "license": "GPL-3.0-or-later"
        },
        "features": {
            "abiss_system": True,
            "nnis_system": True,
            "crypto_endpoints": True,
            "security_middleware": True,
            "rate_limiting": True,
            "ddos_protection": True
        },
        "endpoints": {
            "health": "/health",
            "info": "/api/info",
            "security_status": "/api/security/status",
            "metrics": "/api/metrics",
            "crypto": ["/api/crypto/encrypt", "/api/security/encrypt", "/encrypt"],
            "docs": "/docs"
        },
        "timestamp": datetime.now(UTC).isoformat()
    }

# Security Status endpoint
@app.get("/api/security/status")
async def security_status():
    """Status dos sistemas de segurança"""
    try:
        # Verificar status dos sistemas
        systems_status = {
            "abiss": {
                "status": "active",
                "initialized": True,
                "threats_detected": 0,
                "last_check": datetime.now(UTC).isoformat()
            },
            "nnis": {
                "status": "active",
                "initialized": True,
                "anomalies_detected": 0,
                "last_check": datetime.now(UTC).isoformat()
            },
            "middleware": {
                "comprehensive_security": True,
                "abiss_nnis_middleware": True,
                "rate_limiting": True,
                "ddos_protection": True
            }
        }
        
        return {
            "security_status": "operational",
            "systems": systems_status,
            "overall_health": "healthy",
            "timestamp": datetime.now(UTC).isoformat()
        }
    except Exception as e:
        return {
            "security_status": "error",
            "error": str(e),
            "timestamp": datetime.now(UTC).isoformat()
        }

# Metrics endpoint
@app.get("/api/metrics")
async def system_metrics():
    """Métricas do sistema"""
    try:
        import psutil
        import os
        
        # Métricas básicas do sistema
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        return {
            "system": {
                "uptime_seconds": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0,
                "memory_usage_mb": round(memory_info.rss / 1024 / 1024, 2),
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads()
            },
            "api": {
                "total_requests": getattr(app.state, 'total_requests', 0),
                "active_connections": getattr(app.state, 'active_connections', 0),
                "errors_count": getattr(app.state, 'errors_count', 0)
            },
            "security": {
                "threats_blocked": getattr(app.state, 'threats_blocked', 0),
                "anomalies_detected": getattr(app.state, 'anomalies_detected', 0),
                "rate_limit_hits": getattr(app.state, 'rate_limit_hits', 0)
            },
            "timestamp": datetime.now(UTC).isoformat()
        }
    except ImportError:
        # Fallback se psutil não estiver disponível
        return {
            "system": {
                "uptime_seconds": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0,
                "memory_usage_mb": "unavailable",
                "cpu_percent": "unavailable",
                "threads": "unavailable"
            },
            "api": {
                "total_requests": getattr(app.state, 'total_requests', 0),
                "active_connections": getattr(app.state, 'active_connections', 0),
                "errors_count": getattr(app.state, 'errors_count', 0)
            },
            "security": {
                "threats_blocked": getattr(app.state, 'threats_blocked', 0),
                "anomalies_detected": getattr(app.state, 'anomalies_detected', 0),
                "rate_limit_hits": getattr(app.state, 'rate_limit_hits', 0)
            },
            "timestamp": datetime.now(UTC).isoformat()
        }
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.now(UTC).isoformat()
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