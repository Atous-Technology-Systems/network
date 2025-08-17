"""
Sistema de Gerenciamento de Refresh Tokens ATous Secure Network

Este módulo implementa:
- Geração segura de refresh tokens
- Rotação de tokens para segurança
- Invalidação de tokens comprometidos
- Auditoria de uso de tokens
"""

import secrets
import hashlib
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timedelta, UTC
from dataclasses import dataclass
from enum import Enum
import threading
import logging

logger = logging.getLogger(__name__)


class TokenStatus(Enum):
    """Status dos refresh tokens"""
    ACTIVE = "active"
    USED = "used"
    REVOKED = "revoked"
    EXPIRED = "expired"
    COMPROMISED = "compromised"


@dataclass
class RefreshToken:
    """Modelo de refresh token"""
    token_id: str
    user_id: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    last_used: Optional[datetime] = None
    status: TokenStatus = TokenStatus.ACTIVE
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    family_id: Optional[str] = None  # Para rotação de tokens
    
    def is_valid(self) -> bool:
        """Verificar se o token é válido"""
        now = datetime.now(UTC)
        return (
            self.status == TokenStatus.ACTIVE and
            now < self.expires_at
        )
    
    def is_expired(self) -> bool:
        """Verificar se o token expirou"""
        return datetime.now(UTC) >= self.expires_at


@dataclass
class TokenUsage:
    """Registro de uso de token"""
    timestamp: datetime
    token_id: str
    user_id: str
    action: str  # "refresh", "logout", "revoke"
    ip_address: str
    user_agent: str
    success: bool
    failure_reason: Optional[str] = None


class RefreshTokenManager:
    """
    Gerenciador de refresh tokens com recursos de segurança avançados
    
    Características:
    - Geração segura de tokens
    - Rotação automática de tokens
    - Detecção de uso suspeito
    - Auditoria completa
    - Limpeza automática de tokens expirados
    """
    
    def __init__(self, 
                 token_lifetime_hours: int = 30 * 24,  # 30 dias
                 max_tokens_per_user: int = 5,
                 rotation_threshold_hours: int = 24,  # Rotacionar após 24h
                 cleanup_interval_hours: int = 1):
        
        self.token_lifetime_hours = token_lifetime_hours
        self.max_tokens_per_user = max_tokens_per_user
        self.rotation_threshold_hours = rotation_threshold_hours
        self.cleanup_interval_hours = cleanup_interval_hours
        
        # Storage
        self.tokens: Dict[str, RefreshToken] = {}
        self.token_usage: List[TokenUsage] = []
        
        # Configuração de segurança
        self.token_length = 64  # 64 caracteres para refresh tokens
        self.hash_algorithm = "sha256"
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Limpeza automática
        self._last_cleanup = datetime.now(UTC)
        
        logger.info("Refresh Token Manager initialized")
    
    def _generate_token(self) -> str:
        """Gerar token criptograficamente seguro"""
        return secrets.token_urlsafe(self.token_length)
    
    def _hash_token(self, token: str) -> str:
        """Hash do token para armazenamento seguro"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _generate_family_id(self) -> str:
        """Gerar ID de família para rotação de tokens"""
        return f"family-{secrets.token_hex(8)}"
    
    def _should_rotate_token(self, token: RefreshToken) -> bool:
        """Verificar se o token deve ser rotacionado"""
        if not token.last_used:
            return False
        
        hours_since_last_use = (datetime.now(UTC) - token.last_used).total_seconds() / 3600
        return hours_since_last_use >= self.rotation_threshold_hours
    
    def _cleanup_expired_tokens(self):
        """Limpar tokens expirados"""
        now = datetime.now(UTC)
        expired_tokens = []
        
        for token_id, token in self.tokens.items():
            if token.is_expired():
                expired_tokens.append(token_id)
                # Marcar como expirado se ainda não estiver
                if token.status == TokenStatus.ACTIVE:
                    token.status = TokenStatus.EXPIRED
        
        # Remover tokens expirados
        for token_id in expired_tokens:
            del self.tokens[token_id]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired refresh tokens")
        
        # Limpar logs antigos (manter apenas últimos 10000)
        if len(self.token_usage) > 10000:
            self.token_usage = self.token_usage[-10000:]
    
    def create_refresh_token(self, user_id: str, ip_address: str = None, 
                           user_agent: str = None) -> Tuple[str, str]:
        """
        Criar novo refresh token para usuário
        
        Returns:
            Tuple[str, str]: (token_plain, token_id)
        """
        with self._lock:
            # Limpeza automática se necessário
            if (datetime.now(UTC) - self._last_cleanup).total_seconds() > self.cleanup_interval_hours * 3600:
                self._cleanup_expired_tokens()
                self._last_cleanup = datetime.now(UTC)
            
            # Verificar limite de tokens por usuário
            user_tokens = [t for t in self.tokens.values() if t.user_id == user_id and t.is_valid()]
            if len(user_tokens) >= self.max_tokens_per_user:
                # Revogar token mais antigo
                oldest_token = min(user_tokens, key=lambda t: t.created_at)
                oldest_token.status = TokenStatus.REVOKED
                logger.info(f"Revoked oldest refresh token for user {user_id} due to limit")
            
            # Gerar novo token
            token_plain = self._generate_token()
            token_hash = self._hash_token(token_plain)
            token_id = f"refresh-{secrets.token_hex(16)}"
            family_id = self._generate_family_id()
            
            # Criar token
            refresh_token = RefreshToken(
                token_id=token_id,
                user_id=user_id,
                token_hash=token_hash,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=self.token_lifetime_hours),
                family_id=family_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.tokens[token_id] = refresh_token
            
            # Log de criação
            self._log_token_usage(
                token_id=token_id,
                user_id=user_id,
                action="create",
                ip_address=ip_address or "unknown",
                user_agent=user_agent or "unknown",
                success=True
            )
            
            logger.info(f"Created refresh token {token_id} for user {user_id}")
            return token_plain, token_id
    
    def validate_refresh_token(self, token: str, user_id: str, 
                             ip_address: str = None, user_agent: str = None) -> Optional[str]:
        """
        Validar refresh token e retornar token_id se válido
        
        Args:
            token: Token em texto plano
            user_id: ID do usuário
            ip_address: IP da requisição
            user_agent: User agent da requisição
        
        Returns:
            Optional[str]: token_id se válido, None caso contrário
        """
        with self._lock:
            token_hash = self._hash_token(token)
            
            # Encontrar token pelo hash
            refresh_token = None
            for t in self.tokens.values():
                if t.token_hash == token_hash:
                    refresh_token = t
                    break
            
            if not refresh_token:
                self._log_token_usage(
                    token_id="unknown",
                    user_id=user_id,
                    action="validate",
                    ip_address=ip_address or "unknown",
                    user_agent=user_agent or "unknown",
                    success=False,
                    failure_reason="Token not found"
                )
                return None
            
            # Verificar se o token pertence ao usuário
            if refresh_token.user_id != user_id:
                self._log_token_usage(
                    token_id=refresh_token.token_id,
                    user_id=user_id,
                    action="validate",
                    ip_address=ip_address or "unknown",
                    user_agent=user_agent or "unknown",
                    success=False,
                    failure_reason="Token user mismatch"
                )
                return None
            
            # Verificar se o token é válido
            if not refresh_token.is_valid():
                self._log_token_usage(
                    token_id=refresh_token.token_id,
                    user_id=user_id,
                    action="validate",
                    ip_address=ip_address or "unknown",
                    user_agent=user_agent or "unknown",
                    success=False,
                    failure_reason=f"Token {refresh_token.status.value}"
                )
                return None
            
            # Verificar se deve ser rotacionado
            if self._should_rotate_token(refresh_token):
                logger.info(f"Refresh token {refresh_token.token_id} marked for rotation")
                refresh_token.status = TokenStatus.USED
            
            # Atualizar último uso
            refresh_token.last_used = datetime.now(UTC)
            
            # Log de validação bem-sucedida
            self._log_token_usage(
                token_id=refresh_token.token_id,
                user_id=user_id,
                action="validate",
                ip_address=ip_address or "unknown",
                user_agent=user_agent or "unknown",
                success=True
            )
            
            return refresh_token.token_id
    
    def rotate_refresh_token(self, old_token_id: str, user_id: str,
                           ip_address: str = None, user_agent: str = None) -> Tuple[str, str]:
        """
        Rotacionar refresh token (criar novo e invalidar o antigo)
        
        Returns:
            Tuple[str, str]: (new_token_plain, new_token_id)
        """
        with self._lock:
            old_token = self.tokens.get(old_token_id)
            if not old_token or old_token.user_id != user_id:
                raise ValueError("Invalid token for rotation")
            
            # Marcar token antigo como usado
            old_token.status = TokenStatus.USED
            
            # Criar novo token na mesma família
            new_token_plain = self._generate_token()
            new_token_hash = self._hash_token(new_token_plain)
            new_token_id = f"refresh-{secrets.token_hex(16)}"
            
            new_refresh_token = RefreshToken(
                token_id=new_token_id,
                user_id=user_id,
                token_hash=new_token_hash,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=self.token_lifetime_hours),
                family_id=old_token.family_id,  # Mesma família
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.tokens[new_token_id] = new_refresh_token
            
            # Log de rotação
            self._log_token_usage(
                token_id=old_token_id,
                user_id=user_id,
                action="rotate",
                ip_address=ip_address or "unknown",
                user_agent=user_agent or "unknown",
                success=True
            )
            
            logger.info(f"Rotated refresh token {old_token_id} -> {new_token_id} for user {user_id}")
            return new_token_plain, new_token_id
    
    def revoke_refresh_token(self, token_id: str, user_id: str,
                           ip_address: str = None, user_agent: str = None) -> bool:
        """
        Revogar refresh token específico
        
        Returns:
            bool: True se revogado com sucesso
        """
        with self._lock:
            token = self.tokens.get(token_id)
            if not token or token.user_id != user_id:
                return False
            
            token.status = TokenStatus.REVOKED
            
            # Log de revogação
            self._log_token_usage(
                token_id=token_id,
                user_id=user_id,
                action="revoke",
                ip_address=ip_address or "unknown",
                user_agent=user_agent or "unknown",
                success=True
            )
            
            logger.info(f"Revoked refresh token {token_id} for user {user_id}")
            return True
    
    def revoke_all_user_tokens(self, user_id: str, ip_address: str = None,
                              user_agent: str = None) -> int:
        """
        Revogar todos os tokens de um usuário
        
        Returns:
            int: Número de tokens revogados
        """
        with self._lock:
            revoked_count = 0
            
            for token in self.tokens.values():
                if token.user_id == user_id and token.status == TokenStatus.ACTIVE:
                    token.status = TokenStatus.REVOKED
                    revoked_count += 1
                    
                    # Log de revogação
                    self._log_token_usage(
                        token_id=token.token_id,
                        user_id=user_id,
                        action="revoke_all",
                        ip_address=ip_address or "unknown",
                        user_agent=user_agent or "unknown",
                        success=True
                    )
            
            if revoked_count > 0:
                logger.info(f"Revoked {revoked_count} refresh tokens for user {user_id}")
            
            return revoked_count
    
    def get_user_tokens(self, user_id: str) -> List[RefreshToken]:
        """Obter todos os tokens ativos de um usuário"""
        with self._lock:
            return [
                token for token in self.tokens.values()
                if token.user_id == user_id and token.is_valid()
            ]
    
    def get_token_info(self, token_id: str) -> Optional[RefreshToken]:
        """Obter informações de um token específico"""
        return self.tokens.get(token_id)
    
    def _log_token_usage(self, token_id: str, user_id: str, action: str,
                         ip_address: str, user_agent: str, success: bool,
                         failure_reason: str = None):
        """Registrar uso de token para auditoria"""
        usage = TokenUsage(
            timestamp=datetime.now(UTC),
            token_id=token_id,
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason
        )
        self.token_usage.append(usage)
    
    def get_usage_stats(self, user_id: str = None, hours: int = 24) -> Dict[str, any]:
        """Obter estatísticas de uso de tokens"""
        with self._lock:
            now = datetime.now(UTC)
            cutoff = now - timedelta(hours=hours)
            
            # Filtrar logs por período
            recent_usage = [
                usage for usage in self.token_usage
                if usage.timestamp > cutoff
            ]
            
            if user_id:
                recent_usage = [
                    usage for usage in recent_usage
                    if usage.user_id == user_id
                ]
            
            # Contar por ação
            action_counts = {}
            for usage in recent_usage:
                action_counts[usage.action] = action_counts.get(usage.action, 0) + 1
            
            # Contar sucessos/falhas
            success_count = len([u for u in recent_usage if u.success])
            failure_count = len([u for u in recent_usage if not u.success])
            
            # Tokens ativos
            active_tokens = len([t for t in self.tokens.values() if t.is_valid()])
            
            return {
                "period_hours": hours,
                "total_usage": len(recent_usage),
                "success_count": success_count,
                "failure_count": failure_count,
                "action_counts": action_counts,
                "active_tokens": active_tokens,
                "timestamp": now.isoformat()
            }
    
    def cleanup_old_logs(self, days: int = 30):
        """Limpar logs antigos"""
        with self._lock:
            cutoff = datetime.now(UTC) - timedelta(days=days)
            original_count = len(self.token_usage)
            
            self.token_usage = [
                usage for usage in self.token_usage
                if usage.timestamp > cutoff
            ]
            
            removed_count = original_count - len(self.token_usage)
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} old token usage logs")


# Instância global
refresh_token_manager = RefreshTokenManager()
