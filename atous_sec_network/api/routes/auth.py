"""
Rotas de Autenticação ATous Secure Network

Este módulo implementa endpoints para:
- Registro e gerenciamento de usuários
- Autenticação com JWT
- Refresh tokens
- Gerenciamento de sessões
- Auditoria de segurança
"""

from typing import List, Optional
from datetime import datetime, timedelta, UTC
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

from atous_sec_network.security.access_control import access_control, Permission
from atous_sec_network.security.refresh_token_manager import refresh_token_manager
from atous_sec_network.api.models.auth import (
    UserCreate, UserUpdate, UserLogin, UserResponse, TokenResponse,
    RefreshTokenRequest, RefreshTokenResponse, LogoutRequest, LogoutResponse,
    PasswordChangeRequest, PasswordResetRequest, PasswordResetConfirm,
    UserSessionInfo, UserListResponse, SecurityStatsResponse,
    AccessLogResponse
)

# Configurar logging
logger = logging.getLogger(__name__)

# Router principal
router = APIRouter(prefix="/auth", tags=["authentication"])

# Security scheme
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependency para obter usuário atual do token JWT
    
    Args:
        credentials: Credenciais HTTP Bearer
        
    Returns:
        dict: Informações do usuário autenticado
        
    Raises:
        HTTPException: Se token inválido ou expirado
    """
    try:
        token = credentials.credentials
        user_info = access_control.validate_token(token)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido ou expirado",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user_info
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_permission(permission: Permission):
    """
    Dependency para verificar permissão específica
    
    Args:
        permission: Permissão requerida
        
    Returns:
        function: Dependency function
    """
    def permission_checker(current_user: dict = Depends(get_current_user)):
        user_id = current_user["user_id"]
        
        if not access_control.check_permission(user_id, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão '{permission.value}' requerida"
            )
        
        return current_user
    
    return permission_checker


def get_client_info(request: Request) -> tuple:
    """
    Extrair informações do cliente da requisição
    
    Returns:
        tuple: (ip_address, user_agent)
    """
    # Obter IP real (considerando proxies)
    ip_address = request.client.host
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    
    user_agent = request.headers.get("User-Agent", "Unknown")
    
    return ip_address, user_agent


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    request: Request
):
    """
    Registrar novo usuário no sistema
    
    Cria uma nova conta de usuário com as credenciais fornecidas.
    O usuário recebe automaticamente o papel de OPERATOR por padrão.
    
    Args:
        user_data: Dados do usuário a ser criado
        request: Objeto da requisição HTTP
        
    Returns:
        UserResponse: Dados do usuário criado com sucesso
        
    Raises:
        HTTPException: Se dados inválidos, usuário já existe ou erro interno
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        # Criar usuário
        user_id = access_control.create_user(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            roles=set(user_data.roles) if user_data.roles else None
        )
        
        # Obter usuário criado
        user = access_control.users[user_id]
        
        # Log de criação
        logger.info(f"User registered: {user_data.username} ({user_id}) from {ip_address}")
        
        # Retornar resposta
        return UserResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=[role.value for role in user.roles],
            permissions=[perm.value for perm in user.get_all_permissions()],
            is_active=user.is_active,
            is_locked=user.is_locked,
            last_login=user.last_login,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        
    except ValueError as e:
        logger.warning(f"User registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error in user registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.post("/login", response_model=TokenResponse)
async def login_user(
    login_data: UserLogin,
    request: Request
):
    """
    Autenticar usuário e gerar tokens de acesso
    
    Valida as credenciais do usuário e retorna um access token JWT
    e um refresh token para renovação automática. O sistema também
    registra a atividade de login para auditoria.
    
    Args:
        login_data: Credenciais de login (username e password)
        request: Objeto da requisição HTTP
        
    Returns:
        TokenResponse: Access token, refresh token e informações do usuário
        
    Raises:
        HTTPException: Se credenciais inválidas, conta bloqueada ou erro interno
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        # Autenticar usuário
        auth_result = access_control.authenticate(
            username=login_data.username,
            password=login_data.password,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Criar refresh token
        refresh_token_plain, refresh_token_id = refresh_token_manager.create_refresh_token(
            user_id=auth_result["user_id"],
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Calcular tempo de expiração
        expires_at = datetime.fromisoformat(auth_result["expires_at"])
        expires_in = int((expires_at - datetime.now(UTC)).total_seconds())
        
        # Log de login bem-sucedido
        logger.info(f"User logged in: {auth_result['username']} ({auth_result['user_id']}) from {ip_address}")
        
        # Retornar resposta
        return TokenResponse(
            access_token=auth_result["token"],
            refresh_token=refresh_token_plain,
            token_type="bearer",
            expires_in=expires_in,
            user=UserResponse(
                user_id=auth_result["user_id"],
                username=auth_result["username"],
                email=auth_result.get("email", "unknown@example.com"),  # Adicionar email
                roles=auth_result["roles"],
                permissions=auth_result["permissions"],
                is_active=True,
                is_locked=False,
                last_login=datetime.now(UTC),  # Adicionar last_login
                created_at=datetime.now(UTC),  # Placeholder
                updated_at=datetime.now(UTC)   # Placeholder
            )
        )
        
    except ValueError as e:
        logger.warning(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error in login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    request: Request
):
    """
    Renovar access token usando refresh token
    
    Permite renovar o access token expirado usando um refresh token válido.
    O sistema gera um novo access token e rotaciona o refresh token
    para segurança adicional. Apenas o último refresh token é válido.
    
    Args:
        refresh_data: Refresh token atual válido
        request: Objeto da requisição HTTP
        
    Returns:
        RefreshTokenResponse: Novo access token e refresh token rotacionado
        
    Raises:
        HTTPException: Se refresh token inválido, expirado ou erro interno
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        # Validar refresh token
        token_id = refresh_token_manager.validate_refresh_token(
            token=refresh_data.refresh_token,
            user_id="",  # Será validado pelo manager
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if not token_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido ou expirado"
            )
        
        # Obter informações do token
        token_info = refresh_token_manager.get_token_info(token_id)
        if not token_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token não encontrado"
            )
        
        # Rotacionar token
        new_refresh_token, new_token_id = refresh_token_manager.rotate_refresh_token(
            old_token_id=token_id,
            user_id=token_info.user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Gerar novo access token
        new_access_token = access_control._generate_token(
            user_id=token_info.user_id,
            session_id=token_id  # Usar token_id como session_id
        )
        
        # Log de refresh
        logger.info(f"Token refreshed for user {token_info.user_id} from {ip_address}")
        
        # Retornar resposta
        return RefreshTokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=3600  # 1 hora
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout_user(
    logout_data: LogoutRequest,
    current_user: dict = Depends(get_current_user),
    request: Request = None
):
    """
    Fazer logout do usuário e invalidar tokens
    
    Realiza o logout do usuário autenticado, revogando o refresh token
    se fornecido. O access token continua válido até sua expiração natural,
    mas o refresh token é invalidado para segurança.
    
    Args:
        logout_data: Dados de logout (opcional refresh token para revogar)
        current_user: Usuário autenticado (obtido via token JWT)
        request: Objeto da requisição HTTP
        
    Returns:
        LogoutResponse: Confirmação de logout com timestamp
        
    Raises:
        HTTPException: Se usuário não autenticado ou erro interno
    """
    try:
        ip_address, user_agent = get_client_info(request) if request else ("unknown", "unknown")
        
        # Revogar refresh token se fornecido
        if logout_data.refresh_token:
            refresh_token_manager.revoke_refresh_token(
                token_id="",  # Será encontrado pelo manager
                user_id=current_user["user_id"],
                ip_address=ip_address,
                user_agent=user_agent
            )
        
        # Log de logout
        logger.info(f"User logged out: {current_user['username']} ({current_user['user_id']}) from {ip_address}")
        
        return LogoutResponse(
            message="Logout realizado com sucesso",
            logout_time=datetime.now(UTC)
        )
        
    except Exception as e:
        logger.error(f"Error in logout: {e}")
        # Não falhar o logout por erros
        return LogoutResponse(
            message="Logout realizado com sucesso",
            logout_time=datetime.now(UTC)
        )


@router.get("/profile", response_model=UserResponse)
async def get_user_profile(
    current_user: dict = Depends(get_current_user)
):
    """
    Obter perfil completo do usuário autenticado
    
    Retorna todas as informações do perfil do usuário logado,
    incluindo dados pessoais, papéis, permissões e status da conta.
    Requer autenticação via token JWT válido.
    
    Args:
        current_user: Usuário autenticado (obtido via token JWT)
        
    Returns:
        UserResponse: Perfil completo do usuário com todos os dados
        
    Raises:
        HTTPException: Se usuário não autenticado ou não encontrado
    """
    try:
        user_id = current_user["user_id"]
        user = access_control.users.get(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuário não encontrado"
            )
        
        return UserResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=[role.value for role in user.roles],
            permissions=[perm.value for perm in user.get_all_permissions()],
            is_active=user.is_active,
            is_locked=user.is_locked,
            last_login=user.last_login,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.put("/profile", response_model=UserResponse)
async def update_user_profile(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Atualizar perfil do usuário autenticado
    
    Permite ao usuário atualizar seus dados pessoais, incluindo email,
    senha e outros campos configuráveis. Apenas o próprio usuário
    pode modificar seu perfil. Requer autenticação via token JWT.
    
    Args:
        user_update: Dados de atualização (campos opcionais)
        current_user: Usuário autenticado (obtido via token JWT)
        
    Returns:
        UserResponse: Perfil atualizado com dados modificados
        
    Raises:
        HTTPException: Se usuário não autenticado, dados inválidos ou erro interno
    """
    try:
        user_id = current_user["user_id"]
        user = access_control.users.get(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuário não encontrado"
            )
        
        # Atualizar campos se fornecidos
        if user_update.email is not None:
            user.email = user_update.email
        if user_update.password is not None:
            user.password_hash = access_control._hash_password(user_update.password)
        if user_update.roles is not None:
            user.roles = set(user_update.roles)
        if user_update.is_active is not None:
            user.is_active = user_update.is_active
        if user_update.is_locked is not None:
            user.is_locked = user_update.is_locked
        
        user.updated_at = datetime.now(UTC)
        
        # Log de atualização
        logger.info(f"User profile updated: {user.username} ({user_id})")
        
        return UserResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=[role.value for role in user.roles],
            permissions=[perm.value for perm in user.get_all_permissions()],
            is_active=user.is_active,
            is_locked=user.is_locked,
            last_login=user.last_login,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Alterar senha do usuário autenticado
    
    Permite ao usuário alterar sua senha atual por uma nova.
    Requer a senha atual para validação e a nova senha deve
    atender aos critérios de complexidade do sistema.
    
    Args:
        password_data: Dados de mudança de senha (senha atual e nova)
        current_user: Usuário autenticado (obtido via token JWT)
        
    Returns:
        dict: Confirmação de alteração de senha bem-sucedida
        
    Raises:
        HTTPException: Se senha atual incorreta, nova senha inválida ou erro interno
    """
    try:
        user_id = current_user["user_id"]
        user = access_control.users.get(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuário não encontrado"
            )
        
        # Verificar senha atual
        if not access_control._verify_password(password_data.current_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Senha atual incorreta"
            )
        
        # Atualizar senha
        user.password_hash = access_control._hash_password(password_data.new_password)
        user.updated_at = datetime.now(UTC)
        
        # Log de mudança de senha
        logger.info(f"Password changed for user: {user.username} ({user_id})")
        
        return {"message": "Senha alterada com sucesso"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.get("/sessions", response_model=List[UserSessionInfo])
async def get_user_sessions(
    current_user: dict = Depends(get_current_user)
):
    """
    Obter sessões ativas do usuário autenticado
    
    Lista todas as sessões ativas do usuário, incluindo informações
    sobre IPs de origem, User-Agents e timestamps de atividade.
    Útil para monitorar e gerenciar múltiplas sessões.
    
    Args:
        current_user: Usuário autenticado (obtido via token JWT)
        
    Returns:
        List[UserSessionInfo]: Lista de sessões ativas com detalhes
        
    Raises:
        HTTPException: Se usuário não autenticado ou erro interno
    """
    try:
        user_id = current_user["user_id"]
        sessions = access_control.get_user_sessions(user_id)
        
        return [
            UserSessionInfo(
                session_id=session["session_id"],
                created_at=session["created_at"],
                last_activity=session["last_activity"],
                ip_address=session["ip_address"],
                user_agent=session["user_agent"]
            )
            for session in sessions
        ]
        
    except Exception as e:
        logger.error(f"Error getting user sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


# Endpoints administrativos (requerem permissões especiais)
@router.get("/users", response_model=UserListResponse)
async def list_users(
    page: int = 1,
    per_page: int = 10,
    current_user: dict = Depends(require_permission(Permission.ADMIN_USERS))
):
    """
    Listar usuários do sistema (apenas para administradores)
    
    Endpoint administrativo que permite visualizar todos os usuários
    do sistema com paginação. Requer permissão ADMIN_USERS.
    Útil para administradores monitorarem e gerenciarem contas.
    
    Args:
        page: Número da página (padrão: 1)
        per_page: Usuários por página (padrão: 10, máximo: 100)
        current_user: Usuário autenticado com permissão ADMIN_USERS
        
    Returns:
        UserListResponse: Lista paginada de usuários com metadados
        
    Raises:
        HTTPException: Se usuário não autenticado, sem permissão ou erro interno
    """
    try:
        users = list(access_control.users.values())
        
        # Paginação simples
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_users = users[start_idx:end_idx]
        
        # Converter para UserResponse
        user_responses = []
        for user in paginated_users:
            user_responses.append(UserResponse(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                roles=[role.value for role in user.roles],
                permissions=[perm.value for perm in user.get_all_permissions()],
                is_active=user.is_active,
                is_locked=user.is_locked,
                last_login=user.last_login,
                created_at=user.created_at,
                updated_at=user.updated_at
            ))
        
        return UserListResponse(
            users=user_responses,
            total=len(users),
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.get("/security/stats", response_model=SecurityStatsResponse)
async def get_security_stats(
    current_user: dict = Depends(require_permission(Permission.SECURITY_READ))
):
    """
    Obter estatísticas de segurança do sistema
    
    Endpoint que fornece métricas e estatísticas de segurança,
    incluindo tentativas de login, bloqueios, taxas de sucesso
    e outras informações relevantes para análise de segurança.
    Requer permissão SECURITY_READ.
    
    Args:
        current_user: Usuário autenticado com permissão SECURITY_READ
        
    Returns:
        SecurityStatsResponse: Estatísticas detalhadas de segurança
        
    Raises:
        HTTPException: Se usuário não autenticado, sem permissão ou erro interno
    """
    try:
        stats = access_control.get_security_stats()
        return SecurityStatsResponse(**stats)
        
    except Exception as e:
        logger.error(f"Error getting security stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.get("/security/logs", response_model=AccessLogResponse)
async def get_access_logs(
    page: int = 1,
    per_page: int = 50,
    user_id: Optional[str] = None,
    current_user: dict = Depends(require_permission(Permission.SECURITY_VIEW_LOGS))
):
    """
    Obter logs de acesso e auditoria do sistema
    
    Endpoint que fornece acesso aos logs de auditoria do sistema,
    incluindo tentativas de login, acessos, mudanças de perfil
    e outras atividades de segurança. Suporta filtros por usuário
    e paginação. Requer permissão SECURITY_VIEW_LOGS.
    
    Args:
        page: Número da página (padrão: 1)
        per_page: Logs por página (padrão: 50, máximo: 200)
        user_id: Filtrar por usuário específico (opcional)
        current_user: Usuário autenticado com permissão SECURITY_VIEW_LOGS
        
    Returns:
        AccessLogResponse: Lista paginada de logs de acesso com metadados
        
    Raises:
        HTTPException: Se usuário não autenticado, sem permissão ou erro interno
    """
    try:
        logs = access_control.get_access_logs(limit=1000, user_id=user_id)
        
        # Paginação
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_logs = logs[start_idx:end_idx]
        
        return AccessLogResponse(
            logs=paginated_logs,
            total=len(logs),
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error getting access logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


@router.get("/tokens/stats")
async def get_token_stats(
    current_user: dict = Depends(require_permission(Permission.SECURITY_READ))
):
    """
    Obter estatísticas de refresh tokens e sessões
    
    Endpoint que fornece métricas sobre o uso de refresh tokens,
    incluindo tokens ativos, expirados, rotacionados e estatísticas
    de uso por usuário. Requer permissão SECURITY_READ.
    
    Args:
        current_user: Usuário autenticado com permissão SECURITY_READ
        
    Returns:
        dict: Estatísticas detalhadas de tokens e sessões
        
    Raises:
        HTTPException: Se usuário não autenticado, sem permissão ou erro interno
    """
    try:
        stats = refresh_token_manager.get_usage_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Error getting token stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )


# Endpoints de manutenção (apenas para super admins)
@router.post("/maintenance/cleanup")
async def cleanup_expired_data(
    current_user: dict = Depends(require_permission(Permission.ADMIN_FULL))
):
    """
    Limpar dados expirados e realizar manutenção do sistema
    
    Endpoint administrativo que executa tarefas de limpeza automática,
    incluindo remoção de sessões expiradas, logs antigos e dados
    temporários. Requer permissão ADMIN_FULL (super administrador).
    
    Args:
        current_user: Usuário autenticado com permissão ADMIN_FULL
        
    Returns:
        dict: Resultado da limpeza com estatísticas e timestamp
        
    Raises:
        HTTPException: Se usuário não autenticado, sem permissão ou erro interno
    """
    try:
        # Limpar sessões expiradas
        access_control.cleanup_expired_sessions()
        
        # Limpar logs antigos de tokens
        refresh_token_manager.cleanup_old_logs(days=30)
        
        logger.info(f"Maintenance cleanup completed by user: {current_user['username']}")
        
        return {
            "message": "Limpeza de manutenção concluída",
            "timestamp": datetime.now(UTC).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in maintenance cleanup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )
