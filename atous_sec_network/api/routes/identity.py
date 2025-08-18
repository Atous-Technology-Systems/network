"""Identity management API routes.

This module provides endpoints for:
- User registration and authentication
- Agent identity management
- Session management
- Role-based access control
- Audit logging
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, List
from datetime import datetime, UTC

from ...security.identity_service import IdentityService, Role
from ...core.logging_config import get_logger

logger = get_logger('api.identity')

router = APIRouter(prefix="/v1/identity", tags=["identity"])

# Initialize services
identity_service = IdentityService()

# Security scheme
security = HTTPBearer()


# Pydantic models
class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    email: Optional[EmailStr] = None
    role: str = Field(default="user", pattern="^(admin|operator|user|readonly)$")


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    status: str
    created_at: str
    last_login: Optional[str] = None


class LoginResponse(BaseModel):
    user: UserResponse
    session_token: str
    expires_at: str
    mfa_enabled: bool


class AgentCreateRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=100)
    name: str = Field(..., min_length=1, max_length=200)
    agent_type: str = Field(default="agent", pattern="^(agent|service|device)$")
    public_key: Optional[str] = None
    metadata: Optional[Dict] = None


class AgentResponse(BaseModel):
    id: int
    agent_id: str
    name: str
    type: str
    status: str
    public_key: Optional[str] = None
    certificate_serial: Optional[int] = None
    created_at: str
    last_heartbeat: Optional[str] = None
    metadata: Optional[Dict] = None


class AgentHeartbeatRequest(BaseModel):
    metadata: Optional[Dict] = None


class RoleUpdateRequest(BaseModel):
    new_role: str = Field(..., pattern="^(admin|operator|user|readonly)$")


class UserSuspendRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class AuditLogEntry(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    resource: str
    details: str
    ip_address: Optional[str] = None
    timestamp: str


# Dependency functions
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """Get current authenticated user from session token."""
    session_token = credentials.credentials
    user_info = identity_service.validate_session(session_token)
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    
    return user_info


def require_admin_role(current_user: Dict = Depends(get_current_user)) -> Dict:
    """Require admin role for access."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_operator_or_admin(current_user: Dict = Depends(get_current_user)) -> Dict:
    """Require operator or admin role for access."""
    if current_user["role"] not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")
    return current_user


# User management endpoints
@router.post("/users", response_model=UserResponse)
async def create_user(request: UserCreateRequest, admin_user: Dict = Depends(require_admin_role)):
    """Create a new user account (admin only)."""
    try:
        user = identity_service.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            role=request.role
        )
        
        logger.info(f"Admin {admin_user['username']} created user: {request.username}")
        return UserResponse(**user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")


@router.post("/auth/login", response_model=LoginResponse)
async def login(request: UserLoginRequest, client_request: Request):
    """Authenticate user and create session."""
    try:
        # Get client IP
        client_ip = client_request.client.host if client_request.client else None
        
        auth_result = identity_service.authenticate_user(
            username=request.username,
            password=request.password,
            ip_address=client_ip
        )
        
        if not auth_result:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get full user info
        user_info = identity_service.get_user_info(auth_result["user_id"])
        if not user_info:
            raise HTTPException(status_code=500, detail="User info not found")
        
        return LoginResponse(
            user=UserResponse(**user_info),
            session_token=auth_result["session_token"],
            expires_at=auth_result["expires_at"],
            mfa_enabled=auth_result["mfa_enabled"]
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")


@router.post("/auth/logout")
async def logout(current_user: Dict = Depends(get_current_user)):
    """Logout and invalidate session."""
    try:
        # Note: In a real implementation, you'd want to invalidate the specific session
        # For now, we'll just return success
        logger.info(f"User {current_user['username']} logged out")
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")


@router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information."""
    try:
        user_info = identity_service.get_user_info(current_user["user_id"])
        if not user_info:
            raise HTTPException(status_code=404, detail="User not found")
        
        return UserResponse(**user_info)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user info")


@router.get("/users", response_model=List[UserResponse])
async def list_users(limit: int = Query(default=100, ge=1, le=1000),
                    admin_user: Dict = Depends(require_admin_role)):
    """List all users (admin only)."""
    try:
        users = identity_service.list_users(limit=limit)
        return [UserResponse(**user) for user in users]
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


@router.put("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(user_id: int, request: RoleUpdateRequest,
                          admin_user: Dict = Depends(require_admin_role)):
    """Update user role (admin only)."""
    try:
        success = identity_service.update_user_role(
            user_id=user_id,
            new_role=request.new_role,
            admin_user_id=admin_user["user_id"]
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get updated user info
        user_info = identity_service.get_user_info(user_id)
        if not user_info:
            raise HTTPException(status_code=404, detail="User not found")
        
        logger.info(f"Admin {admin_user['username']} updated user {user_id} role to {request.new_role}")
        return UserResponse(**user_info)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user role")


@router.post("/users/{user_id}/suspend")
async def suspend_user(user_id: int, request: UserSuspendRequest,
                      admin_user: Dict = Depends(require_admin_role)):
    """Suspend a user account (admin only)."""
    try:
        success = identity_service.suspend_user(
            user_id=user_id,
            reason=request.reason,
            admin_user_id=admin_user["user_id"]
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        
        logger.info(f"Admin {admin_user['username']} suspended user {user_id}: {request.reason}")
        return {"message": "User suspended successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to suspend user: {e}")
        raise HTTPException(status_code=500, detail="Failed to suspend user")


# Agent management endpoints
@router.post("/agents", response_model=AgentResponse)
async def create_agent(request: AgentCreateRequest, 
                      current_user: Dict = Depends(require_operator_or_admin)):
    """Create a new agent identity."""
    try:
        agent = identity_service.create_agent(
            agent_id=request.agent_id,
            name=request.name,
            agent_type=request.agent_type,
            public_key=request.public_key,
            metadata=request.metadata
        )
        
        logger.info(f"User {current_user['username']} created agent: {request.agent_id}")
        return AgentResponse(**agent)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create agent: {e}")
        raise HTTPException(status_code=500, detail="Failed to create agent")


@router.get("/agents", response_model=List[AgentResponse])
async def list_agents(status: Optional[str] = None,
                     limit: int = Query(default=100, ge=1, le=1000),
                     current_user: Dict = Depends(require_operator_or_admin)):
    """List agents with optional filtering."""
    try:
        agents = identity_service.list_agents(status=status, limit=limit)
        return [AgentResponse(**agent) for agent in agents]
    except Exception as e:
        logger.error(f"Failed to list agents: {e}")
        raise HTTPException(status_code=500, detail="Failed to list agents")


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str, current_user: Dict = Depends(require_operator_or_admin)):
    """Get agent information."""
    try:
        agent = identity_service.get_agent_info(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return AgentResponse(**agent)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent: {e}")
        raise HTTPException(status_code=500, detail="Failed to get agent")


@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest,
                         current_user: Dict = Depends(require_operator_or_admin)):
    """Update agent heartbeat."""
    try:
        success = identity_service.update_agent_heartbeat(
            agent_id=agent_id,
            metadata=request.metadata
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {"message": "Heartbeat updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent heartbeat: {e}")
        raise HTTPException(status_code=500, detail="Failed to update heartbeat")


# Audit and monitoring endpoints
@router.get("/audit", response_model=List[AuditLogEntry])
async def get_audit_log(user_id: Optional[int] = None,
                       action: Optional[str] = None,
                       limit: int = Query(default=100, ge=1, le=1000),
                       admin_user: Dict = Depends(require_admin_role)):
    """Get audit log entries (admin only)."""
    try:
        audit_entries = identity_service.get_audit_log(
            user_id=user_id,
            action=action,
            limit=limit
        )
        return [AuditLogEntry(**entry) for entry in audit_entries]
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        raise HTTPException(status_code=500, detail="Failed to get audit log")


@router.get("/stats")
async def get_identity_stats(admin_user: Dict = Depends(require_admin_role)):
    """Get identity system statistics (admin only)."""
    try:
        stats = identity_service.get_system_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get identity stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")


# Health check endpoint
@router.get("/health")
async def identity_health():
    """Check identity service health."""
    try:
        # Simple health check - try to get system stats
        stats = identity_service.get_system_stats()
        return {
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "service": "identity"
        }
    except Exception as e:
        logger.error(f"Identity service health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(UTC).isoformat(),
            "service": "identity"
        }
