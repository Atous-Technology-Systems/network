#!/usr/bin/env python3
"""
Servidor de teste simplificado para verificar funcionalidade básica
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import logging

# Configurar logging básico
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Criar aplicação FastAPI
app = FastAPI(
    title="ATous Secure Network - Test Server",
    description="Servidor de teste simplificado para verificar funcionalidade básica",
    version="1.0.0"
)

# Modelos básicos
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    is_active: bool

# Rotas básicas
@app.get("/")
async def root():
    """Rota raiz para teste"""
    return {"message": "ATous Secure Network - Test Server", "status": "running"}

@app.get("/health")
async def health_check():
    """Verificação de saúde do servidor"""
    return {"status": "healthy", "timestamp": "2025-08-17T08:25:00Z"}

@app.post("/auth/register", response_model=UserResponse)
async def register_user(user_data: UserCreate):
    """Registro de usuário simplificado"""
    try:
        # Simular criação de usuário
        user_response = UserResponse(
            user_id="test-user-123",
            username=user_data.username,
            email=user_data.email,
            is_active=True
        )
        logger.info(f"Usuário registrado: {user_data.username}")
        return user_response
    except Exception as e:
        logger.error(f"Erro no registro: {e}")
        raise HTTPException(status_code=500, detail="Erro interno no registro")

@app.post("/auth/login")
async def login_user(user_data: UserCreate):
    """Login de usuário simplificado"""
    try:
        # Simular autenticação
        if user_data.username == "testuser" and user_data.password == "testpass":
            return {
                "message": "Login realizado com sucesso",
                "user_id": "test-user-123",
                "username": user_data.username,
                "access_token": "test-token-123"
            }
        else:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
    except Exception as e:
        logger.error(f"Erro no login: {e}")
        raise HTTPException(status_code=500, detail="Erro interno no login")

@app.get("/docs")
async def get_docs():
    """Documentação da API"""
    return {
        "message": "Documentação da API disponível em /docs",
        "endpoints": [
            "GET / - Rota raiz",
            "GET /health - Verificação de saúde",
            "POST /auth/register - Registro de usuário",
            "POST /auth/login - Login de usuário"
        ]
    }

if __name__ == "__main__":
    logger.info("Iniciando servidor de teste...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
