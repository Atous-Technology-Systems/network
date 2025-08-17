"""API Routes Module

Contém todas as rotas da API REST do sistema ATous Secure Network.
"""

from . import (
    health,
    admin,
    discovery,
    relay,
    agents,
    policies,
    security,
    auth  # Nova importação das rotas de autenticação
)

# Lista de todos os routers disponíveis
__all__ = [
    "health",
    "admin", 
    "discovery",
    "relay",
    "agents",
    "policies",
    "security",
    "auth"  # Incluindo rotas de autenticação
]