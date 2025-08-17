# Endpoints de Autenticacao ATous Secure Network

## Visao Geral

O sistema de autenticacao ATous Secure Network implementa um sistema completo de gerenciamento de usuarios com JWT tokens, refresh tokens e controle de acesso baseado em roles (RBAC).

## Base URL

```
http://127.0.0.1:8000
```

## Endpoints Disponiveis

### 1. Registro de Usuario

**Endpoint:** `POST /auth/register`

**Descricao:**
Registra um novo usuario no sistema.

**Request Body:**
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "SecurePass123!",
  "roles": ["operator"]
}
```

**Response (201):**
```json
{
  "message": "Usuario registrado com sucesso",
  "user_id": "uuid-do-usuario",
  "username": "testuser",
  "email": "test@example.com",
  "roles": ["operator"],
  "is_active": true,
  "created_at": "2024-12-01T10:00:00Z"
}
```

**Validacoes:**
- Username: 3-50 caracteres, apenas letras, numeros, hifens e underscores
- Email: Formato valido de email
- Senha: Minimo 8 caracteres, deve conter maiuscula, minuscula, numero e caractere especial
- Roles: Lista opcional de roles (padrao: guest)

**Headers:**
```
Content-Type: application/json
```

### 2. Login de Usuario

**Endpoint:** `POST /auth/login`

**Descricao:**
Autentica usuario e retorna tokens de acesso.

**Request Body:**
```json
{
  "username": "testuser",
  "password": "SecurePass123!",
  "remember_me": false
}
```

**Response (200):**
```json
{
  "message": "Login realizado com sucesso",
  "access_token": "jwt-access-token",
  "refresh_token": "refresh-token",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "uuid-do-usuario",
    "username": "testuser",
    "email": "test@example.com",
    "roles": ["operator"],
    "is_active": true
  }
}
```

**Headers:**
```
Content-Type: application/json
```

### 3. Refresh Token

**Endpoint:** `POST /auth/refresh`

**Descricao:**
Renova o access token usando o refresh token.

**Request Body:**
```json
{
  "refresh_token": "refresh-token-atual"
}
```

**Response (200):**
```json
{
  "message": "Token renovado com sucesso",
  "access_token": "novo-jwt-access-token",
  "refresh_token": "novo-refresh-token",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Nota:** O refresh token anterior e invalidado e um novo e gerado para seguranca.

### 4. Perfil do Usuario

**Endpoint:** `GET /auth/profile`

**Descricao:**
Obtem o perfil do usuario autenticado.

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "user": {
    "id": "uuid-do-usuario",
    "username": "testuser",
    "email": "test@example.com",
    "roles": ["operator"],
    "is_active": true,
    "created_at": "2024-12-01T10:00:00Z",
    "last_login": "2024-12-01T15:30:00Z"
  }
}
```

### 5. Atualizar Perfil

**Endpoint:** `PUT /auth/profile`

**Descricao:**
Atualiza o perfil do usuario autenticado.

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "is_active": true
}
```

**Headers:**
```
Authorization: Bearer {jwt_token}
Content-Type: application/json
```

**Response (200):**
```json
{
  "message": "Perfil atualizado com sucesso",
  "user": {
    "id": "uuid-do-usuario",
    "username": "testuser",
    "email": "newemail@example.com",
    "roles": ["operator"],
    "is_active": true,
    "updated_at": "2024-12-01T16:00:00Z"
  }
}
```

**Campos Editaveis:**
- `email`: Novo email
- `is_active`: Status ativo/inativo
- `password`: Nova senha (deve seguir as mesmas validacoes)

### 6. Alterar Senha

**Endpoint:** `POST /auth/change-password`

**Descricao:**
Altera a senha do usuario autenticado.

**Request Body:**
```json
{
  "current_password": "SecurePass123!",
  "new_password": "NewSecurePass456!"
}
```

**Headers:**
```
Authorization: Bearer {jwt_token}
Content-Type: application/json
```

**Response (200):**
```json
{
  "message": "Senha alterada com sucesso",
  "password_changed_at": "2024-12-01T16:30:00Z"
}
```

### 7. Sessoes Ativas

**Endpoint:** `GET /auth/sessions`

**Descricao:**
Lista todas as sessoes ativas do usuario.

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "sessions": [
    {
      "session_id": "uuid-da-sessao",
      "device_info": "Chrome 120.0.0.0",
      "ip_address": "192.168.1.100",
      "created_at": "2024-12-01T10:00:00Z",
      "last_activity": "2024-12-01T15:30:00Z",
      "is_current": true
    }
  ],
  "total_sessions": 1
}
```

### 8. Logout

**Endpoint:** `POST /auth/logout`

**Descricao:**
Faz logout do usuario e invalida tokens.

**Request Body:**
```json
{
  "refresh_token": "refresh-token-para-invalidar"
}
```

**Headers:**
```
Authorization: Bearer {jwt_token}
Content-Type: application/json
```

**Response (200):**
```json
{
  "message": "Logout realizado com sucesso",
  "logout_at": "2024-12-01T16:45:00Z"
}
```

### 9. Listar Usuarios

**Endpoint:** `GET /auth/users`

**Descricao:**
Lista todos os usuarios do sistema (requer permissao ADMIN_USERS).

**Query Parameters:**
- `page`: Numero da pagina (padrao: 1)
- `per_page`: Usuarios por pagina (padrao: 10)

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "users": [
    {
      "id": "uuid-do-usuario",
      "username": "testuser",
      "email": "test@example.com",
      "roles": ["operator"],
      "is_active": true,
      "created_at": "2024-12-01T10:00:00Z",
      "last_login": "2024-12-01T15:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 1,
    "pages": 1
  }
}
```

### 10. Estatisticas de Seguranca

**Endpoint:** `GET /auth/security/stats`

**Descricao:**
Obtem estatisticas de seguranca do sistema (requer permissao SECURITY_READ).

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "stats": {
    "total_users": 150,
    "active_users": 89,
    "failed_logins_24h": 23,
    "blocked_ips": 5,
    "security_score": 87,
    "last_incident": "2024-12-01T14:20:00Z"
  }
}
```

### 11. Logs de Acesso

**Endpoint:** `GET /auth/security/logs`

**Descricao:**
Obtem logs de acesso do sistema (requer permissao SECURITY_VIEW_LOGS).

**Query Parameters:**
- `page`: Numero da pagina (padrao: 1)
- `per_page`: Logs por pagina (padrao: 50)
- `user_id`: Filtrar por usuario especifico (opcional)

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "logs": [
    {
      "id": "uuid-do-log",
      "user_id": "uuid-do-usuario",
      "action": "login",
      "ip_address": "192.168.1.100",
      "user_agent": "Chrome 120.0.0.0",
      "status": "success",
      "timestamp": "2024-12-01T15:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1250,
    "pages": 25
  }
}
```

### 12. Estatisticas de Tokens

**Endpoint:** `GET /auth/tokens/stats`

**Descricao:**
Obtem estatisticas de refresh tokens (requer permissao SECURITY_READ).

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "token_stats": {
    "total_tokens": 89,
    "active_tokens": 67,
    "expired_tokens": 22,
    "tokens_created_24h": 15,
    "tokens_revoked_24h": 8,
    "avg_token_lifetime": "7.5 days"
  }
}
```

### 13. Limpeza de Manutencao

**Endpoint:** `POST /auth/maintenance/cleanup`

**Descricao:**
Limpa dados expirados (requer permissao ADMIN_FULL).

**Headers:**
```
Authorization: Bearer {jwt_token}
```

**Response (200):**
```json
{
  "message": "Limpeza de manutencao concluida",
  "cleaned_sessions": 45,
  "cleaned_tokens": 23,
  "cleaned_logs": 156,
  "cleanup_at": "2024-12-01T17:00:00Z"
}
```

## Sistema de Permissoes

### Roles Disponiveis

- **SUPER_ADMIN**: Controle total do sistema
- **ADMIN**: Administracao geral
- **SECURITY_ANALYST**: Analise de seguranca
- **OPERATOR**: Operacoes basicas
- **MONITOR**: Apenas visualizacao
- **GUEST**: Acesso limitado

### Permissoes Principais

- `admin:users`: Gerenciamento de usuarios
- `admin:full`: Controle administrativo total
- `security:read`: Leitura de dados de seguranca
- `security:write`: Escrita de dados de seguranca
- `security:view_logs`: Visualizacao de logs
- `user:profile`: Gerenciamento do proprio perfil

## Seguranca

### Rate Limiting

- **Login**: Maximo 5 tentativas por IP
- **Bloqueio**: 30 minutos apos exceder limite
- **API**: 60 requisicoes por minuto, 1000 por hora

### Validacao de Senhas

- Minimo 8 caracteres
- Deve conter maiuscula, minuscula, numero e caractere especial
- Hash bcrypt com salt unico

### Politica de Tokens

- **JWT**: Validade de 1 hora
- **Refresh Token**: Validade de 30 dias
- **Rotacao**: Tokens sao rotacionados automaticamente
- **Revogacao**: Logout invalida todos os tokens
- **Limite**: Maximo 5 tokens ativos por usuario

### Monitoramento e Auditoria

- Logs de todas as acoes de autenticacao
- Rastreamento de IPs e User-Agents
- Alertas para atividades suspeitas
- Estatisticas de seguranca em tempo real

## Exemplos de Uso

### cURL - Registro de Usuario

```bash
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "SecurePass123!",
    "roles": ["operator"]
  }'
```

### cURL - Login

```bash
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "SecurePass123!"
  }'
```

### cURL - Perfil do Usuario

```bash
curl -X GET "http://127.0.0.1:8000/auth/profile" \
  -H "Authorization: Bearer {jwt_token}"
```

### cURL - Refresh Token

```bash
curl -X POST "http://127.0.0.1:8000/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "{refresh_token}"
  }'
```

## Integracao com Postman

### Variaveis de Ambiente

Configure as seguintes variaveis no Postman:

- `base_url`: http://127.0.0.1:8000
- `jwt_token`: Token JWT obtido no login
- `refresh_token`: Refresh token obtido no login

### Collection

Importe a collection do Postman que inclui todos estes endpoints com exemplos e testes automatizados.

## Codigos de Erro

- **400**: Dados invalidos ou faltando
- **401**: Nao autenticado ou token invalido
- **403**: Permissao insuficiente
- **404**: Recurso nao encontrado
- **429**: Rate limit excedido
- **500**: Erro interno do servidor

## Suporte

Para suporte tecnico ou duvidas sobre a implementacao, consulte a documentacao completa ou entre em contato com a equipe de desenvolvimento.
