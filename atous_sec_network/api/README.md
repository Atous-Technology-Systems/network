# ATous Secure Network API

API REST para o sistema ATous Secure Network com Federated Learning.

## Funcionalidades Implementadas

### ✅ Health Check Endpoint
- **GET /health** - Verificação de saúde dos sistemas
- **GET /api/security/status** - Status dos sistemas de segurança ABISS e NNIS
- **GET /api/metrics** - Métricas detalhadas do sistema

### 📊 Métricas Incluídas
- Tempo de resposta (ms)
- Uso de memória (MB)
- Uptime do sistema (segundos)
- Status dos sistemas (ABISS, NNIS, Model Manager)

## Como Executar

### Desenvolvimento
```bash
# Instalar dependências
pip install -r requirements.txt

# Executar servidor de desenvolvimento
python -m atous_sec_network.api.server
```

### Produção
```bash
# Executar com uvicorn
uvicorn atous_sec_network.api.server:app --host 0.0.0.0 --port 8000
```

## Endpoints Disponíveis

### Health & Info
- `GET /` — informações básicas da API
- `GET /health` — saúde geral e métricas
- `GET /api/info` — informações detalhadas da API
- `GET /api/security/status` — status dos sistemas de segurança
- `GET /api/metrics` — métricas do sistema

### Admin (MVP)
- `GET /v1/admin/overview`
- `GET /v1/admin/events?limit=N`
- `POST /v1/admin/events` (Header opcional: `X-Admin-Api-Key`)

### Discovery
- `POST /v1/discovery/register`
- `GET /v1/discovery/services?name=...`
- `GET /v1/discovery/resolve?name=...&pref=local,lan,wan`
- `GET /v1/discovery/agents/{agent_id}`

### Relay
- `POST /v1/relay/heartbeat`
- `POST /v1/relay/send`
- `GET /v1/relay/poll?agent_id=...`

### Agents
- `POST /v1/agents/enroll`
- `POST /v1/agents/{agent_id}/heartbeat`

### Policies (MVP)
- `GET /v1/policies/active?agent_id=...`

### Criptografia
- `POST /api/crypto/encrypt`
- `POST /api/security/encrypt`
- `POST /encrypt`

### WebSockets
- `WS /ws` — WebSocket principal
- `WS /api/ws` — WebSocket da API
- `WS /websocket` — WebSocket genérico

### Documentação
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Estrutura da Resposta

```json
{
  "status": "healthy",
  "systems": {
    "abiss": {
      "status": "healthy",
      "last_check": "2025-01-01T12:00:00.000000"
    },
    "nnis": {
      "status": "healthy",
      "last_check": "2025-01-01T12:00:00.000000"
    },
    "model_manager": {
      "status": "healthy",
      "last_check": "2025-01-01T12:00:00.000000"
    }
  },
  "timestamp": "2025-01-01T12:00:00.000000",
  "metrics": {
    "response_time_ms": 15.23,
    "memory_usage_mb": 128.45,
    "uptime_seconds": 3600.0
  }
}
```

## Testes

```bash
# Executar testes da API
pytest tests/api/ -v

# Executar testes específicos do health endpoint
pytest tests/api/test_health_endpoint.py -v
```

## Próximos Passos

- [ ] Persistência para discovery/relay (Redis/Postgres)
- [ ] OIDC + RBAC para Admin
- [ ] Agente com mTLS e pinagem de CA
- [ ] Engine de políticas com armazenamento versionado