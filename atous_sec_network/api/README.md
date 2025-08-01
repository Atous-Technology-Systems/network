# ATous Secure Network API

API REST para o sistema ATous Secure Network com Federated Learning.

## Funcionalidades Implementadas

### ✅ Health Check Endpoint
- **GET /health** - Verificação de saúde dos sistemas
- **GET /health/detailed** - Informações detalhadas do sistema
- **GET /health/ping** - Endpoint simples de ping

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

### Health Check
- **URL**: `GET /health`
- **Descrição**: Verifica a saúde de todos os sistemas
- **Resposta**: JSON com status dos sistemas e métricas

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

- [ ] Implementar rotas de modelo (ML)
- [ ] Implementar rotas de segurança
- [ ] Implementar rotas de rede P2P
- [ ] Implementar WebSocket para comunicação em tempo real
- [ ] Adicionar autenticação e autorização
- [ ] Implementar rate limiting
- [ ] Adicionar métricas Prometheus