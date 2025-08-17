# ATous Secure Network – Endpoints Map (REST & WebSocket)

Este documento consolida todos os endpoints atualmente expostos pelo servidor, com exemplos de chamada e notas de autenticação.

## Notas de Autenticação
- Admin (MVP): algumas rotas podem exigir header `X-Admin-Api-Key` quando `ADMIN_AUTH_ENABLED=true`.
- JWT e mTLS: planejados (ainda não exigidos pelas rotas públicas atuais).

Dica (Windows PowerShell): prefira `curl.exe` e use aspas corretas para JSON. Exemplos em bash funcionam em Linux/macOS.

---

## Templates de Chamadas

### Bash (Linux/macOS)
```bash
# Variáveis úteis
BASE_URL="http://127.0.0.1:8000"

# GET simples
curl -sS "$BASE_URL/health"

# POST JSON com header
curl -sS -H 'Content-Type: application/json' \
  -d '{"message":"Hello","algorithm":"AES-256"}' \
  "$BASE_URL/api/crypto/encrypt"

# Admin com API Key (quando habilitado)
curl -sS -H 'X-Admin-Api-Key: dev-admin' "$BASE_URL/v1/admin/overview"
```

### PowerShell (Windows)
```powershell
# Variáveis úteis
$baseUrl = 'http://127.0.0.1:8000'

# GET simples (converte saída para JSON legível)
Invoke-RestMethod -Method Get -Uri "$baseUrl/health" | ConvertTo-Json -Depth 8

# POST JSON (use ConvertTo-Json para evitar problemas de aspas)
$headers = @{ 'Content-Type' = 'application/json' }
$bodyObj = @{ message = 'Hello'; algorithm = 'AES-256' }
$body = $bodyObj | ConvertTo-Json -Depth 8
Invoke-RestMethod -Method Post -Uri "$baseUrl/api/crypto/encrypt" -Headers $headers -Body $body

# Admin com API Key (quando habilitado)
$headers = @{ 'X-Admin-Api-Key' = 'dev-admin' }
Invoke-RestMethod -Method Get -Uri "$baseUrl/v1/admin/overview" -Headers $headers | ConvertTo-Json -Depth 8

# Dica: quando precisar escrever JSON manualmente, use here-string para evitar escaping
$headers = @{ 'Content-Type' = 'application/json' }
$body = @'
{
  "type": "note",
  "payload": { "msg": "hello" }
}
'@
Invoke-RestMethod -Method Post -Uri "$baseUrl/v1/admin/events" -Headers $headers -Body $body
```

Observações:
- No PowerShell, `curl` é alias de `Invoke-WebRequest`. Prefira `Invoke-RestMethod` ou chame `curl.exe` explicitamente.
- Ajuste `-Depth` conforme necessário para objetos aninhados.

---

## Health & Info

- GET `/` – Informações básicas da API
- GET `/health` – Saúde geral e métricas rápidas (retorna 200 ou 503)
- GET `/api/info` – Metadados da API (nome, versão, recursos)
- GET `/api/security/status` – Status de segurança (ABISS/NNIS)
- GET `/api/metrics` – Métricas de processo/API/segurança

Exemplos:
```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/info
curl -s http://127.0.0.1:8000/api/metrics
```

---

## Admin (MVP)

- GET `/v1/admin/overview` – Visão geral (discovery, relay, políticas, métricas)
- GET `/v1/admin/events?limit=N` – Lista eventos registrados (buffer + persistência em `logs/admin_events.ndjson`)
- POST `/v1/admin/events` – Registra um evento admin

Headers (quando habilitado): `X-Admin-Api-Key: <chave>`

Exemplos:
```bash
curl -s -H "X-Admin-Api-Key: dev-admin" http://127.0.0.1:8000/v1/admin/overview
curl -s -H "X-Admin-Api-Key: dev-admin" "http://127.0.0.1:8000/v1/admin/events?limit=50"
curl -s -H "X-Admin-Api-Key: dev-admin" -H 'Content-Type: application/json' \
  -d '{"type":"note","payload":{"msg":"hello"}}' \
  http://127.0.0.1:8000/v1/admin/events
```

---

## Discovery

- POST `/v1/discovery/register` – Registra agente/serviços
- GET `/v1/discovery/services?name=...` – Provedores para um serviço
- GET `/v1/discovery/agents/{agent_id}` – Detalhes do agente
- GET `/v1/discovery/resolve?name=...&pref=local,lan,wan` – Lista de candidatos por preferência

Exemplos:
```bash
curl -s -H 'Content-Type: application/json' -d '{
  "agent_id":"agt-1",
  "services":[{"name":"api-service","port":8000}],
  "addresses":{"local":["http://127.0.0.1:8000"]},
  "ttl":60
}' http://127.0.0.1:8000/v1/discovery/register

curl -s "http://127.0.0.1:8000/v1/discovery/services?name=api-service"
curl -s "http://127.0.0.1:8000/v1/discovery/resolve?name=api-service&pref=local,lan,wan"
```

---

## Relay

- POST `/v1/relay/heartbeat` – Sinaliza presença do agente
- POST `/v1/relay/send` – Enfileira mensagem para outro agente
- GET `/v1/relay/poll?agent_id=...` – Consome mensagens do agente

Exemplos:
```bash
# Heartbeat
curl -s -H 'Content-Type: application/json' -d '{"agent_id":"agt-1"}' \
  http://127.0.0.1:8000/v1/relay/heartbeat

# Enviar
curl -s -H 'Content-Type: application/json' -d '{"from":"agt-1","to":"agt-1","payload":{"msg":"hello"}}' \
  http://127.0.0.1:8000/v1/relay/send

# Buscar
curl -s "http://127.0.0.1:8000/v1/relay/poll?agent_id=agt-1"
```

---

## Agents

- POST `/v1/agents/enroll` – Emite certificado (MVP) a partir de CSR
- POST `/v1/agents/{agent_id}/heartbeat` – Heartbeat com contexto (risco etc.)

Exemplos:
```bash
# Enroll
curl -s -H 'Content-Type: application/json' -d '{
  "device_info": {"model":"dev"},
  "attestation": null,
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."
}' http://127.0.0.1:8000/v1/agents/enroll

# Heartbeat
curl -s -H 'Content-Type: application/json' -d '{
  "version": "2.0.0",
  "services": ["api"],
  "metrics": {"cpu":0.2},
  "risk_score": 0.15
}' http://127.0.0.1:8000/v1/agents/agt-xxxx/heartbeat
```

---

## Policies (MVP)

- GET `/v1/policies/active?agent_id=...` – Política ativa (resposta MVP: `v1/allow`)

Exemplo:
```bash
curl -s "http://127.0.0.1:8000/v1/policies/active?agent_id=agt-1"
```

---

## Criptografia

- POST `/api/crypto/encrypt` - Criptografia principal
- POST `/api/security/encrypt` - Criptografia de segurança
- POST `/encrypt` - Interface simplificada

Exemplo:
```bash
curl -s -H 'Content-Type: application/json' -d '{"message":"Hello","algorithm":"AES-256"}' \
  http://127.0.0.1:8000/api/crypto/encrypt
```

---

## Segurança Avançada

- GET `/api/v1/security/nnis/status` - Status do sistema NNIS
- GET `/api/v1/security/security-report` - Relatório de segurança
- GET `/api/v1/security/threat-intelligence` - Inteligência de ameaças

**Nota**: Endpoints de segurança podem ser bloqueados pelo sistema ABISS com score de ameaça alto.

---

## WebSocket

- WS `/ws` – Canal principal
- WS `/api/ws` – Canal da API
- WS `/websocket` – Canal genérico

Exemplo Python (websockets):
```python
import asyncio, websockets, json

async def main():
    async with websockets.connect('ws://127.0.0.1:8000/ws') as ws:
        await ws.send(json.dumps({"ping":"ok"}))
        print(await ws.recv())

asyncio.run(main())
```

---

## Códigos de Retorno Comuns
- 200 OK: sucesso
- 202 Accepted: processamento assíncrono (quando aplicável)
- 400 Bad Request: entrada inválida
- 401 Unauthorized / 403 Forbidden: autenticação/autorização necessária
- 404 Not Found: recurso inexistente
- 413 Payload Too Large: payload/admin-event excedeu limite
- 429 Too Many Requests: rate limit atingido
- 503 Service Unavailable: degradado/indisponível

## Observações
- Segurança: Middleware com validação de entrada, rate limiting e mitigação básica de DDoS já ativo.
- Admin UI (MVP): disponível em `/admin` quando habilitado.
- Configuração: ver `deploy/env.example` e documentação de deployment.
