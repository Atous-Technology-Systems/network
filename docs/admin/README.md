# ATous Admin (MVP)

Esta é uma UI estática mínima servida em `/admin` que consome as APIs Admin para visão consolidada do sistema. Foi projetada para ser facilmente substituída por um frontend React no futuro (API-first).

## Endpoints Relevantes
- `GET /v1/admin/overview` — resumo de discovery/relay/policies e métricas do servidor
- `POST /v1/admin/events` — registra um evento (`{"type": "...", "payload": {...}}`)
- `GET /v1/admin/events?limit=N` — lista os últimos eventos (buffer em memória + persistência em `logs/admin_events.ndjson`)

## Autenticação
- Quando `ADMIN_AUTH_ENABLED=true` (ou `ADMIN_API_KEY` definido), as rotas Admin exigem o header: `X-Admin-Api-Key: <sua_chave>`.
- Recomenda-se habilitar autenticação em ambientes não locais.

## Como usar
1) Inicie o servidor:
   - `python start_server.py`  (ou `python -m uvicorn atous_sec_network.api.server:app --reload`)
2) Acesse a UI admin:
   - `http://localhost:8000/admin`
3) Acompanhe métricas, discovery, relay e versão de política (MVP)

## Integração futura (React)
- A UI atual apenas consome JSON destes endpoints. Uma app React pode substituir `/admin` e consumir as mesmas rotas.
- Sugestão: criar um app React com rota `/admin` e usar `fetch('/v1/admin/overview')` e `fetch('/v1/admin/events')`.

## Notas
- Persistência de eventos: arquivo `logs/admin_events.ndjson` (rotação simples ~1MB). Em produção, substituir por um sink de logs (por ex.: Elastic/OpenSearch, Loki, S3, etc.).
- Segurança/SSO/RBAC: previstos em etapas futuras (OIDC), mantendo a compatibilidade de APIs.

## Boas Práticas
- Configure `ADMIN_ALLOWED_IPS` no proxy (Nginx) e/ou aplicação para restringir acesso à Administração.
- Inclua o header `X-Admin-Api-Key` nas chamadas Admin quando habilitado.
- Evite payloads grandes em `/v1/admin/events`; o endpoint aplica limite de tamanho (413).

## Referências
- Guia de endpoints consolidados: `docs/technical/ENDPOINTS_MAP.md`
- Documentação de API: `docs/technical/API_DOCUMENTATION.md`
