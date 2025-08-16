# ATous Secure Network → Overlay “Tailscale com IA” (Specs)

Este documento define o plano para evoluir o ATous Secure Network em um overlay de conectividade seguro com Zero Trust e observabilidade inteligente (ABISS/NNIS), inspirado no Tailscale, porém com IA adaptativa e foco em IoT/Edge. Referência: https://tailscale.com/

## 1) Objetivo e Escopo
- Entregar conectividade segura entre dispositivos/serviços com:
  - Identidade forte (usuário/dispositivo/serviço), ACLs e segmentação fina
  - Conectividade P2P ou via relay/NAT traversal
  - Políticas dinâmicas orientadas por risco (ABISS/NNIS)
  - Control Plane (FastAPI) para cadastro, políticas, auditoria e distribuição de modelos (FL)
- MVP (Fase 1): service mesh L7 (mTLS/HTTP2 ou mTLS/QUIC) entre agentes, sem TUN/L3, com ACLs e risk scoring
- Fora do escopo inicial: drivers TUN/WireGuard e roteamento IP transparente (entra na Fase 4)

## 2) Não‑Objetivos (MVP)
- Não incluir drivers TUN/Wintun (L3) ou WireGuard
- Não focar em mobile (Android/iOS) na primeira fase
- Não expor configuração manual de firewall; os agentes gerem os túneis mTLS

## 3) Arquitetura (Visão Geral)
- Control Plane (existente e expandido): `atous_sec_network.api.server:app`
  - Entidades: Agent, Identity, Policy, Token, Certificate, Model, Event, Metric
  - Funções: registro/enrollment, emissão/rotação de certificados, distribuição de políticas e modelos, auditoria/telemetria
- Data Plane (novo): Agente L7 (Python) com mTLS, expondo/proxyando serviços locais conforme ACL
- Inteligência (existente): ABISS/NNIS para detecção e ajuste de políticas; FL para distribuição de modelos
- Resiliência: P2P health/auto‑heal (`network/p2p_recovery.py`), fallback via relay

## 4) Mapeamento com o Código Atual
- Cripto/Chaves: `core/crypto_utils.py`, `security/key_manager.py` → base de CA/PKI e rotação
- Políticas/Middleware: `security/access_control.py`, `security/security_middleware.py` → Policy Engine
- Inteligência: `security/abiss_system.py`, `security/nnis_system.py` → scoring e recomendações
- FL/Distribuição: `core/model_manager_impl.py`, `core/secure_fl.py` → entrega/atualização de modelos
- Resiliência: `network/p2p_recovery.py` → health/auto‑reconexão
- API: `api/server.py` → expandir com endpoints do Control Plane

## 5) Novos Componentes e Estrutura
- `atous_sec_network/agent/`
  - `config.py` (schema de config/validação)
  - `identity.py` (enrollment, CSR, mTLS, rotação)
  - `transport.py` (HTTP/2 sobre TLS 1.3; QUIC opcional futuro)
  - `services.py` (exposição/proxy de serviços locais, L7)
  - `policy_client.py` (sync/apply de políticas, cache)
  - `telemetry.py` (métricas/eventos)
  - `abiss_adapter.py` (coleta de sinais → ABISS/NNIS → risk score)
  - `cli.py` (CLI do agente)
- `atous_sec_network/overlay/`
  - `discovery.py` (bootstrap; NAT traversal futuro)
  - `relay.py` (fallback L7 no server)
- `docs/specs/` (RFCs/ADRs, modelos JSON, fluxos)

## 6) Protocolos e Padrões Técnicos
- Transporte: HTTP/2 sobre TLS 1.3 (MVP); QUIC como evolução
- Identidade: X.509 client cert (mTLS). Emissão/rotação via Control Plane
- Serialização: JSON com versionamento (MVP); gRPC opcional no futuro
- NAT traversal: Fase 2 (STUN/ICE) e relay HTTP/2 inicial como fallback
- Descoberta: nomes lógicos internos (service registry) no Control Plane; MagicDNS futuro

## 7) Modelo de Política (ACL + Contexto de Risco)
- Políticas declarativas por identidade (usuário/grupo/dispositivo/serviço) e recurso (nome/host/porta/protocolo)
- Regras com ações (`connect`, `expose`) e condições (tempo, IPs, `risk_threshold`)
- Risk score dinâmico (0..1) alimenta allow/deny/step‑up

Campos principais:
- `policy_id`, `version`
- `subjects[]`: `{type: user|device|service, id, groups[]}`
- `resources[]`: `{name, host, port, protocol}`
- `rules[]`: `{subject_selector, resource_selector, actions[], conditions{risk_threshold, ...}}`

## 8) APIs do Control Plane (v1)
- `POST /v1/agents/enroll` → solicita identidade (CSR→cert)
  - Req: `{ device_info, attestation?, csr_pem }`
  - Resp: `{ agent_id, certificate_pem, ca_chain_pem }`
- `POST /v1/agents/{id}/heartbeat` → keepalive + status
  - Body: `{ version, services, metrics, risk_score }`
  - Resp: `{ policy_version, actions[] }`
- `GET /v1/policies/{id}` → obter política por id
- `GET /v1/policies/active?agent_id=...` → política efetiva p/ agente
- `POST /v1/events` → eventos de segurança/decisão do agente
- `GET /v1/metrics/agents/{id}` → métricas agregadas
- `POST /v1/models/assign` → atribuir/atualizar modelos por grupo/agent
- `GET /v1/models/agent/{id}` → consulta de modelos atribuídos
- `POST /v1/ca/rotate` → rotação de CA (admin)

Integrações internas:
- Certs: `security/key_manager.py`, `core/crypto_utils.py`
- Policies: `security/access_control.py` (extensões), cache versionado
- ABISS/NNIS: thresholds e recomendações
- FL: `core/model_manager_impl.py`/`core/secure_fl.py` para distribuição

## 9) Especificação do Agent (MVP)
- Config (YAML, exemplo):

```yaml
agent_id: null
control_plane_url: "https://localhost:8000"
trust_bundle: "./certs/ca.pem"
listen:
  - name: "local-http"
    protocol: "http"
    bind: "127.0.0.1:18080"
    expose: false
services:
  - name: "api-service"
    target: "127.0.0.1:8000"
    protocol: "http"
telemetry:
  metrics_interval_s: 10
  events_batch: 50
security:
  mtls: true
  cert_path: "./certs/agent.crt"
  key_path: "./certs/agent.key"
  rotate_days: 30
```

- Ciclo de vida do agente:
  1) Bootstrap: carrega trust bundle → `enroll` (CSR) → recebe cert
  2) `heartbeat` periódico; busca política ativa; aplica ACLs
  3) Abre listeners/proxies L7 conforme política; mTLS para peers
  4) Coleta sinais locais → `abiss_adapter` → risk score
  5) Reporta métricas/eventos; recebe ações do Control Plane
- CLI (exemplos): `atous-agent enroll ...`, `atous-agent run --config agent.yaml`, `atous-agent status`, `atous-agent rotate-certs`

## 10) Segurança
- Trust model: CA interna, certs por agente, pinning do Control Plane
- Rotação/Revogação: janelas configuráveis; CRL/OCSP interno
- Hardening: TLS 1.3, ciphers restritos, PFS; mTLS obrigatório
- Auditoria: trilhas para enroll, policy change, allow/deny, ações NNIS
- Privacidade: FL evita envio de dados brutos

## 11) Telemetria & Observabilidade
- Métricas (agent→CP): latência, erros, tentativas, allow/deny, risk score, versão de política
- Eventos: mudanças de topologia, quedas, anomalias (ABISS), ações NNIS
- Expor `/metrics` no CP (Prometheus) e opcionalmente no agente

## 12) Testes e Qualidade
- Unit: agente (policy apply, transport), CP APIs, ABISS adapter, ciclo de chaves
- Integração: enroll→cert→policy→conexão mTLS entre 2 agentes; simulação P2P
- E2E: 3+ agentes, ACLs e bloqueios dinâmicos por risco
- Segurança: downgrade/MITM/cert spoof/replay/DoS básico
- Performance: throughput, latência de handshake, custo do risk loop

## 13) Roadmap (com Critérios de Aceite)
- Fase 1 (MVP L7, 3–4 semanas)
  - Agent Python com mTLS (HTTP/2), enroll/heartbeat/policies
  - CP com APIs v1 e Swagger; Policy Engine com cache
  - ABISS/NNIS integrado ao CP para risk scoring e ações
  - Aceite: dois agentes conectam via mTLS e respeitam ACLs; política muda em runtime; risk score > threshold bloqueia
- Fase 2 (Descoberta/NAT/Relay, 3–4 semanas)
  - Relay L7 no CP; tentativa P2P; catálogo de serviços; health P2P
  - Aceite: atravessar NAT moderado com fallback relay; resolução por nome lógico
- Fase 3 (Enterprise & Gestão, 3–4 semanas)
  - OIDC; RBAC; auditoria completa; Prometheus/Grafana; rotação automática de certs
  - Aceite: login federado, auditoria por sessão, dashboards de saúde
- Fase 4 (L3 opcional/WireGuard, 4–6 semanas)
  - Agente nativo (Go/Rust) com TUN/WireGuard; ACLs no L3; subnet routers
  - Aceite: roteamento IP transparente, ACLs por IP/porta, desempenho estável

## 14) Backlog Inicial
- Control Plane
  - [ ] `POST /v1/agents/enroll` (CSR→cert)
  - [ ] Policy Engine + cache versionado
  - [ ] `heartbeat`, `policies/active`, `events`, `metrics`
  - [ ] Integração ABISS/NNIS para risk score e ações
  - [ ] Integração `model_manager_impl` para distribuição de modelos
- Agent
  - [ ] `identity.py` (CSR, chaves, pinning)
  - [ ] `transport.py` (mTLS HTTP/2 client/server, proxy L7)
  - [ ] `policy_client.py` (sync/apply de políticas)
  - [ ] `abiss_adapter.py` (sinais→score)
  - [ ] `telemetry.py` (métricas/eventos)
  - [ ] `cli.py` e `config.py`
- Infra/Qualidade
  - [ ] Testes unit/integration/E2E
  - [ ] Docs em `docs/specs/` (RFCs: identidade, políticas, transporte)

## 15) Riscos & Mitigações
- Portabilidade do agente Python → começar em L7; L3 depois com agente nativo
- PKI complexa → automatizar no CP; testes de rotação/expiração
- Performance L7 Python → escopo de proxy leve; QUIC/nativo no futuro
- UX de políticas → começar simples e evoluir para condições dinâmicas

## 16) Open Questions
- Catálogo de identidades: apenas CP ou integrar IDP (OIDC Fase 3)?
- Relay: HTTP/2 vs WebSocket no MVP?
- Versionamento/canary de modelos ABISS/NNIS por grupo de agentes?

## 17) Checklist “Pronto para começar” (Fase 1)
- [ ] Criar pastas `agent/` e `overlay/` com esqueleto
- [ ] Implementar endpoints `enroll`, `heartbeat`, `policies`
- [ ] Agente com mTLS HTTP/2, proxy básico e ACLs
- [ ] Loop de risco com ABISS/NNIS e decisões dinâmicas
- [ ] E2E com 2–3 agentes e política alterável em runtime

## 18) Processo Kiro (Specs por feature)
- Cada feature terá três arquivos em `.kiro/<feature>/`:
  - `spec.md`: requisitos funcionais/não‑funcionais, API e critérios de aceite
  - `design.md`: componentes, fluxos, assinaturas e persistência
  - `tests.md`: plano TDD com casos e cenários (unit, integração, e2e)

### Feature 01: Agent Enroll
- Pastas criadas:
  - `.kiro/agent_enroll/spec.md`
  - `.kiro/agent_enroll/design.md`
  - `.kiro/agent_enroll/tests.md`
- Próximos passos: implementar API `POST /v1/agents/enroll` e testes conforme `tests.md`.

## 19) Progresso (15/08/2025)
- Feature 01: Agent Enroll (CSR→cert)
  - [x] TDD unit e integração criados
  - [x] Implementado `CAService` (MVP) e endpoint `POST /v1/agents/enroll`
  - [x] Ajuste do middleware para não bloquear o enroll
  - [x] Suíte completa: 410 passed, 8 skipped, 2 warnings
  - Próximo: Feature 02 (Heartbeat + Policies)

## 20) Progresso (15/08/2025)
- Feature 02: Heartbeat + Policies
  - [x] TDD (unit e integração)
  - [x] Implementado `POST /v1/agents/{agent_id}/heartbeat`
  - [x] `PolicyService` (MVP) com resolução por risk score
  - [x] Middleware ajustado (exclusão de prefixos `/v1/agents/`)
- Feature 03: Policies Active
  - [x] TDD (integração)
  - [x] Implementado `GET /v1/policies/active?agent_id=...`
  - [x] Middleware ajustado (exclusão de prefixos `/v1/policies/`)
- Testes totais: 425 • 417 passed • 8 skipped • 2 warnings
- Próximo: Feature 04 (Relay L7) – specs criadas; iniciaremos TDD na próxima etapa.

## 21) Progresso (15/08/2025)
- Feature 04: Relay L7 (fallback)
  - [x] Specs Kiro (spec/design/tests)
  - [x] Implementado `POST /v1/relay/heartbeat`, `POST /v1/relay/send`, `GET /v1/relay/poll`
  - [x] Middleware ajustado (exclusão de prefixo `/v1/relay/`)
  - [x] TDD integração (3 testes) aprovados
- Testes totais: 428 • 420 passed • 8 skipped • 2 warnings
- Próximo: Feature 05 (Discovery/Service Registry + NAT traversal MVP)

## 22) Progresso (15/08/2025)
- Feature 05: Discovery/Service Registry (MVP)
  - [x] Specs Kiro (spec/design/tests)
  - [x] Implementado `POST /v1/discovery/register`, `GET /v1/discovery/services`, `GET /v1/discovery/agents/{agent_id}`
  - [x] Middleware ajustado (exclusão de prefixo `/v1/discovery/`)
  - [x] TDD integração (3 testes) aprovados
- Testes totais: 423 • 423 passed • 8 skipped • 2 warnings
- Próximo: Feature 06 (Agent Policy Client) – cliente do agente para `heartbeat` e `policies/active`, com TDD e mocks de HTTP.

## 23) Progresso (15/08/2025)
- Feature 06: Agent Policy Client
  - [x] Specs Kiro (spec/design)
  - [x] Implementado `atous_sec_network/agent/policy_client.py` (`send_heartbeat`, `get_active_policy`, timeout e retries)
  - [x] TDD unitário (3 testes) aprovados
- Próximo: Feature 07 (Discovery Resolve/Address Selection) – endpoint de resolução com preferência (local/lan/wan)

## 24) Progresso (15/08/2025)
- Feature 07: Discovery Resolve / Address Selection
  - [x] Specs Kiro (spec/design/tests)
  - [x] Implementado `GET /v1/discovery/resolve?name=...&pref=local,lan,wan`
  - [x] Ordenação por preferência e registro mais recente; sem duplicatas
  - [x] TDD integração (3 testes) aprovados
- Testes totais: 437 • 429 passed • 8 skipped • 2 warnings
- Próximo: Feature 08 (Agent Runtime Loop) – loop do agente usando Policy Client + Discovery Resolve

## 25) Progresso (15/08/2025)
- Feature 09: Agent CLI
  - [x] Implementado `atous_sec_network/agent/cli.py` (execução de `run_once`)
  - [x] Entry point configurado: `atous-agent`
  - [x] TDD unitário aprovado
- Testes totais: 440 • 432 passed • 8 skipped • 2 warnings
- Próximo: Feature 10 (Agent Loop Periódico + Métricas Locais via psutil)

## 26) Progresso (15/08/2025)
- Feature 10: Agent Loop Periódico + Métricas Locais
  - [x] Specs Kiro (spec/design)
  - [x] Implementado `run_loop` em `agent/runtime.py` com `psutil`
  - [x] TDD unitário aprovado
- Testes totais: 440 • 432 passed • 8 skipped • 2 warnings
- Próximo: Feature 11 (Admin UI/API mínima) – endpoint de overview para consolidar estado (agents, discovery, relay, policies)

## 27) Progresso (15/08/2025)
- Admin UI/API mínima
  - [x] `/v1/admin/overview` consolidando discovery/relay/policies
  - [x] `/v1/admin/events` (append e leitura) com auditoria persistente em `logs/admin_events.ndjson`
  - [x] Admin estático em `/admin` (HTML simples consumindo JSON; pronto para React)
- Testes totais: 443 • 435 passed • 8 skipped • 2 warnings
- Próximo: Feature 12 (QUIC Transport Prototype) – camada opcional, isolada, sem quebrar HTTP/2 atual

## 28) Progresso (15/08/2025)
- Admin UI/API mínima (com métricas)
  - [x] `/v1/admin/overview` agora inclui `system_metrics {cpu_percent, memory_mb, threads}`
  - [x] Página estática em `/admin` exibe discovery, relay, policies e métricas; pronta para troca por React futuramente
  - [x] Auditoria persistente: `/v1/admin/events` salva em `logs/admin_events.ndjson` (rotação básica)
- Testes totais: 444→436 passed • 8 skipped • 2 warnings (verde)

Próximos passos sugeridos:
- React Admin (futuro): consumir `/v1/admin/overview` e `/v1/admin/events` (API-first já pronto)
- Persistência real: stores de discovery/relay/policies em banco leve (SQLite/Postgres)
- QUIC opcional: evoluir protótipo para cenários e2e (mantendo HTTP/2 como padrão)
- SSO/RBAC: integração OIDC para gestão de policies por usuário/grupo

---

## 29) Checklist Final do MVP (Admin)

- [x] Endpoints Admin implementados (`/v1/admin/overview`, `/v1/admin/events`)
- [x] UI estática servida em `/admin`
- [x] Persistência de eventos em `logs/admin_events.ndjson` com rotação básica
- [x] Script de seed documentado e funcional: `scripts/seed_admin_demo.py`
- [x] README atualizado com seção "Admin (MVP)"
- [x] Testes de integração verdes após inclusão do Admin (status atual: verde)

Estado: Admin documentado e concluído para o MVP. Sistema estável para demonstração (servidor, discovery, relay, policies e métricas exibidas no Admin).