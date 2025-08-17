# Production Readiness Plan (MVP → GA)

This document maps the current MVP to production-grade requirements, calling out mocked/simulated parts and concrete actions to harden and ship safely.

## Executive Summary

- Admin API/UI: minimal and functional. Auth via API key (added), recommend OIDC/RBAC for GA.
- Discovery/Relay: in-memory (mocked state). Needs persistent backing store and authN/Z.
- Policies: MVP returns a default policy (simulated). Needs full policy store, evaluation engine, and CRUD.
- CA/Identity: ephemeral in-memory CA (mocked). Needs persistent CA/PKI, rotation, revocation, and HSM/KMS.
- ABISS/NNIS: model loading has stubs/simulation when Hugging Face model is unavailable. Needs proper model provisioning and perf hardening.
- Admin events: NDJSON file (basic). Needs durable sink for audit.

All other platform elements (FastAPI, security middleware, config, logging, metrics, server packaging) are prepared for production with env-driven hardening and reverse-proxy (Nginx) provided.

## Subsystem Readiness and Gaps

### 1) Control Plane API (FastAPI)
- Status: Stable. Input validation, rate limiting, DDoS guard, trusted hosts, CORS, env-driven limits. `/ready` endpoint adicionado.
- Gaps: CSP headers at proxy, ETag/Cache hints for GETs.
- Actions:
  - Implement `/ready` probing external deps (Redis/DB when added).
  - Add CSP in Nginx config, keep HSTS under TLS.

### 2) Admin API/UI
- Status: Auth via API key; static UI served behind env toggle; events persisted to file with rotation.
- Gaps: OIDC SSO + RBAC; IP allowlist; durable audit sink; optional disable static UI in prod.
- Actions:
  - Add OIDC (Auth Code) and role scopes for `read:admin`, `write:admin`.
  - Wire `ADMIN_ALLOWED_IPS` (proxy + app) for extra defense.
  - Sink admin events to Postgres/Elastic or Redis Streams.

### 3) Discovery Service
- Status: In-memory registry with TTL (mocked). Functional for demo. Endpoints: `/v1/discovery/register`, `/v1/discovery/services`, `/v1/discovery/resolve`, `/v1/discovery/agents/{agent_id}`.
- Gaps: Persistence and multi-instance coherence; idempotency; schema validation.
- Actions:
  - Back with Redis (TTL keys + Sets) or Postgres (expires_at index).
  - Define schemas and input validation per service entry.
  - Add idempotent registration (same `agent_id` + version).

### 4) Relay Service
- Status: In-memory queues per agent (mocked). Functional for demo/self-test. Endpoints: `/v1/relay/heartbeat`, `/v1/relay/send`, `/v1/relay/poll`.
- Gaps: Persistence, ordering, backpressure, auth per agent, message size caps.
- Actions:
  - Use Redis Streams (XADD/XREAD) keyed by `agent_id` with TTL.
  - Enforce max payload (e.g., 32 KB) and per-agent quotas.
  - Require agent-auth (mTLS or signed token) for send/poll.

### 5) Policies
- Status: `GET /v1/policies/active` returns default "v1" allow (simulated).
- Gaps: Policy model, storage, versioning, evaluation engine, assignment, audit.
- Actions:
  - Define policy schema (subjects/resources/rules/conditions).
  - Implement Postgres-backed store; CRUD; versioning; ETag.
  - Build evaluator (ABAC with risk thresholds) + caching.

### 6) CA / Identity
- Status: Ephemeral in-memory CA issuing 90-day client certs (mocked).
- Gaps: Persisted CA keys/certs; rotation; revocation (CRL/OCSP); HSM/KMS; audit.
- Actions:
  - Integrate with HashiCorp Vault/AWS KMS/Azure Key Vault for CA keys.
  - Persist CA chain; implement rotation endpoints with approvals.
  - Add CRL endpoint and OCSP responder or alternative revocation checks.

### 7) ABISS / NNIS (Security Intelligence)
- Status: Stubs/simulation path when model unavailable; thresholds tuned for demo.
- Gaps: Model provisioning, performance budgets, feature flags, fallback; dataset/telemetry pipeline.
- Actions:
  - Provision model artifacts (or remote inference) with auth; add `HF_TOKEN` integration.
  - Add `ABISS_ENABLED`/`NNIS_ENABLED` flags; safe fallback on errors.
  - Establish telemetry-driven threshold tuning and evaluation suite.

### 8) Model Manager / Federated Learning
- Status: Functional modules; needs production storage and signing.
- Gaps: Artifact signing/verification; object storage; OTA rollback plan.
- Actions:
  - Store models in S3/GCS/Azure Blob; sign releases; verify signatures.
  - Keep version manifest; support canary rollout and rollback.

### 9) Agent
- Status: CLI/runtime loop; policy client; discovery integrate (MVP). No mTLS transport yet. Endpoints de agente: `/v1/agents/enroll`, `/v1/agents/{agent_id}/heartbeat`.
- Gaps: mTLS handshake, cert pinning; persistent config; policy enforcement; QUIC optional.
- Actions:
  - Implement mTLS HTTP/2 client; enroll flow consuming CAService; cert rotation.
  - Apply policy to L7 proxy rules; metrics/events pipeline.

### 10) Observability
- Status: `/api/metrics` exposed; logs written locally.
- Gaps: Centralized logs, tracing, dashboards, alerts, audit integrity.
- Actions:
  - Emit JSON logs; forward to ELK/Loki; add OpenTelemetry tracing.
  - Prometheus/Grafana dashboards; alerts on error rate, 5xx, rate limits, queue depth.

### 11) Security Hardening
- Status: Security middleware in place; admin auth via API key.
- Gaps: Secrets management; CSP; SSO; IP allowlists; structured secret redaction; mTLS everywhere.
- Actions:
  - Load secrets from secret manager (Vault/KMS); forbid secrets in logs.
  - Enforce mTLS for agent/control-plane; pin CA bundle.
  - Add CSP headers, CSRF defense for admin POSTs.

### 12) Performance & Scale
- Status: Dockerfile and Nginx provided; K8s manifests.
- Gaps: Load tests; HPA thresholds; worker tuning; cache layers.
- Actions:
  - Run k6/Locust load tests; size gunicorn workers; tune timeouts.
  - Add Redis cache where appropriate.

## Deliverables & Acceptance Criteria

- Discovery/Relay persistence (Redis/Postgres) with TTL and tests — providers/resolve stable across restarts.
- Policy engine (CRUD + evaluator) with Postgres, versioned, tested; `active` uses stored policies.
- CA backed by Vault/KMS; rotation and revocation endpoints; audit trail.
- Admin OIDC with RBAC; events sink to durable store; static UI disabled by default in prod.
- ABISS/NNIS models provisioned with feature flags; graceful fallback; perf budget validated.
- Observability: JSON logs, Prometheus scrape, dashboards, SLO alerts.
- Security: CSP at proxy, IP allowlist for admin, secrets from secret manager, mTLS for agents.

## Phased Plan

- Phase A (Foundation, 1–2 weeks)
  - Redis for discovery/relay; `/ready` endpoint; JSON logging; CSP at Nginx.
- Phase B (Identity & Policies, 2–3 weeks)
  - Vault-backed CA; revocation; policy store + evaluator + UI/API.
- Phase C (Intelligence & Observability, 2–3 weeks)
  - ABISS/NNIS provisioning; tracing; dashboards; alerts; rate/limit tuning.
- Phase D (Agent & Transport, 2–3 weeks)
  - mTLS client; policy enforcement; QUIC pilot behind feature flag.

## Configuration Keys (additions)

- ADMIN_ALLOWED_IPS, ADMIN_OIDC_ISSUER, ADMIN_OIDC_CLIENT_ID/SECRET
- DISCOVERY_BACKEND=memory|redis|postgres, RELAY_BACKEND=memory|redis
- DATABASE_URL (Postgres), REDIS_URL
- CA_BACKEND=vault|kms|file, VAULT_ADDR, VAULT_TOKEN
- ABISS_ENABLED, NNIS_ENABLED, HF_TOKEN

## Risks & Mitigations

- Model performance/cost: start with feature-flagged mode and conservative thresholds.
- State integrity: centralize in Redis/Postgres, add migrations and backups.
- Security regressions: add security tests (OWASP) in CI and enable dependency scanning.
