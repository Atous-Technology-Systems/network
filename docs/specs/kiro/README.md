# Kiro Specs – Production Readiness Features

This index kicks off the structured spec/design/tests development for taking the MVP to production.

## Legend
- Spec: Requirements, scope, non-goals, acceptance criteria
- Design: Components, data model, storage, APIs, security, scaling
- Tests: TDD plan (unit/integration/e2e), fixtures, success/edge/failure cases

---

## Feature 01: Discovery & Relay Persistence
- Problem: Current in-memory discovery/relay state is volatile. Need persistence and multi-instance consistency.
- Spec
  - Persist discovery (agents, services, addresses, TTL) and relay queues with expiry
  - Support multiple control-plane instances; consistent view; idempotent register
  - Enforce limits (payload size, per-agent quotas)
  - Non-goals: NAT traversal and WAN relay optimizations (future)
  - Acceptance: Reboot-safe; providers/resolve stable; queues survive during TTL
- Design
  - Backend: Redis (primary) with keys: `disc:agent:<id>`, sets per service; Streams for relay `relay:<agent_id>`
  - TTL-based expiry; atomic operations (Lua/transactions)
  - API unchanged; app layer maps to Redis
  - Security: auth per agent (token/mTLS), payload caps
- Tests
  - Unit: store adapters; expiry logic; idempotent register
  - Integration: register->services->resolve; relay enqueue/poll; restart resilience (fake Redis)
  - E2E: multi-instance (if feasible); quota enforcement

## Feature 02: Policy Engine (Store + Evaluator)
- Problem: Active policy is simulated; need real storage and evaluation.
- Spec
  - Policy schema (subjects/resources/rules/conditions with risk thresholds)
  - CRUD APIs; versioning; assignment per agent/group; caching
  - Evaluator: ABAC + risk score gates; audit decisions
  - Acceptance: deterministic evaluation; versioned policies; cached reads
- Design
  - Postgres schema: policies, versions, assignments; JSONB for rules
  - Evaluator service with cache (LRU/Redis); ETag/If-None-Match on GET
  - Security: RBAC for policy admin; audit trail
- Tests
  - Unit: evaluator truth tables; schema validation
  - Integration: CRUD + active policy resolution; cache invalidation
  - E2E: agent heartbeat receives correct actions across versions

## Feature 03: CA / Identity (Vault/KMS-backed)
- Problem: Ephemeral in-memory CA; need durable PKI with rotation & revocation.
- Spec
  - Store CA key/cert in Vault/KMS; CSR intake; issue client certs; chain return
  - Rotation workflow; CRL endpoint (or OCSP); audit
  - Acceptance: issued certs verifiable; rotation not disruptive; revocation effective
- Design
  - Integrate Vault PKI or KMS + internal signing service; persist chain
  - Endpoints: enroll, rotate, revoke; auth & approvals
  - Security: strict key access; audit logging; rate limits
- Tests
  - Unit: CSR validation; chain building; error paths
  - Integration: enroll/rotate/revoke; CRL retrieval
  - E2E: agent enroll + mTLS handshake (future feature)

## Feature 04: Admin Auth (OIDC + RBAC) & Audit Sink
- Problem: API key only; events to NDJSON.
- Spec
  - OIDC auth with roles; IP allowlist; CSRF for admin POST
  - Persist events to Postgres/Elastic/Redis Streams with retention
  - Acceptance: admin routes protected; audit durable & queryable
- Design
  - OIDC middleware; role checks; proxy IP allowlist
  - Event writer abstraction with pluggable sinks
- Tests
  - Unit: role checks; event redaction
  - Integration: OIDC happy-path; 403/401 cases; event persistence & rotation

## Feature 05: ABISS/NNIS Provisioning & Flags
- Problem: Model stubs if HF unavailable; thresholds for demo.
- Spec
  - Provision models with `HF_TOKEN` or local artifact; feature flags `ABISS_ENABLED`/`NNIS_ENABLED`
  - Fallback path (log + allow) on errors; perf budget
  - Acceptance: predictable behavior under flag on/off; stable latency
- Design
  - Model loader with retries; artifact validation; cached pipelines
  - Configurable thresholds; observability (timers/counters)
- Tests
  - Unit: loader paths; flag toggles
  - Integration: middleware decision matrix; error fallback

## Feature 06: Readiness & Observability
- Problem: No readiness endpoint; limited observability.
- Spec
  - `/ready` endpoint checking Redis/Postgres/Vault when configured
  - JSON logs; tracing (OTel); Prometheus dashboards & alerts
  - Acceptance: readiness reflects dependencies; traces visible; alerts configured
- Design
  - Dependency pings with timeouts; structured logs; OTel exporters
- Tests
  - Unit: readiness probes; logging redaction
  - Integration: metrics counters; dashboards snapshots (doc)

---

## Next Steps
- Author detailed Spec/Design/Tests per feature in dedicated files.
- Implement Feature 01 and 02 first (state & policies), then 03 (PKI), followed by 04–06.
