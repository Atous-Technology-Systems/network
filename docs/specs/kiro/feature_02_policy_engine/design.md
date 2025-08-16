# Feature 02: Policy Engine (Store + Evaluator) – Design

## Storage
- Postgres (SQLAlchemy or async equivalent)
- Tables:
  - policies (policy_id PK)
  - policy_versions (policy_id FK, version, jsonb schema, created_at)
  - assignments (agent_id/group, policy_id, version, created_at)
  - audits (decision logs)
- Indexes:
  - policy_versions: (policy_id, version)
  - assignments: (agent_id), (group)

## API Layer
- Pydantic models for policy schema; strict validation
- ETag/If-None-Match for GETs; pagination for list
- RBAC: admin-only for write ops

## Evaluator
- Inputs: agent_id, risk_score, optional metadata (groups)
- Resolve assigned policy version; load from cache or DB
- Match rules by subject_selector (groups) and resource_selector (name)
- Apply conditions.risk_threshold: actions allowed if risk_score <= threshold
- Return actions; log audit entry

## Caching
- In-memory LRU (per instance) + TTL; optional Redis cache (future)
- Invalidate on writes to the same policy_id

## Migration
- Alembic migrations for tables
- Seed a default policy (v1)

## Observability
- Metrics: cache hits/misses, eval time P95, DB query counts
- Logs: policy changes, evaluation audits (with redaction)

## Failure Handling
- DB down: return 503 for write; for reads, fallback to last cached version if available

## Security Considerations
- Strict input validation; limit payload sizes
- Authorization for write endpoints
- Audit trail is append-only (consider WORM store in future)
