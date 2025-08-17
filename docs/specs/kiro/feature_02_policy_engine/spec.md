# Feature 02: Policy Engine (Store + Evaluator) – Spec

## Goal
Provide a persistent policy store with versioning and an evaluator to derive effective actions for agents.

## Scope
- Policy schema (subjects/resources/rules/conditions)
- CRUD APIs and versioning; assignment to agents/groups
- Evaluation engine (ABAC + risk thresholds) with caching

## Non-goals
- GUI for policy editing (future)
- Full-blown PDP/PEP split across microservices (stay in-process)

## Functional Requirements
- Create/Update/Delete/List policies and versions
- Assign policies to agents or groups; lookup active policy by agent_id
- Evaluate incoming context (agent + risk score) to a decision (actions)
- Audit evaluation decisions (who/what/why)

## Policy Schema (initial)
```json
{
  "policy_id": "string",
  "version": 1,
  "subjects": [{"type":"device|service|user","id":"string","groups":["g1"]}],
  "resources": [{"name":"api-service","host":"host","port":8000,"protocol":"http"}],
  "rules": [{
    "subject_selector": {"groups": ["edge-nodes"]},
    "resource_selector": {"name": "api-service"},
    "actions": ["connect"],
    "conditions": {"risk_threshold": 0.7}
  }]
}
```

## APIs (v1)
- POST /v1/policies (create)
- PUT  /v1/policies/{id} (update new version)
- GET  /v1/policies/{id}
- GET  /v1/policies (list)
- POST /v1/policies/assign (agent_id/group → policy_id@version)
- GET  /v1/policies/active?agent_id=...

## Config
- DATABASE_URL (Postgres)
- POLICY_CACHE_TTL_SECONDS (default 30)

## Acceptance Criteria
- Deterministic evaluation given policy and risk
- Versioned updates; old versions retrievable; assignments stable
- Cache reduces GET latency; invalidation on writes
- Full tests (unit/integration) green

## Risks
- Complex selectors → start simple (groups + names) and evolve
- Cache staleness → ETag + cache busting on write

## Timeline
- Dev: 4–6 days
- Tests/hardening: 3–4 days
