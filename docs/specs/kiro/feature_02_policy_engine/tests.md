# Feature 02: Policy Engine (Store + Evaluator) – Tests

## Unit Tests
- Schema validation: required fields, enums, thresholds
- Evaluator: subject/resource matching, threshold decisions, edge cases
- Caching: TTL expiration, invalidation on write

## Integration Tests
- CRUD policy versions; ETag; pagination
- Assignments: agent→policy resolution
- Active policy API returns expected version & actions
- Audit entries created for evaluations

## E2E
- Simulate agent risk contexts and verify evaluator decisions
- Cache warm-up improves response latency

## Negative Cases
- Invalid policy schema (400)
- Missing assignment (404 or default policy fallback)
- DB outage → 503 on writes; reads fallback to cache if available

## Tooling
- Postgres via testcontainers or docker-compose in CI
- Alembic migration tests
