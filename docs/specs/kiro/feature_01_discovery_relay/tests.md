# Feature 01: Discovery & Relay Persistence – Tests

## Unit Tests
- Discovery (Memory/Redis adapters)
  - register upsert, service index updates
  - get_providers ordering by `expires_at`
  - TTL expiry behavior
- Relay (Memory/Redis adapters)
  - heartbeat presence + TTL
  - send enforces payload size and queue depth limits
  - poll drains messages

## Integration Tests
- Discovery
  - register → services → resolve flow (Redis backend)
  - restart (simulate) → entries remain within TTL
- Relay
  - heartbeat → send → poll flow (Redis backend)
  - restart (simulate) → messages remain until polled or TTL

## E2E / Contract
- Two app instances pointing to the same Redis
  - concurrent register operations
  - resolve returns consistent candidates
  - relay queues accessible from both instances

## Negative Cases
- Invalid JSON payloads (blocked by middleware)
- Oversized payloads (413)
- Queue depth exceeded (429)
- Missing agent_id (400)

## Performance
- Register/resolve under burst (measure P95 latency target < 50ms with Redis local)
- Relay enqueue/poll throughput (target 500 msg/s local)

## Tooling
- Use testcontainers or docker-compose Redis for CI
- Mark Redis-dependent tests; skip if REDIS_URL missing
