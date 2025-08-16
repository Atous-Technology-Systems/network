# Feature 01: Discovery & Relay Persistence – Spec

## Goal
Persist discovery registry and relay queues to survive restarts and support multi-instance control-plane with consistent views.

## Scope
- Persisted discovery records (agents, services, addresses, TTL)
- Persisted relay message queues per agent with expiry
- Idempotent registration; deterministic resolve ordering
- Quotas: payload size and per-agent enqueue limits

## Non-goals
- NAT traversal, WAN relay optimizations, P2P hole punching (future)
- End-to-end encryption beyond HTTPS/mTLS (future agent work)

## Functional Requirements
- Register: upsert agent record with TTL; update services index
- Services: list providers by service name (ordered by most recent registration)
- Resolve: ordered candidates by preference (local, lan, wan)
- Relay: heartbeat (presence + TTL), send (enqueue), poll (drain)
- Expiration: auto-remove expired agents and purge stale queues

## Data Retention
- Discovery records: TTL configurable (default 60s)
- Relay messages: TTL configurable (default 60s) or until polled

## Limits
- Max payload size: 32 KB per message
- Max queue depth per agent: 100 messages (configurable)

## Security
- Validate JSON strictly; sanitize/size-check inputs
- AuthN/Z for relay send/poll (token/mTLS pre-req; interim: API key per agent if needed)
- Rate limits per IP and per agent

## APIs (unchanged externally)
- POST /v1/discovery/register
- GET  /v1/discovery/services?name=...
- GET  /v1/discovery/resolve?name=...&pref=local,lan,wan
- POST /v1/relay/heartbeat
- POST /v1/relay/send
- GET  /v1/relay/poll?agent_id=...

## Config
- DISCOVERY_BACKEND: memory|redis|postgres (default: memory)
- RELAY_BACKEND: memory|redis (default: memory)
- REDIS_URL / DATABASE_URL
- DISCOVERY_TTL_SECONDS (default 60)
- RELAY_TTL_SECONDS (default 60)
- RELAY_MAX_PAYLOAD_BYTES (default 32768)
- RELAY_MAX_QUEUE_DEPTH (default 100)

## Acceptance Criteria
- Restart-survives: providers/resolve yield the same results during TTL window after restart
- Relay messages survive restarts until TTL or polled
- Concurrency-safe under multi-instance (no duplicate/stale entries)
- Quotas enforced with appropriate error codes (413/429)
- Full test suite green on all supported OS (Windows/Linux)

## Risks
- Redis connection drops → retry/backoff; degrade gracefully to memory if configured
- Clock skew for TTL → rely on store-side TTL where possible (Redis)

## Timeline
- Dev: 3–5 days
- Tests/hardening: 2–3 days
