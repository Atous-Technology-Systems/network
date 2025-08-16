# Feature 01: Discovery & Relay Persistence – Design

## Architecture
- Introduce storage adapters with a common interface for discovery and relay
- Default adapter: in-memory (existing). Production adapter: Redis (v1)

## Components
- discovery_store.py (new)
  - interface: `register`, `get_providers`, `get_agent`, `cleanup`
  - implementations: MemoryDiscoveryStore (existing logic); RedisDiscoveryStore
- relay_store.py (new)
  - interface: `heartbeat`, `send`, `poll`, `cleanup`
  - implementations: MemoryRelayStore (existing logic); RedisRelayStore
- wiring in `api/routes/discovery.py` and `api/routes/relay.py` to select backend via env

## Redis Schema
### Discovery
- Key: `disc:agent:<agent_id>` → hash/json (agent_id, services(json), addresses(json), expires_at)
- Key: `disc:svc:<service_name>` → set of agent_ids
- TTL: set on `disc:agent:<agent_id>`; background cleanup removes service index members

### Relay
- Stream per agent: `relay:<agent_id>` entries `{from, payload, ts}`
- Presence: `relay:agent:<agent_id>` (string with last heartbeat timestamp), TTL

## Operations
- Register (upsert):
  - Set agent record with TTL
  - Diff services to update `disc:svc:*` sets
- Services: read set members; fetch addresses from agent keys; order by `expires_at` desc
- Resolve: compute as today over fetched providers
- Heartbeat: update presence key TTL
- Send: XADD to `relay:<to_id>`; check queue length via XLEN and cap
- Poll: XREAD and trim (e.g., XTRIM MAXLEN) or mark read position per agent

## Validation & Limits
- Enforce `RELAY_MAX_PAYLOAD_BYTES`
- Enforce `RELAY_MAX_QUEUE_DEPTH`

## Security
- Optional mTLS/auth for relay endpoints (token per agent); out of scope here but interfaces should accept `agent_id` identity from auth layer

## Migration & Backward Compatibility
- Default to memory backend when `DISCOVERY_BACKEND`/`RELAY_BACKEND` not set
- No external API changes

## Observability
- Metrics: counters for register, resolve, heartbeat, send, poll; gauges for active agents, queue depth
- Logs: structured events for store operations and errors

## Failure Handling
- Redis down: return 503 for write ops; read ops fallback to empty with clear error message
- Use exponential backoff on connection attempts (client config)

## Open Questions
- Do we need per-service TTLs? (defer)
- Do we store per-agent read offsets for Streams? (v1 poll drains via XREAD with `count=100` then XTRIM)
