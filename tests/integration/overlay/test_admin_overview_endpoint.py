from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_admin_overview_lists_discovery_and_relay():
    client = TestClient(app)
    # discovery register
    client.post(
        "/v1/discovery/register",
        json={
            "agent_id": "agt-ov-1",
            "services": [{"name": "api-service", "protocol": "http", "port": 8000}],
            "addresses": {"local": ["127.0.0.1:18080"], "lan": [], "wan": []},
            "ttl": 60,
        },
    )
    # relay heartbeat
    client.post("/v1/relay/heartbeat", json={"agent_id": "agt-ov-1"})

    resp = client.get("/v1/admin/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "discovery" in data and "relay" in data and "policies" in data
    # discovery
    disc = data["discovery"]
    assert "agt-ov-1" in [a.get("agent_id") for a in disc.get("agents", [])]
    # relay
    rl = data["relay"]
    assert "agt-ov-1" in rl.get("active_agents", [])

