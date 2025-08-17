from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_heartbeat_returns_policy_and_actions():
    client = TestClient(app)
    payload = {
        "version": "agent-0.1.0",
        "services": [{"name": "api-service", "port": 8000, "protocol": "http"}],
        "metrics": {"cpu": 12.3, "mem": 256.5},
        "risk_score": 0.2,
    }
    resp = client.post("/v1/agents/agt-1/heartbeat", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("policy_version") == "v1"
    assert "allow" in data.get("actions", [])


def test_heartbeat_high_risk_returns_restrict():
    client = TestClient(app)
    payload = {
        "version": "agent-0.1.0",
        "services": [],
        "metrics": {},
        "risk_score": 0.9,
    }
    resp = client.post("/v1/agents/agt-2/heartbeat", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("policy_version") == "v1"
    assert "restrict" in data.get("actions", [])


def test_heartbeat_invalid_payload_returns_400():
    client = TestClient(app)
    resp = client.post("/v1/agents/agt-3/heartbeat", json={"risk_score": "not-a-number"})
    assert resp.status_code in (400, 422)


