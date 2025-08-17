from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_policies_active_returns_policy():
    client = TestClient(app)
    resp = client.get("/v1/policies/active", params={"agent_id": "agt-1"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("policy_version") == "v1"
    assert "allow" in data.get("actions", [])


def test_policies_active_requires_agent_id():
    client = TestClient(app)
    resp = client.get("/v1/policies/active")
    assert resp.status_code in (400, 422)


