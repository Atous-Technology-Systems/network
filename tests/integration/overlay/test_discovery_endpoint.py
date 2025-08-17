from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_register_and_query_service():
    client = TestClient(app)
    reg = client.post(
        "/v1/discovery/register",
        json={
            "agent_id": "agt-1",
            "services": [{"name": "api-service", "protocol": "http", "port": 8000}],
            "addresses": {"local": ["127.0.0.1:18080"], "lan": [], "wan": []},
            "ttl": 60,
        },
    )
    assert reg.status_code == 200
    providers = client.get("/v1/discovery/services", params={"name": "api-service"})
    assert providers.status_code == 200
    data = providers.json()
    assert any(p.get("agent_id") == "agt-1" for p in data.get("providers", []))


def test_services_requires_name_param():
    client = TestClient(app)
    resp = client.get("/v1/discovery/services")
    assert resp.status_code in (400, 422)


def test_get_agent_registration():
    client = TestClient(app)
    client.post(
        "/v1/discovery/register",
        json={
            "agent_id": "agt-1",
            "services": [],
            "addresses": {"local": [], "lan": [], "wan": []},
            "ttl": 60,
        },
    )
    detail = client.get("/v1/discovery/agents/agt-1")
    assert detail.status_code == 200
    assert detail.json().get("agent_id") == "agt-1"


