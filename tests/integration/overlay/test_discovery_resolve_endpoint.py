from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def _register(client: TestClient, agent_id: str, addresses: dict):
    return client.post(
        "/v1/discovery/register",
        json={
            "agent_id": agent_id,
            "services": [{"name": "api-service", "protocol": "http", "port": 8000}],
            "addresses": addresses,
            "ttl": 60,
        },
    )


def test_resolve_default_order_local_first():
    client = TestClient(app)
    _register(client, "agt-1", {"local": ["127.0.0.1:1000"], "lan": [], "wan": ["1.1.1.1:1000"]})
    resp = client.get("/v1/discovery/resolve", params={"name": "api-service"})
    assert resp.status_code == 200
    cands = resp.json().get("candidates")
    assert cands[0] == "127.0.0.1:1000"


def test_resolve_with_custom_pref_wan_first():
    client = TestClient(app)
    _register(client, "agt-2", {"local": ["127.0.0.1:2000"], "lan": [], "wan": ["2.2.2.2:2000"]})
    resp = client.get("/v1/discovery/resolve", params={"name": "api-service", "pref": "wan,lan,local"})
    assert resp.status_code == 200
    cands = resp.json().get("candidates")
    assert cands[0] == "2.2.2.2:2000"


def test_resolve_requires_name():
    client = TestClient(app)
    resp = client.get("/v1/discovery/resolve")
    assert resp.status_code in (400, 422)


