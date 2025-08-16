from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_admin_events_append_and_read():
    client = TestClient(app)
    r1 = client.post("/v1/admin/events", json={"type": "info", "payload": {"msg": "hello"}})
    assert r1.status_code == 200
    r2 = client.get("/v1/admin/events", params={"limit": 10})
    assert r2.status_code == 200
    events = r2.json().get("events", [])
    assert any(e.get("type") == "info" for e in events)

