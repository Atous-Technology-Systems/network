from fastapi.testclient import TestClient
from atous_sec_network.api.server import app


def test_relay_register_and_poll_empty():
    client = TestClient(app)
    r = client.post("/v1/relay/heartbeat", json={"agent_id": "agt-1"})
    assert r.status_code == 200
    assert r.json().get("registered") is True

    r2 = client.get("/v1/relay/poll", params={"agent_id": "agt-1"})
    assert r2.status_code == 200
    assert r2.json().get("messages") == []


def test_relay_send_and_poll():
    client = TestClient(app)
    client.post("/v1/relay/heartbeat", json={"agent_id": "agt-1"})
    client.post("/v1/relay/heartbeat", json={"agent_id": "agt-2"})

    send = client.post("/v1/relay/send", json={"from": "agt-1", "to": "agt-2", "payload": {"x": 1}})
    assert send.status_code == 200
    assert send.json().get("enqueued") is True

    poll = client.get("/v1/relay/poll", params={"agent_id": "agt-2"})
    assert poll.status_code == 200
    msgs = poll.json().get("messages")
    assert len(msgs) == 1
    assert msgs[0].get("from") == "agt-1"
    assert msgs[0].get("payload") == {"x": 1}


def test_relay_send_to_unknown_returns_false():
    client = TestClient(app)
    client.post("/v1/relay/heartbeat", json={"agent_id": "agt-1"})
    send = client.post("/v1/relay/send", json={"from": "agt-1", "to": "agt-999", "payload": {}})
    assert send.status_code == 200
    assert send.json().get("enqueued") is False


