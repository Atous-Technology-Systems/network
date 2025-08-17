import json
from unittest.mock import patch, MagicMock

from atous_sec_network.agent.policy_client import AgentPolicyClient


def test_get_active_policy_success():
    client = AgentPolicyClient(base_url="http://localhost:8000")
    with patch("requests.get") as mock_get:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        mock_get.return_value = resp

        data = client.get_active_policy("agt-1")
        assert data["policy_version"] == "v1"
        assert "allow" in data["actions"]


def test_send_heartbeat_success():
    client = AgentPolicyClient(base_url="http://localhost:8000")
    with patch("requests.post") as mock_post:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        mock_post.return_value = resp

        payload = {"version": "agent-0.1.0", "services": [], "metrics": {}, "risk_score": 0.2}
        data = client.send_heartbeat("agt-1", payload)
        assert data["policy_version"] == "v1"


def test_retry_on_5xx_then_success():
    client = AgentPolicyClient(base_url="http://localhost:8000", retries=1)
    with patch("requests.get") as mock_get:
        resp_fail = MagicMock()
        resp_fail.status_code = 500
        resp_ok = MagicMock()
        resp_ok.status_code = 200
        resp_ok.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        mock_get.side_effect = [resp_fail, resp_ok]

        data = client.get_active_policy("agt-1")
        assert data["policy_version"] == "v1"


