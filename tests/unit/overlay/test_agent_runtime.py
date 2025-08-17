from unittest.mock import patch, MagicMock

from atous_sec_network.agent.runtime import AgentRuntime


def test_run_once_allow_action():
    rt = AgentRuntime(base_url="http://localhost:8000")

    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        # resolve
        resp_resolve = MagicMock()
        resp_resolve.status_code = 200
        resp_resolve.json.return_value = {"candidates": ["127.0.0.1:1000"]}
        # policy active
        resp_policy = MagicMock()
        resp_policy.status_code = 200
        resp_policy.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        # heartbeat
        resp_hb = MagicMock()
        resp_hb.status_code = 200
        resp_hb.json.return_value = {"policy_version": "v1", "actions": ["allow"]}

        # order: resolve (GET), policy (GET), heartbeat (POST)
        mock_get.side_effect = [resp_resolve, resp_policy]
        mock_post.side_effect = [resp_hb]

        result = rt.run_once(agent_id="agt-1", service_name="api-service", risk_score=0.2)
        assert result["action"] == "allow"
        assert result["policy_version"] == "v1"
        assert result["candidates"] == ["127.0.0.1:1000"]


def test_run_once_restrict_action():
    rt = AgentRuntime(base_url="http://localhost:8000")
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        resp_resolve = MagicMock(); resp_resolve.status_code = 200; resp_resolve.json.return_value = {"candidates": []}
        resp_policy = MagicMock(); resp_policy.status_code = 200; resp_policy.json.return_value = {"policy_version": "v1", "actions": ["restrict"]}
        resp_hb = MagicMock(); resp_hb.status_code = 200; resp_hb.json.return_value = {"policy_version": "v1", "actions": ["restrict"]}
        mock_get.side_effect = [resp_resolve, resp_policy]
        mock_post.side_effect = [resp_hb]
        result = rt.run_once(agent_id="agt-1", service_name="api-service", risk_score=0.9)
        assert result["action"] == "restrict"

