from unittest.mock import patch, MagicMock

from atous_sec_network.agent.runtime import AgentRuntime


def test_run_loop_sends_multiple_heartbeats():
    rt = AgentRuntime(base_url="http://localhost:8000")

    with patch("requests.get") as mock_get, patch("requests.post") as mock_post, patch("psutil.Process") as MockProc:
        # resolve (first call); policy (second call)
        resp_resolve = MagicMock(); resp_resolve.status_code = 200; resp_resolve.json.return_value = {"candidates": []}
        resp_policy = MagicMock(); resp_policy.status_code = 200; resp_policy.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        mock_get.side_effect = [resp_resolve, resp_policy]

        # heartbeat returns allow
        resp_hb = MagicMock(); resp_hb.status_code = 200; resp_hb.json.return_value = {"policy_version": "v1", "actions": ["allow"]}
        mock_post.return_value = resp_hb

        # psutil mocks
        proc = MagicMock(); proc.memory_info.return_value = MagicMock(rss=100*1024*1024)
        proc.cpu_percent.return_value = 5.0
        MockProc.return_value = proc

        result = rt.run_loop(agent_id="agt-1", service_name="api-service", risk_score=0.2, interval_s=0.0, iterations=3)
        assert result["action"] == "allow"
        assert mock_post.call_count == 3

