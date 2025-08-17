import json
from unittest.mock import patch, MagicMock

import sys


def test_agent_cli_run_once_prints_json(capsys):
    # Simulate CLI args
    sys_argv_backup = sys.argv
    sys.argv = [
        "agent_cli",
        "--base-url",
        "http://localhost:8000",
        "--agent-id",
        "agt-1",
        "--service-name",
        "api-service",
        "--risk-score",
        "0.2",
    ]

    with patch("atous_sec_network.agent.cli.AgentRuntime") as MockRT:
        mock_rt = MagicMock()
        mock_rt.run_once.return_value = {
            "action": "allow",
            "policy_version": "v1",
            "candidates": ["127.0.0.1:1000"],
        }
        MockRT.return_value = mock_rt

        from atous_sec_network.agent.cli import main

        code = main()
        assert code == 0
        out = capsys.readouterr().out.strip()
        data = json.loads(out)
        assert data["action"] == "allow"
        assert data["policy_version"] == "v1"

    sys.argv = sys_argv_backup


