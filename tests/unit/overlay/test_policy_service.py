from atous_sec_network.security.policy_service import PolicyService


def test_policy_low_risk_allow():
    svc = PolicyService()
    version, actions = svc.resolve(agent_id="agt-1", risk_score=0.2, context={})
    assert version == "v1"
    assert "allow" in actions and "restrict" not in actions


def test_policy_high_risk_restrict():
    svc = PolicyService()
    version, actions = svc.resolve(agent_id="agt-1", risk_score=0.95, context={})
    assert version == "v1"
    assert "restrict" in actions


