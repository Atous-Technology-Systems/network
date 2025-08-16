from __future__ import annotations

from typing import Any, Dict, List

import requests
import psutil

from .policy_client import AgentPolicyClient


class AgentRuntime:
    def __init__(self, base_url: str, policy_client: AgentPolicyClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.policy = policy_client or AgentPolicyClient(base_url)

    def resolve_candidates(self, name: str, pref: str = "local,lan,wan") -> List[str]:
        url = f"{self.base_url}/v1/discovery/resolve"
        resp = requests.get(url, params={"name": name, "pref": pref}, timeout=3.0)
        resp.raise_for_status()
        data = resp.json()
        return list(data.get("candidates", []))

    def run_once(self, agent_id: str, service_name: str, risk_score: float) -> Dict[str, Any]:
        # 1) resolve
        candidates = self.resolve_candidates(service_name)
        # 2) policy active (optional read)
        pol = self.policy.get_active_policy(agent_id)
        # 3) heartbeat
        hb = self.policy.send_heartbeat(agent_id, {
            "version": "agent-0.1.0",
            "services": [],
            "metrics": {},
            "risk_score": risk_score,
        })
        actions = (hb or {}).get("actions") or (pol or {}).get("actions") or []
        action = actions[0] if actions else "unknown"
        pv = (hb or {}).get("policy_version") or (pol or {}).get("policy_version") or "unknown"
        return {"action": action, "policy_version": pv, "candidates": candidates}

    def run_loop(self, agent_id: str, service_name: str, risk_score: float, interval_s: float = 1.0, iterations: int = 3) -> Dict[str, Any]:
        # initial resolve + policy read
        _ = self.resolve_candidates(service_name)
        _ = self.policy.get_active_policy(agent_id)
        last: Dict[str, Any] = {}
        proc = psutil.Process()
        for _i in range(iterations):
            mem_mb = round(proc.memory_info().rss / 1024 / 1024, 2)
            cpu = float(proc.cpu_percent())
            hb = self.policy.send_heartbeat(agent_id, {
                "version": "agent-0.1.0",
                "services": [],
                "metrics": {"cpu": cpu, "mem_mb": mem_mb},
                "risk_score": risk_score,
            })
            actions = (hb or {}).get("actions") or []
            last = {
                "action": actions[0] if actions else "unknown",
                "policy_version": (hb or {}).get("policy_version", "unknown"),
            }
            if interval_s > 0:
                try:
                    import time
                    time.sleep(interval_s)
                except Exception:
                    pass
        return last


