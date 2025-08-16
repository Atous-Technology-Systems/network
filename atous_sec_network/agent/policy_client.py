from __future__ import annotations

import time
from typing import Any, Dict

import requests


class AgentPolicyClient:
    def __init__(self, base_url: str, timeout_s: float = 3.0, retries: int = 1) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.retries = max(0, retries)

    def _do_request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.base_url}{path}"
        last_exc: Exception | None = None
        attempts = self.retries + 1
        for attempt in range(attempts):
            try:
                if method.upper() == "GET":
                    resp = requests.get(url, timeout=self.timeout_s, **kwargs)
                elif method.upper() == "POST":
                    resp = requests.post(url, timeout=self.timeout_s, **kwargs)
                else:
                    resp = requests.request(method, url, timeout=self.timeout_s, **kwargs)
                if resp.status_code >= 500 and attempt < attempts - 1:
                    time.sleep(0.1)
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < attempts - 1:
                    time.sleep(0.1)
                    continue
                raise last_exc

    def send_heartbeat(self, agent_id: str, payload: Dict[str, Any]) -> dict:
        return self._do_request("POST", f"/v1/agents/{agent_id}/heartbeat", json=payload)

    def get_active_policy(self, agent_id: str) -> dict:
        return self._do_request("GET", f"/v1/policies/active", params={"agent_id": agent_id})


