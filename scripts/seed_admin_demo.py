#!/usr/bin/env python3
"""
Seed script (MVP) to populate Admin overview with demo data.

Actions:
 - Register a discovery entry for a demo agent
 - Send a relay heartbeat for the same agent
 - Create a few admin events

Usage:
  python scripts/seed_admin_demo.py --base-url http://localhost:8000 \
    --agent-id agt-demo --service-name api-service --port 8000
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import requests


def _post(base: str, path: str, json_body: dict) -> tuple[int, Any]:
    url = f"{base.rstrip('/')}{path}"
    try:
        res = requests.post(url, json=json_body, timeout=3.0)
        return res.status_code, res.json()
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


def _get(base: str, path: str, params: dict | None = None) -> tuple[int, Any]:
    url = f"{base.rstrip('/')}{path}"
    try:
        res = requests.get(url, params=params or {}, timeout=3.0)
        return res.status_code, res.json()
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


def run(base_url: str, agent_id: str, service_name: str, port: int) -> int:
    # 1) discovery register
    code, data = _post(
        base_url,
        "/v1/discovery/register",
        {
            "agent_id": agent_id,
            "services": [{"name": service_name, "protocol": "http", "port": port}],
            "addresses": {"local": [f"127.0.0.1:{port}"], "lan": [], "wan": []},
            "ttl": 60,
        },
    )
    print("discovery.register:", code, data)

    # 2) relay heartbeat
    code, data = _post(base_url, "/v1/relay/heartbeat", {"agent_id": agent_id})
    print("relay.heartbeat:", code, data)

    # 3) admin events
    for evt_type, payload in (
        ("seed_info", {"msg": "seed started"}),
        ("seed_agent", {"agent_id": agent_id, "service": service_name}),
        ("seed_done", {"ok": True}),
    ):
        code, data = _post(base_url, "/v1/admin/events", {"type": evt_type, "payload": payload})
        print(f"admin.events[{evt_type}]:", code, data)

    # 4) overview check
    code, data = _get(base_url, "/v1/admin/overview")
    print("admin.overview:", code)
    if code != 200:
        print(data)
    else:
        # Print small summary
        disc_agents = len((data.get("discovery") or {}).get("agents") or [])
        relay_agents = len((data.get("relay") or {}).get("active_agents") or [])
        print(f"discovery agents: {disc_agents} • relay active: {relay_agents}")
    return 0 if code == 200 else 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser("Seed Admin Demo")
    p.add_argument("--base-url", required=True)
    p.add_argument("--agent-id", default="agt-demo")
    p.add_argument("--service-name", default="api-service")
    p.add_argument("--port", type=int, default=8000)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return run(args.base_url, args.agent_id, args.service_name, args.port)


if __name__ == "__main__":
    raise SystemExit(main())


