from __future__ import annotations

import argparse
import json

from .runtime import AgentRuntime


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser("ATous Agent CLI")
    p.add_argument("--base-url", required=True)
    p.add_argument("--agent-id", required=True)
    p.add_argument("--service-name", required=True)
    p.add_argument("--risk-score", type=float, default=0.2)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rt = AgentRuntime(base_url=args.base_url)
    result = rt.run_once(agent_id=args.agent_id, service_name=args.service_name, risk_score=args.risk_score)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


