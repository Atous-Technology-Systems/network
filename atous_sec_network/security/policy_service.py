from __future__ import annotations

from typing import Tuple, List, Dict, Any


class PolicyService:
    """MVP Policy resolver based on risk score.

    - risk_score < 0.7 → ['allow']
    - risk_score >= 0.7 → ['restrict']
    """

    def __init__(self) -> None:
        self._version = "v1"

    def resolve(self, agent_id: str, risk_score: float, context: Dict[str, Any]) -> tuple[str, list[str]]:
        try:
            score = float(risk_score)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid risk_score") from exc

        if score >= 0.7:
            actions: List[str] = ["restrict"]
        else:
            actions = ["allow"]
        return self._version, actions


