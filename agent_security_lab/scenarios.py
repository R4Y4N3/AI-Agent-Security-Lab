"""Trusted local fixtures. Their plans are never passed to a model."""

import json
from importlib.resources import files

SCENARIOS = ("benign", "payment-redirect", "data-exfiltration", "approval-bypass")
CANARY = "LAB_ONLY_CUSTOMER_RECORD_0042"


def load_scenario(name: str) -> dict:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}")
    return json.loads(
        files("agent_security_lab").joinpath("fixtures", f"{name}.json").read_text()
    )
