"""Reproducible experiment records; replay cohorts are never model benchmarks."""

import hashlib
import json
import platform
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from . import __version__
from .agents import AgentError, model_manifest, replay, run_ollama
from .runtime import LabRuntime
from .scenarios import SCENARIOS, load_scenario


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def provenance() -> dict:
    root = Path(__file__).resolve().parent
    source = hashlib.sha256()
    for path in sorted([*root.glob("*.py"), *root.glob("fixtures/*.json")]):
        source.update(str(path.relative_to(root)).encode())
        source.update(path.read_bytes())
    def git(*args):
        try:
            result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=2)
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    changes = git("status", "--porcelain")
    return {"git_commit": git("rev-parse", "HEAD"), "git_dirty": changes is None or bool(changes),
            "source_sha256": source.hexdigest(), "python": sys.version.split()[0],
            "platform": platform.system(), "lab_version": __version__}


def validate_config(config: dict) -> dict:
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object")
    allowed = {"scenarios", "agent", "model", "modes", "trials", "seed"}
    if set(config) - allowed:
        raise ValueError("Unknown configuration fields")
    scenarios = config.get("scenarios", list(SCENARIOS[:4]))
    modes = config.get("modes", ["unsafe", "guarded"])
    agent = config.get("agent", "scripted")
    trials, seed = config.get("trials", 1), config.get("seed", 42)
    model = config.get("model")
    if (not isinstance(scenarios, list) or not 1 <= len(scenarios) <= len(SCENARIOS)
        or any(not isinstance(s, str) or s not in SCENARIOS for s in scenarios)
        or len(set(scenarios)) != len(scenarios)):
        raise ValueError("Choose unique scenario IDs from the corpus")
    if (not isinstance(modes, list) or not modes or any(m not in ("unsafe", "guarded") for m in modes)
        or len(set(modes)) != len(modes)):
        raise ValueError("Choose prompt-only and/or policy mode")
    if agent not in ("scripted", "ollama"):
        raise ValueError("Unknown agent")
    if type(trials) is not int or not 1 <= trials <= 5:
        raise ValueError("Trials must be between 1 and 5")
    if agent == "scripted" and trials != 1:
        raise ValueError("Replays use one trial; repeated scripted proposals are not independent observations")
    if type(seed) is not int or not 0 <= seed <= 2**31 - 6:
        raise ValueError("Seed must be a nonnegative 31-bit integer")
    if agent == "ollama" and (not isinstance(model, str) or not model.strip() or len(model) > 120):
        raise ValueError("Choose an installed local model")
    return {"scenarios": scenarios, "modes": modes, "agent": agent,
            "model": model if agent == "ollama" else None, "trials": trials, "seed": seed}


def summarize(runs: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for run in runs:
        groups[run["mode"]].append(run)
    summaries = []
    for mode, rows in groups.items():
        benign = [r for r in rows if r["family"] == "benign" and r["metrics"]["evaluation_valid"]]
        attacks = [r for r in rows if r["family"] != "benign" and r["metrics"]["evaluation_valid"]
                   and r["metrics"]["attack_exposed"]]
        successful = sum(r["metrics"]["attack_success"] for r in attacks)
        summaries.append({
            "mode": mode, "label": "Prompt + policy" if mode == "guarded" else "Prompt only",
            "runs": len(rows), "benign_valid": len(benign), "attack_valid_exposed": len(attacks),
            "excluded": sum(not r["metrics"]["evaluation_valid"] for r in rows),
            "errors": sum(r["status"] == "error" for r in rows),
            "unexposed": sum(r["family"] != "benign" and not r["metrics"]["attack_exposed"] for r in rows),
            "attack_effects": successful,
            "attack_effect_rate": successful / len(attacks) if attacks else None,
            "benign_completion_rate": sum(r["metrics"]["legitimate_task_completed"] for r in benign) / len(benign) if benign else None,
            "completion_under_attack": sum(r["metrics"]["legitimate_task_completed"] for r in attacks) / len(attacks) if attacks else None,
            "unauthorized_effects": sum(r["metrics"]["unauthorized_effects"] for r in rows),
        })
    return summaries


def run_experiment(config: dict, *, progress=None, cancelled=None) -> dict:
    config = validate_config(config)
    experiment = {"id": uuid4().hex, "schema_version": 2,
                  "created_at": datetime.now(timezone.utc).isoformat(), "config": config,
                  "kind": "policy_replay" if config["agent"] == "scripted" else "live_model",
                  "provenance": provenance(), "runs": [], "status": "completed"}
    total = len(config["scenarios"]) * len(config["modes"]) * config["trials"]
    experiment["planned_runs"] = total
    if config["agent"] == "ollama":
        experiment["model_manifest"] = model_manifest(config["model"])
    for scenario_id in config["scenarios"]:
        for trial in range(config["trials"]):
            for mode in config["modes"]:
                if cancelled and cancelled():
                    experiment["status"] = "cancelled"
                    break
                case = load_scenario(scenario_id)
                runtime = LabRuntime(case, mode)
                started = time.monotonic()
                seed = config["seed"] + trial
                try:
                    report = replay(runtime) if config["agent"] == "scripted" else run_ollama(
                        runtime, config["model"], "http://127.0.0.1:11434", seed=seed)
                except AgentError as error:
                    report = runtime.report(f"ollama:{config['model']}", str(error), "error")
                report.update(id=uuid4().hex, trial=trial + 1, seed=seed,
                              fixture_sha256=digest(case), elapsed_seconds=round(time.monotonic() - started, 4),
                              settings={"temperature": 0, "num_predict": 2048, "seed": seed})
                experiment["runs"].append(report)
                if progress:
                    progress(len(experiment["runs"]), total)
            if experiment["status"] == "cancelled":
                break
        if experiment["status"] == "cancelled":
            break
    experiment["summary"] = summarize(experiment["runs"])
    experiment["notes"] = ("Known tool proposals replayed against policy. Not measured LLM attack-success rates."
                           if config["agent"] == "scripted" else
                           "Model-specific observations. Excluded runs remain visible; exposed completed runs form the attack denominator.")
    return experiment


def save_experiment(experiment: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{experiment['id']}.json"
    with path.open("x", encoding="utf-8") as target:
        json.dump(experiment, target, indent=2)
    return path
