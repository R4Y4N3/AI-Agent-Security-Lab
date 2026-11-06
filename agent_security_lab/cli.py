"""CLI entry point. Runs offline by default; outputs are synthetic."""

import argparse
import json
import sys
from pathlib import Path

from .agents import AgentError, replay, run_ollama
from .runtime import LabRuntime
from .scenarios import SCENARIOS, load_scenario
from .experiments import run_experiment, save_experiment
from .reporting import markdown, verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Security Lab — synthetic tools, real policy boundaries")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List local scenarios")
    verify_parser = sub.add_parser("verify", help="Self-check all seeded replay controls; no model requests")
    verify_parser.add_argument("--directory", type=Path, default=Path("artifacts/experiments"))
    report_parser = sub.add_parser("report", help="Render a saved experiment as Markdown without raw payloads")
    report_parser.add_argument("input", type=Path)
    report_parser.add_argument("--output", type=Path, required=True)
    serve_parser = sub.add_parser("serve", help="Open the loopback-only web research console")
    serve_parser.add_argument("--port", type=int, default=8787)
    batch = sub.add_parser("experiment", help="Run a repeatable paired batch and save its evidence")
    batch.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS[:4]))
    batch.add_argument("--agent", choices=("scripted", "ollama"), default="scripted")
    batch.add_argument("--model")
    batch.add_argument("--trials", type=int, default=1)
    batch.add_argument("--seed", type=int, default=42)
    batch.add_argument("--modes", nargs="+", choices=("unsafe", "guarded"), default=["unsafe", "guarded"])
    batch.add_argument("--directory", type=Path, default=Path("artifacts/experiments"))
    demo = sub.add_parser("demo", help="Compare unsafe and guarded scripted policy replays")
    demo.add_argument("--json", action="store_true", help="Emit a full JSON report")
    run = sub.add_parser("run", help="Run one scenario")
    run.add_argument("scenario", choices=SCENARIOS)
    run.add_argument("--mode", choices=("unsafe", "guarded"), default="guarded")
    run.add_argument("--agent", choices=("scripted", "ollama"), default="scripted")
    run.add_argument("--model", help="Your already-installed, tool-capable Ollama model")
    run.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    run.add_argument("--output", type=Path, help="Save JSON to a new file (never overwrite)")
    args = parser.parse_args(argv)
    if args.command == "report":
        try:
            body = markdown(json.loads(args.input.read_text()))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as output:
                output.write(body)
        except (ValueError, OSError, KeyError, TypeError) as error:
            print(f"Cannot export report: {error}", file=sys.stderr)
            return 1
        print(args.output)
        return 0
    if args.command == "verify":
        record = run_experiment({"scenarios": list(SCENARIOS)})
        issues = verify(record)
        try:
            path = save_experiment(record, args.directory)
        except OSError as error:
            print(str(error), file=sys.stderr)
            return 1
        print(f"Evidence: {path}")
        if issues:
            print("\n".join(issues), file=sys.stderr)
            return 1
        print("All 24 seeded replays passed their controls. Not a model-security certification.")
        return 0
    if args.command == "serve":
        if not 0 <= args.port <= 65535:
            parser.error("Port must be between 0 and 65535")
        from .server import serve
        serve(args.port)
        return 0
    if args.command == "experiment":
        try:
            config = {key: getattr(args, key) for key in ("scenarios", "agent", "model", "trials", "seed", "modes")}
            experiment = run_experiment(config)
            path = save_experiment(experiment, args.directory)
        except (ValueError, OSError) as error:
            print(str(error), file=sys.stderr)
            return 1
        print(json.dumps({"path": str(path), "kind": experiment["kind"], "summary": experiment["summary"]}, indent=2))
        return 0 if all(r["status"] == "completed" for r in experiment["runs"]) else 1
    if args.command == "list":
        for name in SCENARIOS:
            print(f"{name:20} {load_scenario(name)['description']}")
        return 0
    if args.command == "demo":
        reports = [replay(LabRuntime(load_scenario(name), mode))
                   for name in SCENARIOS for mode in ("unsafe", "guarded")]
        if args.json:
            print(json.dumps(reports, indent=2))
        else:
            print("AGENT SECURITY LAB / OFFLINE POLICY REPLAY")
            print("Scripted proposals, NOT measured LLM attack-success rates. All effects simulated.\n")
            print(f"{'SCENARIO':22} {'MODE':9} {'TASK DONE':10} {'ATTACK EFFECT':14} {'BLOCKED':7}")
            for report in reports:
                metrics = report["metrics"]
                effect = "n/a" if report["scenario"] == "benign" else str(metrics["attack_success"])
                print(f"{report['scenario']:22} {report['mode']:9} "
                      f"{str(metrics['legitimate_task_completed']):10} {effect:14} {metrics['blocked_calls']:<7}")
            print("\nBlocked attack proposals may leave the original task unfinished; this is reported, not hidden.")
        return 0
    if args.agent == "ollama" and not args.model:
        parser.error("--model is required with --agent ollama")
    if args.agent == "scripted" and args.model:
        parser.error("--model requires --agent ollama")
    if args.output and args.output.exists():
        parser.error(f"Output already exists: {args.output}")
    runtime = LabRuntime(load_scenario(args.scenario), args.mode)
    try:
        report = replay(runtime) if args.agent == "scripted" else run_ollama(runtime, args.model, args.ollama_url)
    except AgentError as error:
        print(f"Model run stopped: {error}", file=sys.stderr)
        report = runtime.report(f"ollama:{args.model}", str(error), status="error")
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as target:
                target.write(serialized)
        except OSError as error:
            print(f"Could not save output: {error}", file=sys.stderr)
            return 1
    print(serialized, end="")
    return 0 if report["status"] == "completed" else 1
