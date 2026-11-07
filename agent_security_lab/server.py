"""Loopback-only research console. Never expose this development server publicly."""

import json
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from .agents import NoRedirect
from .experiments import run_experiment, save_experiment, validate_config
from .scenarios import SCENARIOS, load_scenario
from .reporting import markdown
from .deepseek import provider_status
from .training import public_labs, run_attempt, validate_attempt

WEB = Path(__file__).resolve().parent / "web"
IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")


def local_models() -> dict:
    try:
        opener = build_opener(ProxyHandler({}), NoRedirect())
        with opener.open("http://127.0.0.1:11434/api/tags", timeout=2) as response:
            data = json.loads(response.read(2_000_001))
        models = data.get("models", [])
        if not isinstance(models, list):
            raise ValueError("Invalid model list")
        return {"available": True, "models": [{"name": m["name"], "digest": m.get("digest")}
                for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]}
    except (URLError, OSError, ValueError, AttributeError):
        return {"available": False, "models": [], "message": "Start local Ollama and install a tool-capable model to run live experiments."}


class Console:
    def __init__(self, directory: Path):
        self.directory = directory
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.jobs: dict[str, dict] = {}

    def submit_attempt(self, config):
        config = validate_attempt(config)
        status = provider_status()
        if not status["ready"]:
            raise ValueError(status["message"])
        with self.lock:
            if any(j["status"] in ("queued", "running") for j in self.jobs.values()):
                raise ValueError("An attempt is already running. Wait for it to finish.")
            job_id = uuid4().hex
            self.jobs[job_id] = {"id": job_id, "kind": "training", "status": "queued", "cancel_requested": False}
        self.executor.submit(self._work_attempt, job_id, config)
        return job_id

    def _work_attempt(self, job_id, config):
        with self.lock:
            self.jobs[job_id]["status"] = "running"
        try:
            attempt = run_attempt(config)
            directory = self.directory / "attempts"
            directory.mkdir(parents=True, exist_ok=True)
            with (directory / (attempt["id"] + ".json")).open("x", encoding="utf-8") as output:
                json.dump(attempt, output, indent=2)
            with self.lock:
                self.jobs[job_id].update(status="completed", attempt_id=attempt["id"])
        except Exception:
            with self.lock:
                self.jobs[job_id].update(status="error", error="The live attempt could not finish. Check DeepSeek configuration and connectivity; no success is assumed.")

    def experiments(self):
        if not self.directory.exists():
            return []
        rows = []
        for path in sorted(self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
            if not IDENTIFIER.fullmatch(path.stem):
                continue
            try:
                value = json.loads(path.read_text())
                if not isinstance(value, dict) or value.get("schema_version") != 2:
                    continue
                rows.append({key: value.get(key) for key in ("id", "created_at", "kind", "config", "status", "summary", "notes", "planned_runs")})
            except (OSError, ValueError):
                continue
        return rows

    def submit(self, config):
        config = validate_config(config)
        with self.lock:
            if any(j["status"] in ("queued", "running") for j in self.jobs.values()):
                raise ValueError("An experiment is already running. Wait or cancel it first.")
            job_id = uuid4().hex
            self.jobs[job_id] = {"id": job_id, "status": "queued", "completed": 0,
                                 "total": len(config["scenarios"]) * len(config["modes"]) * config["trials"],
                                 "cancel_requested": False}
        self.executor.submit(self._work, job_id, config)
        return job_id

    def _work(self, job_id, config):
        with self.lock:
            self.jobs[job_id]["status"] = "running"
        def progress(done, total):
            with self.lock:
                self.jobs[job_id].update(completed=done, total=total)
        def cancelled():
            with self.lock:
                return self.jobs[job_id]["cancel_requested"]
        try:
            manifest = local_models() if config["agent"] == "ollama" else None
            if manifest is not None and (not manifest["available"] or
                config["model"] not in [m["name"] for m in manifest["models"]]):
                raise ValueError("Selected model is not available in local Ollama. No model was downloaded or started.")
            experiment = run_experiment(config, progress=progress, cancelled=cancelled)
            if manifest is not None:
                experiment["model_manifest"] = next(m for m in manifest["models"] if m["name"] == config["model"])
            save_experiment(experiment, self.directory)
            with self.lock:
                self.jobs[job_id].update(status="completed", experiment_id=experiment["id"])
        except Exception as error:
            with self.lock:
                self.jobs[job_id].update(status="error", error=str(error))


def create_server(port=8787, directory=Path("artifacts/experiments")):
    console = Console(directory)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            pass

        def _trusted(self):
            allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            origin = self.headers.get("Origin")
            return self.headers.get("Host") in allowed and (origin is None or origin in {"http://" + h for h in allowed})

        def send(self, data, status=200, kind="application/json"):
            body = json.dumps(data).encode() if kind == "application/json" else data
            self.send_response(status)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self._trusted():
                return self.send({"error": "Untrusted origin or Host"}, 403)
            path = self.path.split("?", 1)[0]
            assets = {"/": ("index.html", "text/html"), "/app.css": ("app.css", "text/css"),
                      "/app.js": ("app.js", "text/javascript"), "/favicon.svg": ("favicon.svg", "image/svg+xml")}
            if path in assets:
                filename, kind = assets[path]
                return self.send((WEB / filename).read_bytes(), kind=kind)
            if path == "/api/session":
                return self.send({"token": console.token, "local_only": True})
            if path == "/api/labs":
                return self.send({"labs": public_labs(), "provider": provider_status()})
            match = re.fullmatch(r"/api/attempts/([a-f0-9]{32})", path)
            if match:
                try:
                    attempt = json.loads((console.directory / "attempts" / (match[1] + ".json")).read_text())
                    if attempt.get("kind") != "training_attempt" or attempt.get("id") != match[1]:
                        raise ValueError("Invalid attempt")
                    return self.send(attempt)
                except (OSError, ValueError, AttributeError):
                    return self.send({"error": "Attempt not found"}, 404)
            if path == "/api/corpus":
                return self.send([ {key: case[key] for key in ("name", "description", "family", "split", "variant", "email")}
                                  for case in map(load_scenario, SCENARIOS)])
            if path == "/api/models":
                return self.send(local_models())
            if path == "/api/experiments":
                return self.send(console.experiments())
            match = re.fullmatch(r"/api/experiments/([a-f0-9]{32})/report.md", path)
            if match:
                try:
                    record = json.loads((console.directory / (match[1] + ".json")).read_text())
                    return self.send(markdown(record).encode(), kind="text/markdown")
                except (OSError, ValueError, KeyError, TypeError):
                    return self.send({"error": "Experiment report not found"}, 404)
            match = re.fullmatch(r"/api/experiments/([a-f0-9]{32})", path)
            if match:
                file = console.directory / (match[1] + ".json")
                try:
                    return self.send(json.loads(file.read_text()))
                except (OSError, ValueError):
                    return self.send({"error": "Experiment not found"}, 404)
            match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})", path)
            if match:
                with console.lock:
                    job = dict(console.jobs.get(match[1], {}))
                return self.send(job if job else {"error": "Job not found"}, 200 if job else 404)
            return self.send({"error": "Not found"}, 404)

        def do_POST(self):
            if not self._trusted() or not secrets.compare_digest(self.headers.get("X-Lab-Token", ""), console.token):
                return self.send({"error": "Request not authorized"}, 403)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send({"error": "Expected application/json"}, 415)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 16384:
                    raise ValueError("Request body must be 1–16384 bytes")
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/attempts":
                    return self.send({"job_id": console.submit_attempt(data)}, 202)
                if self.path == "/api/experiments":
                    return self.send({"job_id": console.submit(data)}, 202)
                match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/cancel", self.path)
                if match:
                    with console.lock:
                        if match[1] not in console.jobs:
                            return self.send({"error": "Job not found"}, 404)
                        console.jobs[match[1]]["cancel_requested"] = True
                    return self.send({"cancel_requested": True})
                return self.send({"error": "Not found"}, 404)
            except (ValueError, TypeError) as error:
                return self.send({"error": str(error)}, 400)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.console = console
    return server


def serve(port=8787, directory=Path("artifacts/experiments")):
    server = create_server(port, directory)
    print(f"AI Agent Security Lab: http://127.0.0.1:{server.server_port}/", flush=True)
    print("Loopback only. Synthetic effects. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with server.console.lock:
            for job in server.console.jobs.values():
                job["cancel_requested"] = True
        server.server_close()
        server.console.executor.shutdown(wait=True, cancel_futures=True)
