import http.client
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from agent_security_lab.server import create_server


class ConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = create_server(0, Path(cls.temp.name))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.console.executor.shutdown(wait=True)
        cls.thread.join()
        cls.temp.cleanup()

    def request(self, path, method="GET", data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        defaults = {"Content-Type": "application/json"}
        defaults.update(headers or {})
        body = json.dumps(data) if data is not None else None
        connection.request(method, path, body, defaults)
        response = connection.getresponse()
        content = response.read()
        result = (response.status, dict(response.getheaders()), content)
        connection.close()
        return result

    def test_server_binds_only_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_home_is_labs_only(self):
        _, _, body = self.request("/")
        self.assertIn(b"Choose a lab.", body)
        for old in (b"Run replay demo", b"History", b"Comparison", b"Ollama"):
            self.assertNotIn(old, body)

    def test_fonts_are_local_woff2_with_correct_media_type(self):
        for path in ("/inter-latin-variable.woff2", "/jetbrains-mono-latin.woff2"):
            status, headers, body = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "font/woff2")
            self.assertEqual(body[:4], b"wOF2")

    def test_motion_and_local_font_fallbacks(self):
        _, _, css = self.request("/app.css")
        self.assertIn(b"prefers-reduced-motion: reduce", css)
        self.assertIn(b'font-family: "Inter"', css)
        self.assertIn(b"font-display: swap", css)
        self.assertNotIn(b"fonts.googleapis.com", css)

    def test_public_labs_do_not_call_provider_or_expose_keys(self):
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "test-private-key"}, clear=True), patch("agent_security_lab.deepseek.request_message") as request:
            status, _, body = self.request("/api/labs")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["labs"]), 8)
        self.assertNotIn(b"test-private-key", body)
        request.assert_not_called()

    def test_attempts_require_token_consent_and_enabled_provider(self):
        config = {"lab": "tool-hijack", "payload": "custom attack", "allow_api_call": True}
        self.assertEqual(self.request("/api/attempts", "POST", config)[0], 403)
        headers = {"X-Lab-Token": self.server.console.token}
        with patch("agent_security_lab.server.provider_status", return_value={"ready": False, "message": "Not configured"}):
            self.assertEqual(self.request("/api/attempts", "POST", config, headers)[0], 400)

    def test_training_attempt_end_to_end_with_mock_provider_only(self):
        def respond(runtime):
            runtime.input_observed = True
            return runtime.report("mock-provider")
        config = {"lab": "tool-hijack", "payload": "custom attack", "allow_api_call": True}
        headers = {"X-Lab-Token": self.server.console.token}
        with patch("agent_security_lab.server.provider_status", return_value={"ready": True}), patch("agent_security_lab.training.run_deepseek", side_effect=respond):
            status, _, body = self.request("/api/attempts", "POST", config, headers)
            self.assertEqual(status, 202)
            job_id = json.loads(body)["job_id"]
            for _ in range(100):
                _, _, raw = self.request("/api/jobs/" + job_id)
                job = json.loads(raw)
                if job["status"] not in ("queued", "running"):
                    break
                time.sleep(.01)
        self.assertEqual(job["status"], "completed", job)
        status, _, raw = self.request("/api/attempts/" + job["attempt_id"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["verdict"], "objective_not_reached")
        self.assertEqual(self.request("/api/attempts/../../README.md")[0], 404)

    def test_static_assets_and_csp(self):
        for path in ("/", "/app.js", "/app.css", "/favicon.svg"):
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertTrue(body)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_corpus_is_data_only_and_has_no_replay_plans(self):
        status, _, body = self.request("/api/corpus")
        self.assertEqual(status, 200)
        cases = json.loads(body)
        self.assertEqual(len(cases), 12)
        self.assertNotIn("plan", cases[0])

    def test_wrong_host_and_origin_are_rejected(self):
        for headers in ({"Host": "evil.example"}, {"Origin": "https://evil.example"}):
            self.assertEqual(self.request("/api/session", headers=headers)[0], 403)

    def test_token_required_before_job_creation(self):
        self.assertEqual(self.request("/api/experiments", "POST", {"agent": "scripted"})[0], 403)

    def test_wrong_content_type_is_rejected(self):
        headers = {"X-Lab-Token": self.server.console.token, "Content-Type": "text/plain"}
        self.assertEqual(self.request("/api/experiments", "POST", {}, headers)[0], 415)

    def test_bad_configs_are_rejected_before_scheduling(self):
        headers = {"X-Lab-Token": self.server.console.token}
        for data in ({"scenarios": ["../../etc/passwd"]}, {"trials": True}, []):
            self.assertEqual(self.request("/api/experiments", "POST", data, headers)[0], 400)

    def test_no_filesystem_browsing(self):
        for path in ("/../README.md", "/api/experiments/../../README.md", "/.git/config"):
            self.assertEqual(self.request(path)[0], 404)

    def test_end_to_end_replay_job_and_saved_evidence(self):
        headers = {"X-Lab-Token": self.server.console.token}
        status, _, body = self.request("/api/experiments", "POST", {"scenarios": ["benign", "data-exfiltration"]}, headers)
        self.assertEqual(status, 202)
        job_id = json.loads(body)["job_id"]
        for _ in range(100):
            _, _, body = self.request("/api/jobs/" + job_id)
            job = json.loads(body)
            if job["status"] not in ("queued", "running"):
                break
            time.sleep(0.01)
        self.assertEqual(job["status"], "completed")
        status, _, body = self.request("/api/experiments/" + job["experiment_id"])
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["kind"], "policy_replay")
        self.assertEqual(len(result["runs"]), 4)
        self.assertEqual(result["summary"][1]["unauthorized_effects"], 0)
        status, headers, body = self.request("/api/experiments/" + job["experiment_id"] + "/report.md")
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", headers["Content-Type"])
        self.assertIn(b"not measured LLM", body)
        self.assertEqual(self.request("/api/experiments/" + "f" * 32 + "/report.md")[0], 404)


if __name__ == "__main__":
    unittest.main()
