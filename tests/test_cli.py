import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_security_lab.agents import AgentError
from agent_security_lab.cli import main
from agent_security_lab.scenarios import SCENARIOS


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(list(args))
        return code, out.getvalue()

    def test_demo_labels_replays_honestly(self):
        code, text = self.invoke("demo")
        self.assertEqual(code, 0)
        self.assertIn("NOT measured LLM", text)
        self.assertIn("approval-bypass", text)

    def test_demo_json_is_machine_readable(self):
        _, text = self.invoke("demo", "--json")
        reports = json.loads(text)
        self.assertEqual(len(reports), len(SCENARIOS) * 2)
        self.assertTrue(all(r["simulated"] for r in reports))

    def test_report_output_is_saved_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "report.json"
            code, text = self.invoke("run", "benign", "--output", str(target))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(target.read_text()), json.loads(text))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                self.invoke("run", "benign", "--output", str(target))
            self.assertEqual(error.exception.code, 2)

    def test_local_model_failure_has_nonzero_exit_and_error_report(self):
        with patch("agent_security_lab.cli.run_ollama", side_effect=AgentError("test error")):
            with contextlib.redirect_stderr(io.StringIO()):
                code, text = self.invoke("run", "benign", "--agent", "ollama", "--model", "mock")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["status"], "error")

    def test_ollama_requires_an_explicit_model(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            self.invoke("run", "benign", "--agent", "ollama")
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
