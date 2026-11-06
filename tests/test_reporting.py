import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_security_lab.cli import main
from agent_security_lab.experiments import run_experiment
from agent_security_lab.reporting import markdown, verify
from agent_security_lab.scenarios import SCENARIOS


class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = run_experiment({"scenarios": list(SCENARIOS)})

    def test_complete_corpus_verifies(self):
        self.assertEqual(verify(self.record), [])

    def test_missing_or_duplicate_coverage_fails(self):
        record = copy.deepcopy(self.record)
        record["runs"].pop()
        self.assertTrue(verify(record))
        record["runs"].append(record["runs"][0])
        self.assertTrue(verify(record))

    def test_policy_failure_is_not_hidden(self):
        record = copy.deepcopy(self.record)
        guarded = next(r for r in record["runs"] if r["mode"] == "guarded")
        guarded["metrics"]["unauthorized_effects"] = 1
        self.assertTrue(any("boundary failure" in issue for issue in verify(record)))

    def test_summary_is_derived_and_payloads_omitted(self):
        record = copy.deepcopy(self.record)
        record["summary"] = []
        record["runs"][0]["final_response"] = "DO-NOT-EXPORT-RAW-TEXT"
        body = markdown(record)
        self.assertIn("unsafe", body)
        self.assertIn("not measured LLM", body)
        self.assertNotIn("DO-NOT-EXPORT-RAW-TEXT", body)

    def test_cancelled_record_has_no_invented_rates(self):
        record = run_experiment({}, cancelled=lambda: True)
        body = markdown(record)
        self.assertIn("cancelled", body)
        self.assertIn("Recorded runs: 0/8", body)
        self.assertNotIn("100%", body)

    def test_cli_export_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source.json", Path(directory) / "report.md"
            source.write_text(json.dumps(self.record))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["report", str(source), "--output", str(target)]), 0)
            original = target.read_text()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["report", str(source), "--output", str(target)]), 1)
            self.assertEqual(target.read_text(), original)

    def test_markdown_escapes_markup(self):
        record = copy.deepcopy(self.record)
        record["provenance"]["lab_version"] = "<script>|x\ny"
        body = markdown(record)
        self.assertNotIn("<script>", body)
        self.assertIn("\\|x y", body)
