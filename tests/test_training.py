import copy
import json
import os
import unittest
from unittest.mock import patch

from agent_security_lab.agents import AgentError
from agent_security_lab.deepseek import ENDPOINT, provider_status, request_message, wire_messages
from agent_security_lab.training import public_labs, run_attempt, validate_attempt
from tests.test_agents import message


CONFIG = {"lab": "tool-hijack", "payload": "A learner's custom email.", "allow_api_call": True}


class TrainingTests(unittest.TestCase):
    def test_labs_are_briefs_not_replay_solutions(self):
        labs = public_labs()
        self.assertEqual(len(labs), 8)
        self.assertNotIn("plan", json.dumps(labs))
        self.assertNotIn("family", labs[0])

    def test_invalid_payload_and_consent_rejected(self):
        for change in ({"lab": "../secrets"}, {"payload": ""}, {"payload": "é" * 4001},
                       {"allow_api_call": False}, {"allow_api_call": 1}, {"mode": "scripted"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_attempt({**CONFIG, **change})

    @patch("agent_security_lab.training.run_deepseek")
    def test_learner_payload_replaces_only_untrusted_surface(self, model):
        def respond(runtime):
            self.assertEqual(runtime.scenario["email"], CONFIG["payload"])
            self.assertEqual(runtime.scenario["plan"], [])
            self.assertEqual(runtime.scope.payee, "vendor-approved")
            runtime.input_observed = True
            return runtime.report("mock-model")
        model.side_effect = respond
        result = run_attempt(CONFIG)
        self.assertEqual(result["verdict"], "objective_not_reached")

    @patch("agent_security_lab.training.run_deepseek")
    def test_claimed_success_without_effect_is_not_solved(self, model):
        def respond(runtime):
            runtime.input_observed = True
            return runtime.report("mock-model", "I redirected the payment.")
        model.side_effect = respond
        self.assertEqual(run_attempt(CONFIG)["verdict"], "objective_not_reached")

    @patch("agent_security_lab.training.run_deepseek")
    def test_observed_effect_succeeds(self, model):
        def respond(runtime):
            runtime.input_observed = True
            runtime.call("pay_invoice", {"invoice_id": "INV-001", "payee": "vendor-attacker", "amount_cents": 2000, "idempotency_key": "test"})
            return runtime.report("mock-model")
        model.side_effect = respond
        self.assertEqual(run_attempt(CONFIG)["verdict"], "objective_reached")

    @patch("agent_security_lab.training.run_deepseek")
    def test_failed_unexposed_and_partial_runs_are_not_solved(self, model):
        for status in ("error", "truncated", "call_limit", "completed"):
            model.side_effect = lambda runtime: runtime.report("mock-model", status=status)
            self.assertEqual(run_attempt(CONFIG)["verdict"], "inconclusive")
        def partial(runtime):
            runtime.input_observed = True
            runtime.call("pay_invoice", {"invoice_id": "INV-001", "payee": "vendor-attacker", "amount_cents": 2000, "idempotency_key": "test"})
            return runtime.report("mock-model", status="error")
        model.side_effect = partial
        self.assertEqual(run_attempt(CONFIG)["verdict"], "effect_observed_incomplete")

    @patch("agent_security_lab.training.run_deepseek")
    def test_each_attempt_has_a_fresh_secret_and_state(self, model):
        canaries = []
        def respond(runtime):
            self.assertEqual(runtime.payments, [])
            canaries.append(runtime.canary)
            return runtime.report("mock-model")
        model.side_effect = respond
        first, second = run_attempt(CONFIG), run_attempt(CONFIG)
        self.assertNotEqual(first["id"], second["id"])
        self.assertNotEqual(canaries[0], canaries[1])


class DeepSeekTests(unittest.TestCase):
    def test_provider_requires_both_key_and_explicit_enable_flag(self):
        for environment in ({}, {"DEEPSEEK_API_KEY": "test-key"}, {"DEEPSEEK_ENABLE_REQUESTS": "1"}):
            with patch.dict(os.environ, environment, clear=True):
                self.assertFalse(provider_status()["ready"])
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret", "DEEPSEEK_ENABLE_REQUESTS": "1"}, clear=True):
            self.assertTrue(provider_status()["ready"])
            self.assertNotIn("test-secret", json.dumps(provider_status()))

    @patch("agent_security_lab.deepseek.build_opener")
    def test_disabled_provider_makes_no_network_call(self, opener):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(AgentError):
            request_message(ENDPOINT, "test", [])
        opener.assert_not_called()

    def test_wire_format_uses_matching_call_ids_and_json_arguments(self):
        call = message("read_email", {"email_id": "renewal"})
        call["tool_calls"][0]["id"] = "call-1"
        original = copy.deepcopy(call)
        result = wire_messages([call, {"role": "tool", "tool_name": "read_email", "content": "response"}])
        self.assertEqual(json.loads(result[0]["tool_calls"][0]["function"]["arguments"]), {"email_id": "renewal"})
        self.assertEqual(result[1]["tool_call_id"], "call-1")
        self.assertEqual(call, original)

    @patch("agent_security_lab.deepseek.build_opener")
    def test_response_arguments_and_truncation_are_preserved(self, opener):
        response = {"model": "mock", "choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call-1", "function": {"name": "read_email", "arguments": '{"email_id":"renewal"}'}}
        ]}}]}
        opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(response).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret", "DEEPSEEK_ENABLE_REQUESTS": "1"}, clear=True):
            result = request_message(ENDPOINT, "mock", [])
        self.assertEqual(result["tool_calls"][0]["function"]["arguments"], {"email_id": "renewal"})
        self.assertEqual(result["_response_meta"]["done_reason"], "length")
        self.assertNotIn("test-secret", json.dumps(result))
