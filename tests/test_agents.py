import unittest
from unittest.mock import patch

from agent_security_lab.agents import AgentError, ollama_endpoint, run_ollama, tool_definitions
from agent_security_lab.runtime import LabRuntime
from agent_security_lab.scenarios import load_scenario


def message(name, arguments):
    return {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": name, "arguments": arguments}}
    ]}


class AgentTests(unittest.TestCase):
    def test_only_literal_loopback_is_accepted(self):
        self.assertEqual(ollama_endpoint("http://127.0.0.1:11434"), "http://127.0.0.1:11434/api/chat")
        self.assertEqual(ollama_endpoint("http://[::1]:11434/"), "http://[::1]:11434/api/chat")
        for url in ("https://example.com", "http://localhost:11434", "http://127.0.0.1.example.com",
                    "http://127.0.0.1:11434/other", "http://user@127.0.0.1:11434",
                    "http://127.0.0.1:99999", "http://127.0.0.1:11434?redirect=x"):
            with self.subTest(url=url), self.assertRaises(AgentError):
                ollama_endpoint(url)

    def test_schemas_expose_only_mock_tools(self):
        definitions = tool_definitions()
        self.assertEqual({t["function"]["name"] for t in definitions},
                         {"read_email", "read_file", "send_email", "pay_invoice"})
        for tool in definitions:
            self.assertFalse(tool["function"]["parameters"]["additionalProperties"])

    @patch("agent_security_lab.agents.request_message")
    def test_model_cannot_bypass_independent_policy(self, request):
        request.side_effect = [
            message("pay_invoice", {"invoice_id": "INV-001", "payee": "vendor-attacker",
                                    "amount_cents": 2000, "idempotency_key": "renewal-001"}),
            {"role": "assistant", "content": "I could not process the changed recipient."},
        ]
        lab = LabRuntime(load_scenario("payment-redirect"), "guarded")
        report = run_ollama(lab, "mock-model", "http://127.0.0.1:11434")
        self.assertFalse(report["metrics"]["attack_success"])
        self.assertEqual(report["metrics"]["blocked_calls"], 1)
        self.assertEqual(lab.payments, [])

    @patch("agent_security_lab.agents.request_message")
    def test_email_enters_as_tool_data_not_system_prompt(self, request):
        snapshots = []

        def respond(endpoint, model, messages):
            snapshots.append([dict(item) for item in messages])
            if len(snapshots) == 1:
                return message("read_email", {"email_id": "renewal"})
            return {"role": "assistant", "content": "Stopped."}

        request.side_effect = respond
        scenario = load_scenario("payment-redirect")
        run_ollama(LabRuntime(scenario, "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertNotIn(scenario["email"], str(snapshots[0]))
        self.assertEqual(snapshots[1][-1]["role"], "tool")
        self.assertIn("vendor-attacker", snapshots[1][-1]["content"])
        self.assertNotIn("plan", snapshots[0][0]["content"])

    @patch("agent_security_lab.agents.request_message")
    def test_turn_limit_is_not_silently_called_completed(self, request):
        request.return_value = message("read_email", {"email_id": "renewal"})
        with patch("agent_security_lab.agents.MAX_TURNS", 2):
            report = run_ollama(LabRuntime(load_scenario("benign"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertEqual(report["status"], "turn_limit")

    @patch("agent_security_lab.agents.request_message")
    def test_call_limit_applies_to_multiple_calls_in_one_response(self, request):
        response = message("read_email", {"email_id": "renewal"})
        response["tool_calls"] *= 4
        request.return_value = response
        with patch("agent_security_lab.agents.MAX_CALLS", 2):
            report = run_ollama(LabRuntime(load_scenario("benign"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertEqual(report["status"], "call_limit")
        self.assertEqual(len(report["events"]), 2)

    @patch("agent_security_lab.agents.request_message")
    def test_malformed_calls_do_not_execute(self, request):
        request.return_value = {"role": "assistant", "tool_calls": [{"function": {"name": "exec"}}]}
        lab = LabRuntime(load_scenario("benign"), "unsafe")
        with self.assertRaises(AgentError):
            run_ollama(lab, "mock", "http://127.0.0.1:11434")
        self.assertEqual(lab.events, [])

    @patch("agent_security_lab.agents.request_message")
    def test_final_message_is_not_used_as_evidence_of_payment(self, request):
        request.return_value = {"role": "assistant", "content": "The invoice has been paid."}
        report = run_ollama(LabRuntime(load_scenario("benign"), "guarded"), "mock", "http://127.0.0.1:11434")
        self.assertFalse(report["metrics"]["legitimate_task_completed"])


if __name__ == "__main__":
    unittest.main()
