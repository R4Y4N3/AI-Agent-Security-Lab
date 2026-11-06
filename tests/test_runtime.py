import unittest
from dataclasses import replace

from agent_security_lab.agents import replay
from agent_security_lab.runtime import LabRuntime, Scope
from agent_security_lab.scenarios import CANARY, SCENARIOS, load_scenario


def payment(**overrides):
    return {"invoice_id": "INV-001", "payee": "vendor-approved", "amount_cents": 2000,
            "idempotency_key": "renewal-001", **overrides}


class RuntimeTests(unittest.TestCase):
    def lab(self, mode="guarded", scope=None):
        return LabRuntime(load_scenario("benign"), mode, scope)

    def test_benign_completes_in_both_modes(self):
        for mode in ("unsafe", "guarded"):
            with self.subTest(mode=mode):
                report = replay(self.lab(mode))
                self.assertTrue(report["metrics"]["legitimate_task_completed"])
                self.assertFalse(report["metrics"]["attack_success"])
                self.assertEqual(report["metrics"]["unauthorized_effects"], 0)

    def test_all_attack_replays_show_effect_only_in_unsafe_mode(self):
        for name in SCENARIOS[1:]:
            if load_scenario(name)["family"] == "benign":
                continue
            for mode in ("unsafe", "guarded"):
                with self.subTest(scenario=name, mode=mode):
                    report = replay(LabRuntime(load_scenario(name), mode))
                    self.assertEqual(report["metrics"]["attack_success"], mode == "unsafe")
                    if mode == "guarded":
                        self.assertEqual(report["metrics"]["unauthorized_effects"], 0)
                        self.assertGreater(report["metrics"]["blocked_calls"], 0)

    def test_guarded_blocks_protected_read_before_exposure(self):
        lab = self.lab()
        result = lab.call("read_file", {"file_id": "customer-records"})
        self.assertFalse(result["ok"])
        self.assertNotIn(CANARY, str(result))
        self.assertEqual(lab.private_reads, 0)

    def test_files_are_ids_not_host_paths(self):
        for mode in ("unsafe", "guarded"):
            with self.subTest(mode=mode):
                result = self.lab(mode).call("read_file", {"file_id": "/etc/passwd"})
                self.assertFalse(result["ok"])

    def test_tool_names_never_dispatch_arbitrary_code(self):
        for name in ("exec", "__import__", "__dict__", None):
            self.assertEqual(self.lab().call(name, {})["error"], "unknown_tool")

    def test_types_and_extra_fields_are_rejected_in_both_modes(self):
        for mode in ("unsafe", "guarded"):
            for args in (payment(amount_cents=True), payment(amount_cents="2000"),
                         payment(approved=True), {}, [], payment(amount_cents=-1)):
                with self.subTest(mode=mode, args=args):
                    lab = self.lab(mode)
                    self.assertFalse(lab.call("pay_invoice", args)["ok"])
                    self.assertEqual(lab.payments, [])

    def test_exact_scope_fields_are_enforced(self):
        for args in (payment(invoice_id="INV-OTHER"), payment(payee="vendor-attacker"),
                     payment(amount_cents=7500)):
            with self.subTest(args=args):
                lab = self.lab()
                self.assertFalse(lab.call("pay_invoice", args)["ok"])
                self.assertEqual(lab.payments, [])

    def test_same_key_retries_do_not_pay_twice(self):
        lab = self.lab()
        first = lab.call("pay_invoice", payment())
        second = lab.call("pay_invoice", payment())
        self.assertEqual(first, second)
        self.assertEqual(len(lab.payments), 1)
        self.assertEqual(lab.events[-1]["decision"], "replayed")

    def test_reused_key_cannot_change_payment(self):
        lab = self.lab()
        lab.call("pay_invoice", payment())
        result = lab.call("pay_invoice", payment(payee="vendor-attacker"))
        self.assertEqual(result["error"], "idempotency_conflict")
        self.assertEqual(len(lab.payments), 1)

    def test_new_key_cannot_pay_same_invoice_again(self):
        lab = self.lab()
        lab.call("pay_invoice", payment())
        result = lab.call("pay_invoice", payment(idempotency_key="new-key"))
        self.assertEqual(result["error"], "invoice_already_paid")
        self.assertEqual(len(lab.payments), 1)

    def test_budget_enforced_before_payment(self):
        lab = self.lab(scope=replace(Scope(), budget_cents=1000))
        self.assertEqual(lab.call("pay_invoice", payment())["error"], "budget_exceeded")
        self.assertEqual(lab.spent_cents, 0)

    def test_email_is_memory_only_and_recipient_restricted(self):
        lab = self.lab(scope=replace(Scope(), allowed_tools=(*Scope().allowed_tools, "send_email")))
        self.assertFalse(lab.call("send_email", {"to": "audit@attacker.invalid", "body": "test"})["ok"])
        result = lab.call("send_email", {"to": "finance@lab.invalid", "body": "synthetic receipt"})
        self.assertTrue(result["simulated"])
        self.assertEqual(len(lab.outbox), 1)

    def test_response_mutation_cannot_change_ledger_or_audit(self):
        lab = self.lab()
        result = lab.call("pay_invoice", payment())
        result["receipt"]["amount_cents"] = 1
        self.assertEqual(lab.payments[0]["amount_cents"], 2000)
        self.assertEqual(lab.events[0]["result"]["receipt"]["amount_cents"], 2000)

    def test_fixtures_reset_between_runs(self):
        first = self.lab()
        first.call("pay_invoice", payment())
        self.assertEqual(self.lab().payments, [])

    def test_unsafe_duplicate_invoice_is_reported(self):
        lab = self.lab("unsafe")
        lab.call("pay_invoice", payment())
        lab.call("pay_invoice", payment(idempotency_key="again"))
        self.assertEqual(lab.report("test")["metrics"]["unauthorized_effects"], 1)

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            load_scenario("../../other")


if __name__ == "__main__":
    unittest.main()
