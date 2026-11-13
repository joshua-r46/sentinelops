import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location("gate", pathlib.Path("/app/main.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class SafetyGateTests(unittest.TestCase):
    def policy(self, name, target="api", parameters=None):
        return gate.validate_action(gate.ActionProposal(action_type=name, target=target, parameters=parameters or {}))

    def test_r0_read_is_auto_allowed(self):
        decision, risk, *_ = self.policy("read_logs")
        self.assertEqual(("ALLOW", "R0"), (decision, risk))

    def test_r1_rollback_is_typed_and_reversible(self):
        decision, risk, _, _, snapshot, reversible = self.policy("rollback_deployment", "api", {"version": "1.0.0"})
        self.assertEqual(("ALLOW", "R1", True, "reversible"), (decision, risk, snapshot, reversible))

    def test_postgres_restart_is_r2(self):
        decision, risk, *_ = self.policy("restart_service", "postgres")
        self.assertEqual(("REQUIRE_APPROVAL", "R2"), (decision, risk))

    def test_api_restart_requires_human_approval_before_executor_dispatch(self):
        decision, risk, _, _, snapshot, reversible = self.policy("restart_service", "api")
        self.assertEqual(("REQUIRE_APPROVAL", "R2", True, "reversible"),
                         (decision, risk, snapshot, reversible))

    def test_budgeted_resource_change_is_r2(self):
        decision, risk, *_ = self.policy("set_resource_limit", "worker", {"cpu": 1, "memory": 512})
        self.assertEqual(("REQUIRE_APPROVAL", "R2"), (decision, risk))

    def test_unknown_and_irreversible_actions_are_r3_blocked(self):
        for name in ("delete", "exec", "remove_volume", "drop_database", "scale_to_zero", "invent_action"):
            with self.subTest(name=name):
                self.assertEqual(("BLOCK", "R3"), self.policy(name)[:2])

    def test_schema_and_privilege_fail_closed(self):
        self.assertEqual(("BLOCK", "R3"), self.policy("restart_service", "api", {"command": "x"})[:2])
        self.assertEqual(("BLOCK", "R3"), self.policy("read_logs", "outside_scope")[:2])
        self.assertEqual(("BLOCK", "R3"), self.policy("set_resource_limit", "api", {"cpu": 99, "memory": 1})[:2])


if __name__ == "__main__":
    unittest.main()
