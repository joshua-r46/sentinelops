import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location("verifier", pathlib.Path("agentshield/verifier.py"))
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def sample(error=0.0, latency=20.0, healthy=True, collateral=True):
    return {
        "http_status": 200 if healthy else 503,
        "health": {"status": "healthy" if healthy else "unhealthy",
                   "dependencies": {"postgres": "connected", "redis": "connected"}},
        "metrics": {"error_rate": error, "average_latency_ms": latency, "requests_total": 100},
        "collateral": {"worker": {"http_status": 200 if collateral else 503,
                                    "health": {"status": "healthy" if collateral else "unhealthy"}}},
    }


class IndependentVerificationTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"error_rate": 0.01, "average_latency_ms": 25.0}

    def test_success_requires_all_consecutive_probes(self):
        outcome, reasons = verifier.evaluate([sample(), sample(), sample()], self.baseline)
        self.assertEqual(("PASSED", []), (outcome, reasons))

    def test_intermittent_failure_fails_consecutive_health_requirement(self):
        outcome, reasons = verifier.evaluate([sample(), sample(healthy=False), sample()], self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("target_health_probe_failed", reasons)

    def test_persistent_failure_fails_verification(self):
        outcome, reasons = verifier.evaluate([sample(healthy=False)] * 3, self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("target_health_probe_failed", reasons)

    def test_degraded_latency_is_compared_to_recorded_baseline(self):
        outcome, reasons = verifier.evaluate([sample(latency=500)] * 3, self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("latency_degraded_vs_baseline", reasons)

    def test_collateral_service_failure_fails_verification(self):
        outcome, reasons = verifier.evaluate([sample(collateral=False)] * 3, self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("collateral_health_failed:worker", reasons)

    def test_dependent_database_failure_fails_verification(self):
        failed = sample()
        failed["health"]["dependencies"]["postgres"] = "unavailable"
        outcome, reasons = verifier.evaluate([failed] * 3, self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("collateral_health_failed:postgres", reasons)

    def test_missing_baseline_never_claims_recovery(self):
        outcome, reasons = verifier.evaluate([sample()] * 3, None)
        self.assertEqual(("FAILED", ["missing_baseline"]), (outcome, reasons))

    def test_missing_metrics_fail_closed(self):
        invalid = sample()
        invalid["metrics"] = {}
        outcome, reasons = verifier.evaluate([invalid] * 3, self.baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("target_metrics_missing", reasons)

    def test_metric_counter_reset_fails_closed(self):
        baseline = {**self.baseline, "requests_total": 100}
        outcome, reasons = verifier.evaluate([sample()] * 3, baseline)
        self.assertEqual("PASSED", outcome)
        reset_sample = sample()
        reset_sample["metrics"]["requests_total"] = 0
        outcome, reasons = verifier.evaluate([sample(), reset_sample, sample()], baseline)
        self.assertEqual("FAILED", outcome)
        self.assertIn("metrics_counter_reset_or_stale", reasons)


if __name__ == "__main__":
    unittest.main()
