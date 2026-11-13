from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = [ROOT / "tests" / name for name in (
    "run_phase4_integration.sh", "run_phase5_integration.sh",
    "run_phase6_snapshot_integration.sh", "run_phase6_recovery_integration.sh",
    "run_phase6_3_disposable.sh")]


class DockerIsolationStaticTests(unittest.TestCase):
    def test_all_harnesses_source_shared_fail_closed_helper(self):
        for path in SCRIPTS:
            with self.subTest(path=path.name):
                source = path.read_text()
                self.assertRegex(source, r"source .*tests/lib/isolated_docker\.sh")
                self.assertIn("isolated_docker_init", source)

    def test_no_host_socket_mount_or_default_context(self):
        for path in SCRIPTS:
            with self.subTest(path=path.name):
                source = path.read_text()
                self.assertNotIn("/var/run/docker.sock", source)
                self.assertNotRegex(source, r"docker\s+--context\s+default")
        for compose_name in ("docker-compose.yml", "docker-compose.phase6.3.yml"):
            with self.subTest(compose=compose_name):
                self.assertNotIn("/var/run/docker.sock", (ROOT / compose_name).read_text())

    def test_helper_requires_explicit_remote_endpoint_and_fails_closed(self):
        source = (ROOT / "tests/lib/isolated_docker.sh").read_text()
        self.assertIn("ISOLATED_DOCKER_HOST:?", source)
        self.assertIn("refusing fallback", source)
        self.assertIn("command docker --host", source)

    def test_cleanup_uses_exact_run_label(self):
        source = (ROOT / "tests/lib/isolated_docker.sh").read_text()
        self.assertIn('label=${AGENTSHIELD_LABEL_KEY}=${AGENTSHIELD_LABEL_VALUE}', source)
        self.assertNotIn("docker system prune", source)


if __name__ == "__main__":
    unittest.main()
