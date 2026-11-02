import unittest
import importlib.util
from pathlib import Path
from workspace.scripts.queue_utils import is_safe_url

# Load preflight-check module dynamically due to hyphen in name
PREFLIGHT_PATH = Path(__file__).resolve().parent.parent / "workspace" / "scripts" / "preflight-check.py"
spec = importlib.util.spec_from_file_location("preflight_check", PREFLIGHT_PATH)
preflight_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight_check)


class TestPreflightSecurity(unittest.TestCase):
    def test_is_safe_url_blocks_file_scheme(self):
        safe, reason = is_safe_url("file:///etc/passwd")
        self.assertFalse(safe)
        self.assertIn("Unsupported URL scheme", reason)

    def test_is_safe_url_blocks_loopback_localhost(self):
        safe, reason = is_safe_url("http://localhost:8765")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

    def test_is_safe_url_blocks_loopback_ip(self):
        safe, reason = is_safe_url("http://127.0.0.1:8765")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

    def test_is_safe_url_blocks_aws_metadata(self):
        safe, reason = is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(safe)
        self.assertIn("link-local", reason.lower())

    def test_is_safe_url_blocks_private_ips(self):
        safe_10, _ = is_safe_url("http://10.0.0.1/internal")
        self.assertFalse(safe_10)

        safe_192, _ = is_safe_url("http://192.168.1.100/admin")
        self.assertFalse(safe_192)

        safe_172, _ = is_safe_url("http://172.16.0.5/api")
        self.assertFalse(safe_172)

    def test_preflight_check_url_returns_dead_on_unsafe_urls(self):
        status, reason = preflight_check.check_url("file:///etc/passwd")
        self.assertEqual(status, "DEAD")
        self.assertIn("Invalid URL", reason)

        status, reason = preflight_check.check_url("http://127.0.0.1:8765")
        self.assertEqual(status, "DEAD")
        self.assertIn("Invalid URL", reason)


if __name__ == "__main__":
    unittest.main()
