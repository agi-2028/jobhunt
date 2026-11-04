import importlib.util
import os
import sys
import unittest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "workspace", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from queue_utils import is_safe_url  # noqa: E402

# Import preflight-check.py using importlib due to hyphen in module name
spec = importlib.util.spec_from_file_location("preflight_check", os.path.join(SCRIPTS_DIR, "preflight-check.py"))
preflight_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight_check)


class TestPreflightSecurity(unittest.TestCase):
    def test_is_safe_url_blocks_loopback(self):
        safe, reason = is_safe_url("http://127.0.0.1:8765")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

        safe, reason = is_safe_url("http://localhost:8765")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

    def test_is_safe_url_blocks_link_local_metadata(self):
        safe, reason = is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(safe)
        self.assertIn("link-local", reason.lower())

    def test_is_safe_url_blocks_private_networks(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            safe, reason = is_safe_url(f"http://{ip}/job")
            self.assertFalse(safe)
            self.assertIn("private", reason.lower())

    def test_is_safe_url_blocks_unsupported_schemes(self):
        safe, reason = is_safe_url("file:///etc/passwd")
        self.assertFalse(safe)
        self.assertIn("unsupported scheme", reason.lower())

        safe, reason = is_safe_url("gopher://127.0.0.1:70")
        self.assertFalse(safe)
        self.assertIn("unsupported scheme", reason.lower())

    def test_preflight_check_blocks_dangerous_urls(self):
        status, reason = preflight_check.check_url("http://127.0.0.1:8765")
        self.assertEqual(status, "DEAD")
        self.assertIn("Invalid URL", reason)

        status, reason = preflight_check.check_url("file:///etc/passwd")
        self.assertEqual(status, "DEAD")
        self.assertIn("Invalid URL", reason)

    def test_ssl_context_verification_enabled(self):
        self.assertTrue(preflight_check.CTX.check_hostname)
        self.assertNotEqual(preflight_check.CTX.verify_mode, preflight_check.ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()
