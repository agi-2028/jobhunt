import importlib.util
import os
import ssl
import sys
import unittest

# Ensure workspace scripts directory is on sys.path
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "workspace", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from queue_utils import is_safe_url  # noqa: E402


class PreflightSecurityTest(unittest.TestCase):
    def setUp(self):
        script_path = os.path.join(SCRIPTS_DIR, "preflight-check.py")
        spec = importlib.util.spec_from_file_location("preflight_check", script_path)
        self.preflight = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.preflight)

    def test_ssl_verification_enforced(self):
        """Verify SSL context enforces hostname checking and certificate validation."""
        ctx = self.preflight.CTX
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_safe_urls(self):
        """Legitimate external URLs should be recognized as safe."""
        safe, reason = is_safe_url("https://boards.greenhouse.io/stripe/jobs/123")
        self.assertTrue(safe)
        self.assertEqual(reason, "Safe")

    def test_block_unsupported_schemes(self):
        """Unsupported URL schemes such as file:// and gopher:// must be blocked."""
        for url in ["file:///etc/passwd", "gopher://127.0.0.1/", "ftp://example.com"]:
            safe, reason = is_safe_url(url)
            self.assertFalse(safe)
            self.assertIn("Unsupported scheme", reason)

            status, output_reason = self.preflight.check_url(url)
            self.assertEqual(status, "DEAD")
            self.assertIn("Invalid URL", output_reason)

    def test_block_loopback_and_internal_ssrf(self):
        """Loopback, private network, and cloud metadata addresses must be blocked."""
        unsafe_urls = [
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://10.0.0.1/admin",
            "http://172.16.0.1/status",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
        ]
        for url in unsafe_urls:
            safe, reason = is_safe_url(url)
            self.assertFalse(safe, f"Expected {url} to be blocked")
            status, output_reason = self.preflight.check_url(url)
            self.assertEqual(status, "DEAD")
            self.assertIn("Invalid URL", output_reason)


if __name__ == "__main__":
    unittest.main()
