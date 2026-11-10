import importlib.util
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "workspace", "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from queue_utils import is_safe_url  # noqa: E402

# Load preflight-check.py module dynamically
preflight_path = os.path.join(SCRIPTS_DIR, "preflight-check.py")
spec = importlib.util.spec_from_file_location("preflight_check", preflight_path)
preflight_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight_check)


class TestPreflightSecurity(unittest.TestCase):
    def test_blocks_file_scheme(self):
        safe, reason = is_safe_url("file:///etc/passwd")
        self.assertFalse(safe)
        self.assertIn("Unsupported scheme", reason)

        status, reason = preflight_check.check_url("file:///etc/passwd")
        self.assertEqual(status, "DEAD")
        self.assertIn("Invalid URL", reason)

    def test_blocks_loopback(self):
        for url in ["http://127.0.0.1:8765", "http://localhost:8765"]:
            safe, reason = is_safe_url(url)
            self.assertFalse(safe, f"Failed for {url}")
            self.assertIn("loopback", reason.lower())

            status, reason = preflight_check.check_url(url)
            self.assertEqual(status, "DEAD")
            self.assertIn("loopback", reason.lower())

    def test_blocks_private_ips(self):
        private_urls = [
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.1.1",
        ]
        for url in private_urls:
            safe, reason = is_safe_url(url)
            self.assertFalse(safe, f"Failed for {url}")
            self.assertIn("private", reason.lower())

            status, reason = preflight_check.check_url(url)
            self.assertEqual(status, "DEAD")
            self.assertIn("private", reason.lower())

    def test_blocks_link_local_metadata(self):
        meta_url = "http://169.254.169.254/latest/meta-data/"
        safe, reason = is_safe_url(meta_url)
        self.assertFalse(safe)
        self.assertIn("link-local", reason.lower())

        status, reason = preflight_check.check_url(meta_url)
        self.assertEqual(status, "DEAD")
        self.assertIn("link-local", reason.lower())

    def test_allows_public_https_url(self):
        safe, reason = is_safe_url("https://www.google.com")
        self.assertTrue(safe)
        self.assertEqual(reason, "Safe")


if __name__ == "__main__":
    unittest.main()
