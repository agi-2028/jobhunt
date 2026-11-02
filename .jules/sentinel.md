# Sentinel Security Journal

## 2026-03-10 - SSRF and Insecure SSL Certificate Verification in Preflight Checker
**Vulnerability:** `workspace/scripts/preflight-check.py` disabled SSL certificate verification (`check_hostname = False`, `verify_mode = ssl.CERT_NONE`), exposing outgoing requests to MITM attacks. Furthermore, it did not restrict URL schemes (allowing `file://` reading local files) and permitted requests to loopback (`127.0.0.1`, `localhost`), link-local (e.g. AWS metadata `169.254.169.254`), and internal private network IPs, causing SSRF risks.
**Learning:** Utilities performing automated URL preflight checks in the pipeline must enforce scheme restrictions (http/https only) and resolve hostnames through `socket.getaddrinfo` to validate IP addresses before issuing HTTP/network requests, while preserving standard TLS certificate verification.
**Prevention:** Consolidated `is_safe_url` in `workspace/scripts/queue_utils.py` and enforce scheme plus resolved IP boundary checks (blocking loopback, private, link-local, and multicast addresses) before any network calls, avoiding unverified SSL contexts.
