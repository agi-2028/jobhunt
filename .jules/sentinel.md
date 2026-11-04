# Sentinel Journal

## 2026-03-10 - SSRF and Insecure SSL Certificate Verification in Preflight URL Checkers
**Vulnerability:** Job URL checkers (e.g., `preflight-check.py`) accepted arbitrary user URLs without verifying scheme or network destination, while simultaneously disabling SSL verification (`ssl.CERT_NONE` and `check_hostname = False`). This allowed arbitrary internal network probing (SSRF against cloud metadata 169.254.169.254, localhost, private RFC 1918 subnets) as well as MITM risks.
**Learning:** URL preflight checks designed to verify job openings often fetch remote HTML or query ATS endpoints. Without strict hostname resolution to IP check and scheme restrictions (http/https only), untrusted user input directly controls server-side requests.
**Prevention:** Validate outbound URLs using a centralized `is_safe_url` helper before fetching: resolve hostnames, block loopback, link-local, private, and reserved IPs, and enforce standard TLS certificate verification via `ssl.create_default_context()`.
