"""
Project 2 — Vulnerability Scanner
Crawls the target app and tests for SQLi, XSS, and IDOR.
Dependencies: pip install requests beautifulsoup4
Start the app first: python app.py
Then run:            python scanner.py
"""

import json
import requests

BASE = "http://127.0.0.1:5000"

SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "admin'--"]
XSS_PAYLOADS  = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

findings = []


def log(severity: str, vuln: str, url: str, detail: str = "") -> None:
    findings.append({"severity": severity, "vuln": vuln, "url": url, "detail": detail})
    icon = {"HIGH": "🔴", "MED": "🟡", "INFO": "🔵"}.get(severity, "•")
    print(f"  {icon} [{severity}] {vuln} @ {url}")
    if detail:
        print(f"     └─ {detail}")


def test_sqli() -> None:
    print("\n[*] Testing SQL Injection...")
    for payload in SQLI_PAYLOADS:
        r = requests.post(f"{BASE}/login",
                          data={"username": payload, "password": "x"},
                          allow_redirects=True)
        if "Welcome" in r.text or r.url.endswith("/dashboard"):
            log("HIGH", "SQL Injection", f"{BASE}/login", f"Payload: {payload}")
            return
    print("  ✓ No SQLi found")


def test_xss() -> None:
    print("\n[*] Testing Reflected XSS...")
    for payload in XSS_PAYLOADS:
        r = requests.get(f"{BASE}/search", params={"q": payload})
        if payload in r.text:
            log("HIGH", "Reflected XSS", f"{BASE}/search",
                f"Payload reflected: {payload[:50]}")
            return
    print("  ✓ No XSS found")


def test_idor() -> None:
    print("\n[*] Testing IDOR...")
    for uid in range(1, 5):
        r = requests.get(f"{BASE}/profile/{uid}")
        if r.status_code == 200:
            log("MED", "IDOR", f"{BASE}/profile/{uid}",
                f"Unauthenticated access: {r.text[:80]}")
    if not any(f["vuln"] == "IDOR" for f in findings):
        print("  ✓ No IDOR found")


def report() -> None:
    print(f"\n{'='*50}")
    print(f" Scan complete — {len(findings)} finding(s)")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med  = sum(1 for f in findings if f["severity"] == "MED")
    print(f" HIGH: {high}   MED: {med}")
    print(f"{'='*50}")
    with open("scan_report.json", "w") as fh:
        json.dump(findings, fh, indent=2)
    print(" Full report → scan_report.json\n")


if __name__ == "__main__":
    print(f"[*] Scanning {BASE}")
    test_sqli()
    test_xss()
    test_idor()
    report()
