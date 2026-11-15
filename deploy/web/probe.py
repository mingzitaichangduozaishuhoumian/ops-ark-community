#!/usr/bin/python3 -I
"""Bounded administrator Web probes against the fixed owned loopback lab only."""

import argparse
import http.client
import json
import os
import time

HOST = "127.0.0.1"
PORT = 18880
DOMAIN = "opsark-lab.invalid"
CASES = {
    "normal": [
        ("GET", "/", "Mozilla/5.0", {}),
        ("GET", "/healthz", "Mozilla/5.0", {}),
        ("GET", "/robots.txt", "Googlebot", {}),
        ("GET", "/sitemap.xml", "bingbot", {}),
        ("GET", "/static/app.css", "Mozilla/5.0", {}),
        ("POST", "/callback", "callback-client", {}),
        ("POST", "/callback", "callback-client", {}),
    ],
    "spoofed_forwarding": [
        (
            "GET",
            "/healthz",
            "Mozilla/5.0",
            {"X-Forwarded-For": "198.51.100.44", "CF-Connecting-IP": "203.0.113.44"},
        )
        for _ in range(5)
    ],
    "scan": [
        ("GET", path, "OpsArk-Controlled-Probe/1", {})
        for path in (
            "/.env",
            "/.git/config",
            "/wp-login.php",
            "/phpmyadmin/",
            "/.env.local",
            "/.git/HEAD",
        )
    ],
    "crawler_scan": [
        ("GET", path, "Googlebot", {})
        for path in (
            "/.env",
            "/.git/config",
            "/wp-login.php",
            "/phpmyadmin/",
            "/.env.local",
            "/.git/HEAD",
        )
    ],
    "errors": [("GET", "/lab-error", "OpsArk-Controlled-Probe/1", {}) for _ in range(12)],
}


def run(case):
    if case not in CASES or not 1 <= len(CASES[case]) <= 30:
        raise ValueError("Only fixed, bounded lab probes are permitted")
    observed = []
    for method, path, agent, extra in CASES[case]:
        connection = http.client.HTTPConnection(HOST, PORT, timeout=2)
        try:
            headers = {"Host": DOMAIN, "User-Agent": agent, "Accept-Encoding": "identity", **extra}
            connection.request(
                method, path, body=b"" if method == "POST" else None, headers=headers
            )
            response = connection.getresponse()
            body = response.read(8193)
            observed.append(
                {
                    "method": method,
                    "path_category": case,
                    "status": response.status,
                    "bounded_body": len(body) <= 8192,
                }
            )
        finally:
            connection.close()
        time.sleep(0.2)
    return {
        "case": case,
        "requests": len(observed),
        "target": "127.0.0.1:18880",
        "origin": "controlled_web_probe",
        "observed": observed,
        "public_or_third_party_requests": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=tuple(CASES))
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("Administrator-only test fixture")
    print(json.dumps(run(args.case)))


if __name__ == "__main__":
    main()
