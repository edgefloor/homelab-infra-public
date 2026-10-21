#!/usr/bin/env python3
"""Check private API access and the public Rickroll 404 fallback."""

import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys

import yaml


def fetch(hostname, path, *, public_address=None, tls=True):
    if tls:
        connection = http.client.HTTPSConnection(
            hostname, timeout=15, context=ssl.create_default_context()
        )
    else:
        connection = http.client.HTTPConnection(hostname, timeout=15)
    if public_address:
        # Override only the destination IP. Preserve the HTTP Host, TLS SNI,
        # and normal system certificate validation for the real hostname.
        connection._create_connection = lambda address, *args, **kwargs: socket.create_connection(
            (public_address, address[1]), *args, **kwargs
        )
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        return response.status, response.getheader("Content-Type", ""), response.read(2 * 1024 * 1024), response.getheader("Location", "")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dns-server", action="append", help="resolver to check; default 1.1.1.1 and 1.0.0.1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    routing = yaml.safe_load((root / "inventory/routes.yml").read_text())["homelab_routing"]
    hostname = "alagut-api." + routing["base_domain"]
    assert hostname in routing["client_private_hostnames"]
    failures = []

    def check(label, action):
        try:
            action()
            print("PASS", label)
        except Exception as error:
            failures.append(label)
            print("FAIL", label, str(error))

    for server in args.dns_server or ["1.1.1.1", "1.0.0.1"]:
        for record_type in ["A", "AAAA", "CNAME"]:
            def dns_check(server=server, record_type=record_type):
                result = subprocess.run(
                    ["dig", "@" + server, hostname, record_type, "+noall", "+comments", "+answer", "+time=3", "+tries=1"],
                    capture_output=True, text=True, check=True, timeout=10,
                ).stdout
                assert "status: NOERROR" in result, "DNS query failed or name missing"
                answers = [line for line in result.splitlines() if line and not line.startswith(";")]
                if record_type == "A":
                    assert len(answers) == 1 and answers[0].split()[-1] == routing["pangolin_vps_address"], "public wildcard address missing"
                else:
                    assert not answers, "unexpected public DNS answer " + "; ".join(answers)
            check(f"public DNS {server} {record_type} uses the wildcard fallback", dns_check)

    for tls in [False, True]:
        for path in ["/", "/v1", "/v1/docs/", "/_next/static/chunks/40-hj65qwx9-p.css", "/favicon.ico"]:
            def public_check(tls=tls, path=path):
                status, content_type, body, location = fetch(
                    hostname, path, public_address=routing["pangolin_vps_address"], tls=tls,
                )
                if tls:
                    expected = (root / "rickroll/index.html").read_bytes()
                    assert status == 404 and content_type.startswith("text/html") and body == expected, (
                        f"expected the supplied Rickroll HTML with HTTP 404, got HTTP {status}, {content_type}, {len(body)} bytes"
                    )
                else:
                    assert status in {301, 302, 307, 308} and location == "https://" + hostname + path, (
                        f"expected HTTPS redirect, got HTTP {status}, {location}"
                    )
            check(f"public HTTPS {path} serves Rickroll 404" if tls else f"public HTTP {path} redirects to HTTPS", public_check)

    def health_check():
        status, _, body, _ = fetch(hostname, "/v1")
        assert status == 200 and json.loads(body) == {"message": "Healthy"}, f"API health failed: HTTP {status}"
    check("connected Mac reaches private API over verified HTTPS", health_check)

    def api_auth_check():
        status, _, body, _ = fetch(hostname, "/v1/org/homelab/sites")
        assert status == 401 and json.loads(body)["message"] == "API key required", f"API authentication failed: HTTP {status}"
    check("private API requires a key for protected endpoints", api_auth_check)

    def docs_check():
        status, _, body, _ = fetch(hostname, "/v1/docs/")
        assert status == 200 and b"Swagger UI" in body, f"private documentation failed: HTTP {status}"
    check("connected Mac reaches private API documentation", docs_check)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
