#!/usr/bin/env python3
"""Regression tests for the public Pangolin edge hardening policy."""

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PANGOLIN_ROLE = REPO_ROOT / "ansible" / "roles" / "pangolin"


class PangolinEdgeHardeningTests(unittest.TestCase):
    def test_icmp_timestamp_requests_are_dropped_before_general_icmp_accept(self):
        policy = (PANGOLIN_ROLE / "templates" / "nftables.conf.j2").read_text()

        timestamp_drop = "icmp type timestamp-request drop"
        general_accept = "ip protocol icmp accept"
        self.assertIn(timestamp_drop, policy)
        self.assertLess(policy.index(timestamp_drop), policy.index(general_accept))

    def test_https_entrypoint_applies_hsts_middleware(self):
        static_config = (
            PANGOLIN_ROLE / "templates" / "traefik_config.yml.j2"
        ).read_text()
        dynamic_config = (
            PANGOLIN_ROLE / "templates" / "dynamic_config.yml.j2"
        ).read_text()

        self.assertIn("security-headers@file", static_config)
        self.assertIn("security-headers:", dynamic_config)
        self.assertIn("stsSeconds: 31536000", dynamic_config)

    def test_tls_policy_rejects_unknown_sni_and_uses_aead_for_tls_1_2(self):
        dynamic_config = (
            PANGOLIN_ROLE / "templates" / "dynamic_config.yml.j2"
        ).read_text()

        self.assertIn("sniStrict: true", dynamic_config)
        self.assertIn("minVersion: VersionTLS12", dynamic_config)
        self.assertIn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", dynamic_config)
        self.assertIn("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", dynamic_config)
        self.assertIn("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", dynamic_config)
        self.assertNotIn("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", dynamic_config)
        self.assertNotIn("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", dynamic_config)

    def test_wildcard_certificate_uses_dns_challenge_and_a_file_secret(self):
        static_config = (
            PANGOLIN_ROLE / "templates" / "traefik_config.yml.j2"
        ).read_text()
        dynamic_config = (
            PANGOLIN_ROLE / "templates" / "dynamic_config.yml.j2"
        ).read_text()
        compose = (
            PANGOLIN_ROLE / "templates" / "docker-compose.yml.j2"
        ).read_text()

        self.assertIn("letsencrypt-wildcard:", static_config)
        self.assertIn("dnsChallenge:", static_config)
        self.assertIn("provider: cloudflare", static_config)
        self.assertIn("defaultGeneratedCert:", dynamic_config)
        self.assertIn("- '*.{{ pangolin_base_domain }}'", dynamic_config)
        self.assertIn("CF_DNS_API_TOKEN_FILE: /run/secrets/cloudflare_dns_api_token", compose)
        self.assertIn("/run/secrets/cloudflare_dns_api_token:ro", compose)

    def test_unknown_zone_subdomains_redirect_to_https_without_a_backend(self):
        dynamic_config = (
            PANGOLIN_ROLE / "templates" / "dynamic_config.yml.j2"
        ).read_text()

        self.assertIn("wildcard-http-redirect:", dynamic_config)
        self.assertIn("HostRegexp(`^", dynamic_config)
        self.assertIn("$`)", dynamic_config)
        self.assertIn("service: noop@internal", dynamic_config)
        self.assertIn("priority: 1", dynamic_config)
        self.assertIn("middlewares: [redirect-to-https]", dynamic_config)

    def test_unknown_https_subdomains_use_the_isolated_fallback(self):
        compose = (
            PANGOLIN_ROLE / "templates" / "docker-compose.yml.j2"
        ).read_text()
        dynamic_config = (
            PANGOLIN_ROLE / "templates" / "dynamic_config.yml.j2"
        ).read_text()
        firewall = (
            PANGOLIN_ROLE / "templates" / "nftables.conf.j2"
        ).read_text()

        self.assertIn("rickroll-fallback:", compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("cap_drop:", compose)
        self.assertIn("- ALL", compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("internal: true", compose)
        self.assertNotIn("/var/run/docker.sock", compose)
        self.assertIn("wildcard-https-fallback:", dynamic_config)
        self.assertIn("service: rickroll-fallback-service", dynamic_config)
        self.assertIn("priority: 1", dynamic_config)
        self.assertIn("ip saddr {{ pangolin_fallback_address }} drop", firewall)

    def test_ssh_policy_excludes_sha1_hmacs(self):
        ssh_policy = (
            PANGOLIN_ROLE / "templates" / "sshd-hardening.conf.j2"
        ).read_text()

        self.assertIn("hmac-sha2-512-etm@openssh.com", ssh_policy)
        self.assertIn("hmac-sha2-256-etm@openssh.com", ssh_policy)
        self.assertNotIn("hmac-sha1", ssh_policy)


if __name__ == "__main__":
    unittest.main()
