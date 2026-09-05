from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible/roles/homelab_agent_target/files"))
import homelab_evidence_sources as sources


class EvidenceSourceTests(unittest.TestCase):
    def test_private_and_rebinding_addresses_are_rejected_before_connect(self):
        for ips in (
            ["127.0.0.1"],
            ["169.254.169.254"],
            ["8.8.8.8", "10.0.0.1"],
            ["::1"],
        ):
            addresses = [(2, 1, 6, "", (ip, 443)) for ip in ips]
            with (
                self.subTest(ips=ips),
                mock.patch.object(
                    sources.socket, "getaddrinfo", return_value=addresses
                ),
                mock.patch.object(sources.socket, "create_connection") as connect,
            ):
                with self.assertRaises(ValueError):
                    sources.public_get("https://vendor.example/advisory")
                connect.assert_not_called()

    def test_source_scheme_port_and_credentials_are_rejected(self):
        for url in (
            "file:///etc/passwd",
            "http://vendor.example/a",
            "https://vendor.example:8080/a",
            "https://user:pass@vendor.example/a",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                sources.public_get(url)

    def test_reference_only_comes_from_scoped_advisory(self):
        lookup = mock.Mock(
            return_value={"references": [{"url": "https://vendor.example/fix"}]}
        )
        with mock.patch.object(
            sources,
            "public_get",
            return_value=(b"<p>Fix details.</p>", {"Content-Type": "text/html"}),
        ) as get:
            result = sources.advisory_reference(
                {}, {"advisory": "CVE-2099-1000", "reference_index": 0}, lookup
            )
            self.assertEqual(result["content"], "Fix details.")
            get.assert_called_once_with("https://vendor.example/fix")
            with self.assertRaises(ValueError):
                sources.advisory_reference(
                    {}, {"advisory": "CVE-2099-1000", "reference_index": 1}, lookup
                )

    def test_registry_repositories_are_explicit(self):
        self.assertEqual(
            sources.registry_location("docker.io/library/alpine:3.20"),
            ("registry-1.docker.io", "library/alpine"),
        )
        self.assertEqual(
            sources.registry_location("ghcr.io/example/app:1"),
            ("ghcr.io", "example/app"),
        )
        with self.assertRaises(ValueError):
            sources.registry_location("private.example/app:1")

    def manifest_responses(self, wrong_platform=False):
        return [
            (
                {
                    "manifests": [
                        {
                            "digest": "sha256:" + "a" * 64,
                            "platform": {"os": "linux", "architecture": "amd64"},
                        }
                    ]
                },
                "sha256:" + "0" * 64,
            ),
            (
                {"layers": [{"size": 100}], "config": {"digest": "sha256:" + "b" * 64}},
                "sha256:" + "a" * 64,
            ),
            (
                {"os": "linux", "architecture": "arm64" if wrong_platform else "amd64"},
                "sha256:" + "b" * 64,
            ),
        ]

    def test_candidate_is_platform_bound_and_immutable(self):
        for repository in ("example/app:1", "ghcr.io/example/app:1"):
            with mock.patch.object(
                sources, "registry_json", side_effect=self.manifest_responses()
            ):
                result = sources.candidate_manifest(repository, "2", "linux/amd64")
            self.assertTrue(result["image"].endswith("@sha256:" + "a" * 64))
            self.assertEqual(result["platform"], "linux/amd64")

    def test_candidate_platform_and_digest_mismatch_rejected(self):
        with mock.patch.object(
            sources, "registry_json", side_effect=self.manifest_responses(True)
        ):
            with self.assertRaisesRegex(ValueError, "platform"):
                sources.candidate_manifest("example/app", "2", "linux/amd64")
        replies = self.manifest_responses()
        replies[1] = (replies[1][0], "sha256:" + "c" * 64)
        with mock.patch.object(sources, "registry_json", side_effect=replies):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                sources.candidate_manifest("example/app", "2", "linux/amd64")

    def test_large_candidate_is_rejected_before_scan(self):
        manifest = {
            "layers": [{"size": sources.MAX_IMAGE_BYTES + 1}],
            "config": {"digest": "sha256:" + "b" * 64},
        }
        with mock.patch.object(
            sources, "registry_json", return_value=(manifest, "sha256:" + "a" * 64)
        ):
            with self.assertRaisesRegex(ValueError, "download limit"):
                sources.candidate_manifest("example/app", "2", "linux/amd64")

    def test_candidate_verification_requires_package_coverage_and_no_advisory(self):
        for scenario, verified in [
            ("fixed", True),
            ("affected", False),
            ("missing", False),
            ("eol", None),
            ("failed", None),
        ]:
            report = {
                "Metadata": {"OS": {"EOSL": scenario == "eol"}},
                "Results": [
                    {
                        "Target": "/app",
                        "Packages": []
                        if scenario == "missing"
                        else [{"Name": "example/module", "Version": "2.1"}],
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-1000"}]
                        if scenario == "affected"
                        else [],
                    }
                ],
            }
            scan = mock.Mock(
                return_value={
                    "returncode": 1 if scenario == "failed" else 0,
                    "overflow": False,
                    "timed_out": False,
                    "stdout": json.dumps(report),
                }
            )
            run = mock.Mock(
                return_value={
                    "returncode": 0,
                    "stdout": "linux/amd64",
                    "truncated": False,
                }
            )
            candidate = {
                "image": "docker.io/example/app@sha256:" + "a" * 64,
                "platform": "linux/amd64",
            }
            with (
                self.subTest(scenario=scenario),
                mock.patch.object(
                    sources, "candidate_manifest", return_value=candidate
                ),
                mock.patch.object(Path, "is_file", return_value=True),
            ):
                result = sources.verify_candidate(
                    {"advisories": ["CVE-2099-1000"], "packages": ["example/module"]},
                    {
                        "advisory": "CVE-2099-1000",
                        "package": "example/module",
                        "tag": "2",
                    },
                    "example/app",
                    {"image_id": "sha256:old"},
                    run,
                    scan,
                )
            if verified is None:
                self.assertEqual(result["status"], "unavailable")
            else:
                self.assertEqual(result["verified"], verified)
            argv = scan.call_args.args[0]
            self.assertIn("--image-src", argv)
            self.assertIn("remote", argv)
            self.assertEqual(argv[-1], candidate["image"])
            self.assertIn("disk_limit", scan.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
