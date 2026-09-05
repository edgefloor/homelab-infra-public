#!/usr/bin/env python3
"""Unit tests for the release and deployed-state CVE monitors."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CVE = load_module(
    "homelab_cve_monitor",
    "ansible/roles/update_monitor/files/homelab_cve_monitor.py",
)
RELEASE = load_module(
    "homelab_release_monitor",
    "ansible/roles/update_monitor/files/homelab_release_monitor.py",
)


class CveMonitorTests(unittest.TestCase):
    def test_rebuilt_artifact_is_reassessed_even_when_versions_do_not_change(self):
        finding = {"id": "CVE-2026-1", "package": "stdlib", "installed": "1", "fixed": "2", "severity": "HIGH", "target": "/usr/bin/caddy", "artifact_id": "sha256:old"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            CVE.save_state(root / "state.json", {CVE.finding_key(finding): finding})
            current = {**finding, "artifact_id": "sha256:new"}
            with mock.patch.object(CVE.sys, "argv", ["monitor", "--state", str(root / "state.json"), "--cache", str(root)]), \
                    mock.patch.dict(CVE.os.environ, {"UPDATE_MONITOR_WEBHOOK_URL": "https://example.invalid"}), \
                    mock.patch.object(CVE, "scan_reports", return_value=[]), \
                    mock.patch.object(CVE, "extract_findings", return_value={CVE.finding_key(current): current}), \
                    mock.patch.object(CVE, "read_credential", return_value="test-secret"), \
                    mock.patch.object(CVE, "send_notification") as send:
                CVE.main()
            self.assertEqual(send.call_count, 1)

    def test_failed_docker_inventory_never_means_no_containers(self):
        with mock.patch.object(CVE.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(CVE.subprocess, "run", return_value=mock.Mock(returncode=1, stdout="")):
            with self.assertRaisesRegex(RuntimeError, "coverage is unknown"):
                CVE.docker_runtime_images()

    def test_large_finding_delivery_preserves_every_occurrence(self):
        findings = [{"id": f"CVE-2026-{i // 85}", "package": f"module{i % 25}",
                     "fixed": "", "severity": "HIGH", "target": f"/bin/tool{i}", "installed": "1"}
                    for i in range(200)]
        batches = CVE.finding_batches(findings)
        self.assertEqual([item for batch in batches for item in batch], findings)
        for batch in batches:
            context = CVE.build_finding_context(batch)
            self.assertFalse(context["truncated"])
            self.assertLessEqual(len(batch), 40)
            self.assertEqual(len({f["id"] for f in batch}), 1)

    def test_snapshot_does_not_notify_and_initial_regular_scan_does(self):
        report = {"Results": [{"Target": "debian", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-1", "PkgName": "lib", "InstalledVersion": "1", "Severity": "HIGH"}
        ]}]}
        for snapshot in (True, False):
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                argv = ["monitor", "--state", str(root / "state.json"), "--cache", str(root)]
                if snapshot:
                    argv.append("--snapshot-only")
                with mock.patch.object(CVE.sys, "argv", argv), \
                        mock.patch.dict(CVE.os.environ, {"UPDATE_MONITOR_WEBHOOK_URL": "https://example.invalid"}), \
                        mock.patch.object(CVE, "scan_reports", return_value=[report]), \
                        mock.patch.object(CVE, "read_credential", return_value="test-secret") as credential, \
                        mock.patch.object(CVE, "send_notification") as send:
                    self.assertEqual(CVE.main(), 0)
                self.assertEqual(send.call_count, 0 if snapshot else 1)
                self.assertEqual(credential.call_count, 0 if snapshot else 1)
                self.assertEqual(json.loads((root / "state.status.json").read_text())["status"], "complete")

    def test_scan_failure_alert_is_deduplicated_and_keeps_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state.json"
            CVE.save_state(state, {"retained": {"id": "CVE-2026-1"}})
            before = state.read_bytes()
            with mock.patch.object(CVE.sys, "argv", ["monitor", "--state", str(state), "--cache", str(root)]), \
                    mock.patch.dict(CVE.os.environ, {"UPDATE_MONITOR_WEBHOOK_URL": "https://example.invalid"}), \
                    mock.patch.object(CVE, "scan_reports", side_effect=RuntimeError("failed")), \
                    mock.patch.object(CVE, "read_credential", return_value="test-secret"), \
                    mock.patch.object(CVE, "send_notification") as send:
                for _ in range(2):
                    with self.assertRaises(RuntimeError):
                        CVE.main()
            self.assertEqual(send.call_count, 1)
            self.assertEqual(send.call_args.kwargs["kind"], "system")
            self.assertEqual(state.read_bytes(), before)

    def test_native_go_scan_preserves_absolute_path_digest_and_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "caddy"
            binary.write_bytes(b"test executable")
            report = {"Results": [{"Target": "caddy", "Type": "gobinary", "Class": "lang-pkgs",
                "Packages": [{"Name": "stdlib", "Version": "v1.26.4"}],
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-46600", "PkgName": "stdlib",
                    "InstalledVersion": "v1.26.4", "FixedVersion": "1.26.6", "Severity": "HIGH"}]}]}
            with mock.patch.object(CVE, "run_json", return_value=report) as run:
                scanned = CVE.scan_go_binary("trivy", root, root, binary)
            command = run.call_args.args[0]
            self.assertEqual(command[1], "rootfs")
            self.assertEqual(command[-1], str(binary.resolve()))
            self.assertIn("--list-all-pkgs", command)
            finding = next(iter(CVE.extract_findings([scanned]).values()))
            occurrence = CVE.build_finding_context([finding])["groups"][0]["occurrences"][0]
            self.assertEqual(occurrence["reported_file"], str(binary.resolve()))
            self.assertEqual(occurrence["containers"], [])
            self.assertTrue(occurrence["artifact_id"].startswith("sha256:"))
            state = root / "state.json"
            CVE.save_state(state, {}, [scanned["_homelab_host_binary"]])
            self.assertEqual(CVE.load_state(state)["native_go_coverage"][0]["go_versions"], ["v1.26.4"])

    def test_native_go_scan_rejects_empty_analyzer_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "caddy"
            binary.write_bytes(b"test executable")
            with mock.patch.object(CVE, "run_json", return_value={"Results": []}):
                with self.assertRaisesRegex(RuntimeError, "coverage is unknown"):
                    CVE.scan_go_binary("trivy", binary.parent, binary.parent, binary)

    def test_native_go_scan_rejects_binary_replaced_during_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "caddy"
            binary.write_bytes(b"old")
            def replace(*args):
                binary.write_bytes(b"new")
                return {"Results": []}
            with mock.patch.object(CVE, "run_json", side_effect=replace):
                with self.assertRaisesRegex(RuntimeError, "changed during"):
                    CVE.scan_go_binary("trivy", binary.parent, binary.parent, binary)

    def test_native_go_scan_failure_preserves_previous_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state.json"
            state.write_text('{"schema":1,"findings":{}}')
            previous = state.read_bytes()
            with mock.patch.object(CVE.sys, "argv", ["monitor", "--state", str(state), "--cache", str(root), "--snapshot-only"]), \
                    mock.patch.dict(CVE.os.environ, {"UPDATE_MONITOR_WEBHOOK_URL": "https://example.invalid"}), \
                    mock.patch.object(CVE, "scan_reports", side_effect=RuntimeError("coverage unknown")):
                with self.assertRaisesRegex(RuntimeError, "coverage unknown"):
                    CVE.main()
            self.assertEqual(state.read_bytes(), previous)

    def test_runtime_inventory_preserves_full_identity_for_evidence_binding(self):
        container_id = "a" * 64
        inspected = "\t".join(json.dumps(value) for value in (
            container_id, "/app", "sha256:" + "b" * 64, "example/app:1"
        )) + "\n"
        with mock.patch.object(CVE.shutil, "which", return_value="/usr/bin/docker"), mock.patch.object(
            CVE.subprocess, "run", side_effect=[
                mock.Mock(returncode=0, stdout=container_id[:12] + "\n"),
                mock.Mock(returncode=0, stdout=inspected),
            ]
        ):
            images = CVE.docker_runtime_images()
        self.assertEqual(images[0]["containers"][0]["id"], container_id)

    def test_docker_runtime_inventory_requests_only_non_secret_fields(self):
        responses = [
            mock.Mock(returncode=0, stdout="container-a\ncontainer-b\n", stderr=""),
            mock.Mock(
                returncode=0,
                stdout=(
                    '"container-a"\t"/crowdsec"\t"sha256:same"\t'
                    '"crowdsecurity/crowdsec:v1"\n'
                    '"container-b"\t"/worker"\t"sha256:same"\t'
                    '"crowdsecurity/crowdsec:v1"\n'
                ),
                stderr="",
            ),
        ]
        with mock.patch.object(CVE.shutil, "which", return_value="/usr/bin/docker"), mock.patch.object(
            CVE.subprocess, "run", side_effect=responses
        ) as run:
            images = CVE.docker_runtime_images()

        inspect_argv = run.call_args_list[1].args[0]
        self.assertIn("--format", inspect_argv)
        self.assertNotIn(".Config.Env", " ".join(inspect_argv))
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["image_id"], "sha256:same")
        self.assertEqual(
            [container["name"] for container in images[0]["containers"]],
            ["crowdsec", "worker"],
        )

    def test_detects_high_and_critical_even_without_a_published_fix(self):
        reports = [
            {
                "Results": [
                    {
                        "Target": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "1.1",
                                "Severity": "CRITICAL",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-2",
                                "PkgName": "curl",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "",
                                "Severity": "HIGH",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-3",
                                "PkgName": "zlib",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "1.1",
                                "Severity": "MEDIUM",
                            },
                        ],
                    }
                ]
            }
        ]

        findings = CVE.extract_findings(reports + reports)

        self.assertEqual(len(findings), 2)
        finding = next(iter(findings.values()))
        self.assertEqual(finding["id"], "CVE-2026-1")
        self.assertIn("1 new high/critical", CVE.format_findings([finding], 1))
        unfixed = [f for f in findings.values() if not f["fixed"]]
        self.assertEqual(unfixed[0]["id"], "CVE-2026-2")
        self.assertIn("no published fix", CVE.format_findings(unfixed, 2))
        self.assertNotIn("--ignore-unfixed", CVE.trivy_scan_command("trivy", Path("/tmp"), "image"))

    def test_state_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            findings = {"key": {"id": "CVE-2026-1"}}
            CVE.save_state(path, findings)
            self.assertEqual(CVE.load_state(path)["findings"], findings)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_groups_duplicate_go_findings_by_cve_and_product(self):
        reports = [
            {
                "ArtifactName": "crowdsecurity/crowdsec:v1.7.8-debian@sha256:old",
                "Results": [
                    {
                        "Target": f"usr/local/bin/tool-{index}",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-56854",
                                "PkgName": "golang.org/x/crypto",
                                "InstalledVersion": "v0.50.0",
                                "FixedVersion": "0.55.0",
                                "Severity": "CRITICAL",
                            }
                        ],
                    }
                    for index in range(8)
                ],
            },
            {
                "ArtifactName": "fosrl/gerbil:1.5.0@sha256:old",
                "Results": [
                    {
                        "Target": "usr/local/bin/gerbil",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-56854",
                                "PkgName": "golang.org/x/crypto",
                                "InstalledVersion": "v0.53.0",
                                "FixedVersion": "0.55.0",
                                "Severity": "CRITICAL",
                            }
                        ],
                    }
                ],
            },
        ]

        findings = CVE.extract_findings(reports)
        message = CVE.format_findings(list(findings.values()), len(findings))

        self.assertEqual(len(findings), 9)
        self.assertIn("1 new high/critical vulnerability group", message)
        self.assertIn("9 occurrences", message)
        self.assertIn("1 critical group", message)
        self.assertEqual(message.count("CVE-2026-56854"), 1)
        self.assertIn("crowdsecurity/crowdsec:v1.7.8-debian v0.50.0, 8 binaries", message)
        self.assertIn("fosrl/gerbil:1.5.0 v0.53.0", message)

    def test_display_metadata_does_not_change_existing_finding_identity(self):
        finding = {
            "id": "CVE-2026-1",
            "package": "example",
            "installed": "1",
            "fixed": "2",
            "severity": "HIGH",
            "target": "binary",
        }
        original = CVE.finding_key(finding)
        finding["artifact"] = "example/image:1"
        self.assertEqual(CVE.finding_key(finding), original)

    def test_preserves_minimal_immutable_runtime_metadata(self):
        report = {
            "ArtifactName": "sha256:image",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:image",
                "RepoDigests": ["example/app@sha256:digest"],
            },
            "_homelab_runtime": {
                "image_id": "sha256:image",
                "configured_refs": ["example/app:1.2.3"],
                "containers": [{"id": "abc123", "name": "app"}],
            },
            "Results": [
                {
                    "Class": "lang-pkgs",
                    "Type": "gobinary",
                    "Target": "usr/local/bin/app",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-1",
                            "PkgName": "example/module",
                            "InstalledVersion": "v1.0.0",
                            "FixedVersion": "v1.1.0",
                            "Severity": "HIGH",
                            "Title": "specific failure mode",
                            "Description": "trigger and impact",
                            "PrimaryURL": "https://example.test/advisory",
                            "References": ["https://example.test/reference"],
                            "DataSource": {"ID": "test"},
                        }
                    ],
                }
            ],
        }

        finding = next(iter(CVE.extract_findings([report]).values()))

        self.assertEqual(finding["artifact"], "example/app:1.2.3")
        self.assertEqual(finding["artifact_id"], "sha256:image")
        self.assertEqual(finding["repo_digests"], ["example/app@sha256:digest"])
        self.assertEqual(finding["result_type"], "gobinary")
        self.assertNotIn("title", finding)
        self.assertNotIn("description", finding)
        self.assertEqual(finding["containers"][0]["name"], "app")

    def test_immutable_image_scan_preserves_os_finding_identity(self):
        common = {
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:image",
                "RepoTags": ["example/app:1.2.3"],
                "OS": {"Family": "debian", "Name": "12.13"},
            },
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Target": "example/app:1.2.3 (debian 12.13)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-2",
                            "PkgName": "libexample1",
                            "InstalledVersion": "1",
                            "FixedVersion": "2",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
        previous = CVE.extract_findings(
            [{**common, "ArtifactName": "example/app:1.2.3"}]
        )
        immutable = CVE.extract_findings(
            [
                {
                    **common,
                    "ArtifactName": "sha256:image",
                    "_homelab_runtime": {
                        "image_id": "sha256:image",
                        "configured_refs": ["example/app:1.2.3@sha256:digest"],
                        "containers": [{"id": "abc123", "name": "app"}],
                    },
                }
            ]
        )

        self.assertEqual(set(previous), set(immutable))

        migrated = dict(next(iter(immutable.values())))
        migrated["target"] = "sha256:image (debian 12.13)"
        self.assertEqual(
            CVE.finding_key(CVE.canonicalize_finding(migrated)),
            next(iter(previous)),
        )

    def test_finding_context_stops_at_normalized_starting_facts(self):
        finding = {
            "id": "CVE-2026-1",
            "package": "example/module",
            "installed": "v1.0.0",
            "fixed": "v1.1.0",
            "severity": "HIGH",
            "target": "usr/local/bin/app",
            "artifact": "example/app:1.0",
            "artifact_type": "container_image",
            "artifact_id": "sha256:image",
            "repo_digests": ["example/app@sha256:digest"],
            "containers": [{"id": "abc123", "name": "app"}],
            "result_class": "lang-pkgs",
            "result_type": "gobinary",
        }

        context = CVE.build_finding_context([finding, finding])

        self.assertEqual(context["schema"], 2)
        self.assertEqual(len(context["groups"]), 1)
        self.assertEqual(context["groups"][0]["occurrence_count"], 2)
        occurrence = context["groups"][0]["occurrences"][0]
        self.assertEqual(occurrence["reported_file"], "/usr/local/bin/app")
        self.assertNotIn("reachability", occurrence)
        self.assertNotIn("advisory", context["groups"][0])

    def test_group_limit_is_reported_as_incomplete_input(self):
        findings = [{"id": f"CVE-2099-{1000+i}", "package": "example/module", "fixed": "2",
                     "installed": "1", "severity": "HIGH", "artifact": "host rootfs"}
                    for i in range(21)]
        context = CVE.build_finding_context(findings)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["total_occurrences"], 21)
        self.assertEqual(context["included_occurrences"], 20)


class ReleaseMonitorTests(unittest.TestCase):
    def test_parses_atom_and_filters_prereleases(self):
        atom = b"""<?xml version="1.0"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry><id>tag:stable</id><title>v2.0.0</title>
            <link rel="alternate" href="https://example.test/v2" />
            <updated>2026-08-31T00:00:00Z</updated></entry>
          <entry><id>tag:rc</id><title>v2.1.0-rc.1</title></entry>
        </feed>"""

        entries = RELEASE.parse_feed(atom)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["url"], "https://example.test/v2")
        self.assertTrue(RELEASE.is_stable(entries[0]["title"]))
        self.assertFalse(RELEASE.is_stable(entries[1]["title"]))

    def test_formats_release_notification(self):
        message = RELEASE.format_releases(
            [
                {
                    "source": "Caddy",
                    "title": "v2.10.2",
                    "url": "https://example.test/release",
                }
            ]
        )
        self.assertIn("1 new stable upstream release", message)
        self.assertIn("Caddy: v2.10.2", message)

    def test_new_feed_establishes_a_silent_baseline(self):
        entries = [
            {"id": "tag:v2", "title": "v2.0.0", "url": "", "published": ""},
            {"id": "tag:v1", "title": "v1.0.0", "url": "", "published": ""},
        ]

        self.assertEqual(RELEASE.newly_seen_stable_entries(entries, None), [])

    def test_existing_feed_reports_only_unseen_stable_entries(self):
        entries = [
            {"id": "tag:v3", "title": "v3.0.0", "url": "", "published": ""},
            {"id": "tag:rc", "title": "v3.0.0-rc.1", "url": "", "published": ""},
            {"id": "tag:v2", "title": "v2.0.0", "url": "", "published": ""},
        ]

        releases = RELEASE.newly_seen_stable_entries(entries, ["tag:v2"])

        self.assertEqual([entry["id"] for entry in releases], ["tag:v3"])


if __name__ == "__main__":
    unittest.main()
