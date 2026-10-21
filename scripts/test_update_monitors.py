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
    def test_every_scan_uses_central_configuration_and_forbids_local_db_updates(self):
        for kind in ('rootfs', 'image'):
            command = CVE.trivy_scan_command('trivy', Path('/tmp/cache'), kind)
            self.assertIn('--skip-db-update', command)
            self.assertEqual(command[command.index('--config') + 1],
                             '/etc/homelab-update-monitor/trivy-client.json')

    def test_missing_or_unsafe_server_configuration_never_starts_trivy(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'client.json'
            with mock.patch.dict(CVE.os.environ, {'TRIVY_CLIENT_CONFIG': str(config)}), \
                    mock.patch.object(CVE.subprocess, 'run') as run:
                for content in (None, {}, {'server': {'addr': 'http://example.org', 'token': 'x' * 64}},
                                {'server': {'addr': 'https://example.org', 'token': ''}},
                                {'server': 'https://example.org', 'token': 'x' * 64}):
                    if content is not None:
                        config.write_text(json.dumps(content))
                    with self.assertRaises((OSError, ValueError, RuntimeError)):
                        CVE.run_json(CVE.trivy_scan_command('trivy', Path(directory), 'rootfs'), Path(directory))
                run.assert_not_called()

    def test_remote_failure_is_not_retried_locally_and_environment_cannot_override_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'client.json'
            config.write_text(json.dumps({'server': {'addr': 'https://example.org', 'token': 'x' * 64}}))
            result = mock.Mock(returncode=1, stderr='connection refused')
            with mock.patch.dict(CVE.os.environ, {'TRIVY_CLIENT_CONFIG': str(config), 'TRIVY_SERVER': '', 'TRIVY_TOKEN': 'wrong'}), \
                    mock.patch.object(CVE.subprocess, 'run', return_value=result) as run:
                with self.assertRaisesRegex(RuntimeError, 'connection refused'):
                    CVE.run_json(CVE.trivy_scan_command('trivy', Path(directory), 'rootfs'), Path(directory))
                run.assert_called_once()
                self.assertFalse(any(k.startswith('TRIVY_') for k in run.call_args.kwargs['env']))
                self.assertNotIn('x' * 64, ' '.join(run.call_args.args[0]))

    def test_temporary_remote_overload_has_bounded_remote_only_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'client.json'
            config.write_text(json.dumps({'server': {'addr': 'https://example.org', 'token': 'x' * 64}}))
            result = mock.Mock(returncode=1, stderr='HTTP status code 429 Too Many Requests')
            with mock.patch.dict(CVE.os.environ, {'TRIVY_CLIENT_CONFIG': str(config)}), \
                    mock.patch.object(CVE.subprocess, 'run', return_value=result) as run, \
                    mock.patch('time.sleep'):
                with self.assertRaisesRegex(RuntimeError, '429'):
                    CVE.run_json(CVE.trivy_scan_command('trivy', Path(directory), 'rootfs'), Path(directory))
                self.assertEqual(run.call_count, 3)
                for call in run.call_args_list:
                    self.assertIn('--config', call.args[0])
                    self.assertIn('--skip-db-update', call.args[0])

    def test_watchdog_owns_failure_and_recovery_alerts_when_configured(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state.json'
            argv = ['monitor', '--state', str(state), '--cache', str(root), '--health-managed-by-watchdog']
            with mock.patch.object(CVE.sys, 'argv', argv), \
                    mock.patch.dict(CVE.os.environ, {'UPDATE_MONITOR_WEBHOOK_URL': 'https://example.invalid'}), \
                    mock.patch.object(CVE, 'scan_reports', side_effect=RuntimeError('failed')) as scan, \
                    mock.patch.object(CVE, 'read_credential', return_value='test-secret'), \
                    mock.patch.object(CVE, 'send_notification') as send:
                with self.assertRaises(RuntimeError):
                    CVE.main()
                self.assertEqual(json.loads(state.with_suffix('.status.json').read_text())['status'], 'failed')
                scan.side_effect = None
                scan.return_value = []
                self.assertEqual(CVE.main(), 0)
                self.assertEqual(json.loads(state.with_suffix('.status.json').read_text())['status'], 'complete')
                send.assert_not_called()

    def test_saved_findings_ignore_artifact_runtime_and_container_churn(self):
        finding = {"id": "CVE-2026-1", "package": "stdlib", "installed": "1", "fixed": "2", "severity": "HIGH", "target": "/usr/bin/caddy"}
        # Exercise persisted finding comparison, not just the identity helper.
        changes = {
            'artifact_id': ('sha256:old', 'sha256:new'),
            'runtime_sha256': ('sha256:old', 'sha256:new'),
            'artifact': ('old-label', 'new-label'),
            'containers': ([{'id': 'old'}], [{'id': 'new'}]),
        }
        for identity, (old_value, new_value) in changes.items():
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / 'state.json'
                previous = {**finding, identity: old_value}
                current = {**finding, identity: new_value}
                key = CVE.finding_key(finding)
                CVE.save_state(state, {key: previous})
                with mock.patch.object(CVE.sys, "argv", ["monitor", "--state", str(state), "--cache", str(root)]), \
                        mock.patch.dict(CVE.os.environ, {"UPDATE_MONITOR_WEBHOOK_URL": "https://example.invalid"}), \
                        mock.patch.object(CVE, "scan_reports", return_value=[]), \
                        mock.patch.object(CVE, "extract_findings", return_value={key: current}), \
                        mock.patch.object(CVE, "read_credential", return_value="test-secret"), \
                        mock.patch.object(CVE, "send_notification") as send:
                    CVE.main()
                    send.assert_not_called()
                    self.assertEqual(CVE.load_state(state)['findings'][key], current)
                    self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_failed_docker_inventory_never_means_no_containers(self):
        with mock.patch.object(CVE.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(CVE.subprocess, "run", return_value=mock.Mock(returncode=1, stdout="")):
            with self.assertRaisesRegex(RuntimeError, "coverage is unknown"):
                CVE.docker_runtime_images()

    def test_stopped_images_are_scanned_and_inventory_races_invalidate_the_scan(self):
        def docker(argv, **kwargs):
            if argv[1] == 'ps':
                return mock.Mock(returncode=0, stdout='running\nstopped\n' if '--all' in argv else 'running\n')
            return mock.Mock(returncode=0, stdout='"running"\t"/app"\t"sha256:one"\t"app:1"\ttrue\t"web"\n"stopped"\t"/old-app"\t"sha256:two"\t"app:0"\tfalse\tnull\n')
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(CVE.shutil, 'which', return_value='docker'), \
                mock.patch.object(CVE.subprocess, 'run', side_effect=docker), mock.patch.object(CVE, 'run_json', side_effect=lambda *a: {'Results': []}):
            reports = CVE.scan_reports('trivy', Path(temp), Path(temp))
            self.assertEqual({r['_homelab_runtime']['image_id'] for r in reports[1:]}, {'sha256:one', 'sha256:two'})
            state = {c['name']: c['running'] for report in reports[1:]
                     for c in report['_homelab_runtime']['containers']}
            self.assertEqual({'app': True, 'old-app': False}, state)
            with mock.patch.object(CVE, 'docker_runtime_images', side_effect=[[{'image_id': 'old'}], [{'image_id': 'new'}]]):
                with self.assertRaisesRegex(RuntimeError, 'changed during scanning'):
                    CVE.scan_reports('trivy', Path(temp), Path(temp))

    def test_large_finding_delivery_preserves_every_occurrence_without_one_alert_per_advisory(self):
        findings = [{"id": f"CVE-2026-{i}", "package": f"module{i % 25}",
                     "fixed": "", "severity": "HIGH", "target": f"/bin/tool{i}", "installed": "1"}
                    for i in range(41)]
        batches = CVE.finding_batches(findings)
        self.assertCountEqual([item for batch in batches for item in batch], findings)
        self.assertEqual(len(batches), 1)
        context = CVE.build_finding_context(batches[0])
        self.assertFalse(context["truncated"])
        self.assertEqual(len(context["groups"]), 41)

    def test_finding_batches_stay_below_the_matrix_context_size_limit(self):
        findings = [{"id": f"CVE-2026-{i}", "package": "large-module", "fixed": "2",
                     "severity": "HIGH", "target": "/" + (str(i) * 40000), "installed": "1"}
                    for i in range(3)]
        batches = CVE.finding_batches(findings)
        self.assertGreater(len(batches), 1)
        for batch in batches:
            encoded = json.dumps(CVE.build_finding_context(batch), separators=(",", ":")).encode()
            self.assertLessEqual(len(encoded), CVE.MAX_FINDING_CONTEXT_BYTES)

    def test_snapshot_and_initial_regular_scan_establish_quiet_baselines(self):
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
                send.assert_not_called()
                credential.assert_not_called()
                self.assertEqual(json.loads((root / "state.status.json").read_text())["status"], "complete")

    def test_failed_delivery_keeps_exact_pending_notification_for_retry(self):
        finding = {"id": "CVE-2026-1", "package": "stdlib", "installed": "1", "fixed": "2",
                   "severity": "HIGH", "target": "/usr/bin/caddy"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state.json'
            CVE.save_state(state, {})
            key = CVE.finding_key(finding)
            argv = ['monitor', '--state', str(state), '--cache', str(root)]
            with mock.patch.object(CVE.sys, 'argv', argv), \
                    mock.patch.dict(CVE.os.environ, {'UPDATE_MONITOR_WEBHOOK_URL': 'https://example.invalid'}), \
                    mock.patch.object(CVE, 'scan_reports', return_value=[]), \
                    mock.patch.object(CVE, 'extract_findings', return_value={key: finding}), \
                    mock.patch.object(CVE, 'read_credential', return_value='test-secret'), \
                    mock.patch.object(CVE, 'send_notification', side_effect=RuntimeError('delivery failed')):
                with self.assertRaisesRegex(RuntimeError, 'delivery failed'):
                    CVE.main()
            pending = CVE.load_state(state)['pending_notifications']
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['context']['groups'][0]['id'], finding['id'])
            observed_at = pending[0]['observed_at']

            with mock.patch.object(CVE.sys, 'argv', argv), \
                    mock.patch.dict(CVE.os.environ, {'UPDATE_MONITOR_WEBHOOK_URL': 'https://example.invalid'}), \
                    mock.patch.object(CVE, 'scan_reports', return_value=[]), \
                    mock.patch.object(CVE, 'extract_findings', return_value={key: finding}), \
                    mock.patch.object(CVE, 'read_credential', return_value='test-secret'), \
                    mock.patch.object(CVE, 'send_notification') as send:
                self.assertEqual(CVE.main(), 0)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(send.call_args.kwargs['observed_at'], observed_at)
            self.assertEqual(CVE.load_state(state)['pending_notifications'], [])

    def test_notification_bytes_are_stable_after_sorted_state_reload(self):
        bodies = []

        class Response:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def capture(outgoing, timeout):
            bodies.append(outgoing.data)
            return Response()

        with mock.patch.object(CVE.request, 'urlopen', side_effect=capture):
            CVE.send_notification('https://example.invalid', 'secret', 'host', 'message',
                                  {'z': 1, 'a': {'y': 2, 'b': 3}}, observed_at='2026-09-08T00:00:00+00:00')
            CVE.send_notification('https://example.invalid', 'secret', 'host', 'message',
                                  {'a': {'b': 3, 'y': 2}, 'z': 1}, observed_at='2026-09-08T00:00:00+00:00')
        self.assertEqual(bodies[0], bodies[1])

    def test_failed_regular_and_audit_scans_preserve_findings_without_duplicate_alerts(self):
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = root / 'state.json'
                CVE.save_state(state, {'retained': {'id': 'CVE-2026-1'}})
                before = state.read_bytes()
                argv = ['monitor', '--state', str(state), '--cache', str(root)]
                if snapshot:
                    argv.append('--snapshot-only')
                with mock.patch.object(CVE.sys, 'argv', argv), \
                        mock.patch.dict(CVE.os.environ, {'UPDATE_MONITOR_WEBHOOK_URL': 'https://example.invalid'}), \
                        mock.patch.object(CVE, 'scan_reports', side_effect=RuntimeError('failed')), \
                        mock.patch.object(CVE, 'read_credential', return_value='test-secret'), \
                        mock.patch.object(CVE, 'send_notification') as send:
                    for _ in range(2):
                        with self.assertRaises(RuntimeError):
                            CVE.main()
                self.assertEqual(send.call_count, 0 if snapshot else 1)
                if not snapshot:
                    self.assertEqual(send.call_args.kwargs['kind'], 'system')
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

    def test_docker_runtime_inventory_requests_only_non_secret_fields(self):
        responses = [
            mock.Mock(returncode=0, stdout="aaaaaaaaaaaa\nbbbbbbbbbbbb\n", stderr=""),
            mock.Mock(
                returncode=0,
                stdout=(
                    json.dumps('a' * 64) + '\t"/crowdsec"\t"sha256:same"\t'
                    '"crowdsecurity/crowdsec:v1"\ttrue\t"crowdsec"\n'
                    + json.dumps('b' * 64) + '\t"/worker"\t"sha256:same"\t'
                    '"crowdsecurity/crowdsec:v1"\tfalse\tnull\n'
                ),
                stderr="",
            ),
        ]
        with mock.patch.object(CVE.shutil, "which", return_value="/usr/bin/docker"), mock.patch.object(
            CVE.subprocess, "run", side_effect=responses
        ) as run:
            images = CVE.docker_runtime_images()

        self.assertEqual([c['id'] for c in images[0]['containers']], ['a' * 64, 'b' * 64])
        inspect_argv = run.call_args_list[1].args[0]
        self.assertIn("--format", inspect_argv)
        self.assertNotIn(".Config.Env", " ".join(inspect_argv))
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["image_id"], "sha256:same")
        self.assertEqual(
            [container["name"] for container in images[0]["containers"]],
            ["crowdsec", "worker"],
        )
        self.assertEqual(images[0]['containers'][0]['compose_service'], 'crowdsec')

    def test_detects_high_and_critical_even_without_a_published_fix(self):
        vulnerabilities = [
            {'VulnerabilityID': 'CVE-2026-1', 'PkgName': 'openssl', 'InstalledVersion': '1.0', 'FixedVersion': '1.1', 'Severity': 'CRITICAL'},
            {'VulnerabilityID': 'CVE-2026-2', 'PkgName': 'curl', 'InstalledVersion': '1.0', 'FixedVersion': '', 'Severity': 'HIGH'},
            {'VulnerabilityID': 'CVE-2026-3', 'PkgName': 'zlib', 'InstalledVersion': '1.0', 'FixedVersion': '1.1', 'Severity': 'MEDIUM'},
        ]
        reports = [{'Results': [{'Target': 'debian', 'Vulnerabilities': vulnerabilities}]}]
        findings = CVE.extract_findings(reports + reports)
        self.assertEqual({f['id'] for f in findings.values()}, {'CVE-2026-1', 'CVE-2026-2'})
        self.assertEqual(len(findings), 2)
        unfixed = [f for f in findings.values() if not f['fixed']]
        self.assertEqual(unfixed[0]['id'], 'CVE-2026-2')
        self.assertIn('no published fix', CVE.format_findings(unfixed, 2))
        self.assertNotIn('--ignore-unfixed', CVE.trivy_scan_command('trivy', Path('/tmp'), 'image'))

    def test_groups_duplicate_go_findings_by_cve_and_product(self):
        vulnerability = {'VulnerabilityID': 'CVE-2026-56854', 'PkgName': 'golang.org/x/crypto',
                         'FixedVersion': '0.55.0', 'Severity': 'CRITICAL'}
        reports = [
            {'ArtifactName': artifact, 'Results': [
                {'Target': f'usr/local/bin/tool-{index}', 'Vulnerabilities': [{**vulnerability, 'InstalledVersion': version}]}
                for index in range(count)]}
            for artifact, version, count in [
                ('crowdsecurity/crowdsec:v1.7.8-debian@sha256:old', 'v0.50.0', 8),
                ('fosrl/gerbil:1.5.0@sha256:old', 'v0.53.0', 1)]
        ]
        findings = CVE.extract_findings(reports)
        message = CVE.format_findings(list(findings.values()), len(findings))
        self.assertEqual(len(findings), 9)
        self.assertIn('1 new high/critical vulnerability group', message)
        self.assertIn('9 occurrences', message)
        self.assertEqual(message.count('CVE-2026-56854'), 1)
        self.assertIn('crowdsecurity/crowdsec:v1.7.8-debian v0.50.0, 8 binaries', message)
        self.assertIn('fosrl/gerbil:1.5.0 v0.53.0', message)

    def test_scanned_image_identity_survives_finding_context(self):
        report = {
            'ArtifactName': 'sha256:image', 'ArtifactType': 'container_image',
            'Metadata': {'ImageID': 'sha256:image', 'RepoDigests': ['example/app@sha256:digest']},
            '_homelab_runtime': {'image_id': 'sha256:image', 'configured_refs': ['example/app:1.2.3'],
                                 'containers': [{'id': 'a' * 64, 'name': 'app'}]},
            'Results': [{'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': 'usr/local/bin/app',
                         'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1', 'PkgName': 'example/module',
                                              'InstalledVersion': 'v1.0.0', 'FixedVersion': 'v1.1.0', 'Severity': 'HIGH'}]}],
        }
        finding = next(iter(CVE.extract_findings([report]).values()))
        context = CVE.build_finding_context([finding, finding])
        self.assertEqual(context['schema'], 2)
        self.assertEqual(len(context['groups']), 1)
        self.assertEqual(context['groups'][0]['occurrence_count'], 2)
        occurrence = context['groups'][0]['occurrences'][0]
        self.assertEqual(occurrence['artifact'], 'example/app:1.2.3')
        self.assertEqual(occurrence['artifact_id'], 'sha256:image')
        self.assertEqual(occurrence['repo_digests'], ['example/app@sha256:digest'])
        self.assertEqual(occurrence['reported_file'], '/usr/local/bin/app')
        self.assertEqual(occurrence['containers'], [{'id': 'a' * 64, 'name': 'app'}])
        self.assertNotIn('reachability', occurrence)

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

    def test_group_limit_is_reported_as_incomplete_input(self):
        findings = [{"id": f"CVE-2099-{1000+i}", "package": "example/module", "fixed": "2",
                     "installed": "1", "severity": "HIGH", "artifact": "host rootfs"}
                    for i in range(CVE.MAX_FINDING_GROUPS + 1)]
        context = CVE.build_finding_context(findings)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["total_occurrences"], CVE.MAX_FINDING_GROUPS + 1)
        self.assertEqual(context["included_occurrences"], CVE.MAX_FINDING_GROUPS)


class ReleaseMonitorTests(unittest.TestCase):
    def test_feed_baseline_and_subsequent_releases_exclude_seen_and_prerelease_entries(self):
        atom = b"""<feed xmlns="http://www.w3.org/2005/Atom">
          <entry><id>tag:v3</id><title>v3.0.0</title><link rel="alternate" href="https://example.test/v3" /></entry>
          <entry><id>tag:rc</id><title>v3.1.0-rc.1</title></entry>
          <entry><id>tag:v2</id><title>v2.0.0</title></entry>
        </feed>"""
        entries = RELEASE.parse_feed(atom)
        self.assertEqual(RELEASE.newly_seen_stable_entries(entries, None), [])
        releases = RELEASE.newly_seen_stable_entries(entries, ['tag:v2'])
        self.assertEqual([entry['id'] for entry in releases], ['tag:v3'])
        self.assertEqual(releases[0]['url'], 'https://example.test/v3')
        self.assertEqual(RELEASE.newly_seen_stable_entries(entries, ['tag:v2', 'tag:v3']), [])

if __name__ == "__main__":
    unittest.main()
