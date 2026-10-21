from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class EvidenceGatewayTests(unittest.TestCase):
    def accepted_snapshot(self, **changes):
        snapshot = {'schema': 1, 'source': 'caddy', 'generation': 'one', 'sequence': 3,
                    'observed_at': self.gateway.time.time(), 'complete_scopes': ['binary:/bouncer:/bouncer'],
                    'coverage': {'discovery': {'gaps': []}}, 'packages': [],
                    'findings': [{'id': 'CVE-2026-2303', 'severity': 'MEDIUM', 'scope': 'binary:/bouncer:/bouncer'}],
                    **changes}
        digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        (self.root/'cve-state.incident-snapshot.json').write_text(json.dumps({'sha256': digest, 'snapshot': snapshot}))
        return digest

    def test_coverage_uses_all_severity_acknowledged_snapshot_not_newer_filtered_audit(self):
        digest = self.accepted_snapshot()
        (self.root/'coverage-audit.json').write_text(json.dumps({'findings': {}, 'coverage': {}}))
        (self.root/'coverage-audit.status.json').write_text('{"status":"complete"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root):
            result = self.gateway.observe('deployment_coverage', {'advisory': 'CVE-2026-2303'})['result']['result']
        self.assertEqual(result['matching_findings'][0]['severity'], 'MEDIUM')
        self.assertEqual(result['snapshot']['sha256'], digest)
        self.assertEqual(result['snapshot']['sequence'], 3)

    def test_corrupt_acknowledged_snapshot_never_falls_back_to_filtered_clear_result(self):
        self.accepted_snapshot()
        path = self.root/'cve-state.incident-snapshot.json'
        value = json.loads(path.read_text()); value['snapshot']['findings'] = []
        path.write_text(json.dumps(value))
        (self.root/'cve-state.json').write_text('{"findings":{}}')
        (self.root/'cve-state.status.json').write_text('{"status":"complete"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root):
            receipt = self.gateway.observe('deployment_coverage', {'advisory': 'CVE-2026-2303'})['result']
        self.assertEqual(receipt['status'], 'failed')

    def test_newer_scan_failure_preserves_matches_but_reports_unknown_coverage(self):
        self.accepted_snapshot()
        (self.root/'cve-state.status.json').write_text('{"status":"failure_notified"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root):
            result = self.gateway.observe('deployment_coverage', {'advisory': 'CVE-2026-2303'})['result']['result']
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(len(result['matching_findings']), 1)

    def test_stale_snapshot_retains_positive_findings_without_fresh_coverage(self):
        self.accepted_snapshot(observed_at=self.gateway.time.time()-37*3600)
        (self.root/'cve-state.status.json').write_text('{"status":"complete"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root):
            result = self.gateway.observe('deployment_coverage', {'advisory': 'CVE-2026-2303'})['result']['result']
        self.assertFalse(result['snapshot']['fresh'])
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(len(result['matching_findings']), 1)

    def test_enrolled_source_without_acknowledged_snapshot_does_not_use_legacy_state(self):
        config = self.root/'incident.json'
        config.write_text('{"source":"caddy","generation":"one"}')
        (self.root/'cve-state.json').write_text('{"findings":{}}')
        (self.root/'cve-state.status.json').write_text('{"status":"complete"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config):
            result = self.gateway.observe('deployment_coverage', {})['result']['result']
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['reason'], 'no acknowledged incident snapshot')

    def test_acknowledged_snapshot_from_old_source_generation_is_rejected(self):
        self.accepted_snapshot()
        config = self.root/'incident.json'
        config.write_text('{"source":"caddy","generation":"replacement"}')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config):
            receipt = self.gateway.observe('deployment_coverage', {})['result']
        self.assertEqual(receipt['status'], 'failed')

    def test_observe_returns_current_scan_with_its_original_status_and_matching_findings(self):
        state = self.root / 'cve-state.json'
        state.write_text(json.dumps({'updated_at': '2026-09-06T10:00:00Z',
            'coverage': {'discovery': {'gaps': ['scheduled jobs not inspected']}},
            'findings': {'one': {'id': 'CVE-2019-16226', 'package': 'liblmdb0'},
                         'two': {'id': 'CVE-2000-0001', 'package': 'another'}}}))
        state.with_suffix('.status.json').write_text(json.dumps({'status': 'complete'}))
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root):
            receipt = self.gateway.observe('deployment_coverage', {'advisory': 'CVE-2019-16226'})['result']
        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(receipt['result']['scan_status'], {'status': 'complete'})
        self.assertEqual(receipt['result']['matching_findings'], [{'id': 'CVE-2019-16226', 'package': 'liblmdb0'}])
        self.assertEqual(receipt['result']['discovery_gaps'], ['scheduled jobs not inspected'])

    def test_operational_reads_need_no_finding_but_enforce_host_file_policy(self):
        config = self.config_root / 'Caddyfile'
        config.write_text('reverse_proxy app:8080\npassword=private-value\n')
        receipt = self.gateway.observe('read_config', {'path': str(config)})['result']
        self.assertEqual(receipt['status'], 'success')
        self.assertIn('app:8080', json.dumps(receipt))
        self.assertNotIn('private-value', json.dumps(receipt))
        outside = self.root / 'outside'
        outside.write_text('private-outside-root')
        (self.config_root / 'escape').symlink_to(outside)
        for path in (outside, self.config_root / 'escape'):
            result = self.gateway.observe('read_config', {'path': str(path)})['result']
            self.assertEqual(result['status'], 'failed')
            self.assertNotIn('private-outside-root', json.dumps(result))
        with mock.patch.object(self.gateway, 'bounded_run') as run:
            for operation in ('restart', 'exec', 'extract_file', 'run_analyzer'):
                with self.assertRaisesRegex(ValueError, 'unsupported operational read'):
                    self.gateway.observe(operation, {})
            run.assert_not_called()
        self.assertFalse(list(self.capabilities.glob('*.json')))

    def test_operational_reads_never_disclose_livekit_keypairs_or_credential_directories(self):
        # A generated key is not a descriptive field name, so content redaction
        # cannot establish that this file is safe to read.
        secret = 'b' * 64
        for relative in ('livekit-keypair', 'secrets/livekit', 'credentials/livekit'):
            with self.subTest(path=relative):
                path = self.config_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('a' * 20 + ': ' + secret + '\n')
                path.chmod(0o600)
                receipt = self.gateway.observe('read_config', {'path': str(path)})['result']
                self.assertEqual(receipt['status'], 'failed')
                self.assertNotIn(secret, json.dumps(receipt))

    def test_credential_mount_is_rejected_even_when_renamed_inside_container(self):
        path = self.config_root / 'livekit-keypair'
        path.write_text('a' * 20 + ': ' + 'b' * 64 + '\n')
        scope = self.gateway.normalized_scope(self.scope())
        mount = {'Type': 'bind', 'Source': str(path), 'Destination': '/config/livekit'}
        with mock.patch.object(self.gateway, 'bounded_run', return_value={
                'stdout': json.dumps([mount]), 'returncode': 0, 'truncated': False}):
            self.assertEqual(self.gateway.configuration_locations(scope, scope['containers'][0]), [])

    def test_network_state_returns_parsed_addresses_and_routes_without_firewall(self):
        address = {
            'returncode': 0,
            'stdout': '[{"ifname":"eth0"}]',
            'stderr': '',
            'truncated': False,
        }
        routes = {
            'returncode': 0,
            'stdout': '[{"dst":"default"}]',
            'stderr': '',
            'truncated': False,
        }

        with mock.patch.object(self.gateway, 'bounded_run', side_effect=[address, routes]) as run:
            receipt = self.gateway.observe('network_state', {})['result']

        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(
            receipt['result'],
            {
                'addresses': [{'ifname': 'eth0'}],
                'routes': [{'dst': 'default'}],
            },
        )
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(['/usr/sbin/ip', '-j', 'address'], 20),
                mock.call(['/usr/sbin/ip', '-j', 'route'], 20),
            ],
        )

    def test_firewall_query_returns_terse_inventory_without_set_elements(self):
        responses = [
            {'nftables': [{'metainfo': {'version': '1.1.3'}},
                           {'table': {'family': 'ip', 'name': 'crowdsec'}}]},
            {'nftables': [{'metainfo': {'version': '1.1.3'}},
                           {'chain': {'family': 'ip', 'table': 'crowdsec',
                                      'name': 'crowdsec-chain-input'}}]},
            {'nftables': [{'metainfo': {'version': '1.1.3'}},
                           {'set': {'family': 'ip', 'table': 'crowdsec',
                                    'name': 'crowdsec-blacklists-CAPI',
                                    'type': 'ipv4_addr'}}]},
        ]
        command_results = [
            {'returncode': 0, 'stdout': json.dumps(value), 'stderr': '',
             'truncated': False}
            for value in responses
        ]

        with mock.patch.object(
            self.gateway, 'bounded_run', side_effect=command_results
        ) as run:
            receipt = self.gateway.observe('firewall_query', {})['result']

        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(receipt['result']['query'], 'inventory')
        self.assertEqual(receipt['result']['tables'], [responses[0]['nftables'][1]['table']])
        self.assertEqual(receipt['result']['chains'], [responses[1]['nftables'][1]['chain']])
        self.assertEqual(receipt['result']['sets'], [responses[2]['nftables'][1]['set']])
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(['/usr/sbin/nft', '-j', '-t', 'list', 'tables'], 20),
                mock.call(['/usr/sbin/nft', '-j', '-t', 'list', 'chains'], 20),
                mock.call(['/usr/sbin/nft', '-j', '-t', 'list', 'sets'], 20),
            ],
        )

    def test_firewall_query_reads_one_selected_chain(self):
        document = {
            'nftables': [
                {'metainfo': {'version': '1.1.3'}},
                {'chain': {'family': 'ip', 'table': 'crowdsec',
                           'name': 'crowdsec-chain-input'}},
                {'rule': {'family': 'ip', 'table': 'crowdsec',
                          'chain': 'crowdsec-chain-input', 'handle': 8}},
            ]
        }
        command_result = {
            'returncode': 0,
            'stdout': json.dumps(document),
            'stderr': '',
            'truncated': False,
        }

        with mock.patch.object(
            self.gateway, 'bounded_run', return_value=command_result
        ) as run:
            receipt = self.gateway.observe(
                'firewall_query',
                {'family': 'ip', 'table': 'crowdsec',
                 'chain': 'crowdsec-chain-input'},
            )['result']

        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(receipt['result']['query'], 'chain')
        self.assertEqual(receipt['result']['objects'], document['nftables'][1:])
        run.assert_called_once_with(
            ['/usr/sbin/nft', '-j', '-t', 'list', 'chain', 'ip', 'crowdsec',
             'crowdsec-chain-input'],
            20,
        )

    def test_firewall_query_checks_one_address_without_listing_set_elements(self):
        metadata = {
            'nftables': [
                {'metainfo': {'version': '1.1.3'}},
                {'set': {'family': 'ip', 'table': 'crowdsec',
                         'name': 'crowdsec-blacklists-CAPI',
                         'type': 'ipv4_addr'}},
            ]
        }
        command_results = [
            {'returncode': 0, 'stdout': json.dumps(metadata), 'stderr': '',
             'truncated': False},
            {'returncode': 1, 'stdout': '',
             'stderr': 'Error: No such file or directory', 'truncated': False},
        ]

        with mock.patch.object(
            self.gateway, 'bounded_run', side_effect=command_results
        ) as run:
            receipt = self.gateway.observe(
                'firewall_query',
                {'family': 'ip', 'table': 'crowdsec',
                 'set': 'crowdsec-blacklists-CAPI', 'address': '192.0.2.1'},
            )['result']

        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(receipt['result']['query'], 'set_address')
        self.assertFalse(receipt['result']['present'])
        self.assertEqual(
            run.call_args_list[-1],
            mock.call(
                ['/usr/sbin/nft', '-j', 'get', 'element', 'ip', 'crowdsec',
                 'crowdsec-blacklists-CAPI', '{', '192.0.2.1', '}'],
                20,
            ),
        )

    def test_native_evidence_rejects_a_different_binary_than_the_scan(self):
        for prefix in ('', 'sha256:'):
            with self.subTest(prefix=prefix):
                scope = {"bindings": [{"container_id": None, "reported_file": "/usr/bin/caddy",
                                        "artifact_id": prefix + "a" * 64}]}
                self.gateway.validate_host_binary(scope, "/usr/bin/caddy", "a" * 64)
                with self.assertRaisesRegex(ValueError, "changed since the scan"):
                    self.gateway.validate_host_binary(scope, "/usr/bin/caddy", "b" * 64)

    def test_host_executable_metadata_uses_the_captured_digest_bytes(self):
        source = self.root / "host-app"
        source.write_bytes(b"first executable bytes")
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        scope = {"bindings": [], "reported_files": [str(source)]}
        calls = []

        def run(command, _timeout):
            calls.append(command)
            source.write_bytes(b"replacement executable bytes")
            if command[0] == "/usr/bin/file":
                return {"returncode": 0, "stdout": "ELF test\n", "stderr": ""}
            return {"returncode": 1, "stdout": "", "stderr": "not dynamic"}

        def build_info(local, *_):
            self.assertNotEqual(source, local)
            self.assertEqual(b"first executable bytes", local.read_bytes())
            return {"status": "available", "sha256": expected}

        with mock.patch.object(self.gateway, "bounded_run", side_effect=run), \
                mock.patch.object(self.gateway, "go_build_info", side_effect=build_info):
            result = self.gateway.inspect_executable(scope, {"path": str(source)})

        self.assertEqual(expected, result["sha256"])
        self.assertEqual(expected, result["go_build"]["sha256"])
        self.assertEqual(2, len(calls))

    def test_snapshot_artifact_inspects_digest_bound_release_symlink(self):
        release = self.root / 'opt/releases/1/app'
        release.parent.mkdir(parents=True)
        release.write_bytes(b'ELF retained release fixture')
        selected = self.root / 'usr/local/bin/app'
        selected.parent.mkdir(parents=True)
        selected.symlink_to(release)
        finding = {'id': 'CVE-2026-12345', 'package': 'app',
                   'target': str(selected), 'artifact_id': hashlib.sha256(release.read_bytes()).hexdigest()}
        snapshot = self.accepted_snapshot(findings=[finding])
        config = self.root / 'incident.json'
        config.write_text('{"source":"caddy","generation":"one"}')
        parsed = []

        def run(argv, _timeout):
            parsed.append(Path(argv[-1]).read_bytes())
            return {'returncode': 0, 'stdout': '', 'stderr': '', 'truncated': False}

        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), \
                mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config), \
                mock.patch.object(self.gateway, 'bounded_run', side_effect=run):
            result = self.gateway.snapshot_artifact('inspect_executable', {
                'snapshot_sha256': snapshot, 'finding_sha256': self.gateway.object_sha256(finding),
                'path': str(selected)})
            expected_bytes = release.read_bytes()
            release.write_bytes(b'changed since accepted scan')
            rejected = self.gateway.snapshot_artifact('inspect_executable', {
                'snapshot_sha256': snapshot, 'finding_sha256': self.gateway.object_sha256(finding),
                'path': str(selected)})
            with self.assertRaisesRegex(ValueError, 'exact scanner-reported artifact'):
                self.gateway.snapshot_artifact('inspect_executable', {
                    'snapshot_sha256': snapshot, 'finding_sha256': self.gateway.object_sha256(finding),
                    'path': str(release)})
        self.assertEqual('success', result['result']['status'], result)
        self.assertEqual(finding['artifact_id'], result['result']['result']['sha256'])
        self.assertEqual('failed', rejected['result']['status'], rejected)
        self.assertIn('changed since the scan', str(rejected['result']['limitations']))
        self.assertEqual([expected_bytes] * 3, parsed)

    def test_host_extraction_uses_digest_checked_stable_capture_and_size_limit(self):
        release = self.root / 'opt/releases/1/app'
        release.parent.mkdir(parents=True)
        release.write_bytes(b'accepted extraction bytes')
        selected = self.root / 'usr/local/bin/app'
        selected.parent.mkdir(parents=True)
        selected.symlink_to(release)
        digest = hashlib.sha256(release.read_bytes()).hexdigest()
        finding = {
            'id': 'CVE-2026-12345',
            'package': 'app',
            'target': str(selected),
            'artifact_id': digest,
            'containers': [],
            'scope': 'binary:' + str(selected),
        }
        snapshot = self.accepted_snapshot(findings=[finding])
        config = self.root / 'incident.json'
        config.write_text('{"source":"caddy","generation":"one"}')
        arguments = {
            'snapshot_sha256': snapshot,
            'finding_sha256': self.gateway.object_sha256(finding),
            'path': str(selected),
        }

        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), \
                mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config):
            response = self.gateway.snapshot_artifact('extract_file', arguments)
        result = response['result']['result']
        self.assertEqual(b'accepted extraction bytes',
                         self.gateway.base64.b64decode(result['base64']))
        self.assertEqual(digest, result['sha256'])
        self.assertEqual({
            'snapshot_sha256': snapshot,
            'finding_sha256': self.gateway.object_sha256(finding),
        }, response['snapshot_binding'])
        release.write_bytes(b'changed after accepted snapshot')
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), \
                mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config):
            changed = self.gateway.snapshot_artifact('extract_file', arguments)
        self.assertEqual('failed', changed['result']['status'])
        self.assertIn('changed since the scan',
                      ' '.join(changed['result']['limitations']))

        release.write_bytes(b'x' * (self.gateway.MAX_EXTRACT_BYTES + 1))
        oversized_digest = hashlib.sha256(release.read_bytes()).hexdigest()
        oversized_finding = {**finding, 'artifact_id': oversized_digest}
        oversized_snapshot = self.accepted_snapshot(findings=[oversized_finding])
        oversized_arguments = {
            'snapshot_sha256': oversized_snapshot,
            'finding_sha256': self.gateway.object_sha256(oversized_finding),
            'path': str(selected),
        }
        with mock.patch.object(self.gateway, 'SCAN_STATE_DIR', self.root), \
                mock.patch.object(self.gateway, 'INCIDENT_CONFIG', config):
            oversized_response = self.gateway.snapshot_artifact(
                'extract_file', oversized_arguments)
        self.assertEqual('unavailable', oversized_response['result']['status'])
        oversized = oversized_response['result']['result']
        self.assertEqual({
            'status': 'too_large',
            'path': str(selected),
            'size': self.gateway.MAX_EXTRACT_BYTES + 1,
            'limit': self.gateway.MAX_EXTRACT_BYTES,
        }, oversized)

    def test_bound_capture_follows_relative_and_intermediate_links_without_lexical_collapse(self):
        release = self.root / 'opt/releases/1/app'
        release.parent.mkdir(parents=True)
        release.write_bytes(b'retained release')
        links = self.root / 'usr/local/bin'
        links.mkdir(parents=True)
        (links / 'directory').symlink_to(release.parent, target_is_directory=True)
        selected = links / 'app'
        selected.symlink_to('directory/../1/app')
        digest = hashlib.sha256(release.read_bytes()).hexdigest()
        copied = self.root / 'copy'
        self.assertEqual(digest, self.gateway.capture_host_file(
            str(selected), copied, expected_digests={digest}))
        self.assertEqual(release.read_bytes(), copied.read_bytes())
        with self.assertRaises(OSError):
            self.gateway.capture_host_file(str(selected), self.root / 'unbound')
        with self.assertRaisesRegex(ValueError, 'changed since the scan'):
            self.gateway.capture_host_file(str(selected), self.root / 'wrong', expected_digests={'f' * 64})

    def test_bound_capture_rejects_symlink_switch_and_cycles(self):
        selected = self.root / 'app'
        original = self.root / 'original'
        original.write_bytes(b'expected')
        replacement = self.root / 'replacement'
        replacement.write_bytes(b'unexpected')
        selected.symlink_to(original)
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        readlink = os.readlink

        def switch(name, **kwargs):
            result = readlink(name, **kwargs)
            if name == 'app':
                selected.unlink()
                selected.symlink_to(replacement)
            return result

        with mock.patch.object(self.gateway.os, 'readlink', side_effect=switch):
            with self.assertRaisesRegex(ValueError, 'path changed'):
                self.gateway.capture_host_file(str(selected), self.root / 'copy', expected_digests={digest})
        selected.unlink()
        selected.symlink_to('app')
        with self.assertRaisesRegex(ValueError, 'symlink limit'):
            self.gateway.capture_host_file(str(selected), self.root / 'cycle', expected_digests={digest})

    def test_host_analyzer_reads_captured_release_and_not_a_changed_original(self):
        original = self.root / 'release'
        original.write_bytes(b'expected analyzer input')
        selected = self.root / 'app'
        selected.symlink_to(original)
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        scope = {'containers': [], 'advisories': ['CVE-2026-12345'], 'bindings': [
            {'container_id': None, 'reported_file': str(selected), 'artifact_id': digest}]}
        parsed = []

        def run(argv, _timeout):
            original.write_bytes(b'changed after capture')
            parsed.append(Path(argv[-1]).read_bytes())
            return {'returncode': 1, 'stdout': '', 'stderr': '', 'truncated': False}

        with mock.patch.object(self.gateway, 'bounded_run', side_effect=run), \
                mock.patch.object(self.gateway, 'GOVULNCHECK', self.root / 'uninstalled-analyzer'):
            result = self.gateway.run_analyzer(scope, {'path': str(selected),
                'advisory': 'CVE-2026-12345', 'analyzer': 'govulncheck'})
        self.assertEqual('govulncheck is not installed', result['reason'])
        self.assertEqual([b'expected analyzer input'], parsed)

    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway = load_module(
            "homelab_evidence_gateway_under_test",
            ROOT
            / "ansible"
            / "roles"
            / "homelab_agent_target"
            / "files"
            / "homelab_evidence_gateway.py",
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_root = self.root / "config"
        self.config_root.mkdir()
        self.policy = self.root / "evidence-policy.json"
        self.units = self.root / "units.json"
        self.capabilities = self.root / "capabilities"
        self.policy.write_text(
            json.dumps({"config_roots": [str(self.config_root)]}), encoding="utf-8"
        )
        self.units.write_text(json.dumps({"app": "app.service"}), encoding="utf-8")
        self.patchers = [
            mock.patch.object(self.gateway, "POLICY_FILE", self.policy),
            mock.patch.object(self.gateway, "UNIT_FILE", self.units),
            mock.patch.object(self.gateway, "CAPABILITY_DIR", self.capabilities),
            mock.patch.object(self.gateway, "audit"),
            mock.patch.object(
                self.gateway,
                "docker_inventory",
                return_value={
                    "app": {
                        "id": "a" * 64,
                        "short_id": "a" * 12,
                        "name": "app",
                        "image_id": "sha256:" + "b" * 64,
                        "image_ref": "example/app:1.0",
                    }
                },
            ),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    @staticmethod
    def scope(image_id: str | None = None) -> dict:
        return {
            "schema": 2,
            "groups": [
                {
                    "id": "CVE-2026-12345",
                    "package": "example.org/module",
                    "installed": "1.0.0",
                    "fixed": "1.1.0",
                    "severity": "HIGH",
                    "occurrences": [
                        {
                            "artifact": "example/app:1.0",
                            "artifact_id": image_id or "sha256:" + "b" * 64,
                            "containers": [{"id": "a" * 64, "name": "app"}],
                            "reported_file": "/usr/local/bin/app",
                        }
                    ],
                }
            ],
        }

    def test_open_binds_running_artifact_and_creates_private_state(self) -> None:
        opened = self.gateway.open_capability(self.scope())

        capability_path = self.gateway.capability_path(opened["token"])
        state = json.loads(capability_path.read_text(encoding="utf-8"))
        self.assertEqual(os.stat(capability_path).st_mode & 0o777, 0o600)
        self.assertEqual(state["scope"]["containers"][0]["name"], "app")
        self.assertEqual(state["scope"]["advisories"], ["CVE-2026-12345"])
        self.assertEqual(state["scope"]["reported_files"], ["/usr/local/bin/app"])
        self.assertEqual(opened["protocol"], 2)
        self.assertLessEqual(opened["limits"]["calls"], self.gateway.MAX_CALLS)

    def test_open_rejects_stale_container_image(self) -> None:
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            self.gateway.open_capability(self.scope("sha256:" + "c" * 64))

    def test_missing_container_is_not_reported_as_stopped(self):
        with mock.patch.object(self.gateway, 'docker_inventory', return_value={}):
            with self.assertRaises(ValueError) as caught:
                self.gateway.normalized_scope(self.scope())
        self.assertEqual(caught.exception.details['code'], 'not_found')
        self.assertEqual(caught.exception.details['requested']['name'], 'app')

    def test_stopped_container_has_resolved_identity_and_distinct_result(self):
        item = {'id': 'a'*64, 'short_id': 'a'*12, 'name': 'app', 'image_id': 'sha256:'+'b'*64,
                'running': False, 'state': 'exited', 'pid': 0}
        with mock.patch.object(self.gateway, 'docker_inventory', return_value={'app': item}):
            with self.assertRaises(ValueError) as caught:
                self.gateway.normalized_scope(self.scope())
        self.assertEqual(caught.exception.details['code'], 'not_running')
        self.assertEqual(caught.exception.details['resolved']['id'], 'a'*64)

    def test_out_of_scope_container_has_machine_readable_policy_denial(self):
        with self.assertRaises(ValueError) as caught:
            self.gateway.scoped_container({'containers': []}, 'outside')
        self.assertEqual(caught.exception.details['code'], 'policy_denied')

    def test_mounted_configuration_is_read_inside_the_scoped_container(self):
        config = self.config_root / "Caddyfile"
        config.write_text("host copy is not the observed content")
        scope = self.gateway.normalized_scope(self.scope())
        mount = {
            "Type": "bind",
            "Source": str(config),
            "Destination": "/etc/caddy/Caddyfile",
        }

        def run(argv, *_args, **_kwargs):
            stdout = (
                json.dumps([mount]) if "inspect" in argv else "/etc/caddy/Caddyfile\n"
            )
            return {"stdout": stdout, "returncode": 0, "truncated": False}

        def copy(container, path, destination, limit):
            self.assertEqual(container["id"], "a" * 64)
            self.assertEqual(path, mount["Destination"])
            self.assertEqual(limit, self.gateway.MAX_CONFIG_BYTES)
            destination.write_text("reverse_proxy server:8080\npassword: hidden\n")

        with (
            mock.patch.object(self.gateway, "bounded_run", side_effect=run),
            mock.patch.object(self.gateway, "copy_container_file", side_effect=copy),
        ):
            result = self.gateway.read_config(
                scope, {"container": "app", "path": mount["Destination"]}
            )
        self.assertIn("reverse_proxy server:8080", result["content"])
        self.assertNotIn("host copy", result["content"])
        self.assertNotIn("hidden", result["content"])
        self.assertIn("[REDACTED]", result["content"])

    def test_container_directory_mount_obeys_host_config_file_allowlist(self):
        approved = self.config_root / "datacenter.cfg"
        approved.write_text("approved configuration\n")
        unlisted = self.config_root / "other.cfg"
        unlisted.write_text("unlisted configuration\n")
        self.policy.write_text(json.dumps({
            "config_roots": [str(self.config_root)],
            "config_files": [str(approved)],
        }))
        scope = self.gateway.normalized_scope(self.scope())
        mount = {"Type": "bind", "Source": str(self.config_root), "Destination": "/config"}

        def run(argv, *_args, **_kwargs):
            path = json.dumps([mount]) if "inspect" in argv else f"{argv[-1]}\n"
            return {"stdout": path, "returncode": 0, "truncated": False}

        def copy(_container, _path, destination, _limit):
            destination.write_text("approved configuration\n")

        with (
            mock.patch.object(self.gateway, "bounded_run", side_effect=run),
            mock.patch.object(self.gateway, "copy_container_file", side_effect=copy) as copied,
        ):
            result = self.gateway.read_config(scope, {"container": "app", "path": "/config/datacenter.cfg"})
            self.assertIn("approved configuration", result["content"])
            with self.assertRaises(ValueError):
                self.gateway.read_config(scope, {"container": "app", "path": "/config/other.cfg"})
            self.assertEqual(copied.call_count, 1)

    def test_mount_mapping_never_grants_unapproved_host_paths_or_symlink_escape(self):
        scope = self.gateway.normalized_scope(self.scope())
        outside = self.root / "outside"
        outside.write_text("not approved")
        link = self.config_root / "escaped"
        link.symlink_to(outside)
        for source in (outside, link):
            mount = {
                "Type": "bind",
                "Source": str(source),
                "Destination": "/etc/caddy/Caddyfile",
            }
            with (
                mock.patch.object(
                    self.gateway,
                    "bounded_run",
                    return_value={"stdout": json.dumps([mount]), "returncode": 0},
                ),
                mock.patch.object(self.gateway, "copy_container_file") as copy,
            ):
                with self.assertRaisesRegex(ValueError, "approved roots"):
                    self.gateway.read_config(
                        scope, {"container": "app", "path": mount["Destination"]}
                    )
                copy.assert_not_called()

    def test_container_configuration_symlink_cannot_escape_authorized_mount(self):
        config = self.config_root / "Caddyfile"
        config.write_text("approved")
        scope = self.gateway.normalized_scope(self.scope())
        mount = {
            "Type": "bind",
            "Source": str(config),
            "Destination": "/etc/caddy/Caddyfile",
        }
        with (
            mock.patch.object(
                self.gateway,
                "bounded_run",
                side_effect=[
                    {"stdout": json.dumps([mount]), "returncode": 0},
                    {"stdout": "/etc/shadow\n", "returncode": 0},
                ],
            ),
            mock.patch.object(self.gateway, "copy_container_file") as copy,
        ):
            with self.assertRaisesRegex(ValueError, "symlink escapes"):
                self.gateway.read_config(
                    scope, {"container": "app", "path": mount["Destination"]}
                )
            copy.assert_not_called()

    def test_go_build_metadata_preserves_versions_and_safe_build_settings(self):
        def inline(value):
            size = len(value)
            encoded = bytearray()
            while size >= 128:
                encoded.append((size & 127) | 128)
                size >>= 7
            return bytes(encoded) + bytes([size]) + value

        module = (
            b"x" * 16
            + (
                b"path\texample/app\nmod\tgithub.com/example/app\tv1.2.3\n"
                b"dep\tgolang.org/x/net\tv0.55.0\n"
                b"build\tCGO_ENABLED=0\nbuild\t-ldflags=secret-value\n"
            )
            + b"y" * 16
        )
        blob = (
            b"\xff Go buildinf:"
            + bytes([8, 2])
            + bytes(16)
            + inline(b"go1.26.3")
            + inline(module)
        )
        build = self.gateway.parse_go_build_info(blob)
        self.assertEqual(build["go_version"], "go1.26.3")
        self.assertEqual(build["modules"][0]["version"], "v0.55.0")
        self.assertEqual(build["settings"], {"CGO_ENABLED": "0"})
        self.assertNotIn("secret-value", json.dumps(build))
        with self.assertRaises(ValueError):
            self.gateway.parse_go_build_info(blob[:-20])



    def test_startup_metadata_does_not_disclose_other_arguments(self):
        response = {
            "returncode": 0,
            "stdout": json.dumps("caddy")
            + "\t"
            + json.dumps(
                [
                    "run",
                    "--config",
                    "/etc/caddy/Caddyfile",
                    "--password",
                    "do-not-return",
                ]
            ),
        }
        with mock.patch.object(self.gateway, "bounded_run", return_value=response):
            value = self.gateway.startup_configuration({"id": "a" * 64})
        self.assertEqual(value["configuration_paths"], ["/etc/caddy/Caddyfile"])
        self.assertNotIn("do-not-return", json.dumps(value))

    def test_successful_invoke_accounts_for_calls_and_output_bytes(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        with mock.patch.object(
            self.gateway,
            "invoke_operation",
            return_value={"listeners": ["127.0.0.1:8080"]},
        ) as invoked:
            result = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {"container": "app"}
            )

        self.assertEqual(result["operation"], "list_listeners")
        invoked.assert_called_once()
        state = json.loads(
            self.gateway.capability_path(opened["token"]).read_text(encoding="utf-8")
        )
        self.assertEqual(state["calls"], 1)
        self.assertGreater(state["bytes"], 0)

    def test_failed_invoke_is_audited_with_operation(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        self.gateway.audit.reset_mock()
        with mock.patch.object(
            self.gateway, "invoke_operation", side_effect=ValueError("outside scope")
        ):
            receipt = self.gateway.invoke_capability(
                opened["token"], "package_info", {}
            )["result"]
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("outside scope", receipt["limitations"][0])

        event = self.gateway.audit.call_args.args[0]
        self.assertEqual(event["action"], "invoke")
        self.assertEqual(event["operation"], "package_info")
        self.assertEqual(event["status"], "failed")

    def test_credential_like_configuration_path_is_never_readable(self) -> None:
        scope = self.gateway.normalized_scope(self.scope())
        with self.assertRaisesRegex(ValueError, "never readable"):
            self.gateway.read_config(
                scope, {"path": str(self.config_root / "service-token.yml")}
            )

    def test_host_file_allowlist_rejects_private_keys_and_symlink_targets(self) -> None:
        approved = self.config_root / "datacenter.cfg"
        approved.write_text("keyboard: en-us\n", encoding="utf-8")
        private = self.config_root / "priv"
        private.mkdir()
        key = private / "authkey.key"
        key.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
        disguised = self.config_root / "safe.cfg"
        disguised.symlink_to(key)
        self.policy.write_text(json.dumps({
            "config_roots": [str(self.config_root)],
            "config_files": [str(approved), str(disguised)],
        }))
        scope = self.gateway.normalized_scope(self.scope())

        self.assertIn("keyboard: en-us", self.gateway.read_config(
            scope, {"path": str(approved)})["content"])
        for path in (key, disguised, self.config_root / "unlisted.cfg"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.gateway.read_config(scope, {"path": str(path)})

    def test_pem_private_key_in_allowed_file_is_redacted(self) -> None:
        config = self.config_root / "service.yml"
        config.write_text("name: app\n-----BEGIN PRIVATE KEY-----\nsecret\n"
                          "-----END PRIVATE KEY-----\nnext: retained\n")
        scope = self.gateway.normalized_scope(self.scope())

        content = self.gateway.read_config(scope, {"path": str(config)})["content"]
        self.assertIn("[REDACTED PRIVATE KEY]", content)
        self.assertIn("next: retained", content)
        self.assertNotIn("secret", content)

    def test_nested_secret_values_are_removed_from_allowed_configuration(self) -> None:
        config = self.config_root / "service.yml"
        config.write_text(
            "public: retained\ntokens:\n  - must-not-leak\nnext: retained\n",
            encoding="utf-8",
        )
        scope = self.gateway.normalized_scope(self.scope())

        result = self.gateway.read_config(scope, {"path": str(config)})

        self.assertIn("public: retained", result["content"])
        self.assertIn("tokens:[REDACTED]", result["content"])
        self.assertIn("next: retained", result["content"])
        self.assertNotIn("must-not-leak", result["content"])

    def test_api_keys_are_removed_from_allowed_configuration(self) -> None:
        config = self.config_root / "bouncer.yml"
        config.write_text(
            "api_url: http://127.0.0.1:8080/\n"
            "api_key: exposed-value\n"
            "insecure_skip_verify: false\n",
            encoding="utf-8",
        )
        scope = self.gateway.normalized_scope(self.scope())

        result = self.gateway.read_config(scope, {"path": str(config)})

        self.assertIn("api_key: [REDACTED]", result["content"])
        self.assertNotIn("exposed-value", result["content"])
        structured = self.gateway.redact_result({"api_key": "exposed-value"})
        self.assertEqual(structured, {"api_key": "[REDACTED]"})

    def test_expired_capability_cannot_be_invoked(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        capability_path = self.gateway.capability_path(opened["token"])
        state = json.loads(capability_path.read_text(encoding="utf-8"))
        state["expires"] = 0
        capability_path.write_text(json.dumps(state), encoding="utf-8")

        result = self.gateway.invoke_capability(opened["token"], "list_processes", {})[
            "result"
        ]
        self.assertEqual(result["status"], "failed")
        self.assertIn("expired", result["limitations"][0].lower())

    def test_close_revokes_capability(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        capability_path = self.gateway.capability_path(opened["token"])

        self.gateway.close_capability(opened["token"])

        self.assertFalse(capability_path.exists())

    def test_artifact_investigation_owns_and_closes_the_capability(self) -> None:
        with mock.patch.object(
            self.gateway,
            'invoke_capability',
            return_value={
                'operation': 'inspect_executable',
                'result': {
                    'status': 'success',
                    'remaining': {'calls': 3, 'bytes': 4096, 'seconds': 120},
                },
            },
        ) as invoke:
            result = self.gateway.artifact_investigation(
                self.scope(),
                'inspect_executable',
                {'container': 'app', 'path': '/usr/local/bin/app'},
            )

        self.assertEqual(result['result']['status'], 'success')
        self.assertNotIn('remaining', result['result'])
        token = invoke.call_args.args[0]
        self.assertFalse(self.gateway.capability_path(token).exists())

    def test_artifact_investigation_rejects_operational_reads(self) -> None:
        with mock.patch.object(self.gateway, 'open_capability') as opened:
            with self.assertRaisesRegex(ValueError, 'unsupported artifact operation'):
                self.gateway.artifact_investigation(
                    self.scope(), 'list_processes', {}
                )
        opened.assert_not_called()

    def test_public_legacy_artifact_dispatch_cannot_open_a_capability(self) -> None:
        request = json.dumps({
            'action': 'artifact',
            'scope': self.scope(),
            'operation': 'extract_file',
            'arguments': {'container': 'app', 'path': '/usr/local/bin/app'},
        }).encode()
        stdin = mock.Mock()
        stdin.buffer = io.BytesIO(request)

        with mock.patch.object(sys, 'stdin', stdin), \
                mock.patch.object(self.gateway, 'artifact_investigation',
                                  return_value={}) as legacy, \
                mock.patch.object(self.gateway, 'open_capability') as opened, \
                self.assertRaisesRegex(ValueError, 'unsupported action'):
            self.gateway.main()

        legacy.assert_not_called()
        opened.assert_not_called()
        self.assertFalse(list(self.capabilities.glob('*.json')))

    def test_govulncheck_preserves_scoped_advisory_versions_and_symbols(self) -> None:
        stream = "".join(
            json.dumps(message)
            for message in [
                {'config': {'protocol_version': 'v1.0.0', 'scan_mode': 'binary', 'scan_level': 'symbol'}},
                {'SBOM': {'modules': [{'path': 'example.org/module', 'version': 'v1.0.0'}]}},
                {
                    "osv": {
                        "id": "GO-2026-9999",
                        "aliases": ["CVE-2026-12345"],
                        "summary": "Affected server callback.",
                    }
                },
                {
                    "finding": {
                        "osv": "GO-2026-9999",
                        "fixed_version": "v1.1.0",
                        "trace": [
                            {
                                "module": "example.org/module",
                                "version": "v1.0.0",
                                "receiver": "Server",
                                "package": "example.org/module/server",
                                "function": "Serve",
                            }
                        ],
                    }
                },
                {"osv": {"id": "GO-2026-OTHER", "summary": "unrelated"}},
            ]
        )

        result = self.gateway.summarize_govulncheck(stream, "CVE-2026-12345")

        self.assertEqual(result["status"], "symbol_reported")
        self.assertEqual(result["advisories"][0]["id"], "GO-2026-9999")
        self.assertEqual(result["symbols"], ["example.org/module/server.Server.Serve"])
        self.assertNotIn("GO-2026-OTHER", json.dumps(result))
        self.assertEqual(result['affected_versions'], [{'module': 'example.org/module', 'installed': 'v1.0.0', 'fixed': 'v1.1.0'}])


    def test_container_listeners_are_read_from_its_network_namespace(self) -> None:
        scope = self.gateway.normalized_scope(self.scope())
        with (
            mock.patch.object(self.gateway, "process_ids", return_value=[1234]),
            mock.patch.object(
                self.gateway,
                "bounded_run",
                return_value={
                    "returncode": 0,
                    "stdout": "tcp LISTEN 0 10 *:8080\n",
                    "stderr": "",
                },
            ) as run,
        ):
            result = self.gateway.invoke_operation(
                scope, "list_listeners", {"container": "app"}
            )

        self.assertEqual(result["listeners"], ["tcp LISTEN 0 10 *:8080"])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/nsenter", "--target", "1234", "--net"])

    def test_failed_attempts_are_charged_and_budget_denial_is_a_receipt(self):
        opened = self.gateway.open_capability(self.scope())
        path = self.gateway.capability_path(opened["token"])
        state = json.loads(path.read_text())
        state["limits"]["calls"] = 1
        path.write_text(json.dumps(state))
        with mock.patch.object(
            self.gateway, "invoke_operation", side_effect=RuntimeError("check failed")
        ):
            first = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {}
            )["result"]
            second = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {}
            )["result"]
        self.assertEqual(first["status"], "failed")
        self.assertIn("budget", second["limitations"][0])
        self.assertEqual(json.loads(path.read_text())["calls"], 1)

    def test_lock_allows_two_reads_and_revocation_discards_inflight_result(self):
        import threading

        opened = self.gateway.open_capability(self.scope())
        entered = threading.Barrier(3)
        release = threading.Event()
        results = []

        def invoke(*args):
            entered.wait(timeout=3)
            release.wait(timeout=3)
            return {"listeners": []}

        def worker():
            results.append(
                self.gateway.invoke_capability(opened["token"], "list_listeners", {})[
                    "result"
                ]
            )

        with mock.patch.object(self.gateway, "invoke_operation", side_effect=invoke):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            try:
                entered.wait(timeout=3)
                self.gateway.close_capability(opened["token"])
            finally:
                release.set()
                for thread in threads:
                    thread.join(timeout=3)
        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(r["status"] == "failed" and not r["result"] for r in results)
        )

    def test_stale_runtime_never_produces_successful_empty_result(self):
        opened = self.gateway.open_capability(self.scope())
        with mock.patch.object(self.gateway, "docker_inventory", return_value={}):
            result = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {"container": "app"}
            )["result"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result['failure']['code'], 'not_found')
        self.assertEqual(result['failure']['lookup']['stage'], 'before_operation')

    def test_failed_listener_command_is_not_negative_evidence(self):
        with mock.patch.object(
            self.gateway,
            "bounded_run",
            return_value={
                "returncode": 1,
                "stdout": "",
                "stderr": "denied",
                "truncated": False,
            },
        ):
            with self.assertRaises(RuntimeError):
                self.gateway.invoke_operation({"containers": []}, "list_listeners", {})

    def test_discovered_executable_is_bound_to_its_container(self):
        scope = self.gateway.normalized_scope(self.scope())
        scope["discovered_files"] = {"a" * 64: ["/usr/bin/discovered"]}
        container = scope["containers"][0]
        self.assertEqual(
            self.gateway.allowed_reported_file(scope, "/usr/bin/discovered", container),
            "/usr/bin/discovered",
        )
        with self.assertRaises(ValueError):
            self.gateway.allowed_reported_file(scope, "/usr/bin/discovered", None)

    def test_nested_failure_and_truncation_produce_incomplete_receipts(self):
        opened = self.gateway.open_capability(self.scope())
        for result in ({'state': {'returncode': 1}}, {'maps': {'truncated': True}}):
            with self.subTest(result=result), mock.patch.object(self.gateway, 'invoke_operation', return_value=result):
                receipt = self.gateway.invoke_capability(opened['token'], 'list_processes', {})['result']
            self.assertEqual(receipt['status'], 'incomplete')
            self.assertTrue(receipt['truncated'])

    def test_failed_or_empty_analyzer_output_cannot_establish_absence(self):
        analyzer_path = self.root / 'govulncheck'
        analyzer_path.write_bytes(b'analyzer fixture')
        for returncode in (0, 1):
            with self.subTest(returncode=returncode):
                opened = self.gateway.open_capability(self.scope())
                def copy_file(container, path, destination):
                    destination.write_bytes(b'ELF fixture')
                with mock.patch.object(self.gateway, 'copy_container_file', side_effect=copy_file), \
                        mock.patch.object(self.gateway, 'GOVULNCHECK', analyzer_path), \
                        mock.patch.object(self.gateway, 'govulncheck_database_revision', return_value=None), \
                        mock.patch.object(self.gateway, 'limited_output_run', return_value={
                            'returncode': returncode, 'stdout': '', 'stderr': '', 'overflow': False, 'timed_out': False}) as run:
                    result = self.gateway.invoke_capability(opened['token'], 'run_analyzer', {
                        'analyzer': 'govulncheck', 'container': 'app', 'path': '/usr/local/bin/app', 'advisory': 'CVE-2026-12345'})['result']
                analyzer_calls = [call for call in run.call_args_list if call.args[0][0] == str(analyzer_path)]
                self.assertEqual(len(analyzer_calls), 1)
                self.assertEqual(result['status'], 'unavailable')
                expected_reason = 'invalid govulncheck output' if returncode == 0 else 'govulncheck failed'
                self.assertIn(expected_reason, result['result']['reason'])

    def test_binary_analysis_is_reused_only_after_hashing_current_file(self):
        scope = self.gateway.normalized_scope(self.scope())
        content = [b"same executable"]
        analyzer_path = self.root / 'govulncheck'
        analyzer_path.write_bytes(b'analyzer fixture')
        revision = {'modified': '2026-09-08T10:00:00Z', 'sha256': 'd' * 64}

        def copy_file(container, path, destination):
            destination.write_bytes(content[0])

        stream = json.dumps({'config': {'protocol_version': 'v1.0.0', 'scan_mode': 'binary', 'scan_level': 'symbol',
                            'scanner_name': 'govulncheck', 'scanner_version': 'v1.1.4', 'db': 'https://vuln.go.dev',
                            'db_last_modified': revision['modified']}})
        stream += json.dumps({'SBOM': {'modules': [{'path': 'example.org/module', 'version': 'v1.0.0'}]}})
        with (
            mock.patch.object(
                self.gateway, "copy_container_file", side_effect=copy_file
            ),
            mock.patch.object(self.gateway, 'GOVULNCHECK', analyzer_path),
            mock.patch.object(self.gateway, 'govulncheck_database_revision', return_value=revision),
            mock.patch.object(
                self.gateway,
                "limited_output_run",
                return_value={
                    "returncode": 0,
                    "stdout": stream,
                    "stderr": "",
                    "overflow": False,
                    "timed_out": False,
                },
            ) as analyzer,
        ):
            args = {
                "analyzer": "govulncheck",
                "container": "app",
                "path": "/usr/local/bin/app",
                "advisory": "CVE-2026-12345",
            }
            self.gateway.run_analyzer(scope, args)
            reused = self.gateway.run_analyzer(scope, args)
            self.assertTrue(reused["reused_analysis"])
            self.assertEqual(
                sum(
                    call.args[0][0] == str(analyzer_path)
                    for call in analyzer.call_args_list
                ),
                1,
            )
            content[0] = b"changed executable"
            self.gateway.run_analyzer(scope, args)
            self.assertEqual(
                sum(
                    call.args[0][0] == str(analyzer_path)
                    for call in analyzer.call_args_list
                ),
                2,
            )

    def test_small_read_budget_cannot_overbook_concurrent_reservations(self):
        import threading

        opened = self.gateway.open_capability(self.scope())
        path = self.gateway.capability_path(opened["token"])
        state = json.loads(path.read_text())
        state["limits"]["total_bytes"] = self.gateway.MAX_RESULT_BYTES
        path.write_text(json.dumps(state))
        entered, release = threading.Event(), threading.Event()

        def invoke(*args):
            entered.set()
            release.wait(timeout=3)
            return {"listeners": []}

        with mock.patch.object(self.gateway, "invoke_operation", side_effect=invoke):
            thread = threading.Thread(
                target=lambda: self.gateway.invoke_capability(
                    opened["token"], "list_listeners", {}
                )
            )
            thread.start()
            try:
                self.assertTrue(entered.wait(timeout=3))
                second = self.gateway.invoke_capability(
                    opened["token"], "list_listeners", {}
                )["result"]
                self.assertEqual(second["status"], "failed")
                self.assertIn("budget", second["limitations"][0])
            finally:
                release.set()
                thread.join(timeout=3)
        self.assertEqual(json.loads(path.read_text())["pending"], {})


if __name__ == "__main__":
    unittest.main()
