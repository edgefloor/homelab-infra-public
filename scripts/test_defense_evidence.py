import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from defense_readiness import assess as readiness

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUEST = load('guest_router_test', 'ansible/roles/homelab_agent_target/files/homelab_guest_agent.py')
CANDIDATE = load('candidate_test', 'ansible/roles/update_monitor/files/homelab_verify_candidate.py')
COVERAGE = load('coverage_reader_test', 'ansible/roles/update_monitor/files/homelab_coverage_read.py')


class DefenseEvidenceTests(unittest.TestCase):
    def test_proxy_denies_arbitrary_guests_commands_and_restarts(self):
        config = {'external_guests': [{'id': 112}]}
        request = {'guest': 112, 'command': ['evidence'], 'input': '{}'}
        self.assertIn('112', GUEST.validate(request, config))
        for invalid in ({**request, 'guest': 205}, {**request, 'guest': '112;sh'},
                        {**request, 'command': ['sh']}, {**request, 'command': ['restart', 'ssh']},
                        {**request, 'input': 'x' * (128 * 1024 + 1)}):
            with self.subTest(request=invalid.get('command')):
                with self.assertRaises(ValueError):
                    GUEST.validate(invalid, config)

    def test_zero_candidate_packages_never_means_fixed(self):
        self.assertEqual(CANDIDATE.assess({'Results': []}, 'stdlib', 'gobinary', 'CVE-2026-1')['status'], 'unknown')

    def test_candidate_advisory_match_blocks_verification(self):
        report = {'Results': [{'Type': 'gobinary', 'Packages': [{'Name': 'stdlib', 'Version': '1.0'}],
                               'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1'}]}]}
        self.assertEqual(CANDIDATE.assess(report, 'stdlib', 'gobinary', 'CVE-2026-1')['status'], 'affected')
        self.assertEqual(CANDIDATE.assess(report, 'stdlib', 'gobinary', 'CVE-2026-2')['status'], 'verified_for_advisory')

    def test_config_drift_invalidates_a_recent_successful_scan(self):
        config = {'host': 'test', 'deployments': []}
        now = datetime.now(UTC)
        state = {'updated_at': now.isoformat(), 'findings': {}, 'coverage': {'discovery': {'config_sha256': 'outdated'}}}
        status = {'status': 'complete', 'observed_at': now.isoformat()}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'cve-state.json').write_text(json.dumps(state))
            (root / 'cve-state.status.json').write_text(json.dumps(status))
            self.assertEqual(COVERAGE.snapshot(config, '', root)['status'], 'unknown')
        self.assertFalse(readiness(config, state, status, now)['scan_current'])

    def test_stale_coverage_cannot_publish_a_negative_advisory_result(self):
        config = {'host': 'test', 'deployments': []}
        old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        state = {'updated_at': old, 'findings': {}, 'coverage': {'discovery': {
            'config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'cve-state.json').write_text(json.dumps(state))
            (root / 'cve-state.status.json').write_text(json.dumps({'status': 'complete', 'observed_at': old}))
            result = COVERAGE.snapshot(config, 'CVE-2026-1', root)
            self.assertEqual(result['status'], 'unknown')

    def test_complete_os_scan_does_not_enable_native_application_patching(self):
        config = {'host': 'test', 'deployments': [{'id': 'app', 'adapters': ['os_packages', 'rust_artifact_sbom']}]}
        now = datetime.now(UTC)
        state = {'updated_at': now.isoformat(), 'coverage': {'os_packages': True, 'discovery': {
            'config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}}}
        result = readiness(config, state, {'status': 'complete', 'observed_at': now.isoformat()}, now)
        deployment = result['deployments'][0]
        self.assertFalse(deployment['automatic_patch_eligible'])
        self.assertEqual(deployment['adapters']['rust_artifact_sbom']['status'], 'unsupported')
