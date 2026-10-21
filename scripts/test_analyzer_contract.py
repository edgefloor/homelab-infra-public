"""Govulncheck evidence levels and reuse boundaries, without scanning a host."""
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PATH = Path(os.environ.get('HOMELAB_TEST_INSTALLED_GATEWAY') or
            Path(__file__).resolve().parents[1] / 'ansible/roles/homelab_agent_target/files/homelab_evidence_gateway.py')
spec = importlib.util.spec_from_file_location('analyzer_gateway', PATH,
           loader=importlib.machinery.SourceFileLoader('analyzer_gateway', str(PATH)))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
ADVISORY = 'CVE-2026-12345'
REVISION = {'modified': '2026-09-08T10:00:00Z', 'sha256': 'd' * 64}


def stream(frame=None, *, mode='binary', level='symbol', revision=None):
    messages = [
        {'config': {'protocol_version': 'v1.0.0', 'scanner_name': 'govulncheck',
                    'scanner_version': 'v1.1.4', 'scan_mode': mode, 'scan_level': level,
                    'db': 'https://vuln.go.dev', 'db_last_modified': (revision or REVISION)['modified']}},
        {'SBOM': {'go_version': 'go1.26.4', 'modules': [{'path': 'example.org/lib', 'version': 'v1.0.0'}]}},
        {'osv': {'id': 'GO-2026-9999', 'aliases': [ADVISORY], 'modified': REVISION['modified']}},
    ]
    if frame is not None:
        messages.append({'finding': {'osv': 'GO-2026-9999', 'trace': frame, 'fixed_version': 'v1.1.0'}})
    return ''.join(json.dumps(m) for m in messages)


class AnalyzerContractTests(unittest.TestCase):
    def test_module_scan_does_not_claim_absent_packages_or_symbols(self):
        result = gateway.summarize_govulncheck(stream([{'module': 'example.org/lib'}], level='module'), ADVISORY)
        self.assertEqual(result['evidence_level'], 'module')
        self.assertEqual(result['checks']['symbol'], 'not_checked')
        self.assertNotIn('no affected package', result['interpretation'])
        self.assertEqual(result['deployment_exposure'], 'not_assessed')

    def test_binary_symbols_are_reported_not_proof_of_exploitability(self):
        result = gateway.summarize_govulncheck(stream([{'module': 'example.org/lib', 'package': 'example.org/lib', 'function': 'Parse'}]), ADVISORY)
        self.assertEqual(result['evidence_level'], 'symbol')
        self.assertEqual(result['status'], 'symbol_reported')
        self.assertEqual(result['checks']['call_path'], 'not_checked')
        self.assertEqual(result['artifact_applicability'], 'not_established')
        self.assertTrue(any('fallback' in v for v in result['limitations']))

    def test_source_trace_uses_vulnerable_first_frame_not_entry_point(self):
        trace = [{'module': 'example.org/lib', 'version': 'v1.0.0', 'package': 'example.org/lib', 'function': 'Parse'},
                 {'module': 'app', 'version': 'v9.0.0', 'package': 'app', 'function': 'main'}]
        result = gateway.summarize_govulncheck(stream(trace, mode='source'), ADVISORY)
        self.assertEqual(result['evidence_level'], 'call_path')
        self.assertEqual(result['symbols'], ['example.org/lib.Parse'])
        self.assertEqual(result['affected_versions'][0]['module'], 'example.org/lib')
        self.assertEqual(result['deployment_exposure'], 'not_assessed')

    def test_unknown_or_incomplete_protocol_cannot_be_a_clean_result(self):
        for value in ('{}', '[]', json.dumps({'config': {'scanMode': 'binary'}}),
                      stream().replace('v1.0.0', 'v99.0.0'), stream().replace('"SBOM"', '"unexpected"'),
                      stream() + json.dumps({'finding': {'osv': 'GO-2026-9999', 'trace': []}})):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gateway.summarize_govulncheck(value, ADVISORY)

    def test_not_reported_is_not_a_non_reachable_verdict(self):
        result = gateway.summarize_govulncheck(stream(), ADVISORY)
        self.assertEqual(result['status'], 'not_reported')
        self.assertEqual(result['artifact_applicability'], 'not_established')
        self.assertEqual(result['checks']['symbol'], 'not_reported')

    def test_cache_rechecks_database_and_analyzer_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / 'artifact'
            artifact.write_bytes(b'ELF fixture')
            analyzer = Path(directory) / 'govulncheck'
            analyzer.write_bytes(b'analyzer one')
            scope = {'advisories': [ADVISORY], 'analyzer_cache': {}}
            current_revision = copy.deepcopy(REVISION)
            def analyze(*args, **kwargs):
                return {'stdout': stream(revision=current_revision), 'stderr': '', 'returncode': 0,
                        'timed_out': False, 'overflow': False}
            with mock.patch.object(gateway, 'GOVULNCHECK', analyzer, create=True), \
                 mock.patch.object(gateway, 'govulncheck_database_revision', side_effect=lambda: copy.deepcopy(current_revision), create=True), \
                 mock.patch.object(gateway.Path, 'exists', return_value=True), \
                 mock.patch.object(gateway, 'scoped_container', return_value=None), \
                 mock.patch.object(gateway, 'allowed_reported_file', return_value=str(artifact)), \
                 mock.patch.object(gateway, 'validate_host_binary'), \
                 mock.patch.object(gateway, 'go_build_info', return_value={'status': 'available'}), \
                 mock.patch.object(gateway, 'limited_output_run', side_effect=analyze) as run:
                args = {'analyzer': 'govulncheck', 'advisory': ADVISORY}
                gateway.run_analyzer(scope, args)
                self.assertTrue(gateway.run_analyzer(scope, args)['reused_analysis'])
                self.assertEqual(run.call_count, 1)
                current_revision.update(modified='2026-09-08T11:00:00Z', sha256='e' * 64)
                self.assertFalse(gateway.run_analyzer(scope, args).get('reused_analysis', False))
                analyzer.write_bytes(b'analyzer two')
                self.assertFalse(gateway.run_analyzer(scope, args)['reused_analysis'])
                artifact.write_bytes(b'changed executable')
                self.assertFalse(gateway.run_analyzer(scope, args)['reused_analysis'])
                self.assertEqual(run.call_count, 4)
                with mock.patch.object(gateway, 'govulncheck_database_revision', return_value=None):
                    result = gateway.run_analyzer(scope, args)
                    self.assertFalse(result['reused_analysis'])
                    self.assertFalse(result['cache']['eligible'])
                self.assertTrue(all('executable' not in entry and 'go_build' not in entry
                                    for entry in scope['analyzer_cache'].values()))
                scope['analyzer_cache'] = {}
                with mock.patch.object(gateway, 'govulncheck_database_revision', side_effect=[current_revision, REVISION]):
                    self.assertFalse(gateway.run_analyzer(scope, args)['cache']['eligible'])
                    self.assertFalse(scope['analyzer_cache'])
                with mock.patch.object(gateway, 'limited_output_run', return_value={
                        'stdout': stream(mode='source'), 'stderr': '', 'returncode': 0,
                        'timed_out': False, 'overflow': False}):
                    self.assertEqual(gateway.run_analyzer(scope, args)['status'], 'unavailable')

    def test_cache_identity_changes_with_advisory_options_and_adapter(self):
        original = gateway.analyzer_cache_identity('a' * 64, ADVISORY, 'b' * 64, REVISION)
        self.assertNotEqual(original, gateway.analyzer_cache_identity('a' * 64, 'CVE-2026-99999', 'b' * 64, REVISION))
        with mock.patch.object(gateway, 'ANALYZER_ADAPTER_VERSION', 999):
            self.assertNotEqual(original, gateway.analyzer_cache_identity('a' * 64, ADVISORY, 'b' * 64, REVISION))
        with mock.patch.object(gateway, 'GOVULNCHECK_OPTIONS', ('-mode', 'source')):
            self.assertNotEqual(original, gateway.analyzer_cache_identity('a' * 64, ADVISORY, 'b' * 64, REVISION))

    def test_database_probe_is_bounded_and_rejects_missing_or_invalid_revisions(self):
        for raw in (b'{}', b'[]', b'x' * 8193, b'{"modified":"invalidZ"}', b'{"modified":null}'):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = gateway.GO_VULN_DB + '/index/db.json'
            response.read.return_value = raw
            with self.subTest(raw=raw[:40]), mock.patch.object(gateway.urllib.request, 'urlopen', return_value=response):
                self.assertIsNone(gateway.govulncheck_database_revision())
                response.read.assert_called_once_with(8193)

    def test_reported_warnings_are_not_lost(self):
        result = gateway.summarize_govulncheck(stream() + json.dumps({'progress': {'message': 'warning: incomplete build metadata'}}), ADVISORY)
        self.assertEqual(result['warnings'], ['warning: incomplete build metadata'])

    def test_binary_mode_never_accepts_source_call_paths(self):
        trace = [{'module': 'example.org/lib', 'function': 'Parse'}, {'module': 'app', 'function': 'main'}]
        with self.assertRaises(ValueError):
            gateway.summarize_govulncheck(stream(trace), ADVISORY)


if __name__ == '__main__':
    unittest.main()
