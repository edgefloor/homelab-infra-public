"""Cross-source cache authorization, single-flight leases and retention."""
import copy
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'ansible/roles/vulnerability_incidents/files'))
from incident_service import IncidentAPI
from incident_store import IncidentStore
from test_analyzer_contract import gateway, stream, ADVISORY, REVISION


class SharedArtifactCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1000000
        self.store = IncidentStore(Path(self.temp.name)/'db', clock=lambda: self.now)
        self.api = IncidentAPI(self.store, {name: {'role': role, 'token': name, 'generation': 'one'}
                              for name, role in [('a', 'source'), ('b', 'source'), ('worker', 'worker'), ('reader', 'reader')]})
        self.identity = gateway.analyzer_cache_identity('a'*64, ADVISORY, 'b'*64, REVISION)
        self.report = {**gateway.summarize_govulncheck(stream(), ADVISORY), 'sha256': 'a'*64,
                       'advisory': ADVISORY, 'analyzer': 'govulncheck', 'analysis_timestamp': self.now,
                       'cache': {'eligible': True, 'identity': self.identity, 'scope': 'artifact_only', 'storage': 'shared'},
                       'reused_analysis': False}

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def call(self, source, action, **kwargs):
        return self.api.call('Bearer '+source, {'action': 'artifact_cache_'+action, 'identity': self.identity, **kwargs})

    def test_sources_share_one_analysis_but_worker_cannot_publish(self):
        lease = self.call('a', 'acquire')
        self.assertEqual(lease['status'], 'acquired')
        self.assertEqual(self.call('b', 'acquire')['status'], 'busy')
        for source in ('b', 'worker', 'reader'):
            with self.subTest(source=source), self.assertRaises((PermissionError, ValueError)):
                self.call(source, 'publish', lease=lease['lease'], report=self.report)
        self.call('a', 'publish', lease=lease['lease'], report=self.report)
        hit = self.call('b', 'acquire')
        self.assertEqual(hit['status'], 'hit')
        self.assertEqual(hit['publisher'], 'a')
        self.assertEqual(hit['report']['sha256'], 'a'*64)
        self.identity = {**self.identity, 'analyzer_sha256': 'c'*64}
        self.assertEqual(self.call('b', 'acquire')['status'], 'acquired')

    def test_rejects_deployment_state_bad_provenance_and_oversized_reports(self):
        lease = self.call('a', 'acquire')['lease']
        for change in ({'executable': '/private/path'}, {'deployment_exposure': 'safe'}, {'sha256': 'c'*64},
                       {'details': 'x'*70000}, {'cache': {'eligible': False}}, {'warnings': ['incomplete']}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.call('a', 'publish', lease=lease, report={**copy.deepcopy(self.report), **change})
        self.call('a', 'publish', lease=lease, report=self.report)

    def test_expired_lease_is_fenced_and_cache_expires(self):
        old = self.call('a', 'acquire')['lease']
        self.now += 401
        new = self.call('b', 'acquire')['lease']
        with self.assertRaises(ValueError):
            self.call('a', 'publish', lease=old, report=self.report)
        self.report['analysis_timestamp'] = self.now
        self.call('b', 'publish', lease=new, report=self.report)
        self.now += 8*86400
        self.assertEqual(self.call('a', 'acquire')['status'], 'acquired')

    def test_gateway_reuses_across_independent_capabilities_and_paths(self):
        self.now = gateway.time.time()
        root = Path(self.temp.name)
        artifact = root/'app'
        artifact.write_bytes(b'exact binary')
        other = root/'another-path'
        other.write_bytes(artifact.read_bytes())
        analyzer = root/'govulncheck'
        analyzer.write_bytes(b'analyzer fixture')
        config = root/'settings'
        config.write_text('{}')
        publisher = 'a'
        def transport(action, identity, **kwargs):
            return self.api.call('Bearer '+publisher, {'action': 'artifact_cache_'+action, 'identity': identity, **kwargs})
        with mock.patch.object(gateway, 'INCIDENT_CONFIG', config), mock.patch.object(gateway, 'GOVULNCHECK', analyzer), \
             mock.patch.object(gateway, 'shared_cache_call', side_effect=transport), \
             mock.patch.object(gateway, 'govulncheck_database_revision', return_value=REVISION), \
             mock.patch.object(gateway, 'scoped_container', return_value=None), \
             mock.patch.object(gateway, 'allowed_reported_file', side_effect=lambda scope, path, container: path), \
             mock.patch.object(gateway, 'validate_host_binary'), mock.patch.object(gateway, 'go_build_info', return_value={'status': 'available'}), \
             mock.patch.object(gateway, 'limited_output_run', return_value={'stdout': stream(), 'stderr': '', 'returncode': 0,
                                                                         'timed_out': False, 'overflow': False}) as run:
            arguments = {'path': str(artifact), 'advisory': ADVISORY, 'analyzer': 'govulncheck'}
            first = gateway.run_analyzer({'advisories': [ADVISORY]}, arguments)
            self.assertFalse(first['reused_analysis'])
            publisher = 'b'
            second = gateway.run_analyzer({'advisories': [ADVISORY]}, {**arguments, 'path': str(other)})
            self.assertTrue(second['reused_analysis'])
            self.assertEqual(second['executable'], str(other))
            self.assertEqual(second['shared_provenance']['publisher'], 'a')
            self.assertEqual(run.call_count, 1)

    def test_capacity_is_bounded_and_revoked_publishers_are_not_reused(self):
        import artifact_cache
        with mock.patch.object(artifact_cache, 'MAX_ENTRIES', 2):
            for char in ('a', 'b', 'c'):
                self.identity['executable_sha256'] = char*64
                self.report['sha256'] = char*64
                lease = self.call('a', 'acquire')['lease']
                self.call('a', 'publish', lease=lease, report=self.report)
            self.assertEqual(self.store.db.execute('SELECT count(*) FROM artifact_reports').fetchone()[0], 2)
            del self.api.credentials['a']
            self.api = IncidentAPI(self.store, self.api.credentials)
            self.assertEqual(self.call('b', 'acquire')['status'], 'acquired')


if __name__ == '__main__':
    unittest.main()
