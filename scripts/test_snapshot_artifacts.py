"""Artifact reads must derive authority from acknowledged scan bytes."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_analyzer_contract import gateway


class SnapshotArtifactTests(unittest.TestCase):
    def test_advisory_endpoint_rejects_urls_and_reports_pagination(self):
        with self.assertRaises(ValueError):
            gateway.advisory_record({'advisory': 'https://example.test/private'})
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps({'id': 'CVE-2026-12345', 'details': 'a'*2000}).encode()
        with mock.patch.object(gateway.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = response
            result = gateway.advisory_record({'advisory': 'CVE-2026-12345'})
            self.assertEqual(result['next_offset'], 1800)
            self.assertEqual(len(result['content']), 1800)
            self.assertEqual(opener.return_value.open.call_args.args[0], 'https://api.osv.dev/v1/vulns/CVE-2026-12345')

    def test_binding_rejects_stale_scan_changed_finding_and_unreported_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = {'id': 'CVE-2026-12345', 'package': 'stdlib', 'target': '/usr/bin/app',
                       'artifact_id': 'a'*64, 'containers': [], 'scope': 'binary:/usr/bin/app'}
            snapshot = {'schema': 1, 'source': 'test', 'generation': 'one', 'sequence': 1,
                        'observed_at': gateway.time.time(), 'findings': [finding]}
            sha = lambda v: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
            envelope = {'snapshot': snapshot, 'sha256': sha(snapshot)}
            (root/'cve-state.incident-snapshot.json').write_text(json.dumps(envelope))
            config = root/'config.json'
            config.write_text(json.dumps({'source': 'test', 'generation': 'one'}))
            args = {'snapshot_sha256': sha(snapshot), 'finding_sha256': sha(finding), 'path': '/usr/bin/app'}
            with mock.patch.object(gateway, 'SCAN_STATE_DIR', root), mock.patch.object(gateway, 'INCIDENT_CONFIG', config), \
                 mock.patch.object(gateway, 'artifact_investigation', return_value={'ok': True}) as invoke:
                gateway.snapshot_artifact('inspect_executable', args)
                gateway.snapshot_artifact('extract_file', args)
                self.assertEqual(invoke.call_args.args[0]['groups'][0]['occurrences'][0]['artifact_id'], 'a'*64)
                for operation in ('inspect_executable', 'extract_file'):
                    for changes in ({'snapshot_sha256': 'b'*64},
                                    {'finding_sha256': 'c'*64},
                                    {'path': '/etc/shadow'}):
                        with self.subTest(operation=operation, changes=changes), \
                                self.assertRaises(ValueError):
                            gateway.snapshot_artifact(
                                operation, {**args, **changes})
                self.assertEqual(invoke.call_count, 2)
                snapshot['observed_at'] -= 40*3600
                (root/'cve-state.incident-snapshot.json').write_text(json.dumps({'snapshot': snapshot, 'sha256': sha(snapshot)}))
                with self.assertRaises(ValueError):
                    gateway.snapshot_artifact('inspect_executable', {**args, 'snapshot_sha256': sha(snapshot)})
                (root/'cve-state.incident-snapshot.json').unlink()
                with self.assertRaisesRegex(ValueError, 'unavailable'):
                    gateway.snapshot_artifact('extract_file', args)


if __name__ == '__main__':
    unittest.main()
