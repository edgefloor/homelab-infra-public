import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / 'ansible/roles/homelab_agent_target/files/homelab_alert_read.py'
SPEC = importlib.util.spec_from_file_location('homelab_alert_read', SOURCE)
ALERTS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ALERTS)


class AlertReadTests(unittest.TestCase):
    def write_record(self, root: Path, record_id: str, *, kind: str, payload: dict, received_at: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{record_id}.json').write_text(json.dumps({
            'schema': 1,
            'record_id': record_id,
            'received_at': received_at,
            'kind': kind,
            'status': 'delivered',
            'payload': payload,
            'deliveries': [{
                'room': 'vulnerabilities',
                'transaction_id': record_id,
                'matrix_event_id': '$event',
            }],
        }))

    def test_list_filters_without_discarding_retrievable_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cve_id = 'crowdsec_' + 'a' * 40
            release_id = 'crowdsec_' + 'b' * 40
            cve_payload = {'source': 'Caddy', 'context': {'groups': [{'id': 'CVE-2026-1234'}]}}
            self.write_record(root, cve_id, kind='cve', payload=cve_payload,
                              received_at='2026-09-07T17:30:00+00:00')
            self.write_record(root, release_id, kind='release', payload={'source': 'Caddy'},
                              received_at='2026-09-07T17:31:00+00:00')

            listed = ALERTS.query(root, {
                'action': 'list', 'kind': 'cve', 'contains': 'CVE-2026-1234', 'limit': 10,
            })
            fetched = ALERTS.query(root, {'action': 'get', 'record_id': cve_id})

        self.assertEqual([item['record_id'] for item in listed['records']], [cve_id])
        self.assertNotIn('payload', listed['records'][0])
        self.assertEqual(fetched['record']['payload'], cve_payload)

    def test_get_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                ALERTS.query(Path(directory), {'action': 'get', 'record_id': '../secrets'})


if __name__ == '__main__':
    unittest.main()
