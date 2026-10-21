"""Exercise inventory-to-Matrix delivery with a captured HTTP transport."""
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock
import test_vulnerability_incidents as fixtures

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ansible/roles/vulnerability_incidents/files'))
sys.path.insert(0,str(ROOT/'ansible/roles/tuwunel/files'))
from incident_service import IncidentAPI, delivery_loop, message_html
from crowdsec_matrix_bridge import MatrixClient


class DeliveryTests(unittest.TestCase):
    setUp=fixtures.IncidentTests.setUp
    tearDown=fixtures.IncidentTests.tearDown

    def test_work_alert_keeps_minimal_html_fallback_and_stable_root_delivery(self):
        self.store.ingest(fixtures.snapshot())
        incident=self.store.get_incident('CVE-2026-1234')
        work=self.store.lifecycle.ensure_work(incident['id'],'targetable_path','decision:one')
        card=self.store.lifecycle.next_publication()
        self.store.lifecycle.publication_sent(card['id'],'kanban://card/1')
        root_intent=self.store.lifecycle.next_publication()
        matrix=MatrixClient('http://matrix.invalid','!room','beszel-token')
        def deliver(event):
            stop=mock.Mock()
            stop.wait.side_effect=[False,True]
            with mock.patch('crowdsec_matrix_bridge.request.urlopen') as request:
                request.return_value.__enter__.return_value=io.BytesIO(json.dumps({'event_id':event}).encode())
                delivery_loop(self.store,matrix,stop,lifecycle_enabled=True)
                sent=request.call_args.args[0]
                return json.loads(sent.data),sent.get_header('Authorization')
        root,root_auth=deliver('$root')
        self.assertEqual(root_auth,'Bearer beszel-token')
        self.assertTrue(root['formatted_body'].startswith('<strong>CVE-2026-1234'))
        self.assertEqual(root['body'].splitlines()[1],'Reason: targetable_path')
        self.assertIn('kanban://card/1',root['body'])
        self.assertNotIn('Zig',root['body'])
        self.assertNotIn('m.relates_to',root)
        self.assertEqual('$root',self.store.lifecycle.work(work['id'])['thread'])
        sent=self.store.db.execute('SELECT external_id,state FROM lifecycle_publications WHERE id=?',(root_intent['id'],)).fetchone()
        self.assertEqual(('$root','sent'),tuple(sent))

    def test_lifecycle_publication_stays_pending_until_activation(self):
        self.store.ingest(fixtures.snapshot())
        incident=self.store.get_incident('CVE-2026-1234')
        self.store.lifecycle.ensure_work(incident['id'],'targetable_path','decision:disabled')
        card=self.store.lifecycle.next_publication()
        self.store.lifecycle.publication_sent(card['id'],'kanban://card/disabled')
        with self.store.db:
            self.store.db.execute('DELETE FROM outbox')
        stop=mock.Mock()
        stop.wait.side_effect=[False,True]
        matrix=mock.Mock()
        delivery_loop(self.store,matrix,stop,lifecycle_enabled=False)
        matrix.send.assert_not_called()
        self.assertEqual('matrix_root',self.store.lifecycle.next_publication()['kind'])

    def test_lost_matrix_ack_retries_the_same_transaction(self):
        self.store.ingest(fixtures.snapshot())
        incident=self.store.get_incident('CVE-2026-1234')
        work=self.store.lifecycle.ensure_work(
            incident['id'],'targetable_path','decision:matrix-retry')
        card=self.store.lifecycle.next_publication()
        self.store.lifecycle.publication_sent(card['id'],'t_retry')
        root=self.store.lifecycle.next_publication()
        with self.store.db:
            self.store.db.execute('DELETE FROM outbox')
        calls=[]
        class Matrix:
            def send(inner,body,transaction,*_args,**_kwargs):
                calls.append(transaction)
                if len(calls)==1:
                    raise TimeoutError('acknowledgement lost')
                return '$same-root'
        stop=mock.Mock()
        stop.wait.side_effect=[False,False,True]
        with mock.patch('incident_service.LOG.exception'):
            delivery_loop(self.store,Matrix(),stop,lifecycle_enabled=True)
        self.assertEqual([root['transaction_id'],root['transaction_id']],calls)
        self.assertEqual('$same-root',self.store.lifecycle.work(work['id'])['thread'])

    def test_evidence_html_is_escaped(self):
        formatted=message_html('<img src=x onerror=alert(1)>\n<script>bad</script>\nhttps://osv.dev/vulnerability/CVE-2026-1234')
        self.assertNotIn('<script>',formatted)
        self.assertNotIn('<img',formatted)
        self.assertIn('&lt;script&gt;',formatted)

    def test_retired_job_api_is_unreachable_and_lifecycle_permissions_are_scoped(self):
        self.store.ingest(fixtures.snapshot())
        incident=self.store.get_incident('CVE-2026-1234')
        work=self.store.lifecycle.ensure_work(incident['id'],'targetable_path','decision:one')
        api=IncidentAPI(self.store,{
            'operator':{'role':'operator','token':'operator'},
            'collector':{'role':'collector','token':'collector'},
            'worker':{'role':'worker','token':'worker'},
            'reader':{'role':'reader','token':'reader'}})
        self.assertEqual(work['id'],api.call('Bearer reader',{
            'action':'work','work':work['id']})['work']['id'])
        self.assertIsNotNone(api.call('Bearer operator',{
            'action':'next_publication'})['publication'])
        for token in ('reader','collector'):
            with self.assertRaises(PermissionError):
                api.call('Bearer '+token,{'action':'next_publication'})
        for action in ('request','request_status','claim','next_reply','finish','fail'):
            with self.assertRaises(PermissionError):
                api.call('Bearer operator',{'action':action})
        with self.assertRaises(PermissionError):
            api.call('Bearer worker',{'action':'list'})

    def test_collector_api_evaluation_returns_evaluator_version(self):
        resource = 'deployment:api:test'
        scope = 'paths:' + resource
        evidence = 'evidence-api-evaluator'
        with self.store.db:
            incident = self.store._incident('CVE-2026-7331')
        self.store.lifecycle.stage_graph_change(
            'api-evaluator-graph', resources=[{
                'resource_key': resource, 'kind': 'deployment', 'name': 'test',
            }], evidence=[{
                'id': evidence, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'status': 'complete', 'content': {'targetable': True},
            }], assertions=[{
                'logical_key': 'api-evaluator-targetable', 'version': 'v1',
                'subject': resource, 'relation': 'TARGETABLE_PATH',
                'value': True, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'evidence_id': evidence,
            }], coverage=[{
                'logical_key': 'api-evaluator-coverage', 'version': 'v1',
                'scope': scope, 'relationship': 'paths',
                'producer': 'fixture', 'complete': True, 'status': 'valid',
                'evidence_id': evidence,
            }])
        self.store.lifecycle.acknowledge_graph_change('api-evaluator-graph')
        self.store.lifecycle.add_occurrence(
            incident, 'occ-api-evaluator', resource, service='api', host='host',
            deployment='test')
        api = IncidentAPI(self.store, {
            'collector': {'role': 'collector', 'token': 'collector'},
            'reader': {'role': 'reader', 'token': 'reader'},
        })

        result = api.call('Bearer collector', {
            'action': 'evaluate', 'incident': incident,
            'occurrence': 'occ-api-evaluator', 'rule_version': 'rules/api',
            'advisory_version': 'advisory/api', 'dependency_scopes': [scope],
        })
        stored = api.call('Bearer reader', {
            'action': 'decision', 'decision_id': result['id'],
        })['decision']

        self.assertRegex(result['evaluator_version'],
                         r'^cve_lifecycle\.py:sha256:[0-9a-f]{64}$')
        self.assertEqual(result['evaluator_version'],
                         stored['evaluator_version'])
        self.assertEqual('rules/api', stored['rule_version'])
        self.assertEqual('advisory/api', stored['advisory_version'])
