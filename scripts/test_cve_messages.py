import json
import unittest
import test_vulnerability_incidents as fixtures


class CVEMessagesTests(unittest.TestCase):
    setUp = fixtures.IncidentTests.setUp
    tearDown = fixtures.IncidentTests.tearDown

    def test_cutover_is_silent_and_new_cves_get_separate_roots_without_jobs(self):
        self.store.ingest(fixtures.snapshot())
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())
        self.store.ingest(fixtures.snapshot(sequence=2, findings=[fixtures.finding(), fixtures.finding('CVE-2026-9999'), fixtures.finding('CVE-2026-8888')]))
        self.now += 61
        self.store.publish_notifications()
        rows = list(self.store.db.execute('SELECT * FROM outbox'))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIsNotNone(row['incident'])
            self.assertNotIn('vuln_', row['body'])
            self.assertNotIn('CVE-2026-1234', row['body'])
            self.assertIn("Exposure hasn't been checked", row['body'])
            self.assertLess(len(row['body']),900)
            self.assertNotIn('investigation has been requested', row['body'])
        self.assertEqual(self.store.stats()['jobs'], 0)

    def test_shared_artifact_and_changed_evidence_reuse_one_cve_thread(self):
        self.store.publish_notifications()
        f = fixtures.finding(artifact_id='a'*64)
        self.store.ingest(fixtures.snapshot(findings=[f]))
        self.store.ingest(fixtures.snapshot(source='two', findings=[f]))
        self.now += 61
        self.store.publish_notifications()
        first = self.store.pending_delivery()
        self.assertEqual(first['body'].count('stdlib 1.0'), 1)
        self.assertNotIn('/usr/bin/caddy',first['body'])
        self.assertIn('one', first['body'])
        self.assertIn('two', first['body'])
        self.assertNotIn('a'*64, first['body'])
        self.store.delivered(first['id'], '$root')
        self.store.ingest(fixtures.snapshot(sequence=2, findings=[f]))
        self.now += 601
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())
        self.store.ingest(fixtures.snapshot(sequence=3, findings=[{**f, 'installed': '1.0.1'}]))
        self.now += 61
        self.store.publish_notifications()
        update = self.store.pending_delivery()
        self.assertEqual(update['thread_root'], '$root')
        self.assertIn('Installed: one/proxy: stdlib 1.0.1', update['body'])
        self.assertNotIn('Scanner severity:',update['body'])

    def test_new_roots_are_rate_limited_without_overflow_lists(self):
        self.store.publish_notifications()
        self.store.ingest(fixtures.snapshot(findings=[fixtures.finding(f'CVE-2026-{9000+i}') for i in range(25)]))
        self.now += 61
        self.store.publish_notifications()
        self.store.publish_notifications()
        self.assertEqual(self.store.stats()['outbox'], 10)
        self.assertEqual(self.store.stats()['jobs'], 0)

    def test_manual_root_does_not_get_a_duplicate_automatic_update(self):
        self.store.publish_notifications()
        self.store.ingest(fixtures.snapshot())
        self.store.ensure_root('CVE-2026-1234')
        first = self.store.pending_delivery()
        self.store.delivered(first['id'], '$requested-root')
        self.now += 61
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())

    def test_legacy_publishers_cannot_restore_inventory_lists_after_cutover(self):
        self.store.publish_notifications()
        self.store.ingest(fixtures.snapshot())
        self.store.publish_digest(bootstrap=True)
        self.store.publish_digest()
        self.store.publish_threads()
        self.assertIsNone(self.store.pending_delivery())

    def test_scoped_assessment_and_staleness_are_not_overwritten_by_scanner_label(self):
        import json
        self.store.ingest(fixtures.snapshot())
        incident = self.store.get_incident('CVE-2026-1234')
        report = {'summary': 'The verified Linux artifact does not meet the platform prerequisite.',
                  'claims': [{'classification': 'non_reachable'}]}
        self.store.db.execute('INSERT INTO assessments VALUES (?,?,?,?,?,?)',
                              ('test',incident['id'],incident['revision'],self.now,json.dumps(report),1))
        body = self.store.notification_body(incident['id'], 'Assessment retained.')
        self.assertIn('Exploit path not reachable in checked scope', body)
        self.assertNotIn('Not investigated', body)
        self.assertIn('Investigated ', body)
        self.now += 37*3600
        self.assertIn('Earlier assessment needs rechecking', self.store.notification_body(incident['id'], 'Coverage changed.'))

    def root(self):
        self.store.publish_notifications()
        self.store.ingest(fixtures.snapshot())
        self.now += 61
        self.store.publish_notifications()
        first = self.store.pending_delivery()
        self.store.delivered(first['id'],'$root')
        return first

    def test_alias_and_advisory_prose_changes_are_silent_but_retained(self):
        self.root()
        self.store.record_advisory({'id':'CVE-2026-1234','modified':'2026-09-09T00:00:00Z','summary':'A better description'},'https://api.osv.dev/v1/vulns/CVE-2026-1234')
        self.store.add_aliases('CVE-2026-1234',['GHSA-aaaa-bbbb-cccc'],'https://api.osv.dev/v1/vulns/CVE-2026-1234','revision-2')
        self.now += 601
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())
        self.assertIn('GHSA-aaaa-bbbb-cccc',self.store.get_incident('CVE-2026-1234')['aliases'])

    def test_artifact_identity_churn_does_not_notify(self):
        self.root()
        self.store.ingest(fixtures.snapshot(sequence=2,findings=[fixtures.finding(artifact_id='a'*64)]))
        self.now += 601
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())

    def test_fix_severity_scope_and_withdrawal_changes_notify(self):
        self.root()
        self.store.ingest(fixtures.snapshot(sequence=2,findings=[fixtures.finding(fixed='1.2',severity='CRITICAL')]))
        self.store.ingest(fixtures.snapshot(source='two'))
        self.store.record_advisory({'id':'CVE-2026-1234','modified':'2026-09-09T00:00:00Z','withdrawn':'2026-09-09T00:00:00Z'},'https://api.osv.dev/v1/vulns/CVE-2026-1234')
        self.now += 601
        self.store.publish_notifications()
        body=self.store.pending_delivery()['body']
        self.assertIn('two/proxy',body)
        self.assertIn('1.2',body)
        self.assertIn('withdrawal',body)
        self.assertIn('critical',body)
        self.assertLess(len(body),1200)
        self.assertEqual(self.store.stats()['jobs'],0)

    def test_coverage_aging_and_recovery_notify_without_version_change(self):
        self.root()
        self.now += 37*3600
        self.store.publish_notifications()
        stale=self.store.pending_delivery()
        self.assertIn('Missing or stale scans',stale['body'])
        self.store.delivered(stale['id'],'$stale')
        self.store.ingest(fixtures.snapshot(sequence=2,observed_at=self.now))
        self.now += 601
        self.store.publish_notifications()
        self.assertIn('Scans current again',self.store.pending_delivery()['body'])

    def test_presentation_migration_preserves_history_and_pending_transaction(self):
        self.root()
        self.store.ensure_root('CVE-2026-1234')
        self.store._outbox('pending','CVE-2026-1234','Already prepared','$root')
        before=self.store.stats()
        pending=self.store.pending_delivery()
        self.store.db.execute("DELETE FROM meta WHERE key='notification-policy'")
        self.store.publish_notifications()
        self.assertEqual(before,self.store.stats())
        self.assertEqual(pending,self.store.pending_delivery())
        self.assertEqual(self.store.get_incident('CVE-2026-1234')['root'],'$root')

    def test_failure_and_expiry_deliver_once_in_original_thread(self):
        for expired in (False,True):
            with self.subTest(expired=expired):
                self.root() if not self.store.list_incidents() else None
                request=self.store.request_investigation('CVE-2026-1234',str(expired))
                job=self.store.claim_job()
                if expired:
                    self.now += fixtures.STORE.JOB_SECONDS+1
                    self.store.claim_job()
                    self.store.claim_job()
                else:
                    self.store.fail_job(job['id'],job['fence'])
                    with self.assertRaises(ValueError):
                        self.store.fail_job(job['id'],job['fence'])
                message=self.store.pending_delivery()
                self.assertEqual(message['thread_root'],'$root')
                self.assertEqual(message['sender'],'zig')
                self.assertEqual(json.loads(message['body'])['kind'],'failure')
                self.store.delivered(message['id'],'$failure'+str(expired))
                self.assertIsNone(self.store.pending_delivery())

    def test_root_groups_multiple_claims_for_one_deployment(self):
        import json
        self.store.ingest(fixtures.snapshot())
        incident=self.store.get_incident('CVE-2026-1234')
        report={'complete':True,'summary':'Long investigation retained.', 'journal':[
            {'source':'one','scope':'proxy','classification':label}
            for label in ('scanner_match','binary_affected','visibility_gap')]}
        self.store.db.execute('INSERT INTO assessments VALUES (?,?,?,?,?,?)',
                              ('grouped',incident['id'],incident['revision'],self.now,json.dumps(report),1))
        body=self.store.notification_body(incident['id'])
        self.assertEqual(body.count('Exposure unknown in proxy on one.'),1)
        self.assertNotIn('More investigated deployments',body)

    def test_fix_in_another_semver_major_does_not_notify(self):
        self.store.publish_notifications()
        f=fixtures.finding(package='axios',installed='1.15.0',fixed='1.15.1, 0.31.1')
        self.store.ingest(fixtures.snapshot(findings=[f]))
        self.now+=61
        self.store.publish_notifications()
        first=self.store.pending_delivery()
        self.assertNotIn('0.31.1',first['body'])
        self.store.delivered(first['id'],'$root')
        self.store.ingest(fixtures.snapshot(sequence=2,findings=[{**f,'fixed':'1.15.1, 0.31.2'}]))
        self.now+=601
        self.store.publish_notifications()
        self.assertIsNone(self.store.pending_delivery())

    def test_assessment_preserves_answer_action_uncertainty_and_staleness(self):
        self.root()
        self.store.request_investigation('CVE-2026-1234','test-result')
        job=self.store.claim_job()
        report={'complete':True,'summary':'The proxy cannot reach the affected code.',
                'next_step':'Keep the current deployment; recheck if that feature is enabled.',
                'journal':[{'source':'one','scope':'proxy','classification':'non_reachable','visibility_gap':'The second deployment was not checked.'}]}
        self.store.ingest(fixtures.snapshot(sequence=2,findings=[fixtures.finding(installed='1.0.1')]))
        self.store.finish_job(job['id'],job['fence'],report)
        context=json.loads(self.store.pending_delivery()['body'])
        self.assertFalse(context['current'])
        self.assertEqual(context['assessment']['summary'],report['summary'])
        self.assertEqual(context['assessment']['next_step'],report['next_step'])
        self.assertEqual(context['assessment']['journal'],report['journal'])
        result=self.store.query_incidents(['CVE-2026-1234'],'')['incidents'][0]['assessments'][0]
        self.assertEqual(result['journal'],report['journal'])


if __name__ == '__main__':
    unittest.main()
