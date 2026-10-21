import unittest
import test_vulnerability_incidents as fixtures
snapshot, finding = fixtures.snapshot, fixtures.finding


class ConversationTests(unittest.TestCase):
    setUp = fixtures.IncidentTests.setUp
    tearDown = fixtures.IncidentTests.tearDown
    def test_summary_keeps_full_membership_and_revision_without_jobs(self):
        self.store.ingest(snapshot(findings=[finding('CVE-2026-'+str(1000+i)) for i in range(25)]))
        self.store.publish_digest()
        notification = self.store.pending_delivery()
        self.store.delivered(notification['id'], '$summary')
        context = self.store.conversation_context('$summary')
        self.assertEqual(context['total'], 25)
        self.assertTrue(context['complete'])
        self.assertEqual(len(context['identifiers']), 25)
        self.assertEqual(self.store.stats()['jobs'], 0)

    def test_old_summary_is_explicitly_partial_and_query_is_read_only(self):
        self.store.ingest(snapshot())
        self.store._outbox('old', None, 'CVE-2026-1234. 100 more incidents retained.')
        notification = self.store.pending_delivery()
        self.store.delivered(notification['id'], '$old')
        context = self.store.conversation_context('$old')
        self.assertFalse(context['complete'])
        report = self.store.query_incidents(['CVE-2026-1234'], '')
        self.assertEqual(report['incidents'][0]['name'], 'CVE-2026-1234')
        self.assertEqual(self.store.stats()['jobs'], 0)


if __name__ == '__main__':
    unittest.main()
