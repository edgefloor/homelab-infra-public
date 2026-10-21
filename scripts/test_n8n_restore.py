import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('rehearse_n8n_restore.py')
SPEC = importlib.util.spec_from_file_location('n8n_restore', SCRIPT)
RESTORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESTORE)


class N8nRestoreTests(unittest.TestCase):
    def test_failed_account_cleanup_cannot_publish_a_passed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'disposable'
            directory.mkdir()
            output = Path(temp) / 'receipt.json'
            receipt = {'status': 'passed'}
            account = SimpleNamespace(pw_uid=1234, pw_gid=1235)
            with mock.patch.object(RESTORE, 'remove_rehearsal_account',
                                   side_effect=RuntimeError('account cleanup failed')):
                with self.assertRaisesRegex(RuntimeError, 'account cleanup failed'):
                    RESTORE.finalize_rehearsal(None, None, account, directory, receipt, output)
            written = json.loads(output.read_text())
            self.assertEqual('failed', written['status'])
            self.assertNotIn('disposable_account_removed', written)
            self.assertTrue(written['disposable_runtime_removed'])
            self.assertFalse(directory.exists())
            self.assertEqual(0o600, output.stat().st_mode & 0o777)

    def test_candidate_cannot_reuse_production_identity_or_privileges(self):
        account = SimpleNamespace(pw_uid=1234, pw_gid=1235)
        argv = RESTORE.candidate_command(Path('/opt/n8n/candidates/test'), Path('/tmp/copy'), ['start'], account)
        self.assertNotIn('runuser', argv)
        for required in ['--reuid=1234', '--regid=1235', '--clear-groups', '--no-new-privs',
                         '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all']:
            self.assertIn(required, argv)

    def test_production_access_probe_fails_closed_on_any_missing_boundary(self):
        account = SimpleNamespace(pw_uid=1234, pw_gid=1235)
        for failed in RESTORE.ISOLATION_CHECKS:
            checks = {name: name != failed for name in RESTORE.ISOLATION_CHECKS}
            with self.subTest(failed=failed), mock.patch.object(RESTORE, 'command', return_value=json.dumps(checks)):
                with self.assertRaisesRegex(RuntimeError, 'isolation'):
                    RESTORE.verify_isolation(Path('/tmp/copy'), account, '99', Path('/var/backups/n8n/test'))
        checks = dict.fromkeys(RESTORE.ISOLATION_CHECKS, True)
        with mock.patch.object(RESTORE, 'command', return_value=json.dumps(checks)):
            self.assertEqual(RESTORE.verify_isolation(Path('/tmp/copy'), account, '99',
                                                     Path('/var/backups/n8n/test')), checks)

    def fixture(self, path):
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.executescript('''
                CREATE TABLE user (id, password, roleSlug, disabled, mfaEnabled, mfaSecret, mfaRecoveryCodes);
                INSERT INTO user VALUES ('owner', 'hash', 'global:owner', 0, 1, 'secret', 'codes');
                CREATE TABLE workflow_entity (id, nodes, connections, active, activeVersionId);
                INSERT INTO workflow_entity VALUES ('flow', '[]', '{}', 1, 'version');
                CREATE TABLE credentials_entity (id, type, data);
                INSERT INTO credentials_entity VALUES ('credential', 'matrixApi', 'ciphertext');
                CREATE TABLE migrations (id);
            ''')

    def test_unpublishing_copy_preserves_definition_and_authentication_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'database.sqlite'
            self.fixture(path)
            before = RESTORE.inspect_database(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute('UPDATE workflow_entity SET active=0, activeVersionId=NULL')
            after = RESTORE.inspect_database(path)
        self.assertEqual(1, before['counts']['active_workflows'])
        self.assertEqual(0, after['counts']['active_workflows'])
        self.assertEqual(before['content_sha256'], after['content_sha256'])

    def test_content_changes_are_detected_even_when_counts_match(self):
        for name, query in [
            ('workflow_definitions', "UPDATE workflow_entity SET nodes='[{}]'"),
            ('credentials', "UPDATE credentials_entity SET data='changed'"),
            ('account_authentication', "UPDATE user SET mfaEnabled=0"),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'database.sqlite'
                self.fixture(path)
                before = RESTORE.inspect_database(path)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(query)
                after = RESTORE.inspect_database(path)
                self.assertEqual(before['counts'], after['counts'])
                self.assertNotEqual(before['content_sha256'][name], after['content_sha256'][name])

    def test_running_release_and_symlink_escape_are_rejected(self):
        for path in ['/opt/n8n/releases/2.42.6', '/var/lib/n8n', '/opt/n8n/current']:
            with self.subTest(path=path), mock.patch.object(Path, 'resolve', return_value=Path(path)):
                with self.assertRaisesRegex(ValueError, 'separately installed candidate'):
                    RESTORE.validate_release('/opt/n8n/candidates/escape')

    def test_unreviewed_candidate_version_is_rejected(self):
        with mock.patch.object(Path, 'resolve', return_value=Path('/opt/n8n/candidates/new')), \
                mock.patch.object(Path, 'read_text', return_value=json.dumps({'version': '2.43.9'})):
            with self.assertRaisesRegex(ValueError, 'reviewed for n8n'):
                RESTORE.validate_release('/opt/n8n/candidates/new')

    def test_reviewed_candidate_exact_versions_are_accepted(self):
        candidate = Path('/opt/n8n/candidates/reviewed')
        for version in ['2.43.7', '2.43.8']:
            with self.subTest(version=version), mock.patch.object(Path, 'resolve', return_value=candidate), \
                    mock.patch.object(Path, 'read_text', return_value=json.dumps({'version': version})):
                self.assertEqual(RESTORE.validate_release(str(candidate)), candidate)


if __name__ == '__main__':
    unittest.main()
