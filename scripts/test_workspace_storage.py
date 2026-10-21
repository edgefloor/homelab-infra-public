import fcntl
import hashlib
import importlib.util
import tempfile
import sys
import unittest
import os
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]/'ansible/roles/homelab_agent_service/files/workspace_storage.py'
spec = importlib.util.spec_from_file_location('workspace_storage', SOURCE)
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.now = 1000
        self.manager = storage.Workspaces(self.root/'jobs', self.root/'cache', clock=lambda:self.now,
                                          min_free=0, job_limit=1024, total_limit=4096, cache_limit=4096)

    def tearDown(self):
        self.temp.cleanup()

    def test_only_completed_expired_scratch_is_deleted_and_evidence_survives(self):
        job = self.manager.create('CVE test')
        (job/'scratch'/'download').write_bytes(b'disposable')
        (job/'evidence'/'report.md').write_text('keep this report')
        self.now += 2*86400
        self.manager.cleanup()
        self.assertTrue((job/'scratch'/'download').exists())
        self.manager.finish(job.name)
        self.now += 86401
        self.manager.cleanup()
        self.assertFalse((job/'scratch').exists())
        self.assertEqual((job/'evidence'/'report.md').read_text(), 'keep this report')

    def test_active_lease_and_symlink_are_never_cleaned(self):
        job = self.manager.create('active')
        self.manager.finish(job.name)
        self.now += 86401
        with (job/'.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.manager.cleanup()
            self.assertTrue((job/'scratch').exists())
        (job/'scratch').rmdir()
        outside = self.root/'outside'
        outside.mkdir()
        (outside/'important').write_text('keep')
        (job/'scratch').symlink_to(outside, target_is_directory=True)
        self.manager.cleanup()
        self.assertEqual((outside/'important').read_text(), 'keep')

    def test_budget_refuses_new_work_and_unenrolled_directories_are_preserved(self):
        job = self.manager.create('large')
        (job/'scratch'/'large').write_bytes(b'x'*4097)
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.manager.create('another')
        old = self.manager.root/'unmanaged'
        old.mkdir()
        (old/'notes').write_text('legacy evidence')
        self.manager.cleanup()
        self.assertTrue((old/'notes').exists())

    def test_identical_archives_share_one_object_and_bad_hash_is_rejected(self):
        job = self.manager.create('cache')
        source = job/'scratch'/'download.tar.gz'
        source.write_bytes(b'same archive')
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        one = self.manager.cache_add(source, sha)
        two = self.manager.cache_add(source, sha)
        self.assertEqual(one, two)
        with self.assertRaisesRegex(ValueError, 'hash'):
            self.manager.cache_add(source, '0'*64)

    def test_abandoned_work_cannot_admit_an_unbounded_queue(self):
        for _ in range(4):
            self.manager.create('waiting')
        with self.assertRaisesRegex(ValueError, 'reservation budget'):
            self.manager.create('fifth')

    def test_cache_expiry_preserves_referenced_objects(self):
        job = self.manager.create('referenced artifact')
        source = job/'scratch'/'archive'
        source.write_bytes(b'keep while referenced')
        target = self.manager.cache_add(source, hashlib.sha256(source.read_bytes()).hexdigest())
        self.now += 8*86400
        self.manager.cleanup()
        self.assertTrue(target.exists())
        source.unlink()
        self.manager.cleanup()
        self.assertFalse(target.exists())

    def test_run_cannot_start_after_completion(self):
        job = self.manager.create('completed')
        self.manager.finish(job.name)
        with self.assertRaisesRegex(ValueError, 'completed'):
            self.manager.run(job.name, [sys.executable, '-c', 'pass'])

    def test_runner_stops_a_command_that_exceeds_the_file_limit(self):
        job = self.manager.create('oversized output')
        try:
            code = self.manager.run(job.name, [sys.executable, '-c', "open('large','wb').write(b'x'*4096)"])
            self.assertNotEqual(code, 0)
        except ValueError as exc:
            self.assertIn('budget', str(exc))
        self.assertLessEqual((job/'scratch'/'large').stat().st_size, 1024)

    def test_shared_locks_and_manifests_remain_group_writable_under_private_umask(self):
        previous = os.umask(0o077)
        try:
            job = self.manager.create('shared identities')
            self.manager.finish(job.name)
        finally:
            os.umask(previous)
        for path in (self.manager.root/'.lock', job/'.lock', job/'manifest.json'):
            self.assertEqual(0o660, path.stat().st_mode & 0o777, path)
        for path in (self.manager.root, self.manager.cache, job,
                     job/'scratch', job/'evidence'):
            self.assertEqual(0o2770, path.stat().st_mode & 0o7777, path)


if __name__ == '__main__':
    unittest.main()
