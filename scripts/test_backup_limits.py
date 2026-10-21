import importlib.util
from contextlib import closing
import io
from pathlib import Path
import os
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'ansible/roles/incident_backup/files/backup_limits.py'
spec = importlib.util.spec_from_file_location('backup_limits', SOURCE)
limits = importlib.util.module_from_spec(spec)
spec.loader.exec_module(limits)


class BackupLimitsTests(unittest.TestCase):
    def archive(self, root, source, day, size=10):
        path = root / f'{source}-202610{day:02d}T041500Z.tar.zst.age'
        path.write_bytes(b'x' * size)
        os.utime(path, (day, day))
        return path

    def test_capacity_preserves_last_archive_even_for_retired_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for day in range(1, 5):
                self.archive(root, 'incident', day)
            retired = self.archive(root, 'pangolin-history', 1)
            helix = self.archive(root, 'helix', 1)
            limits.prune(root, keep=3, maximum=30, minimum_free=0)
            self.assertEqual(limits.used_bytes(root), 30)
            self.assertTrue(retired.exists())
            self.assertTrue(helix.exists())
            self.assertTrue((root / 'incident-20261004T041500Z.tar.zst.age').exists())
            with self.assertRaisesRegex(ValueError, 'last archive'):
                limits.prune(root, keep=3, maximum=20, minimum_free=0)
            self.assertEqual(len(limits.archives(root)), 3)

    def test_write_limit_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'archive.partial'
            with self.assertRaisesRegex(ValueError, 'limit'):
                limits.bounded_write(io.BytesIO(b'x' * 11), path, limit=10, minimum_free=0)
            self.assertFalse(path.exists())

    def test_disk_reserve_rejects_write_and_removes_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'archive.partial'
            available = limits.shutil.disk_usage(temp)._replace(free=12)
            with patch.object(limits.shutil, 'disk_usage', return_value=available):
                with self.assertRaisesRegex(ValueError, 'free-space'):
                    limits.bounded_write(io.BytesIO(b'x' * 8), path, limit=100, minimum_free=5)
            self.assertFalse(path.exists())

    def test_existing_output_is_never_replaced_or_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'known-good'
            path.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                limits.bounded_write(io.BytesIO(b'new'), path, limit=100, minimum_free=0)
            self.assertEqual(path.read_bytes(), b'preserve')

    def test_sqlite_archive_is_verified_from_bounded_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / 'original.db'
            with closing(sqlite3.connect(database)) as db:
                db.execute('create table evidence (id integer)')
                db.execute('insert into evidence values (42)')
                db.commit()
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                archive.add(database, arcname='incidents.db')
            stream.seek(0)
            destination = root / 'verify'
            destination.mkdir()
            limits.verify_sqlite(stream, destination, minimum_free=0)
            self.assertTrue((destination / 'incidents.db').is_file())
            stream.seek(0)
            full = root / 'full'
            full.mkdir()
            usage = limits.shutil.disk_usage(temp)._replace(free=1)
            with patch.object(limits.shutil, 'disk_usage', return_value=usage):
                with self.assertRaisesRegex(ValueError, 'free-space'):
                    limits.verify_sqlite(stream, full, minimum_free=1)
            self.assertFalse(list(full.iterdir()))

    def test_stale_cleanup_preserves_archives_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, 'retired', 1)
            outside = root / 'preserved'
            outside.mkdir()
            (outside / 'keep').write_text('known-good')
            (root / '.receive-symlink').symlink_to(outside, target_is_directory=True)
            stale = root / '.incident-verify.old'
            stale.mkdir()
            (stale / 'database-copy').write_bytes(b'temporary')
            (root / '.failed.partial').write_bytes(b'temporary')
            limits.clean_stale(root)
            self.assertTrue(archive.exists())
            self.assertTrue((outside / 'keep').exists())
            self.assertTrue((root / '.receive-symlink').is_symlink())
            self.assertFalse(stale.exists())
            self.assertFalse((root / '.failed.partial').exists())
