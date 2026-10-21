"""Fixture checks for native backup and thin-pool failed-unit monitors."""
from decimal import Decimal
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKUP = load('backup_health', 'ansible/roles/tuwunel_backup/files/check_tuwunel_backup.py')
THINPOOL = load('thinpool_health', 'ansible/roles/proxmox_storage_policy/files/check_thinpool_health.py')
GIB = 1024**3


class BackupHealthTests(unittest.TestCase):
    now = 1800000000
    healthy = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'Result': 'success'}

    def archive(self, root, age, name='tuwunel-20261017T000000Z.tar.zst.age', payload=b'archive'):
        archive = root / name
        archive.write_bytes(payload)
        os.utime(archive, (self.now - age, self.now - age))
        return archive

    def check(self, directory, unit=None):
        return BACKUP.problems(directory, self.now, unit or self.healthy, 8 * 86400)

    def test_current_archive_and_successful_idle_unit_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root, 7 * 86400)
            self.assertEqual(self.check(root), [])

    def test_new_partial_cannot_hide_stale_completed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root, 9 * 86400)
            self.archive(root, 0, '.tuwunel-20261018T000000Z.tar.zst.age.partial')
            self.assertTrue(any('seconds old' in item for item in self.check(root)))

    def test_missing_empty_and_symlink_archives_do_not_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(self.check(root / 'missing'))
            self.archive(root, 0, payload=b'')
            target = root / 'unrelated'
            target.write_bytes(b'not-a-completed-backup')
            (root / 'tuwunel-20261018T000000Z.tar.zst.age').symlink_to(target)
            self.assertTrue(any('no completed' in item for item in self.check(root)))

    def test_recent_archive_does_not_hide_failed_or_retrying_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root, 0)
            for state in ('failed', 'activating'):
                unit = self.healthy | {'ActiveState': state, 'Result': 'exit-code'}
                self.assertTrue(any('unresolved failure' in item for item in self.check(root, unit)))

    def test_future_archive_timestamp_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root, -600)
            self.assertTrue(any('future' in item for item in self.check(root)))


class ThinpoolHealthTests(unittest.TestCase):
    def check(self, **changes):
        pool = {'lv_size': str(348 * GIB), 'data_percent': '74.31', 'metadata_percent': '2.96',
                'seg_monitor': 'monitored', 'lv_profile': 'homelab-thinpool'}
        group = {'vg_free': str(16 * GIB), 'vg_extent_size': str(4 * 1024**2)}
        for key, value in changes.items():
            (group if key in group else pool)[key] = value
        return THINPOOL.problems(pool, group, data_limit=Decimal(80), metadata_limit=Decimal(80),
                                 extend_percent=Decimal(3), reserve_bytes=5 * GIB)

    def test_current_capacity_passes(self):
        self.assertEqual(self.check(), [])

    def test_data_and_metadata_fail_at_threshold(self):
        self.assertTrue(any('data usage' in item for item in self.check(data_percent='80')))
        self.assertTrue(any('metadata usage' in item for item in self.check(metadata_percent='80')))

    def test_free_space_after_first_extension_warns_before_second_extension(self):
        self.assertTrue(any('next extension plus reserve' in item
                            for item in self.check(vg_free=str(Decimal('5.54') * GIB))))

    def test_extension_is_rounded_up_to_an_extent(self):
        # 3% of 100 bytes requires one 4-byte extent, plus a 5-byte reserve.
        pool = {'lv_size': '100', 'data_percent': '1', 'metadata_percent': '1',
                'seg_monitor': 'monitored', 'lv_profile': 'homelab-thinpool'}
        group = {'vg_free': '8', 'vg_extent_size': '4'}
        self.assertTrue(THINPOOL.problems(pool, group, data_limit=Decimal(80), metadata_limit=Decimal(80),
                                         extend_percent=Decimal(3), reserve_bytes=5))

    def test_missing_monitor_or_profile_fails(self):
        self.assertTrue(self.check(seg_monitor='not monitored'))
        self.assertTrue(self.check(lv_profile=''))

    def test_missing_percentage_is_not_assumed_healthy(self):
        with self.assertRaises(ArithmeticError):
            self.check(data_percent='')


if __name__ == '__main__':
    unittest.main()
