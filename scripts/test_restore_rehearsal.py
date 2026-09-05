import unittest

from rehearse_lxc_restore import isolated_config


class RestoreIsolationTests(unittest.TestCase):
    def test_network_mounts_hooks_and_autostart_removed_before_boot(self):
        source = '''hostname: homelab-restore-9900
rootfs: local-lvm:vm-9900-disk-0,size=8G
unprivileged: 1
net0: name=eth0,bridge=vmbr0,ip=10.42.0.205/24
mp0: /data,mp=/storage
dev0: /dev/nvidia0
lxc.net.0.type: none
lxc.mount.entry: /data data none bind 0 0
hookscript: local:snippets/production.pl
onboot: 1
protection: 1
'''
        result = isolated_config(source, 9900)
        for value in ('vmbr0', '/data', '/dev/nvidia', 'production.pl', 'onboot: 1', 'protection: 1'):
            self.assertNotIn(value, result)
        self.assertIn('lxc.net.0.type: empty', result)
        self.assertIn('entrypoint: /sbin/init --unit=rescue.target', result)

    def test_refuse_root_volume_belonging_to_production(self):
        with self.assertRaisesRegex(ValueError, 'private unprivileged root disk'):
            isolated_config('rootfs: local-lvm:vm-205-disk-0\nunprivileged: 1\n', 9900)
