"""Execute the backup exporter against isolated service state."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import jinja2


ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / 'ansible/roles/tuwunel_backup/templates/tuwunel-backup-export.sh.j2'


class TuwunelBackupTests(unittest.TestCase):
    def exercise_export(self, tar_status):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = {
                'tuwunel.service': 'active',
                'crowdsec-matrix-bridge.service': 'active',
                'homelab-release-monitor.timer': 'inactive',
                'homelab-cve-monitor.timer': 'inactive',
            }
            state = root / 'state.json'
            state.write_text(json.dumps(initial))
            systemctl = root / 'systemctl'
            systemctl.write_text(f'#!{sys.executable}\n' + '''import json, os, sys
from pathlib import Path
p = Path(os.environ['SERVICE_STATE'])
states = json.loads(p.read_text())
if sys.argv[1] == 'is-active':
    sys.exit(0 if states[sys.argv[-1]] == 'active' else 3)
for unit in sys.argv[2:]:
    states[unit] = 'active' if sys.argv[1] == 'start' else 'inactive'
p.write_text(json.dumps(states))
''')
            systemctl.chmod(0o755)
            tar = root / 'tar'
            tar.write_text('#!/bin/sh\nexit "$TAR_STATUS"\n')
            tar.chmod(0o755)
            timeout = root / 'timeout'
            timeout.write_text('#!/bin/sh\nshift 2\nexec "$@"\n')
            timeout.chmod(0o755)
            env = os.environ | {'PATH': str(root) + ':' + os.environ['PATH'],
                                'SERVICE_STATE': str(state), 'TAR_STATUS': str(tar_status)}
            exporter = root / 'export.sh'
            exporter.write_text(jinja2.Environment(undefined=jinja2.StrictUndefined)
                                .from_string(EXPORT.read_text()).render())
            result = subprocess.run(['bash', str(exporter)], env=env,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, tar_status, result.stderr)
            self.assertEqual(json.loads(state.read_text()), initial)

    def test_success_preserves_inactive_and_retired_units(self):
        self.exercise_export(0)

    def test_archive_failure_restores_only_previously_active_units(self):
        self.exercise_export(2)

    def test_full_receiver_refuses_before_contacting_source_and_preserves_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / 'tuwunel-20261001T000000Z.tar.zst.age'
            previous.write_bytes(b'known-good-encrypted-backup')
            contacted = root / 'source-contacted'
            ssh = root / 'ssh'
            ssh.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(contacted)) + '\nexit 1\n')
            ssh.chmod(0o755)
            template = ROOT / 'ansible/roles/tuwunel_backup/templates/tuwunel-backup-receive.sh.j2'
            environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
            environment.filters['quote'] = shlex.quote
            receiver = root / 'receive.sh'
            receiver.write_text(environment.from_string(template.read_text()).render(
                tuwunel_backup_receiver_dir=str(root), tuwunel_backup_receiver_config_dir=str(root),
                tuwunel_backup_min_free_bytes=2**63, tuwunel_backup_source_user='root',
                tuwunel_backup_source_host='example.invalid', tuwunel_backup_keep=4))
            result = subprocess.run(['bash', str(receiver)], text=True, capture_output=True,
                                    env=os.environ | {'PATH': str(root) + ':' + os.environ['PATH']}, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('backup receiver needs', result.stderr)
            self.assertFalse(contacted.exists())
            self.assertEqual(previous.read_bytes(), b'known-good-encrypted-backup')


if __name__ == '__main__':
    unittest.main()
