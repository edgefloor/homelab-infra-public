from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

import jinja2

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'ansible/roles/incident_backup/templates/incident-backup-receive.sh.j2'
HELPER = ROOT / 'ansible/roles/incident_backup/files/backup_limits.py'


class BackupReceiverTests(unittest.TestCase):
    def fixture(self, root, failed_host, verify_sqlite=False):
        backup = root / 'backup'
        backup.mkdir()
        bins = root / 'bin'
        bins.mkdir()
        stubs = {
            'date': 'printf "%s\\n" "$AUDIT_STAMP"',
            'ssh': 'for arg; do target="$arg"; done; printf "%s\\n" "$target" >> "$AUDIT_LOG"; '
                   'case "$target" in *"$FAILED_HOST") exit 23;; *) printf "incident-archive-payload\\n";; esac',
            'age': 'if [ "$1" = --encrypt ]; then while [ "$#" -gt 0 ] && [ "$1" != -o ]; do shift; done; '
                   'if [ "$#" -gt 0 ]; then shift; cat > "$1"; else cat; fi; '
                   'else for arg; do file="$arg"; done; cat "$file"; fi',
            'zstd': 'cat >/dev/null',
            'tar': 'cat >/dev/null',
            'python3': 'if [ "$1" = - ]; then cat >/dev/null; else exec ' + shlex.quote(sys.executable) + ' "$@"; fi',
            # The original script reaches only cleanup finds when the second source fails.
            'find': 'exit 0',
        }
        for name, body in stubs.items():
            path = bins / name
            path.write_text('#!/bin/bash\n' + body + '\n')
            path.chmod(0o755)
        env = jinja2.Environment()
        env.filters['quote'] = shlex.quote
        env.filters['bool'] = bool
        receiver = root / 'receiver.sh'
        rendered = env.from_string(TEMPLATE.read_text()).render(
            incident_backup_receiver_dir=str(backup), incident_backup_receiver_config_dir=str(root),
            incident_backup_max_bytes=4096, incident_backup_min_free_bytes=0,
            incident_backup_source_user='root', incident_backup_keep_per_source=3,
            incident_backup_incident_host='incident-host', incident_backup_helix_host='helix-host',
            incident_backup_sources=[{'name': 'incident', 'host': 'incident-host', 'verify_sqlite': verify_sqlite},
                                     {'name': 'helix', 'host': 'helix-host', 'verify_sqlite': False}])
        receiver.write_text(rendered.replace('/usr/local/libexec/homelab-backup-limits', str(HELPER)))
        environment = os.environ.copy()
        environment.update(PATH=str(bins) + ':/usr/bin:/bin', FAILED_HOST=failed_host, AUDIT_LOG=str(root / 'sources'))
        return backup, receiver, environment

    def test_helix_failure_does_not_skip_incident_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup, receiver, env = self.fixture(root, 'helix-host')
            for n in range(1, 6):
                env['AUDIT_STAMP'] = f'202610{n:02d}T041500Z'
                result = subprocess.run(['/bin/bash', str(receiver)], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(list(backup.glob('incident-*.tar.zst.age'))), 3)
            self.assertFalse(list(backup.glob('*.partial')))
            self.assertFalse(list(backup.glob('.receive-*')))

    def test_incident_failure_does_not_skip_helix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup, receiver, env = self.fixture(root, 'incident-host')
            env['AUDIT_STAMP'] = '20261001T041500Z'
            result = subprocess.run(['/bin/bash', str(receiver)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(list(backup.glob('helix-*.tar.zst.age'))), 1)

    def test_verification_failure_cleans_plaintext_and_continues_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup, receiver, env = self.fixture(root, 'unavailable-host', verify_sqlite=True)
            env['AUDIT_STAMP'] = '20261001T041500Z'
            # The compression fixture supplies no SQLite tar stream, so verification must fail.
            result = subprocess.run(['/bin/bash', str(receiver)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(list(backup.glob('incident-*.tar.zst.age')))
            self.assertEqual(len(list(backup.glob('helix-*.tar.zst.age'))), 1)
            self.assertFalse(list(backup.glob('.receive-*')))
