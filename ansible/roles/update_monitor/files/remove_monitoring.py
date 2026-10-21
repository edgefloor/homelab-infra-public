#!/usr/bin/env python3
"""Remove the notification-producing deployment, retaining recoverable local evidence."""
import json
import os
import shutil
import subprocess
from pathlib import Path


def main():
    if os.geteuid() != 0:
        raise SystemExit('root is required')
    units = [f'homelab-{name}.{kind}' for name in ('cve-monitor', 'scan-watchdog', 'release-monitor')
             for kind in ('timer', 'service')]
    installed = []
    for unit in units:
        result = subprocess.run(['systemctl', 'show', unit, '--property=LoadState', '--value'],
                                capture_output=True, text=True, check=True)
        if result.stdout.strip() != 'not-found':
            installed.append(unit)
    # Stop schedules first so they cannot restart a service during removal.
    for unit in sorted(installed, key=lambda name: not name.endswith('.timer')):
        subprocess.run(['systemctl', 'stop', unit], check=True)
        subprocess.run(['systemctl', 'disable', unit], check=True)
    paths = [Path('/etc/systemd/system') / name for name in units]
    paths += [Path('/etc/systemd/system') / (name + '.d') for name in units]
    paths += [Path('/usr/local/libexec') / name for name in
              ('homelab-cve-monitor', 'homelab-scan-watchdog', 'homelab-release-monitor',
               'homelab-update-opportunities', 'homelab_incident_snapshot.py')]
    paths += [Path('/etc/homelab-update-monitor') / name for name in
              ('incident.json', 'deployments.json', 'webhook-secret')]
    paths += [Path('/var/lib/homelab-update-monitor') / name for name in
              ('cve-state.json', 'cve-state.status.json', 'cve-state.watchdog.json',
               'cve-state.incident-outbox.json', 'release-state.json', 'coverage-audit.json', 'coverage-audit.status.json')]
    archive = Path('/var/backups/homelab-monitor-removal-20260908')
    moved = []
    for path in paths:
        if not path.exists() and not path.is_symlink():
            continue
        target = archive / path.relative_to('/')
        if target.exists():
            raise RuntimeError(f'archive already contains {path}; refusing to overwrite')
        archive.mkdir(mode=0o700, parents=True, exist_ok=True)
        archive.chmod(0o700)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
        moved.append(str(path))
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Removed services can remain in systemd's failed set after their unit files
    # disappear. Clear only the exact retired names so the guest is not left
    # degraded by unloaded monitoring units.
    subprocess.run(['systemctl', 'reset-failed', *units], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for unit in units:
        result = subprocess.run(['systemctl', 'show', unit, '--property=LoadState', '--value'],
                                capture_output=True, text=True, check=True)
        if result.stdout.strip() != 'not-found':
            raise RuntimeError(f'{unit} remains installed')
        failed = subprocess.run(['systemctl', 'is-failed', unit],
                                capture_output=True, text=True)
        if failed.returncode == 0:
            raise RuntimeError(f'{unit} remains failed')
    print(json.dumps({'removed': moved, 'archive': str(archive), 'monitor_units': 'absent'}))


if __name__ == '__main__':
    main()
