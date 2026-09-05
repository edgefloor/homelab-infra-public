#!/usr/bin/env python3
"""Restore a downloads backup into a disposable, disconnected LXC and test File Browser.

Run on Proxmox as root. No production guest is stopped or modified. The receipt
proves this backup's application startup only, not candidate patch compatibility.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


def run(argv, timeout=300):
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if completed.returncode:
        raise RuntimeError('restore rehearsal command failed: ' + argv[0] + ' ' + argv[1])
    return completed.stdout.strip()


def isolated_config(text: str, vmid: int) -> str:
    kept = []
    for line in text.splitlines():
        key = line.split(':', 1)[0].strip()
        if re.fullmatch(r'(net|mp|dev)\d+', key) or key.startswith('lxc.') or key in {'hookscript', 'features', 'onboot', 'protection', 'startup', 'entrypoint'}:
            continue
        kept.append(line)
    result = '\n'.join(kept) + '\nonboot: 0\nprotection: 0\nlxc.net.0.type: empty\nentrypoint: /sbin/init --unit=rescue.target\n'
    if not re.search(rf'^rootfs: [^\n]*vm-{vmid}-disk-', result, re.M) or not re.search(r'^unprivileged: 1$', result, re.M):
        raise ValueError('restore does not have a private unprivileged root disk')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--test-vmid', type=int, default=9900)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 9000 <= args.test_vmid < 10000 or not re.fullmatch(r'vzdump-lxc-205-[0-9_-]+\.tar\.zst', args.archive.name):
        raise ValueError('this rehearsal supports downloads backups and reserved disposable IDs only')
    config = Path(f'/etc/pve/lxc/{args.test_vmid}.conf')
    if config.exists() or Path(f'/etc/pve/qemu-server/{args.test_vmid}.conf').exists():
        raise ValueError('test ID is already in use')
    archive = args.archive.resolve(strict=True)
    with archive.open('rb') as stream:
        archive_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    receipt = {'schema': 1, 'deployment': 'filebrowser@downloads', 'backup': archive.name,
               'backup_sha256': archive_sha256, 'observed_at': datetime.now(UTC).isoformat(),
               'test_vmid': args.test_vmid, 'network_attached': 'unverified', 'shared_mounts_attached': 'unverified',
               'status': 'failed', 'candidate_compatibility': 'not_tested', 'shared_storage_restore': 'not_tested'}
    owned = False
    try:
        owned = True
        run(['pct', 'restore', str(args.test_vmid), str(archive), '--rootfs', 'local-lvm:8',
             '--hostname', f'homelab-restore-{args.test_vmid}', '--onboot', '0', '--unprivileged', '1'], timeout=900)
        config.write_text(isolated_config(config.read_text(), args.test_vmid))
        receipt['shared_mounts_attached'] = False
        run(['pct', 'start', str(args.test_vmid)])
        prefix = ['pct', 'exec', str(args.test_vmid), '--']
        interfaces = json.loads(run(prefix + ['ip', '-j', 'address', 'show']))
        namespace = run(prefix + ['readlink', '/proc/self/ns/net'])
        if [interface['ifname'] for interface in interfaces] != ['lo'] or namespace == os.readlink('/proc/self/ns/net'):
            receipt['network_attached'] = True
            raise RuntimeError('restored guest has an unexpected network interface')
        receipt['network_attached'] = False
        run(prefix + ['test', '-s', '/var/lib/filebrowser/filebrowser.db'])
        # /storage is deliberately empty: the shared production filesystem is excluded.
        run(prefix + ['mkdir', '-p', '/storage'])
        run(prefix + ['systemctl', 'start', 'filebrowser.service'])
        run(prefix + ['systemctl', 'is-active', '--quiet', 'filebrowser.service'])
        health = 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8080/", timeout=5); assert r.status == 200'
        for attempt in range(20):
            try:
                run(prefix + ['python3', '-c', health], timeout=15)
                break
            except RuntimeError:
                if attempt == 19:
                    raise
                time.sleep(1)
        receipt.update(status='passed', database_present=True, application_health_http=200,
                       restored_version=run(prefix + ['/usr/local/bin/filebrowser', 'version']))
    finally:
        if owned and config.exists():
            # Never destroy an ID whose private root disk or fixture name no longer matches.
            contents = config.read_text()
            if f'hostname: homelab-restore-{args.test_vmid}' not in contents:
                raise RuntimeError('test guest ownership changed; cleanup refused')
            if 'running' in run(['pct', 'status', str(args.test_vmid)]):
                run(['pct', 'stop', str(args.test_vmid)])
            run(['pct', 'destroy', str(args.test_vmid), '--purge', '1'])
            receipt['test_guest_removed'] = not config.exists()
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
        args.output.chmod(0o600)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
