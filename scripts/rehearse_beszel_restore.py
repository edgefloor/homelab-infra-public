#!/usr/bin/env python3
"""Start a Beszel backup with its installed image and no external network.

Run as root on the Beszel Docker host. Only a disposable copy is writable.
This proves same-version startup, not upgrade compatibility or live collection.
"""
import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import uuid


def run(argv, timeout=30):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'rehearsal command failed: {argv[0]} {argv[1]}')
    return result.stdout.strip()


def unpack_backup(archive, destination):
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        if not members or any(Path(member.name).parts[0] != 'data' for member in members):
            raise ValueError('expected an archive containing only the Beszel data directory')
        if len(members) > 50000 or sum(member.size for member in members) > 1024**3:
            raise ValueError('backup exceeds the one-GiB rehearsal limit')
        stream.extractall(destination, members=members, filter='data')
    database = destination / 'data' / 'data.db'
    if not database.is_file():
        raise ValueError('backup does not contain the Beszel database')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('restored Beszel database failed integrity validation')
        return connection.execute('SELECT count(*) FROM systems').fetchone()[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve(strict=True)
    if not re.fullmatch(r'beszel-[0-9]{8}T[0-9]{6}Z\.tar\.gz', archive.name):
        raise ValueError('expected a scheduled Beszel archive')
    production = json.loads(run(['docker', 'inspect', 'beszel']))[0]
    if not production['State']['Running']:
        raise ValueError('production Beszel is not running before the rehearsal')
    image = production['Image']
    with archive.open('rb') as stream:
        archive_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    receipt = {'schema': 1, 'application': 'beszel', 'archive': archive.name,
               'archive_sha256': archive_hash, 'image_id': image,
               'observed_at': datetime.now(UTC).isoformat(), 'status': 'failed',
               'candidate_compatibility': 'not_tested', 'external_collection': 'not_tested'}
    directory = Path(tempfile.mkdtemp(prefix='homelab-beszel-restore-'))
    container = None
    try:
        receipt['restored_system_count'] = unpack_backup(archive, directory)
        name = 'homelab-beszel-restore-' + uuid.uuid4().hex[:12]
        container = run(['docker', 'create', '--pull=never', '--name', name,
                         '--label', 'homelab.restore-rehearsal=beszel',
                         '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                         '--security-opt', 'no-new-privileges', '--memory', '512m',
                         '--cpus', '1', '--pids-limit', '128',
                         '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                         '--mount', f'type=bind,src={directory / "data"},dst=/beszel_data',
                         image, 'serve', '--http=127.0.0.1:8090'])
        config = json.loads(run(['docker', 'inspect', container]))[0]
        binds = [mount for mount in config['Mounts'] if mount['Type'] == 'bind']
        if (config['HostConfig']['NetworkMode'] != 'none'
                or config['HostConfig']['PortBindings']
                or not config['HostConfig']['ReadonlyRootfs']
                or len(binds) != 1
                or binds[0]['Source'] != str(directory / 'data')
                or binds[0]['Destination'] != '/beszel_data'
                or any(mount['Type'] not in {'bind', 'tmpfs'} for mount in config['Mounts'])):
            raise RuntimeError('disposable container isolation does not match the request')
        run(['docker', 'start', container])
        pid = run(['docker', 'inspect', '--format', '{{.State.Pid}}', container])
        interfaces = json.loads(run(['nsenter', '-t', pid, '-n', '--', 'ip', '-j', 'link']))
        if [interface['ifname'] for interface in interfaces] != ['lo']:
            raise RuntimeError('disposable container has an external network interface')
        for attempt in range(30):
            try:
                health = json.loads(run(['nsenter', '-t', pid, '-n', '--', 'curl',
                                         '--fail', '--silent', '--show-error', '--max-time', '2',
                                         'http://127.0.0.1:8090/api/health'], timeout=5))
                if health.get('code') != 200:
                    raise RuntimeError('restored application is not healthy')
                break
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(1)
        current = json.loads(run(['docker', 'inspect', 'beszel']))[0]
        if (current['Id'] != production['Id'] or not current['State']['Running']
                or current['State']['StartedAt'] != production['State']['StartedAt']):
            raise RuntimeError('production Beszel changed during the rehearsal')
        receipt.update(status='passed', database_integrity='ok', application_health_http=200,
                       network='loopback_only', production_container_unchanged=True)
    finally:
        if container:
            owned = json.loads(run(['docker', 'inspect', container]))[0]
            if owned['Config']['Labels'].get('homelab.restore-rehearsal') != 'beszel':
                raise RuntimeError('container ownership changed; cleanup refused')
            run(['docker', 'rm', '--force', container])
            receipt['disposable_container_removed'] = True
        shutil.rmtree(directory)
        receipt['disposable_data_removed'] = not directory.exists()
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
        args.output.chmod(0o600)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
