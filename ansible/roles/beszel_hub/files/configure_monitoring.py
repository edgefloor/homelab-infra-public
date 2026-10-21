#!/usr/bin/env python3
"""Enroll explicit Beszel agents and reconcile native alerts through PocketBase."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

DATA = Path('/opt/beszel/data')


def docker(*args: str) -> str:
    result = subprocess.run(['docker', 'exec', 'beszel', '/beszel', *args],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('Beszel administration command failed')
    return result.stdout


class Client:
    def __init__(self, origin: str):
        self.origin = origin
        self.token = ''

    def request(self, method: str, path: str, body=None):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = self.token
        request = Request(self.origin + path, method=method, headers=headers,
                          data=None if body is None else json.dumps(body).encode())
        try:
            with urlopen(request, timeout=30) as response:
                data = response.read()
                return json.loads(data) if data else None
        except HTTPError as error:
            # Never include response bodies, tokens or request bodies in errors.
            raise RuntimeError(f'Beszel API {method} {path} returned HTTP {error.code}') from None

    def records(self, collection: str):
        data = self.request('GET', f'/api/collections/{collection}/records?perPage=500')
        if data['totalPages'] > 1:
            raise RuntimeError('Refusing an incomplete collection read')
        return data['items']

    def create(self, collection: str, body):
        return self.request('POST', f'/api/collections/{collection}/records', body)

    def update(self, collection: str, record_id: str, body):
        return self.request('PATCH', f'/api/collections/{collection}/records/{record_id}', body)


@contextmanager
def administration():
    inspect = json.loads(subprocess.check_output(['docker', 'inspect', 'beszel'], text=True))[0]
    address = inspect['NetworkSettings']['Networks']['pangolin_frontend']['IPAddress']
    client = Client(f'http://{address}:8090')
    identity = f'homelab-maintenance-{secrets.token_hex(8)}@example.invalid'
    password = secrets.token_urlsafe(40)
    docker('superuser', 'create', identity, password)
    try:
        auth = client.request('POST', '/api/collections/_superusers/auth-with-password',
                              {'identity': identity, 'password': password})
        client.token = auth['token']
        yield client
    finally:
        docker('superuser', 'delete', identity)


def backup_database():
    directory = Path('/var/backups/beszel-maintenance')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    target = directory / f'before-monitoring-{stamp}.db'
    with sqlite3.connect(f'file:{DATA}/data.db?mode=ro', uri=True) as source:
        with sqlite3.connect(target) as destination:
            source.backup(destination)
            if destination.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise RuntimeError('Beszel database backup verification failed')
    os.chmod(target, 0o600)
    return str(target)


def unique_by_name(systems):
    names = [system['name'] for system in systems]
    if len(names) != len(set(names)):
        raise RuntimeError('Ambiguous duplicate Beszel system names')
    return {system['name']: system for system in systems}


def alert_changes(systems, existing, expected_names):
    by_name = unique_by_name(systems)
    missing = set(expected_names) - by_name.keys()
    if missing:
        raise RuntimeError('Expected monitoring systems are missing')
    indexed = {(item['system'], item['user'], item['name']): item for item in existing}
    if len(indexed) != len(existing):
        raise RuntimeError('Duplicate native alerts must be resolved explicitly')
    changes = []
    for name in expected_names:
        system = by_name[name]
        if system['status'] != 'up':
            raise RuntimeError('All managed agents must connect before enabling alerts')
        for user in system['users']:
            for kind, value, minutes in [('Status', 0, 5), ('SystemdFailed', 0, 0), ('Disk', 85, 5)]:
                current = indexed.get((system['id'], user, kind))
                desired = {'system': system['id'], 'user': user, 'name': kind,
                           'value': value, 'min': minutes}
                if current is None:
                    changes.append((None, desired))
                elif kind != 'Status' and any(current[field] != desired[field] for field in ('value', 'min')):
                    changes.append((current['id'], {'value': value, 'min': minutes}))
    return changes


def enroll(client, config):
    systems = client.records('systems')
    owners = {tuple(sorted(system['users'])) for system in systems}
    if len(owners) != 1 or not next(iter(owners)):
        raise RuntimeError('Existing systems must have one unambiguous ownership set')
    users = list(next(iter(owners)))
    by_name = unique_by_name(systems)
    fingerprints = {item['system']: item for item in client.records('fingerprints')}
    result = {}
    created = 0
    for item in config['enroll']:
        system = by_name.get(item['name'])
        if system is None:
            system = client.create('systems', {'name': item['name'], 'host': item['host'],
                                               'port': '45876', 'status': 'pending', 'users': users})
            by_name[item['name']] = system
            created += 1
        if sorted(system['users']) != sorted(users):
            raise RuntimeError('Existing system ownership differs')
        fingerprint = fingerprints.get(system['id'])
        if fingerprint is None:
            fingerprint = client.create('fingerprints', {'system': system['id'], 'token': secrets.token_urlsafe(32)})
        result[item['inventory_host']] = fingerprint['token']
    public_key = subprocess.check_output(['ssh-keygen', '-y', '-f', str(DATA / 'id_ed25519')], text=True).strip()
    return {'created_systems': created, 'enrollment': result, 'hub_public_key': public_key}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['enroll', 'alerts'])
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Root execution is required')
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    backup = backup_database()
    with administration() as client:
        before_settings = client.records('user_settings')
        if args.mode == 'enroll':
            result = enroll(client, config)
        else:
            changes = alert_changes(client.records('systems'), client.records('alerts'), config['expected_system_names'])
            for record_id, data in changes:
                if record_id:
                    client.update('alerts', record_id, data)
                else:
                    client.create('alerts', data)
            remaining = alert_changes(client.records('systems'), client.records('alerts'), config['expected_system_names'])
            if remaining:
                raise RuntimeError('Native alert reconciliation did not converge')
            result = {'changed_alerts': len(changes), 'systems': len(config['expected_system_names']),
                      'alert_counts': dict(Counter(item['name'] for item in client.records('alerts')))}
        if before_settings != client.records('user_settings'):
            raise RuntimeError('User notification settings changed during reconciliation')
        result['notification_settings_unchanged'] = True
    if args.mode == 'enroll':
        # Transfer secrets only through a root-only temporary file. The playbook
        # slurps it with no_log and always removes it after distributing tokens.
        material = {'enrollment': result.pop('enrollment'),
                    'hub_public_key': result.pop('hub_public_key')}
        output = Path('/run/homelab-beszel-enrollment.json')
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(material, stream)
    result['backup'] = backup
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Errors never include API bodies, enrollment tokens or admin credentials.
        print(f'Beszel monitoring configuration failed: {error}', file=sys.stderr)
        raise SystemExit(1)
