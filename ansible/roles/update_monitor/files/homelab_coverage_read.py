#!/usr/bin/env python3
"""Expose bounded, non-secret fleet coverage through the forced agent endpoint."""
import json
import hashlib
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path('/var/lib/homelab-update-monitor')
CONFIG = Path('/etc/homelab-update-monitor/deployments.json')
INCIDENT_CONFIG = Path('/etc/homelab-update-monitor/incident.json')


def snapshot(config, advisory, root=ROOT):
    path = root / 'cve-state.incident-snapshot.json'
    if not path.is_file():
        return {'host': config['host'], 'status': 'unknown',
                'reason': 'no acknowledged all-severity snapshot', 'matches': []}
    if path.stat().st_size > 32 * 1024 * 1024 + 1024:
        raise ValueError('accepted coverage snapshot exceeds limit')
    envelope = json.loads(path.read_text())
    state = envelope['snapshot']
    raw = json.dumps(state, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if state.get('schema') != 1 or hashlib.sha256(raw).hexdigest() != envelope.get('sha256'):
        raise ValueError('accepted coverage snapshot integrity check failed')
    if INCIDENT_CONFIG.exists():
        settings = json.loads(INCIDENT_CONFIG.read_text())
        if (state['source'], state['generation']) != (settings['source'], settings['generation']):
            raise ValueError('accepted coverage snapshot belongs to another source generation')
    observed = state['observed_at']
    if type(observed) not in (int, float) or not 0 < observed <= time.time() + 300:
        raise ValueError('invalid accepted coverage observation time')
    findings = state['findings']
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError('invalid accepted coverage findings')
    status_path = root / 'cve-state.status.json'
    status = json.loads(status_path.read_text()) if status_path.exists() else {'status': 'unknown'}
    matching = [item for item in findings if item.get('id', '').upper() == advisory.upper()]
    complete = set(state['complete_scopes'])
    current = (status.get('status') == 'complete' and
               time.time() - observed <= 36 * 3600 and bool(complete) and
               all(item.get('scope') in complete for item in matching))
    coverage = state.get('coverage', {})
    discovery = coverage.get('discovery', {})
    current = current and discovery.get('config_sha256') == hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    return {'host': config['host'], 'status': 'current_declared_scan' if current else 'unknown',
            'observed_at': datetime.fromtimestamp(observed, UTC).isoformat(),
            'snapshot': {'source': state['source'], 'generation': state['generation'],
                         'sequence': state['sequence'], 'sha256': envelope['sha256'],
                         'basis': 'acknowledged_incident_snapshot'},
            'runtime_sha256': discovery.get('runtime_sha256'),
            'native_go_binaries': len(coverage.get('native_go', [])), 'images': len(coverage.get('docker_images', [])),
            'deployments': [{'id': d['id'], 'required_adapters': d['adapters']} for d in config['deployments']],
            'libraries': [{k: scan.get(k) for k in ['deployment', 'status', 'reason', 'identified_types']} for scan in coverage.get('libraries', [])],
            'gaps': discovery.get('gaps', ['runtime discovery missing']),
            'matches': [{k: f.get(k) for k in ['id', 'severity', 'package', 'installed', 'fixed', 'target', 'artifact_id', 'containers', 'coverage_status']}
                        for f in matching],
            'limitations': coverage.get('limitations', []) +
                           ['No match in this scan does not prove a deployed fix.'],
            'automatic_actions': 'require separate root policy and verified receipts'}


def main():
    raw = sys.stdin.buffer.read(256)
    request = json.loads(raw)
    include_external = request.pop('include_external', True)
    if not isinstance(include_external, bool):
        raise ValueError('invalid external coverage selection')
    advisory = request.get('advisory', '')
    if set(request) != {'advisory'} or not re.fullmatch(r'(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|GO-\d{4}-\d+)?', advisory):
        raise ValueError('invalid coverage query')
    config = json.loads(CONFIG.read_text())
    try:
        hosts = [snapshot(config, advisory)]
    except (OSError, ValueError, KeyError, TypeError):
        hosts = [{'host': config['host'], 'status': 'unknown', 'reason': 'scan evidence unreadable'}]
    for guest in config.get('external_guests', []) if include_external else []:
        try:
            result = subprocess.run(['pct', 'exec', str(guest['id']), '--', '/usr/local/libexec/homelab-coverage-read'],
                                    input=json.dumps(request), capture_output=True, text=True, timeout=30)
            if result.returncode or len(result.stdout) > 128 * 1024:
                raise ValueError('guest coverage query failed')
            hosts.extend(json.loads(result.stdout)['hosts'])
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            hosts.append({'host': guest['name'], 'status': 'unknown', 'reason': 'guest coverage transport failed'})
    if config.get('expected_guest_ids'):
        try:
            result = subprocess.run(['pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise ValueError('guest discovery failed')
            observed = {str(v['vmid']): v.get('name', str(v['vmid'])) for v in json.loads(result.stdout)}
            for vmid, name in observed.items():
                if config['expected_guest_ids'].get(vmid) != name:
                    hosts.append({'host': name, 'vmid': vmid, 'status': 'unknown', 'reason': 'live deployment absent from coverage contract or identity changed'})
            for vmid, name in config['expected_guest_ids'].items():
                if vmid not in observed:
                    hosts.append({'host': name, 'status': 'unknown', 'reason': 'declared guest not observed on platform'})
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            hosts[0].setdefault('gaps', []).append('live-guest-discovery-failed')
    encoded = json.dumps({'hosts': hosts})
    if len(encoded.encode()) > 128 * 1024:
        raise ValueError('coverage response exceeds limit')
    print(encoded)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status': 'unknown', 'reason': 'coverage query failed'}))
        raise SystemExit(1)
