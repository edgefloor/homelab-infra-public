#!/usr/bin/env python3
"""Root-policy action runner with dry runs, identity gates, durable recovery, and expiry.

The caller selects a named action only. Commands and evidence paths come from
root-owned policy. The installed policy contains no enabled actions.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

POLICY = Path('/etc/homelab-update-monitor/defense-policy.json')
STATE = Path('/var/lib/homelab-defense')
PATCH_CHECKS = {'dependency_coverage', 'exposure_assessment', 'build_provenance', 'verified_candidate', 'tested_recovery', 'state_compatibility', 'post_change_checks', 'control_access_preserved'}
EMERGENCY_CHECKS = {'verified_target', 'bounded_scope', 'tested_recovery', 'post_change_checks', 'control_access_preserved'}


def trusted_json(path: Path) -> dict:
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('policy and evidence must be protected by root ownership')
    if path.stat().st_size > 256 * 1024:
        raise ValueError('policy or evidence exceeds size limit')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('policy or evidence must be an object')
    return value


def digest(path: str) -> str:
    value = Path(path)
    if not value.is_absolute() or value.is_symlink() or not value.is_file():
        raise ValueError('action artifact must be a regular absolute file')
    with value.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv: list[str], timeout: int = 90) -> dict:
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) for v in argv) or not Path(argv[0]).is_absolute():
        raise ValueError('action handler must be a fixed absolute command in root policy')
    # No command text, output, or environment is accepted from the requesting agent.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if result.returncode or len(result.stdout) > 64 * 1024:
        raise RuntimeError('action handler failed')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def receipt_identity(receipt: dict) -> str:
    return hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(policy: dict, name: str, receipt: dict, probe: dict, now: float, used_receipts=()) -> dict:
    action = policy.get('actions', {}).get(name)
    if not action:
        return {'action': name, 'eligible': False, 'blockers': ['no action policy for this deployment']}
    blockers = []
    if receipt_identity(receipt) in used_receipts:
        blockers.append('verification receipt already consumed; fresh verification required')
    if policy.get('schema') != 1 or policy.get('enabled') is not True or action.get('enabled') is not True:
        blockers.append('action policy disabled')
    kind = action.get('kind')
    if kind not in {'patch', 'emergency'}:
        blockers.append('unsupported action kind')
    if action.get('current_sha256') == action.get('candidate_sha256'):
        blockers.append('candidate must differ from current artifact')
    if action.get('protects_control_plane') is not False:
        blockers.append('control-plane target requires a separately tested execution path')
    for key in ('deployment', 'current_sha256', 'candidate_sha256', 'runtime_sha256'):
        if not action.get(key) or receipt.get(key) != action[key]:
            blockers.append('receipt binding mismatch: ' + key)
    if not isinstance(receipt.get('expires_at'), (int, float)) or not now < receipt['expires_at'] <= now + 86400:
        blockers.append('receipt missing or stale')
    if probe.get('runtime_sha256') != action.get('runtime_sha256') or probe.get('current_sha256') != action.get('current_sha256'):
        blockers.append('live target changed since verification')
    required = PATCH_CHECKS if kind == 'patch' else EMERGENCY_CHECKS
    for check in sorted(required):
        if receipt.get('checks', {}).get(check) is not True:
            blockers.append('missing verified check: ' + check)
    if kind == 'emergency' and (type(action.get('ttl_seconds')) is not int or not 1 <= action['ttl_seconds'] <= 3600):
        blockers.append('emergency action requires an expiry within one hour')
    for handler in ('probe', 'apply', 'health', 'rollback', 'recovery_check'):
        if not action.get(handler):
            blockers.append('missing handler: ' + handler)
    return {'action': name, 'deployment': action.get('deployment'), 'kind': kind,
            'eligible': not blockers, 'blockers': blockers}


def save(path: Path, value: dict):
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def recover(journal: dict, path: Path, run=command) -> dict:
    # The saved, root-protected handlers survive policy edits and controller loss.
    journal['status'] = 'recovering'
    save(path, journal)
    try:
        run(journal['rollback'])
        run(journal['recovery_check'])
        if digest(journal['artifact']) != journal['current_sha256']:
            raise RuntimeError('restored artifact identity does not match')
        journal['status'] = 'recovered'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        journal['status'] = 'recovery_failed'
    save(path, journal)
    return {'status': journal['status'], 'action': journal['action']}


def execute(action: dict, name: str, path: Path, run=command, receipt_sha256=None) -> dict:
    if digest(action['artifact']) != action['current_sha256'] or digest(action['candidate']) != action['candidate_sha256']:
        raise ValueError('artifact or candidate changed before execution')
    journal = {k: action[k] for k in ('artifact', 'current_sha256', 'rollback', 'recovery_check')}
    journal.update(action=name, status='applying', started_at=time.time(),
                   expires_at=time.time() + action.get('ttl_seconds', 3600), kind=action['kind'], receipt_sha256=receipt_sha256)
    save(path, journal)  # Persist recovery before the first mutation.
    try:
        run(action['apply'])
        if digest(action['artifact']) != action['candidate_sha256']:
            raise RuntimeError('installed artifact differs from verified candidate')
        run(action['health'])
        journal['status'] = 'active' if action['kind'] == 'emergency' else 'completed'
        save(path, journal)
        return {'status': journal['status'], 'action': name}
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return recover(journal, path, run)


def main() -> int:
    if os.geteuid() != 0:
        raise ValueError('runner requires root policy access')
    raw = sys.stdin.buffer.read(4097)
    request = json.loads(raw) if raw else {'mode': 'recover'}
    if len(raw) > 4096 or not isinstance(request, dict) or set(request) - {'mode', 'action'}:
        raise ValueError('invalid action request')
    mode, name = request.get('mode'), request.get('action', '')
    if mode not in {'prepare', 'execute', 'recover'} or (mode != 'recover' and not re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', name)):
        raise ValueError('invalid action selection')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'change.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending = []
        used_receipts = set()
        for path in STATE.glob('*.json'):
            journal = trusted_json(path)
            if journal.get('receipt_sha256'):
                used_receipts.add(journal['receipt_sha256'])
            if journal['status'] in {'applying', 'recovering', 'recovery_failed'} or (journal['status'] == 'active' and time.time() >= journal['expires_at']):
                pending.append({'status': journal['status'], 'action': journal['action']} if mode == 'prepare' else recover(journal, path))
            elif journal['status'] == 'active':
                pending.append({'status': 'active', 'action': journal['action']})
        if mode == 'recover':
            print(json.dumps({'recoveries': pending}))
            return int(any(item['status'] == 'recovery_failed' for item in pending))
        if pending:
            raise ValueError('a previous action requires recovery or has not expired')
        policy = trusted_json(POLICY)
        action = policy.get('actions', {}).get(name)
        if not action:
            result = prepare(policy, name, {}, {}, time.time())
        else:
            receipt = trusted_json(Path(action['receipt']))
            result = prepare(policy, name, receipt, command(action['probe']), time.time(), used_receipts)
        if mode == 'execute' and result['eligible']:
            result = execute(action, name, STATE / (name + '-' + str(time.time_ns()) + '.json'), receipt_sha256=receipt_identity(receipt))
        print(json.dumps(result))
        return 0 if mode == 'prepare' or result.get('status') in {'completed', 'active'} else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'blocked', 'reason': 'policy, identity, handler, or recovery validation failed'}))
        raise SystemExit(1)
