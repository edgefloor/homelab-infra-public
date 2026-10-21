#!/usr/bin/env python3
"""Check scan liveness independently; never run a scan or alter its evidence."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib import request

MAX_AGE = 36 * 3600
MAX_RUNTIME = 2 * 3600 + 300
CLOCK_TOLERANCE = 300


def read_json(path: Path, limit: int = 64 * 1024 * 1024) -> dict:
    with path.open('rb') as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('evidence exceeds read limit')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError('expected a JSON object')
    return value


def timestamp(value: str, now: datetime) -> datetime:
    if not isinstance(value, str):
        raise TypeError('missing timestamp')
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or (parsed - now).total_seconds() > CLOCK_TOLERANCE:
        raise ValueError('untrusted timestamp')
    return parsed


def unit_state(unit: str) -> dict:
    result = subprocess.run(
        ['systemctl', 'show', unit, '--property=LoadState,ActiveState,Result'],
        capture_output=True, text=True, timeout=15, check=True,
    )
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if not props.get('LoadState') or not props.get('ActiveState'):
        raise ValueError('incomplete unit state')
    return props


def assess(state_path: Path, now: datetime) -> dict:
    """A fresh completed scan is healthy scheduling, not complete application coverage."""
    def result(status, reason, **extra):
        return {'status': status, 'reason': reason, **extra}

    status_path = state_path.with_suffix('.status.json')
    try:
        initial_status = read_json(status_path, 4096)
    except (OSError, TypeError, ValueError):
        initial_status = None
    try:
        service = unit_state('homelab-cve-monitor.service')
        timer = unit_state('homelab-cve-monitor.timer')
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        return result('unhealthy', 'Scan service state is unavailable.')
    if service['LoadState'] != 'loaded' or timer['LoadState'] != 'loaded':
        return result('unhealthy', 'Scan service or schedule is missing.')
    if timer['ActiveState'] != 'active':
        return result('unhealthy', 'The daily scan schedule is inactive.')
    active = service['ActiveState'] in {'active', 'activating', 'reloading', 'deactivating'}
    if not active and (service['ActiveState'] == 'failed' or service.get('Result') != 'success'):
        return result('unhealthy', 'The scan service failed or was interrupted.')

    try:
        status = read_json(status_path, 4096)
        observed = timestamp(status.get('observed_at'), now)
        phase = status.get('status')
        if phase not in {'running', 'complete', 'failed', 'failure_notified'}:
            raise ValueError('unknown scan status')
    except FileNotFoundError:
        return result('unhealthy', 'Scan status is missing.')
    except (OSError, TypeError, ValueError):
        return result('unhealthy', 'Scan status is unreadable or invalid.')
    if status != initial_status:
        return result('running', 'Scan status changed during the check; awaiting a stable observation.')
    if phase in {'failed', 'failure_notified'}:
        return result('unhealthy', 'The latest scan failed.')
    if phase == 'running':
        if not active:
            return result('unhealthy', 'The scan stopped before recording completion.')
        if (now - observed).total_seconds() > MAX_RUNTIME:
            return result('unhealthy', 'The scan exceeded its two-hour runtime allowance.')

    try:
        state = read_json(state_path)
        completed = timestamp(state.get('updated_at'), now)
        if state.get('schema') != 1 or not isinstance(state.get('findings'), dict) or not isinstance(state.get('coverage'), dict):
            raise ValueError('invalid scan evidence')
        if (now - completed).total_seconds() > MAX_AGE:
            return result('unhealthy', 'No completed scan within 36 hours.')
        if phase == 'complete' and not 0 <= (observed - completed).total_seconds() <= CLOCK_TOLERANCE:
            raise ValueError('completion does not match evidence')
    except FileNotFoundError:
        if phase == 'running':
            return result('running', 'The first scan is in progress.')
        return result('unhealthy', 'Completed scan evidence is missing.')
    except (OSError, TypeError, ValueError):
        return result('unhealthy', 'Completed scan evidence is unreadable or invalid.')
    if phase == 'running' or active:
        return result('running', 'A scan is in progress.')
    return result('healthy', 'A recent scan completed.', completed_at=completed.isoformat())


def save_observation(path: Path, data: dict) -> None:
    # Only the watchdog writes this file; scanner status and findings are read-only.
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(data, handle, sort_keys=True)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def notify(payload: dict) -> None:
    url = os.environ.get('UPDATE_MONITOR_WEBHOOK_URL', '').strip()
    directory = os.environ.get('CREDENTIALS_DIRECTORY', '')
    if not url or not directory:
        raise RuntimeError('watchdog notification configuration is missing')
    secret = (Path(directory) / 'webhook-secret').read_text().strip()
    if not secret:
        raise RuntimeError('watchdog notification credential is empty')
    body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    outgoing = request.Request(url, data=body, method='POST', headers={
        'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json',
        'User-Agent': 'homelab-scan-watchdog/1',
    })
    with request.urlopen(outgoing, timeout=20) as response:
        if response.status != 202:
            raise RuntimeError('watchdog notification was not accepted')


def check(state_path: Path, observation_path: Path, now: datetime, *, check_only: bool = False) -> dict:
    current = assess(state_path, now)
    if check_only:
        return current
    try:
        prior = read_json(observation_path, 16384)
        if prior.get('schema') != 1 or not isinstance(prior.get('notified'), bool):
            raise ValueError('invalid watchdog state')
        if prior.get('episode_started_at'):
            timestamp(prior['episode_started_at'], now)
    except (OSError, TypeError, ValueError):
        prior = {}
    # Replay the exact payload after an ambiguous acknowledgement. The bridge's
    # Matrix transaction ID is derived from these bytes.
    if prior.get('pending_notification'):
        notify(prior['pending_notification'])
        prior.pop('pending_notification')
        if prior['status'] == 'healthy':
            prior.update(episode_started_at=None, notified=False)
        else:
            prior['notified'] = True
        save_observation(observation_path, prior)
    episode = prior.get('episode_started_at')
    notified = prior.get('notified', False)
    message = None
    if current['status'] == 'healthy' and episode and timestamp(current['completed_at'], now) < timestamp(episode, now):
        current = {'status': 'unhealthy', 'reason': 'A fresh completed scan is required after the interruption.'}
    if current['status'] == 'unhealthy':
        episode = episode or now.isoformat()
        if not notified:
            message = ('CVE scan health unknown. ' + current['reason'] +
                       ' Check homelab-cve-monitor.service and its timer; previous findings remain in cve-state.json.')
    elif current['status'] == 'healthy' and episode:
        if notified:
            message = 'CVE scanning recovered: a fresh scan completed. Application coverage gaps and findings remain separate.'
        else:
            episode = None
    data = {'schema': 1, 'observed_at': now.isoformat(), **current,
            'episode_started_at': episode, 'notified': notified}
    if message:
        data['pending_notification'] = {
            'kind': 'system', 'source': os.environ.get('UPDATE_MONITOR_SYSTEM_NAME', 'unknown host'),
            'message': message, 'context': {}, 'observed_at': now.isoformat(),
        }
    # Persist the episode before delivery; an unavailable bridge must not hide it.
    save_observation(observation_path, data)
    if message:
        notify(data['pending_notification'])
        data.pop('pending_notification')
        if current['status'] == 'healthy':
            data.update(episode_started_at=None, notified=False)
        else:
            data['notified'] = True
        save_observation(observation_path, data)
    return current


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--check-only', action='store_true', help='No notifications or writes')
    args = parser.parse_args()
    observation = args.state.with_suffix('.watchdog.json')
    if args.check_only:
        current = check(args.state, observation, datetime.now(UTC), check_only=True)
    else:
        with observation.with_suffix('.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = check(args.state, observation, datetime.now(UTC))
    print(json.dumps(current, sort_keys=True))
    return 1 if current['status'] == 'unhealthy' else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        # Transport errors can contain credential or endpoint details; keep them private.
        print('homelab-scan-watchdog: check or notification failed; retrying next timer tick', file=sys.stderr)
        raise SystemExit(1)
