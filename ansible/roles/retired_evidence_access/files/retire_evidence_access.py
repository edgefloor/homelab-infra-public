#!/usr/bin/env python3
"""Quarantine the retired evidence capability without touching personal Hermes."""

import argparse
import json
import os
import shutil
import time
from pathlib import Path


ENDPOINT_PATHS = (
    '/etc/sudoers.d/homelab-agent',
    '/var/lib/homelab-agent/.ssh/authorized_keys',
    '/var/lib/homelab-agent/.ssh/authorized_keys2',
    '/usr/local/libexec/homelab-evidence-gateway',
    '/usr/local/libexec/homelab-agent-remote',
    '/usr/local/libexec/homelab-guest-agent',
    '/etc/homelab-agent/evidence-policy.json',
    '/run/homelab-evidence-gateway',
)
CONTROLLER_PATHS = (
    '/usr/local/bin/homelab-agentctl',
    '/var/lib/hermes-agent/.hermes/skills/homelab-oncall',
    '/var/lib/homelab-investigator/.ssh',
    '/etc/homelab-investigator/targets.json',
    '/etc/homelab-investigator/coverage-systems.json',
)
ARCHIVE = '/var/backups/homelab-evidence-retired/2026-10-17'


def retire(root=Path('/'), *, controller=False):
    archive = root / ARCHIVE.lstrip('/')
    archive.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive.chmod(0o700)
    moved = []
    for name in ENDPOINT_PATHS + (CONTROLLER_PATHS if controller else ()):
        source = root / name.lstrip('/')
        if not source.exists() and not source.is_symlink():
            continue
        destination = archive / name.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists() or destination.is_symlink():
            destination = destination.with_name(destination.name + '.' + str(time.time_ns()))
        shutil.move(str(source), str(destination))
        # The enclosing archive is private, including retained directories and
        # symlinks. Regular executable copies also lose execute permission.
        if destination.is_file() and not destination.is_symlink():
            destination.chmod(0o600)
        moved.append(name)
    return {'changed': bool(moved), 'quarantined_paths': moved, 'archive': ARCHIVE}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('retirement requires root')
    print(json.dumps(retire(controller=args.controller), sort_keys=True))
