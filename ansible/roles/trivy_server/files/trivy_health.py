#!/usr/bin/env python3
"""Read-only freshness check for the shared matcher, without agent invocation."""
import json
import time
from datetime import datetime
from urllib.request import urlopen


def validate_version(data, now=None):
    now = time.time() if now is None else now
    db = data.get('VulnerabilityDB', {})
    updated = datetime.fromisoformat(db['UpdatedAt'].replace('Z', '+00:00')).timestamp()
    next_update = datetime.fromisoformat(db['NextUpdate'].replace('Z', '+00:00')).timestamp()
    if data.get('Version') != '0.74.0' or db.get('Version') != 2:
        raise ValueError('Shared Trivy version or database schema differs from the pinned client')
    if updated > now + 3600 or now - updated > 72 * 3600 or now > next_update + 24 * 3600:
        raise ValueError('Shared Trivy database is stale or has an invalid timestamp')


def check():
    with urlopen('https://matrix.homelab.example/_trivy/version', timeout=20) as response:
        validate_version(json.loads(response.read(16384)))


if __name__ == '__main__':
    check()
    print('Shared Trivy database is reachable and fresh.')
