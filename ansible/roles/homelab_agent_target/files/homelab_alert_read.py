#!/usr/bin/env python3
"""Read the exact deterministic alert records retained by the Matrix bridge."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path


STORE = Path('/var/lib/crowdsec-matrix-bridge/alerts')
RECORD_ID = re.compile(r'^crowdsec_[0-9a-f]{40}$')
KIND = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')
MAX_REQUEST_BYTES = 8192
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_LIMIT = 50


def read_record(path: Path) -> dict:
    if path.stat().st_size > MAX_RECORD_BYTES:
        raise ValueError('alert record exceeds size limit')
    record = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(record, dict) or record.get('schema') != 1:
        raise ValueError('invalid alert record')
    if path.name != f"{record.get('record_id')}.json":
        raise ValueError('alert record identity mismatch')
    return record


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('alert time must include a timezone')
    return parsed


def query(root: Path, request: dict) -> dict:
    if not isinstance(request, dict):
        raise ValueError('alert request must be an object')
    action = request.get('action')
    if action == 'get':
        if set(request) != {'action', 'record_id'}:
            raise ValueError('invalid alert get request')
        record_id = request.get('record_id')
        if not isinstance(record_id, str) or not RECORD_ID.fullmatch(record_id):
            raise ValueError('invalid alert record ID')
        return {'record': read_record(root / f'{record_id}.json')}

    if action != 'list':
        raise ValueError('unknown alert action')
    allowed = {'action', 'kind', 'contains', 'since', 'limit'}
    if set(request) - allowed:
        raise ValueError('invalid alert list request')
    kind = request.get('kind', '')
    contains = request.get('contains', '')
    since = request.get('since', '')
    limit = request.get('limit', 10)
    if kind and (not isinstance(kind, str) or not KIND.fullmatch(kind)):
        raise ValueError('invalid alert kind')
    if not isinstance(contains, str) or len(contains) > 200:
        raise ValueError('invalid alert search text')
    if not isinstance(since, str):
        raise ValueError('invalid alert start time')
    since_time = parse_time(since) if since else None
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError('alert limit must be between 1 and 50')

    records = []
    invalid = 0
    paths = sorted(
        root.glob('crowdsec_*.json') if root.is_dir() else [],
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    for path in paths:
        try:
            record = read_record(path)
            if kind and record.get('kind') != kind:
                continue
            if since_time and parse_time(str(record.get('received_at', ''))) < since_time:
                continue
            if contains and contains.casefold() not in json.dumps(
                record.get('payload'), sort_keys=True
            ).casefold():
                continue
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            invalid += 1
            continue
        records.append({key: value for key, value in record.items() if key != 'payload'})
        if len(records) == limit:
            break
    return {'records': records, 'invalid_records': invalid}


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('alert request exceeds size limit')
    request = json.loads(raw)
    print(json.dumps(query(STORE, request), separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({'error': str(exc)}, separators=(',', ':')))
        raise SystemExit(1) from exc
