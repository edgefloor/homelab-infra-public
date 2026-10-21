#!/usr/bin/env python3
"""Read-only archive freshness and backup-unit health check."""
import argparse
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


ARCHIVE = re.compile(r'tuwunel-\d{8}T\d{6}Z\.tar\.zst\.age\Z')


def problems(directory, now, unit, max_age):
    failures = []
    if unit.get('LoadState') != 'loaded':
        failures.append('backup service is not loaded')
    if unit.get('ActiveState') == 'failed' or unit.get('Result') != 'success':
        failures.append('backup service has an unresolved failure')
    completed = []
    if directory.is_dir():
        for path in directory.iterdir():
            if not ARCHIVE.fullmatch(path.name):
                continue
            try:
                metadata = path.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue  # Retention can remove an old archive during this read.
            if stat.S_ISREG(metadata.st_mode) and metadata.st_size:
                completed.append(metadata.st_mtime)
    if not completed:
        failures.append('no completed nonempty encrypted backup exists')
    else:
        age = now - max(completed)
        if age < -300:
            failures.append('newest backup timestamp is more than five minutes in the future')
        elif age > max_age:
            failures.append(f'newest completed backup is {int(age)} seconds old; limit is {max_age}')
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--max-age-seconds', type=int, default=8 * 86400)
    args = parser.parse_args()
    if args.max_age_seconds <= 0:
        parser.error('max-age-seconds must be positive')
    try:
        result = subprocess.run(
            ['systemctl', 'show', 'tuwunel-backup.service', '--property=LoadState',
             '--property=ActiveState', '--property=Result'],
            text=True, capture_output=True, timeout=5, check=True)
        unit = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        failures = problems(args.directory, time.time(), unit, args.max_age_seconds)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f'Cannot inspect Tuwunel backup health: {type(exc).__name__}', file=sys.stderr)
        return 1
    if failures:
        print('; '.join(failures), file=sys.stderr)
        return 1
    print('Tuwunel backup is current and its service has no unresolved failure')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
