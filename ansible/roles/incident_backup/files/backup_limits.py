#!/usr/bin/env python3
"""Bound backup writes and retention without removing a source's last archive."""
import argparse
from collections import defaultdict
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tarfile


ARCHIVE = re.compile(r'([A-Za-z0-9_-]+)-\d{8}T\d{6}Z\.tar\.zst\.age$')


def archives(directory):
    return sorted((path for path in directory.glob('*.tar.zst.age')
                   if path.is_file() and not path.is_symlink()),
                  key=lambda path: (path.stat().st_mtime_ns, path.name))


def used_bytes(directory):
    return sum(path.stat().st_size for path in archives(directory))


def prune(directory, keep, maximum, minimum_free):
    if keep < 1 or maximum < 1 or minimum_free < 0:
        raise ValueError('invalid backup limits')
    sources = defaultdict(list)
    for path in archives(directory):
        match = ARCHIVE.fullmatch(path.name)
        if match:
            sources[match[1]].append(path)
    for copies in sources.values():
        for path in copies[:-keep]:
            path.unlink()
    # Preserve the newest archive of EVERY source, including retired sources.
    protected = {copies[-1] for copies in sources.values()}
    for path in archives(directory):
        if used_bytes(directory) <= maximum and shutil.disk_usage(directory).free >= minimum_free:
            return
        if path not in protected and ARCHIVE.fullmatch(path.name):
            path.unlink()
    if used_bytes(directory) > maximum or shutil.disk_usage(directory).free < minimum_free:
        raise ValueError('backup limit cannot be met while preserving the last archive of each source')


def budget(directory, maximum, minimum_free):
    available = min(maximum - used_bytes(directory), shutil.disk_usage(directory).free - minimum_free)
    if available <= 0:
        raise ValueError('no safe space for a new backup')
    return available


def bounded_write(stream, destination, limit, minimum_free):
    written = 0
    created = False
    try:
        with destination.open('xb') as output:
            created = True
            while chunk := stream.read(1024 * 1024):
                if written + len(chunk) > limit or shutil.disk_usage(destination.parent).free - len(chunk) < minimum_free:
                    raise ValueError('backup write would exceed its size or free-space limit')
                output.write(chunk)
                written += len(chunk)
        if not written:
            raise ValueError('empty backup stream')
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return written


def verify_sqlite(stream, directory, minimum_free):
    expected = {'incidents.db', 'incidents.db-wal', 'incidents.db-shm'}
    extracted = set()
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            if member.name not in expected:
                continue
            if not member.isfile() or member.name in extracted:
                raise ValueError('unexpected incident database archive member')
            if member.size:
                bounded_write(archive.extractfile(member), directory / member.name, member.size, minimum_free)
            else:
                (directory / member.name).touch(exist_ok=False)
            extracted.add(member.name)
    if 'incidents.db' not in extracted:
        raise ValueError('incident database missing from archive')
    connection = sqlite3.connect(f'file:{directory / "incidents.db"}?mode=ro', uri=True)
    try:
        connection.execute('PRAGMA cache_size=-8192')
        connection.execute('PRAGMA temp_store=FILE')
        if connection.execute('PRAGMA quick_check(1)').fetchone()[0] != 'ok':
            raise ValueError('incident database integrity check failed')
    finally:
        connection.close()


def clean_stale(directory):
    # Called under the receiver's flock. These are incomplete copies, never final archives.
    for path in directory.iterdir():
        if path.is_symlink():
            continue
        if path.is_file() and path.name.startswith('.') and path.name.endswith('.partial'):
            path.unlink()
        elif path.is_dir() and path.name.startswith(('.receive-', '.incident-verify.')):
            shutil.rmtree(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['clean', 'prune', 'budget', 'write', 'verify'])
    parser.add_argument('path', type=Path)
    parser.add_argument('--maximum', type=int, default=0)
    parser.add_argument('--minimum-free', type=int, default=0)
    parser.add_argument('--keep', type=int, default=1)
    args = parser.parse_args()
    if args.action == 'clean':
        clean_stale(args.path)
    elif args.action == 'prune':
        prune(args.path, args.keep, args.maximum, args.minimum_free)
    elif args.action == 'budget':
        print(budget(args.path, args.maximum, args.minimum_free))
    elif args.action == 'write':
        bounded_write(sys.stdin.buffer, args.path, args.maximum, args.minimum_free)
    else:
        verify_sqlite(sys.stdin.buffer, args.path, args.minimum_free)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, tarfile.TarError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
