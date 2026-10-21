#!/usr/bin/env python3
"""Explicit scratch lifecycle. Legacy evidence is never classified by extension."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import time
import uuid

GIB = 1024**3
JOB = re.compile(r'job_[0-9a-f]{32}$')
SHA = re.compile(r'[0-9a-f]{64}$')


def save(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
    with temporary.open('x') as stream:
        os.chmod(temporary, 0o660)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def size(path):
    """Logical bytes, without following links; conservative for shared hard links."""
    total = 0
    if path.is_symlink() or not path.is_dir():
        return 0
    for directory, folders, files in os.walk(path, followlinks=False):
        folders[:] = [name for name in folders if not (Path(directory)/name).is_symlink()]
        for name in files:
            try:
                info = (Path(directory)/name).lstat()
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
            except FileNotFoundError:
                pass
    return total


@contextmanager
def locked(path, blocking=True):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o660)
    try:
        # The creator repairs its umask. A peer can reuse the resulting group
        # lock without attempting an owner-only chmod.
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o660:
            os.fchmod(descriptor, 0o660)
        fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(descriptor)


class Workspaces:
    def __init__(self, root, cache, clock=time.time, min_free=3*GIB, job_limit=GIB,
                 total_limit=4*GIB, cache_limit=2*GIB):
        self.root, self.cache = Path(root), Path(cache)
        self.clock = clock
        self.min_free, self.job_limit = min_free, job_limit
        self.total_limit, self.cache_limit = total_limit, cache_limit
        for path in (self.root, self.cache):
            if path.is_symlink() or path.resolve() != path.absolute():
                raise ValueError('storage root must not traverse symlinks')
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if stat.S_IMODE(path.stat().st_mode) != 0o2770:
                os.chmod(path, 0o2770)

    def job(self, identifier):
        if not JOB.fullmatch(identifier):
            raise ValueError('invalid workspace ID')
        path = self.root/identifier
        if path.is_symlink() or not path.is_dir() or (path/'manifest.json').is_symlink():
            raise ValueError('invalid workspace directory')
        metadata = json.loads((path/'manifest.json').read_text())
        if metadata.get('schema') != 1 or metadata.get('id') != identifier:
            raise ValueError('invalid workspace manifest')
        return path, metadata

    def check_budget(self, job=None):
        used = sum(size(p/'scratch') for p in self.root.iterdir() if JOB.fullmatch(p.name) and not p.is_symlink())
        if used >= self.total_limit or shutil.disk_usage(self.root).free < self.min_free:
            raise ValueError('workspace storage budget exhausted')
        if job and size(job/'scratch') >= self.job_limit:
            raise ValueError('per-investigation storage budget exhausted')

    def create(self, label):
        if not isinstance(label, str) or not 1 <= len(label) <= 256:
            raise ValueError('invalid investigation label')
        with locked(self.root/'.lock'):
            self.check_budget()
            active = sum(self.job(p.name)[1]['completed'] is None for p in self.root.iterdir()
                         if JOB.fullmatch(p.name) and not p.is_symlink())
            if active >= 4 or shutil.disk_usage(self.root).free < self.min_free + (active+1)*self.job_limit:
                raise ValueError('workspace reservation budget exhausted')
            path = self.root/('job_' + uuid.uuid4().hex)
            path.mkdir(mode=0o770)
            (path/'scratch').mkdir(mode=0o770)
            (path/'evidence').mkdir(mode=0o770)
            for shared in (path, path/'scratch', path/'evidence'):
                os.chmod(shared, 0o2770)
            save(path/'manifest.json', {'schema':1, 'id':path.name, 'label':label,
                                        'created':self.clock(), 'completed':None})
            return path

    def finish(self, identifier):
        with locked(self.root/'.lock'):
            path, metadata = self.job(identifier)
            with locked(path/'.lock', blocking=False):
                metadata['completed'] = metadata['completed'] or self.clock()
                save(path/'manifest.json', metadata)

    def cleanup(self):
        removed = []
        with locked(self.root/'.lock'):
            for candidate in self.root.iterdir():
                if not JOB.fullmatch(candidate.name) or candidate.is_symlink():
                    continue
                try:
                    path, metadata = self.job(candidate.name)
                    with locked(path/'.lock', blocking=False):
                        scratch = path/'scratch'
                        if (metadata['completed'] is not None and self.clock()-metadata['completed'] >= 86400
                                and scratch.is_dir() and not scratch.is_symlink()):
                            shutil.rmtree(scratch)
                            removed.append(path.name)
                except (ValueError, OSError, KeyError):
                    continue  # Unknown, active, or malformed work is never deleted.
            for path in self.cache.iterdir():
                if not SHA.fullmatch(path.name) or path.is_symlink():
                    continue
                info = path.stat()
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and self.clock()-info.st_mtime > 7*86400:
                    path.unlink()
            save(self.root/'last-cleanup.json', {'checked':self.clock(), 'removed_scratch':removed})
        return removed

    def verify_access(self):
        """Exercise every shared lock through the same interface as normal work."""
        with locked(self.root/'.lock'):
            checked = 1
            for candidate in self.root.iterdir():
                if JOB.fullmatch(candidate.name) and candidate.is_dir() and not candidate.is_symlink():
                    with locked(candidate/'.lock', blocking=False):
                        checked += 1
        return checked

    def cache_add(self, source, expected):
        source = Path(source)
        if not SHA.fullmatch(expected) or source.is_symlink() or source.resolve() != source.absolute():
            raise ValueError('invalid hash or linked artifact path')
        with locked(self.root/'.lock'):
            with source.open('rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > self.job_limit:
                    raise ValueError('artifact storage budget exhausted')
                if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                    raise ValueError('artifact hash mismatch')
                after = os.fstat(stream.fileno())
                if (before.st_ino,before.st_size,before.st_mtime_ns) != (after.st_ino,after.st_size,after.st_mtime_ns):
                    raise ValueError('artifact changed while hashing')
            target = self.cache/expected
            if target.is_symlink():
                raise ValueError('linked cache object refused')
            if target.exists():
                with target.open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                        raise ValueError('cached artifact hash mismatch')
            else:
                if size(self.cache)+before.st_size > self.cache_limit:
                    raise ValueError('shared cache storage budget exhausted')
                os.link(source, target)  # Same filesystem, no second copy or broken references.
                target.chmod(0o444)
            os.utime(target, (self.clock(),self.clock()))
            return target

    def run(self, identifier, command):
        if not command:
            raise ValueError('a command is required')
        path, metadata = self.job(identifier)
        with locked(path/'.lock', blocking=False):
            if metadata['completed'] is not None or (path/'scratch').is_symlink():
                raise ValueError('workspace is completed or invalid')
            self.check_budget(path)
            scratch = path/'scratch'
            temp = scratch/'tmp'
            temp.mkdir(exist_ok=True)
            env = {**os.environ, 'TMPDIR':str(temp), 'XDG_CACHE_HOME':str(scratch/'.cache'),
                   'GOCACHE':str(scratch/'.cache/go-build'), 'GOMODCACHE':str(scratch/'.cache/go-mod'),
                   'UV_CACHE_DIR':str(scratch/'.cache/uv'), 'PIP_CACHE_DIR':str(scratch/'.cache/pip'),
                   'NPM_CONFIG_CACHE':str(scratch/'.cache/npm')}
            def limits():
                resource.setrlimit(resource.RLIMIT_FSIZE, (self.job_limit,self.job_limit))
            start = time.monotonic()
            with (scratch/'run.log').open('ab') as log:
                child = subprocess.Popen(command, cwd=scratch, env=env, stdout=log, stderr=log,
                                         start_new_session=True, preexec_fn=limits)
                try:
                    while child.poll() is None:
                        self.check_budget(path)
                        if time.monotonic()-start > 1200:
                            raise ValueError('investigation command deadline reached')
                        time.sleep(0.5)
                    self.check_budget(path)
                    return child.returncode
                finally:
                    # Do not allow background descendants to outlive the workspace lease.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()


def consolidate_runner(manager):
    """One reviewed legacy artifact only. All paths remain readable with identical bytes."""
    legacy = Path('/var/lib/homelab-investigator/work')
    expected = '70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613'
    records = []
    for source in sorted(legacy.glob('*/actions-runner-linux-x64-2.337.0.tar.gz')):
        if source.is_symlink() or source.parent.is_symlink():
            raise ValueError('linked legacy artifact refused')
        target = manager.cache_add(source, expected)
        if source.stat().st_ino != target.stat().st_ino:
            temporary = source.with_name(source.name + '.' + uuid.uuid4().hex)
            os.link(target, temporary)
            os.replace(temporary, source)
        records.append(str(source))
    save(manager.root/'legacy-runner-artifact.json', {'sha256':expected, 'shared_object':str(manager.cache/expected),
                                                   'references':records, 'verified':manager.clock()})
    return {'references':len(records), 'sha256':expected}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['create','run','finish','cleanup','status','cache-add','consolidate-runner','verify-access'])
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    policy = json.loads(Path('/etc/homelab-investigator/storage.json').read_text())
    manager = Workspaces(**policy)
    if args.action == 'create':
        print(manager.create(' '.join(args.arguments)))
    elif args.action == 'finish':
        manager.finish(args.arguments[0])
    elif args.action == 'run':
        command = args.arguments[1:]
        if command and command[0] == '--':
            command = command[1:]
        return manager.run(args.arguments[0], command)
    elif args.action == 'cleanup':
        print(json.dumps({'removed_scratch':manager.cleanup()}))
    elif args.action == 'cache-add':
        print(manager.cache_add(Path(args.arguments[0]), args.arguments[1]))
    elif args.action == 'consolidate-runner':
        print(json.dumps(consolidate_runner(manager)))
    elif args.action == 'verify-access':
        print(json.dumps({'locks_checked': manager.verify_access()}))
    else:
        print(json.dumps({'root_free_bytes':shutil.disk_usage(manager.root).free,
                          'workspace_bytes':size(manager.root), 'cache_bytes':size(manager.cache)}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(str(exc))
