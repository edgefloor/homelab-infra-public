#!/usr/bin/env python3
"""Read-only deployment discovery. Never retain command lines or environment values."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

MAX_FILE = 512 * 1024 * 1024


def mapped_backing_file(directory: Path, library: str, inode: int, device: tuple) -> Path:
    for candidate in (directory / 'root' / library.lstrip('/'), Path(library)):
        try:
            info = candidate.stat()
            if info.st_ino == inode and (os.major(info.st_dev), os.minor(info.st_dev)) == device:
                return candidate
        except OSError:
            continue
    raise ValueError('mapped backing file unavailable')


def container_binding(container: dict) -> dict:
    value = {k: v for k, v in container.items() if k not in {'changes', 'main_pid'}}
    value['code_changes'] = [line for line in container.get('changes', [])
        if len(line) > 2 and (line[2:].startswith(('/usr/', '/bin/', '/sbin/', '/lib/', '/opt/', '/app/'))
                             or Path(line[2:]).suffix in {'.conf', '.yaml', '.yml', '.toml', '.py', '.js', '.so', '.dll'})]
    return value


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        if os.fstat(stream.fileno()).st_size > MAX_FILE:
            raise ValueError('file exceeds evidence limit')
        before = os.fstat(stream.fileno())
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('file changed during observation')
        return value


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
    if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('discovery command failed or exceeded evidence limit')
    return result.stdout


def properties(unit: str) -> dict:
    if unit.endswith('@.service'):
        for root in ('/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
            path = Path(root) / unit
            if path.is_file():
                return {'Id': unit, 'ActiveState': 'template', 'MainPID': '0', 'FragmentPath': str(path), 'UnitFileState': 'enabled'}
    names = ['Id', 'ActiveState', 'SubState', 'MainPID', 'FragmentPath', 'ControlGroup', 'UnitFileState']
    return dict(line.split('=', 1) for line in run(
        ['systemctl', 'show', '--no-pager', '--property=' + ','.join(names), '--', unit]
    ).splitlines() if '=' in line)


def metadata_inventory(root: Path, limit: int = 100000) -> dict:
    """Bind installed package metadata to its path; source lockfiles are excluded."""
    resolved = root.resolve(strict=True)
    entries, count = [], 0
    if resolved.is_file():
        entries.append({'path': str(resolved), 'sha256': digest(resolved)})
    else:
        def walk_error(error):
            raise error
        for parent, dirs, files in os.walk(resolved, followlinks=False, onerror=walk_error):
            dirs[:] = sorted(d for d in dirs if d not in {'.git', '__pycache__', '.cache', 'logs', 'backups'})
            for name in sorted(files):
                count += 1
                if count > limit:
                    raise ValueError('metadata walk limit exceeded')
                path = Path(parent) / name
                if name in {'METADATA', 'PKG-INFO'} or name.endswith(('.deps.json', '.runtimeconfig.json')) or (name == 'package.json' and 'node_modules' in path.parts) or (not path.is_symlink() and path.stat().st_mode & 0o111):
                    entries.append({'path': str(path), 'sha256': digest(path)})
    payload = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    return {'path': str(root), 'resolved_path': str(resolved), 'sha256': hashlib.sha256(payload).hexdigest(), 'files': entries}


def discover(config: dict, proc: Path = Path('/proc')) -> dict:
    evidence = {'schema': 1, 'host': config['host'], 'observed_at': datetime.now(UTC).isoformat(),
                'config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                'services': [], 'processes': [], 'containers': [], 'scheduled_files': [], 'gaps': []}
    gaps = evidence['gaps']
    cache = {}

    def fingerprint(path: Path):
        stat = path.stat()
        key = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        if key not in cache:
            cache[key] = digest(path)
        after = path.stat()
        if key != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('file identity changed during observation')
        return cache[key]

    try:
        active = {line.split()[0] for line in run(['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--plain', '--no-legend']).splitlines() if len(line.split()) >= 2 and line.split()[1] != 'not-found'}
        enabled = {line.split()[0] for line in run(['systemctl', 'list-unit-files', '--type=service', '--state=enabled,enabled-runtime', '--no-pager', '--no-legend']).splitlines() if line.split()}
        for unit in sorted(active | enabled):
            try:
                item = properties(unit)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                gaps.append('service-discovery-failed:' + unit)
                continue
            owners = sorted(d['id'] for d in config['deployments'] if any(fnmatch.fnmatchcase(unit, pattern) for pattern in d.get('units', [])))
            fragment = item.get('FragmentPath')
            item['deployments'] = owners
            if fragment:
                try:
                    item['fragment_sha256'] = fingerprint(Path(fragment))
                except (OSError, ValueError):
                    gaps.append('service-file-unreadable:' + unit)
                if not owners:
                    result = subprocess.run(['dpkg-query', '-S', fragment], capture_output=True, text=True, timeout=10)
                    # usrmerge installations may retain the old /lib path in dpkg.
                    if result.returncode and fragment.startswith('/usr/lib/'):
                        result = subprocess.run(['dpkg-query', '-S', fragment.removeprefix('/usr')], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        item['os_package'] = result.stdout.split(': ', 1)[0].strip()
            if not owners and not item.get('os_package'):
                gaps.append('unclassified-service:' + unit)
            evidence['services'].append(item)
        evidence['timers'] = run(['systemctl', 'list-unit-files', '--type=timer', '--no-pager', '--no-legend']).splitlines()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        gaps.append('service-discovery-failed')

    for directory in sorted(proc.glob('[0-9]*')):
        try:
            if (directory / 'ns/pid').stat().st_ino != (proc / 'self/ns/pid').stat().st_ino:
                continue  # Guest/container identities belong to their own deployment.
            executable = os.readlink(directory / 'exe')
            item = {'pid': int(directory.name), 'executable': executable,
                    'sha256': fingerprint(directory / 'exe'),
                    'start_ticks': (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                    'cgroup': (directory / 'cgroup').read_text().splitlines()}
            mappings = [line.split(None, 5) for line in (directory / 'maps').read_text().splitlines()]
            mapped_files = {fields[5]: (int(fields[4]), tuple(int(v, 16) for v in fields[3].split(':')))
                            for fields in mappings if len(fields) == 6 and fields[5].startswith('/')}
            libraries = sorted(mapped_files)
            item['loaded_files'] = libraries
            item['loaded_file_identities'] = []
            # Hash current backing files for drift detection, while retaining
            # deleted mappings as gaps instead of substituting replacement files.
            for library in libraries:
                if library.endswith(' (deleted)') or library.startswith(('/dev/', '/memfd:', '/SYSV')):
                    continue
                try:
                    inode, device = mapped_files[library]
                    # A process can load a library before chroot. Only use the
                    # host path when its device/inode match the actual mapping.
                    backing = mapped_backing_file(directory, library, inode, device)
                    item['loaded_file_identities'].append({'path': library, 'sha256': fingerprint(backing), 'inode': inode})
                except (OSError, ValueError):
                    item.setdefault('unresolved_loaded_files', []).append(library)
                    gaps.append('loaded-files-unresolved:' + executable)
            if executable.endswith(' (deleted)') or any(p.endswith(' (deleted)') and not p.startswith(('/dev/', '/memfd:', '/SYSV')) for p in libraries):
                gaps.append('deleted-running-artifact:' + directory.name)
            evidence['processes'].append(item)
        except FileNotFoundError:
            continue  # Processes can exit during the snapshot.
        except (OSError, ValueError, IndexError):
            gaps.append('process-unreadable:' + directory.name)
    try:
        evidence['listeners'] = run(['ss', '-H', '-lntup']).splitlines()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        gaps.append('listener-discovery-failed')

    if shutil.which('docker'):
        try:
            ids = run(['docker', 'ps', '-aq', '--no-trunc']).split()
            for container in ids:
                template = '{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .State.Running}}\t{{json .Mounts}}\t{{json .HostConfig.PortBindings}}\t{{json .State.Pid}}'
                values = [json.loads(value) for value in run(['docker', 'inspect', '--format', template, container]).strip().split('\t')]
                item = dict(zip(['id', 'name', 'image_id', 'running', 'mounts', 'ports', 'main_pid'], values, strict=True))
                if item['running']:
                    try:
                        item['executable_sha256'] = fingerprint(proc / str(item['main_pid']) / 'exe')
                    except (OSError, ValueError):
                        gaps.append('container-executable-unreadable:' + item['name'])
                item['changes'] = run(['docker', 'diff', container]).splitlines()
                owners = [d['id'] for d in config['deployments'] if any(fnmatch.fnmatchcase(item['name'].lstrip('/'), pattern) for pattern in d.get('containers', []))]
                item['deployments'] = owners
                if not owners:
                    gaps.append('unclassified-container:' + item['name'])
                if item['mounts'] or item['changes']:
                    gaps.append('container-runtime-content-needs-assessment:' + item['name'])
                evidence['containers'].append(item)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            gaps.append('container-discovery-failed')

    for root in (Path('/etc/cron.d'), Path('/etc/cron.hourly'), Path('/etc/cron.daily'), Path('/etc/cron.weekly'), Path('/etc/cron.monthly'), Path('/var/spool/cron/crontabs'), Path('/etc/systemd/user')):
        try:
            for path in sorted(root.glob('*')):
                if path.is_file():
                    evidence['scheduled_files'].append({'path': str(path), 'sha256': fingerprint(path)})
        except (OSError, ValueError):
            gaps.append('scheduled-job-discovery-failed:' + str(root))
    if evidence['scheduled_files']:
        gaps.append('scheduled-job-payloads-not-classified')
    if Path('/etc/crontab').is_file():
        evidence['scheduled_files'].append({'path': '/etc/crontab', 'sha256': fingerprint(Path('/etc/crontab'))})
    evidence['configuration_files'] = []
    roots = set(config.get('configuration_roots', []))
    roots.update(m['Source'] for c in evidence['containers'] for m in c.get('mounts', []) if m.get('Source'))
    selected = {'.conf', '.json', '.yml', '.yaml', '.toml', '.service', '.socket', '.timer'}
    for root_name in sorted(roots):
        root = Path(root_name)
        try:
            if not root.exists():
                raise ValueError('declared configuration root missing')
            paths = [root] if root.is_file() else []
            if root.is_dir():
                walked = 0
                def walk_error(error):
                    raise error
                for parent, dirs, files in os.walk(root, onerror=walk_error):
                    dirs[:] = sorted(d for d in dirs if d not in {'.git', 'node_modules', '.venv', 'venv', 'logs', 'backups'})
                    walked += len(files)
                    if walked > 10000:
                        raise ValueError('configuration walk limit')
                    paths.extend(Path(parent) / name for name in sorted(files))
            for path in paths:
                if path.name not in {'Caddyfile', 'Corefile'} and path.suffix not in selected:
                    continue
                if re.search(r'(?i)(secret|token|password|credential|\.env)', str(path)):
                    continue
                if path.is_file():
                    evidence['configuration_files'].append({'path': str(path), 'sha256': fingerprint(path)})
        except (OSError, ValueError):
            gaps.append('configuration-discovery-incomplete:' + root_name)
    evidence['kernel'] = os.uname().release
    evidence['gaps'] = sorted(set(gaps))
    stable = {k: evidence[k] for k in ['containers', 'scheduled_files', 'configuration_files', 'kernel']}
    stable['containers'] = [container_binding(c) for c in evidence['containers']]
    # Ignore scanner/SSH processes and transient OS units. Track the application
    # service generation, its executable, and its loaded-file set instead.
    stable['services'] = [s for s in evidence['services'] if set(s.get('deployments', [])) - {'defensive-monitor'}]
    main_pids = {int(s.get('MainPID') or 0) for s in stable['services']}
    stable['processes'] = sorted({(p['executable'], p['sha256'], tuple(p['loaded_files'])) for p in evidence['processes'] if p['pid'] in main_pids})
    stable['loaded_file_identities'] = [p['loaded_file_identities'] for p in evidence['processes'] if p['pid'] in main_pids]
    stable['listeners'] = sorted(re.sub(r'pid=\d+,fd=\d+', 'process', line) for line in evidence.get('listeners', []))
    evidence['runtime_sha256'] = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
    return evidence
