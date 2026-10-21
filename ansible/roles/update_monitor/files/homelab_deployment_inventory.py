#!/usr/bin/env python3
"""Read-only deployment discovery. Never retain command lines or environment values."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import pwd
import grp
import errno
import stat
from email.parser import Parser
from datetime import UTC, datetime
from pathlib import Path
from urllib import parse

MAX_FILE = 512 * 1024 * 1024
MAX_PACKAGE_FILES = 100000
PACKAGE_PROFILE_RULE = 'package-artifact-profile/v1'
PACKAGE_OBSERVATION_RULE = 'package-runtime-binding/v2'
PACKAGE_CAPABILITY_RULE = 'package-capability-binding/v1'
UNIT_EXECUTION_FIELDS = ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecReload')
UNIT_PRIVILEGE_FIELDS = (
    'User', 'Group', 'DynamicUser', 'CapabilityBoundingSet', 'AmbientCapabilities',
    'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp',
    'ReadWritePaths', 'ReadOnlyPaths', 'InaccessiblePaths', 'NoExecPaths',
    'ExecPaths', 'RootDirectory', 'RootImage', 'RestrictSUIDSGID',
)
UNIT_METADATA_FIELDS = (
    'Id', 'ActiveState', 'SubState', 'MainPID', 'FragmentPath', 'DropInPaths',
    'ControlGroup', 'UnitFileState', 'Triggers', 'TriggeredBy',
)
PROCESS_PRIVILEGE_FIELDS = (
    'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb',
    'NoNewPrivs', 'Seccomp',
)
EXECUTION_OBSERVATION_RULE = 'service-process-identity/v1'
MAX_ACCESS_PATHS = 256
MAX_ACCESS_BYTES = 1024 * 1024
PACKAGE_IDENTITY_DERIVATION_RULE = 'native-package-identity/v1'
FINITE_EXECUTION_OBSERVATION_RULE = 'finite-execution-observation/v1'


def purl_version(purl: str) -> str:
    parsed = parse.urlsplit(str(purl or ''))
    path = parsed.path
    package = path.rsplit('/', 1)[-1]
    version = parse.unquote(package.rsplit('@', 1)[1]) if '@' in package else ''
    epochs = parse.parse_qs(parsed.query).get('epoch', [])
    if version and len(epochs) == 1 and epochs[0] and epochs[0] != '0':
        version = epochs[0] + ':' + version
    return version


def released_version(version, release='', epoch='') -> str:
    value = str(version or '')
    release = str(release or '')
    epoch = str(epoch or '')
    if not value:
        return ''
    if release:
        value += '-' + release
    if epoch and epoch != '0':
        value = epoch + ':' + value
    return value


def native_scanner_identity(package: dict) -> dict:
    identifier = package.get('Identifier') or {}
    purl = str(identifier.get('PURL') or '')
    architectures = parse.parse_qs(parse.urlsplit(purl).query).get('arch', [])
    facts = {
        'version': str(package.get('Version') or ''),
        'release': str(package.get('Release') or ''),
        'epoch': str(package.get('Epoch') or ''),
        'source_name': str(package.get('SrcName') or ''),
        'source_version': str(package.get('SrcVersion') or ''),
        'source_release': str(package.get('SrcRelease') or ''),
        'source_epoch': str(package.get('SrcEpoch') or ''),
        'purl': purl,
    }
    return {
        'version': purl_version(purl) or released_version(
            facts['version'], facts['release'], facts['epoch']),
        'source_name': facts['source_name'],
        'source_version': released_version(
            facts['source_version'], facts['source_release'], facts['source_epoch']),
        'purl': purl,
        'architecture': architectures[0] if len(architectures) == 1 else '',
        'package_identity_derivation': {
            'rule': PACKAGE_IDENTITY_DERIVATION_RULE,
            'facts': facts,
        },
    }


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
    if 'process_privileges' in value:
        observations = [{key: process[key] for key in ('executable', 'privileges')}
                        for process in value['process_privileges']]
        value['process_privileges'] = sorted({
            json.dumps(item, sort_keys=True): item for item in observations}.values(),
            key=lambda item: json.dumps(item, sort_keys=True))
    value['code_changes'] = [line for line in container.get('changes', [])
        if len(line) > 2 and (line[2:].startswith(('/usr/', '/bin/', '/sbin/', '/lib/', '/opt/', '/app/'))
                             or Path(line[2:]).suffix in {'.conf', '.yaml', '.yml', '.toml', '.py', '.js', '.so', '.dll'})]
    return value


def container_resource_key(host: str, container: dict) -> str:
    """Identify the durable container slot, not one engine instance."""
    return 'container:' + host + ':' + str(container.get('name') or '').lstrip('/')


def stable_runtime_identity(evidence: dict) -> str:
    """Hash stable artifacts and relationships without transient process identity."""
    containers = []
    for container in evidence.get('containers', []):
        value = container_binding(container)
        value.pop('id', None)
        containers.append(value)
    package_relationships = []
    for package in evidence.get('package_evidence', []):
        namespace = dict(package.get('namespace') or {})
        namespace.pop('container_id', None)
        observations = []
        for observation in package.get('observations') or []:
            file_identity = observation.get('file') or {}
            consumer = observation.get('consumer') or {}
            observations.append({
                'relation': observation.get('relation'),
                'claim_kind': observation.get('claim_kind'),
                'derivation': observation.get('derivation') or {},
                'file': {key: file_identity.get(key) for key in
                         ('path', 'sha256', 'packaged_md5', 'actual_md5',
                          'replacement_status')},
                'consumer': {key: consumer.get(key) for key in
                             ('kind', 'executable', 'executable_sha256', 'service',
                              'id', 'deployments', 'activation_sources', 'privileges')},
            })
        observations = sorted({json.dumps(item, sort_keys=True,
                                           separators=(',', ':')): item
                               for item in observations}.values(),
                              key=lambda item: json.dumps(
                                  item, sort_keys=True, separators=(',', ':')))
        profile = package.get('artifact_profile') or {}
        capabilities = package.get('declared_capabilities') or []
        execution_domains = package.get('execution_domains') or []
        consumer_dependencies = package.get(
            'consumer_coverage_dependencies') or []
        if (observations or profile or capabilities or execution_domains or
                consumer_dependencies):
            package_relationships.append({
                'namespace': namespace,
                'installed': package.get('installed') or {},
                'slots': package.get('slots') or [],
                'file_inventory_sha256': package.get('file_inventory_sha256'),
                'artifact_profile': profile,
                'declared_capabilities': capabilities,
                'execution_domains': execution_domains,
                'consumer_coverage_dependencies': consumer_dependencies,
                'observations': observations,
            })
    package_relationships = sorted({json.dumps(item, sort_keys=True,
                                                separators=(',', ':')): item
                                    for item in package_relationships}.values(),
                                   key=lambda item: json.dumps(
                                       item, sort_keys=True, separators=(',', ':')))
    stable = {
        'containers': sorted(containers, key=lambda value: json.dumps(value, sort_keys=True)),
        'scheduled_files': evidence.get('scheduled_files', []),
        'activated_units': evidence.get('activated_units', []),
        'configuration_files': evidence.get('configuration_files', []),
        'kernel': evidence.get('kernel', {}),
        'services': evidence.get('services', []),
        'processes': evidence.get('processes', []),
        'loaded_file_identities': evidence.get('loaded_file_identities', []),
        'listeners': evidence.get('listeners', []),
        'execution_observations': evidence.get('execution_observations', []),
        'execution_domains': evidence.get('execution_domains', []),
        'execution_domain_facts': evidence.get('execution_domain_facts', {}),
        'path_access': evidence.get('path_access', []),
        'package_relationships': package_relationships,
    }
    return hashlib.sha256(json.dumps(
        stable, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def digest(path: Path, algorithm: str = 'sha256') -> str:
    with path.open('rb') as stream:
        if os.fstat(stream.fileno()).st_size > MAX_FILE:
            raise ValueError('file exceeds evidence limit')
        before = os.fstat(stream.fileno())
        value = hashlib.file_digest(stream, algorithm).hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('file changed during observation')
        return value


def process_privileges(directory: Path) -> dict:
    """Retain only kernel credential/privilege fields, never process arguments."""
    values = {}
    try:
        with (directory / 'status').open() as handle:
            raw = handle.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError('process status limit')
        for line in raw.splitlines():
            name, separator, value = line.partition(':')
            if not separator or name not in PROCESS_PRIVILEGE_FIELDS:
                continue
            fields = value.split()
            if name in {'Uid', 'Gid'}:
                if len(fields) == 4 and all(part.isdecimal() for part in fields):
                    values[name] = [int(part) for part in fields]
            elif name.startswith('Cap'):
                if len(fields) == 1 and re.fullmatch(r'[0-9a-fA-F]{1,16}', fields[0]):
                    values[name] = fields[0].lower().zfill(16)
            elif len(fields) == 1 and fields[0] in (
                    {'0', '1'} if name == 'NoNewPrivs' else {'0', '1', '2'}):
                values[name] = int(fields[0])
    except (OSError, ValueError):
        pass
    missing = sorted(set(PROCESS_PRIVILEGE_FIELDS) - values.keys())
    return {'kind': 'observation', 'source': 'proc.status', 'values': values,
            'status': 'incomplete' if missing else 'complete',
            'missing_fields': missing}


def process_inventory(proc: Path, namespace_inode: int, fingerprint, gaps: list[str],
                      gap_label: str) -> list[dict]:
    """Read one PID namespace with identical host and container semantics."""
    result = []
    for directory in sorted(proc.glob('[0-9]*')):
        try:
            if (directory / 'ns/pid').stat().st_ino != namespace_inode:
                continue
            initial_stat = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(initial_stat[6]) & 0x00200000:  # PF_KTHREAD has no userspace executable.
                continue
            executable = os.readlink(directory / 'exe')
            executable_stat = (directory / 'exe').stat()
            process = {
                'pid': int(directory.name), 'executable': executable,
                'sha256': fingerprint(directory / 'exe'),
                'executable_identity': {
                    'inode': executable_stat.st_ino,
                    'device': [os.major(executable_stat.st_dev),
                               os.minor(executable_stat.st_dev)]},
                'start_ticks': initial_stat[19],
                'cgroup': (directory / 'cgroup').read_text().splitlines(),
            }
            process['privileges'] = process_privileges(directory)
            if process['privileges']['status'] != 'complete':
                gaps.append('process-privileges-incomplete:' + gap_label + ':' + directory.name)
            mappings = [line.split(None, 5) for line in
                        (directory / 'maps').read_text().splitlines()]
            mapped = {fields[5]: (int(fields[4]),
                      tuple(int(value, 16) for value in fields[3].split(':')))
                      for fields in mappings
                      if len(fields) == 6 and fields[5].startswith('/')}
            process['loaded_files'] = sorted(mapped)
            process['loaded_file_identities'] = []
            for path, (inode, device) in sorted(mapped.items()):
                if path.endswith(' (deleted)'):
                    process.setdefault('unresolved_loaded_files', []).append(path)
                    gaps.append('deleted-running-artifact:' + gap_label + ':' + directory.name)
                    continue
                if path.startswith(('/dev/', '/memfd:', '/SYSV')):
                    continue
                try:
                    backing = mapped_backing_file(directory, path, inode, device)
                    process['loaded_file_identities'].append({
                        'path': path, 'sha256': fingerprint(backing), 'inode': inode,
                        'device': list(device)})
                except (OSError, ValueError):
                    process.setdefault('unresolved_loaded_files', []).append(path)
                    gaps.append('loaded-files-unresolved:' + gap_label + ':' + executable)
            if executable.endswith(' (deleted)'):
                gaps.append('deleted-running-artifact:' + gap_label + ':' + directory.name)
            # A recycled PID must not combine one executable with another user's
            # credentials. Keep the sample out of positive relationships.
            final_start = (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19]
            final_executable = (directory / 'exe').stat()
            if (final_start != process['start_ticks'] or
                    final_executable.st_ino != executable_stat.st_ino or
                    final_executable.st_dev != executable_stat.st_dev):
                gaps.append('process-changed-during-observation:' + gap_label + ':' + directory.name)
                continue
            result.append(process)
        except FileNotFoundError:
            gaps.append('process-disappeared:' + gap_label + ':' + directory.name)
            continue
        except (OSError, ValueError, IndexError):
            gaps.append('process-unreadable:' + gap_label + ':' + directory.name)
    return result


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
    if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('discovery command failed or exceeded evidence limit')
    return result.stdout


def properties(unit: str) -> dict:
    names = (*UNIT_METADATA_FIELDS, *UNIT_EXECUTION_FIELDS, *UNIT_PRIVILEGE_FIELDS)
    return dict(line.split('=', 1) for line in run(
        ['systemctl', 'show', '--no-pager', '--property=' + ','.join(names), '--', unit]
    ).splitlines() if '=' in line and line.split('=', 1)[0] in names)


def unit_executables(unit: dict) -> list[str]:
    paths = []
    for field in UNIT_EXECUTION_FIELDS:
        paths.extend(re.findall(r'(?:^|[;{ ])path=([^ ;}]+)', unit.get(field, '')))
    return sorted(set(path for path in paths if path.startswith('/')))


def unit_evidence(unit: dict) -> dict:
    """Keep executable paths and discard systemd command arguments."""
    value = {key: unit[key] for key in UNIT_METADATA_FIELDS if key in unit}
    value['executables'] = unit_executables(unit)
    fields = {key: unit[key] for key in UNIT_PRIVILEGE_FIELDS if key in unit}
    value['execution_settings'] = {
        'kind': 'observation', 'source': 'systemctl.show', 'values': fields,
        'status': 'complete' if len(fields) == len(UNIT_PRIVILEGE_FIELDS) else 'incomplete',
        'missing_fields': sorted(set(UNIT_PRIVILEGE_FIELDS) - fields.keys()),
    }
    return value


def service_execution_identity(service: dict, processes: list[dict]) -> dict:
    """Compare effective unit identity with a bound main-process observation."""
    result = {'kind': 'derived', 'rule': EXECUTION_OBSERVATION_RULE,
              'status': 'unknown', 'differences': [], 'unknown_fields': [],
              'identity_resolution': {},
              'input_refs': ['systemd-unit:' + service['Id']]}
    pid = int(service.get('MainPID') or 0)
    if not pid:
        result['reason'] = 'no_current_main_process'
        return result
    matches = [process for process in processes if process['pid'] == pid]
    if len(matches) != 1:
        result['reason'] = 'main_process_not_observed'
        return result
    process = matches[0]
    group = service.get('ControlGroup')
    if not group or group not in {line.split(':', 2)[-1] for line in process.get('cgroup', [])}:
        result['reason'] = 'main_process_cgroup_not_confirmed'
        return result
    observed = process.get('privileges', {}).get('values', {})
    result['observed'] = process.get('privileges', {})
    result['input_refs'].append('main-process:' + str(pid) + ':' + str(process.get('start_ticks')))
    settings = service.get('execution_settings', {}).get('values', {})
    for field, status_field, resolver, attribute in (
            ('User', 'Uid', pwd.getpwnam, 'pw_uid'),
            ('Group', 'Gid', grp.getgrnam, 'gr_gid')):
        name = settings.get(field)
        expected = None
        if name:
            try:
                expected = int(name) if str(name).isdecimal() else getattr(resolver(name), attribute)
                result['identity_resolution'][field] = {
                    'kind': 'observation', 'name': name, 'id': expected,
                    'source': 'systemctl.show.numeric' if str(name).isdecimal() else
                              'nss.passwd' if field == 'User' else 'nss.group'}
            except (KeyError, OSError):
                pass
        # Empty systemd identities are retained as empty. Do not silently resolve
        # defaults, DynamicUser allocation or implicit primary groups to root.
        if expected is None or status_field not in observed:
            result['unknown_fields'].append(field)
        elif expected != observed[status_field][1]:
            result['differences'].append({'field': field, 'unit': name,
                                          'unit_id': expected,
                                          'process_effective_id': observed[status_field][1]})
    if settings.get('NoNewPrivileges') == 'yes' and observed.get('NoNewPrivs') == 0:
        result['differences'].append({'field': 'NoNewPrivileges', 'unit': 'yes', 'process': 0})
    if 'NoNewPrivileges' not in settings or 'NoNewPrivs' not in observed:
        result['unknown_fields'].append('NoNewPrivileges')
    result['status'] = ('disagreement' if result['differences'] else
                        'unknown' if result['unknown_fields'] else 'matched_identity')
    if 'Uid' in observed:
        result['effective_uid'] = observed['Uid'][1]
    return result


def path_access_evidence(path: Path) -> dict:
    """Read bounded inode/ACL metadata for one declared path and its ancestors."""
    result = {'path': str(path), 'kind': 'observation', 'source': 'filesystem.metadata',
              'namespace': 'collector-filesystem',
              'entries': [], 'status': 'complete', 'gaps': []}
    if not path.is_absolute():
        return {**result, 'status': 'incomplete', 'gaps': ['relative-path']}
    # Resolve one component at a time. Path.resolve() would hide intermediary
    # links, and normalizing '..' before a link would change kernel semantics.
    pending = ['.', *path.parts[1:]]
    current = Path('/')
    entries = {}
    states = set()
    traversals = 0
    while pending and traversals < 64:
        traversals += 1
        part = pending.pop(0)
        current = current.parent if part == '..' else current / part
        state = (str(current), tuple(pending))
        if state in states:
            result['gaps'].append(str(current) + ':symlink-cycle')
            pending = []
            break
        states.add(state)
        try:
            info = current.lstat()
            entry = {'path': str(current), 'uid': info.st_uid, 'gid': info.st_gid,
                     'mode': oct(stat.S_IMODE(info.st_mode)),
                     'inode': info.st_ino, 'device': info.st_dev,
                     'type': 'symlink' if stat.S_ISLNK(info.st_mode) else
                             'directory' if stat.S_ISDIR(info.st_mode) else
                             'file' if stat.S_ISREG(info.st_mode) else 'special'}
            if stat.S_ISLNK(info.st_mode):
                entry['link'] = os.readlink(current)
                target = Path(entry['link'])
                if target.is_absolute():
                    current_parent = Path('/')
                    next_parts = ['.', *target.parts[1:]]
                else:
                    current_parent = current.parent
                    next_parts = list(target.parts)
            else:
                for field, attribute in (('posix_acl', 'system.posix_acl_access'),
                                         ('file_capabilities', 'security.capability')):
                    try:
                        raw = os.getxattr(current, attribute, follow_symlinks=False)
                        if len(raw) > 64 * 1024:
                            raise ValueError('extended attribute limit')
                        entry[field] = {'status': 'present', 'encoding': 'hex', 'value': raw.hex()}
                    except OSError as exc:
                        if exc.errno in {errno.ENODATA, getattr(errno, 'ENOATTR', errno.ENODATA)}:
                            entry[field] = {'status': 'absent'}
                        else:
                            entry[field] = {'status': 'unknown'}
                            result['gaps'].append(str(current) + ':' + field)
                    except (AttributeError, ValueError):
                        entry[field] = {'status': 'unknown'}
                        result['gaps'].append(str(current) + ':' + field)
            after = current.lstat()
            if (info.st_ino, info.st_dev, info.st_ctime_ns) != (
                    after.st_ino, after.st_dev, after.st_ctime_ns):
                result['gaps'].append(str(current) + ':changed')
            previous = entries.get(entry['path'])
            if previous is not None and previous != entry:
                result['gaps'].append(entry['path'] + ':changed-between-traversals')
            entries[entry['path']] = entry
            if entry['type'] == 'symlink':
                current = current_parent
                pending = next_parts + pending
            elif pending and entry['type'] != 'directory':
                result['gaps'].append(str(current) + ':not-directory')
                pending = []
        except (OSError, ValueError, RuntimeError):
            result['gaps'].append(str(current) + ':unavailable')
            pending = []
    if pending:
        result['gaps'].append('path-chain-limit')
    if result['gaps']:
        result['status'] = 'incomplete'
    result['entries'] = sorted(entries.values(), key=lambda entry: entry['path'])
    return result


def scheduled_file(path: Path, *, filesystem_root: Path = Path('/'),
                   run_parts_selector=None) -> tuple[dict, list[str]]:
    """Resolve bounded cron forms without executing a scheduled command."""
    filesystem_root = Path(filesystem_root)
    try:
        relative = path.relative_to(filesystem_root)
        logical_path = '/' + str(relative)
    except ValueError:
        logical_path = str(path)
    value = {'path': logical_path, 'sha256': digest(path), 'executables': [],
             'unresolved_executables': [], 'scheduler_selection': 'eligible'}

    def select_run_parts(directory: str) -> list[str]:
        if run_parts_selector is not None:
            selected = run_parts_selector(directory)
        else:
            selected = run(['/usr/bin/run-parts', '--test', '--report',
                            directory]).splitlines()
        prefix = directory.rstrip('/') + '/'
        selected = sorted(set(str(item).strip() for item in selected
                              if str(item).strip()))
        if (len(selected) > 512 or any(not item.startswith(prefix)
                                       for item in selected)):
            raise ValueError('invalid run-parts selection')
        return selected

    if path.parent.name in {'cron.hourly', 'cron.daily', 'cron.weekly', 'cron.monthly'}:
        directory = str(Path(logical_path).parent)
        try:
            selected = select_run_parts(directory)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            value['scheduler_selection'] = 'unknown'
            value['selection_reason'] = 'run-parts-selection-failed'
            return value, ['run-parts-selection-failed']
        value['selection_records'] = [{
            'kind': 'run-parts-candidate', 'directory': directory,
            'selected': logical_path in selected}]
        if logical_path in selected:
            value['executables'] = [logical_path]
            return value, []
        value['scheduler_selection'] = 'ineligible'
        value['selection_reason'] = 'not-selected-by-run-parts'
        return value, []
    if (Path(logical_path).parent == Path('/etc/cron.d') and
            not re.fullmatch(r'[A-Za-z0-9_-]+', Path(logical_path).name)):
        value['scheduler_selection'] = 'ineligible'
        value['selection_reason'] = 'invalid-cron.d-filename'
        return value, []
    unsupported = []
    executables = []
    selection_records = []
    try:
        lines = path.read_text(errors='replace').splitlines()
    except OSError:
        return value, ['unreadable']
    system_cron = (logical_path == '/etc/crontab' or
                   Path(logical_path).parent == Path('/etc/cron.d'))

    def rooted(logical: str) -> Path:
        return filesystem_root / logical.lstrip('/')

    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', line):
            continue
        field_count = 6 if system_cron else 5
        cron_fields = re.match(
            r'^\s*(?:\S+[ \t]+){' + str(field_count) + r'}(.*)$', raw)
        if cron_fields is None or not cron_fields.group(1).strip():
            unsupported.append(str(number) + ':missing-command')
            continue
        # Match supported forms against the original command substring. Shell
        # comments begin only at a token boundary, so shlex comments would
        # incorrectly turn "-r#suffix ; command" into the supported "-r".
        command_text = cron_fields.group(1).strip()
        run_parts_match = re.fullmatch(
            r'(test -x /usr/sbin/anacron \|\| \{ )?cd / && '
            r'(?:/usr/bin/)?run-parts --report '
            r'(/etc/cron\.(?:hourly|daily|weekly|monthly));? ?\}?',
            command_text)
        if run_parts_match:
            directory = run_parts_match.group(2)
            guarded = run_parts_match.group(1) is not None
            guard_active = guarded and os.access(
                rooted('/usr/sbin/anacron'), os.X_OK)
            record = {'line': number, 'kind': 'run-parts',
                      'directory': directory,
                      'guard': ('anacron-not-executable' if guarded else None),
                      'guard_active': guard_active}
            if guard_active:
                record['selected'] = []
                selection_records.append(record)
                continue
            try:
                selected = select_run_parts(directory)
            except (OSError, RuntimeError, ValueError,
                    subprocess.SubprocessError):
                unsupported.append(str(number) + ':run-parts-selection-failed')
                value['unresolved_executables'].append('/usr/bin/run-parts')
                continue
            record['selected'] = selected
            selection_records.append(record)
            executables.extend(['/usr/bin/run-parts', *selected])
            continue

        e2scrub_match = re.fullmatch(
            r'test -e /run/systemd/system \|\| SERVICE_MODE=1 '
            r'(?:(/usr/libexec/e2fsprogs/e2scrub_all_cron)|'
            r'(/sbin/e2scrub_all) -A -r)', command_text)
        if e2scrub_match:
            guard_active = rooted('/run/systemd/system').is_dir()
            selection_records.append({
                'line': number, 'kind': 'filesystem-guard',
                'path': '/run/systemd/system', 'guard_active': guard_active,
                'selected': [] if guard_active else [
                    e2scrub_match.group(1) or e2scrub_match.group(2)]})
            if not guard_active:
                executables.append(
                    e2scrub_match.group(1) or e2scrub_match.group(2))
            continue

        try:
            command = shlex.split(command_text, comments=False, posix=True)
        except ValueError:
            unsupported.append(str(number) + ':invalid-shell-syntax')
            continue
        shell_dispatch = (command[0] in {
            '/bin/sh', '/usr/bin/sh', '/bin/bash', '/usr/bin/bash',
            '/bin/dash', '/usr/bin/dash'} and len(command) > 1)
        if (not command[0].startswith('/') or shell_dispatch or
                any(token in command_text for token in
                    ('|', '&&', '||', ';', '&', '$(', '`', '>', '<'))):
            unsupported.append(str(number) + ':unsupported-command')
            if command[0].startswith('/'):
                value['unresolved_executables'].append(command[0])
            continue
        executables.append(command[0])
    value['executables'] = sorted(set(executables))
    value['unresolved_executables'] = sorted(set(
        value['unresolved_executables']))
    if selection_records:
        value['selection_records'] = selection_records
    if unsupported:
        value['unsupported'] = unsupported
    return value, unsupported


def scanner_package_requests(reports: list[dict]) -> dict:
    """Select installed OS package slots independently of current advisories."""
    result = {'host': [], 'images': {}}
    selected = {}
    for report in reports:
        runtime = report.get('_homelab_runtime') or {}
        for item in report.get('Results') or []:
            if runtime and item.get('Class') != 'os-pkgs':
                continue
            if not runtime and report.get('_homelab_scan_kind') != 'os':
                continue
            native = item.get('Class') == 'os-pkgs'
            vulnerable = {(str(finding.get('PkgName') or ''),
                           str(finding.get('InstalledVersion') or ''))
                          for finding in item.get('Vulnerabilities') or []}
            packages = list(item.get('Packages') or [])
            known = {(str(package.get('Name') or ''),
                      (native_scanner_identity(package)['version'] if native else
                       str(package.get('Version') or ''))) for package in packages}
            packages.extend({'Name': name, 'Version': version}
                            for name, version in vulnerable - known if name and version)
            for metadata in packages:
                name = str(metadata.get('Name') or '')
                identity = (native_scanner_identity(metadata) if native else {
                    'version': str(metadata.get('Version') or ''),
                    'source_name': str(metadata.get('SrcName') or ''),
                    'source_version': str(metadata.get('SrcVersion') or ''),
                    'purl': str((metadata.get('Identifier') or {}).get('PURL') or ''),
                    'architecture': '',
                })
                version = identity['version']
                if not name or not version:
                    continue
                purl = identity['purl']
                architectures = parse.parse_qs(parse.urlsplit(purl).query).get('arch', [])
                location = str(metadata.get('FilePath') or metadata.get('PkgPath') or
                               ('/' if runtime else item.get('Target') or '/'))
                request = {
                    'name': name, 'version': version,
                    'ecosystem': str(item.get('Type') or item.get('Class') or 'unknown'),
                    'source_name': identity['source_name'],
                    'source_version': identity['source_version'],
                    'purl': purl,
                    'architecture': identity['architecture'] or (
                        architectures[0] if len(architectures) == 1 else ''),
                    'artifact_id': str(runtime.get('image_id') or ''),
                    'consumer_class': 'runtime-os' if runtime else 'host-os',
                    'location': location,
                    'vulnerable': (name, version) in vulnerable,
                }
                if identity.get('package_identity_derivation'):
                    request['package_identity_derivation'] = identity[
                        'package_identity_derivation']
                context = runtime.get('image_id') if runtime else 'host'
                key = (context, name, version, request['ecosystem'], location,
                       request['architecture'])
                prior = selected.get(key)
                if prior:
                    prior['vulnerable'] = prior['vulnerable'] or request['vulnerable']
                    continue
                selected[key] = request
                target = result['images'].setdefault(runtime['image_id'], []) if runtime else result['host']
                target.append(request)
    result['host'].sort(key=lambda value: (value['name'], value['version']))
    for requests in result['images'].values():
        requests.sort(key=lambda value: (value['name'], value['version']))
    return result


def scanner_snapshot_artifact_inputs(reports: list[dict], host: str) -> list[dict]:
    """Bind admitted host artifacts; retain container inputs as unsupported."""
    selected = {}
    for report in reports:
        runtime = report.get('_homelab_runtime') or {}
        if runtime:
            artifact_id = str(runtime.get('image_id') or '')
            for result in report.get('Results') or []:
                raw_path = str(result.get('Target') or '')
                path = '/' + raw_path.lstrip('/')
                candidate = Path(path)
                if (not result.get('Vulnerabilities') or
                        '..' in candidate.parts or len(path) > 1024):
                    continue
                path = str(candidate)
                namespaces = [{
                    'kind': 'container', 'host': host,
                    'image_id': artifact_id,
                    **({'container_id': str(container.get('id') or ''),
                        'container_name': str(container.get('name') or '').lstrip('/')}
                       if container else {}),
                } for container in (runtime.get('containers') or [None])]
                for namespace in namespaces:
                    key = ('container', json.dumps(namespace, sort_keys=True),
                           path, artifact_id)
                    selected[key] = {
                        'namespace': namespace, 'path': path,
                        'artifact_id': artifact_id,
                        'support_status': 'unsupported',
                        'reason': 'container-input-authority-unavailable',
                    }
            continue
        binary = report.get('_homelab_host_binary') or {}
        artifact_sha256 = str(binary.get('sha256') or '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', artifact_sha256):
            continue
        for result in report.get('Results') or []:
            path = str(result.get('Target') or '')
            candidate = Path(path)
            if (not result.get('Vulnerabilities') or not candidate.is_absolute() or
                    '..' in candidate.parts):
                continue
            key = ('host', '', path, artifact_sha256)
            selected[key] = {
                'namespace': {'kind': 'host', 'host': host},
                'path': path, 'sha256': artifact_sha256,
                'artifact_id': 'sha256:' + artifact_sha256,
            }
    return [selected[key] for key in sorted(
        selected, key=lambda key: (key[0] != 'host', key))]


def _debian_records(root: Path) -> list[dict]:
    status = root / 'var/lib/dpkg/status'
    if not status.is_file():
        return []
    records = []
    for raw in status.read_text(errors='replace').split('\n\n'):
        if not raw.strip():
            continue
        fields = Parser().parsestr(raw)
        if fields.get('Status') != 'install ok installed':
            continue
        source = fields.get('Source', fields.get('Package', ''))
        match = re.fullmatch(r'([^ ]+)(?: \(([^)]+)\))?', source)
        dependencies = []
        for clause in (fields.get('Pre-Depends', '') + ',' +
                       fields.get('Depends', '')).split(','):
            alternatives = clause.split('|')
            if not alternatives:
                continue
            name = re.split(r'[ (:]', alternatives[0].strip(), maxsplit=1)[0]
            if name:
                dependencies.append(name)
        records.append({
            'manager': 'dpkg', 'binary_package': fields.get('Package', ''),
            'version': fields.get('Version', ''),
            'architecture': fields.get('Architecture', ''),
            'multiarch': fields.get('Multi-Arch', ''),
            'source_package': match.group(1) if match else source,
            'source_version': match.group(2) if match and match.group(2) else fields.get('Version', ''),
            'dependencies': sorted(set(dependencies)),
        })
    return records


def _alpine_records(root: Path) -> list[dict]:
    installed = root / 'lib/apk/db/installed'
    if not installed.is_file():
        return []
    records = []
    for raw in installed.read_text(errors='replace').split('\n\n'):
        values, files, directory = {}, [], ''
        for line in raw.splitlines():
            if len(line) < 2 or line[1] != ':':
                continue
            key, value = line[0], line[2:]
            if key in {'P', 'V', 'A', 'o'}:
                values[key] = value
            elif key == 'F':
                directory = value
            elif key == 'R':
                files.append('/' + '/'.join(filter(None, (directory, value))))
        if values.get('P'):
            records.append({
                'manager': 'apk', 'binary_package': values['P'],
                'version': values.get('V', ''), 'architecture': values.get('A', ''),
                'source_package': values.get('o', values['P']),
                'source_version': values.get('V', ''), 'files': files,
            })
    return records


def package_file_inventory(root: Path, requests: list[dict]) -> list[dict]:
    """Read installed package databases through one host or container root."""
    records = _debian_records(root)
    manager = 'dpkg'
    if not records:
        records = _alpine_records(root)
        manager = 'apk'
    requested = {}
    for item in requests:
        requested.setdefault((item['name'].split(':', 1)[0], item['version']), []).append(item)
    selected = []
    for record in records:
        matches = requested.get((record['binary_package'], record['version']), [])
        matches = [item for item in matches if not item.get('architecture') or
                   item['architecture'] == record['architecture']]
        if not matches:
            continue
        files = record.get('files')
        if files is None:
            info = root / 'var/lib/dpkg/info'
            candidates = [info / (record['binary_package'] + '.list'),
                          info / (record['binary_package'] + ':' + record['architecture'] + '.list')]
            listing = next((path for path in candidates if path.is_file()), None)
            files = listing.read_text(errors='replace').splitlines() if listing else []
            checksum_candidates = [info / (record['binary_package'] + '.md5sums'),
                                   info / (record['binary_package'] + ':' + record['architecture'] + '.md5sums')]
            checksum_file = next((path for path in checksum_candidates if path.is_file()), None)
            record['packaged_md5'] = {}
            if checksum_file:
                for line in checksum_file.read_text(errors='replace').splitlines():
                    checksum, separator, path = line.partition('  ')
                    if separator and re.fullmatch(r'[0-9a-f]{32}', checksum):
                        record['packaged_md5']['/' + path.lstrip('/')] = checksum
        files = sorted(set(path for path in files if path.startswith('/')))
        if len(files) > MAX_PACKAGE_FILES:
            raise ValueError('package file inventory limit exceeded')
        selected.append({**record, 'manager': manager,
                         'scanner_slots': matches, 'files': files,
                         'file_inventory_sha256': hashlib.sha256(
                             json.dumps(files, separators=(',', ':')).encode()).hexdigest()})
    return selected


def package_artifact_profile(root: Path, files: list[str]) -> dict:
    regular, missing, executable = [], [], []
    for path in files:
        candidate = root / path.lstrip('/')
        try:
            if candidate.is_file():
                regular.append(path)
                if candidate.stat().st_mode & 0o111:
                    executable.append(path)
            elif not candidate.exists():
                missing.append(path)
        except OSError:
            missing.append(path)
    header_roots = ('/usr/include/', '/usr/lib/linux/uapi/')
    ignored_roots = ('/usr/share/doc/', '/usr/share/man/', '/usr/share/lintian/',
                     '/usr/share/bug/')
    functional = [path for path in regular
                  if not path.startswith(ignored_roots)]
    header_only = (bool(functional) and not missing and not executable and
                   all(path.startswith(header_roots) and path.endswith('.h')
                       for path in functional))
    return {
        'kind': 'development-headers' if header_only else 'runtime-or-command',
        'regular_file_count': len(regular),
        'executable_file_count': len(executable),
        'missing_path_count': len(missing),
        'functional_files': sorted(functional),
        'executable_files': sorted(executable),
        'classification_complete': not missing,
        'claim_kind': 'derived',
        'derivation': {
            'rule': PACKAGE_PROFILE_RULE,
            'input_refs': ['package-file-manifest:sha256:' + hashlib.sha256(
                json.dumps(sorted(files), separators=(',', ':')).encode()).hexdigest()],
        },
    }


def capability_bindings(packages: list[dict], capabilities: list[dict],
                        root: Path) -> dict[str, list[dict]]:
    records = {item['binary_package']: item for item in packages}
    bindings = {}
    for capability in capabilities:
        root_package = capability.get('root_package')
        if root_package not in records:
            continue
        required = capability.get('required_executables') or []
        if (not required or any(not (root / path.lstrip('/')).is_file()
                                for path in required)):
            continue
        paths = {root_package: [root_package]}
        queue = [root_package]
        while queue:
            package = queue.pop(0)
            for dependency in records[package].get('dependencies', []):
                if dependency in records and dependency not in paths:
                    paths[dependency] = [*paths[package], dependency]
                    queue.append(dependency)
        allowed = set(capability.get('binary_packages') or paths)
        for package, dependency_path in paths.items():
            if package not in allowed:
                continue
            bindings.setdefault(package, []).append({
                'id': capability['id'],
                'applications': capability.get('applications', []),
                'evidence': capability.get('evidence', []),
                'required_executables': required,
                'dependency_path': dependency_path,
                'claim_kind': 'derived',
                'derivation': {
                    'rule': PACKAGE_CAPABILITY_RULE,
                    'input_refs': [
                        'package-dependency-path:' + '>'.join(dependency_path),
                        *['required-executable:' + path for path in required],
                        *['declaration-evidence:' + value
                          for value in capability.get('evidence', [])],
                    ],
                },
            })
    return bindings


def _process_unit(process: dict, services: list[dict]) -> dict | None:
    for service in services:
        control_group = service.get('ControlGroup') or ''
        if (str(service.get('MainPID')) == str(process.get('pid')) or
                control_group and any(line.endswith(control_group) or
                                      control_group + '/' in line
                                      for line in process.get('cgroup', []))):
            return service
    return None


def reconcile_execution_domains(packages: list[dict], declarations: list[dict],
                                observations: list[dict]) -> dict:
    """Reconcile finite declared domain members against raw current observations."""
    observed = {}
    for item in observations:
        if item.get('id'):
            observed.setdefault(item['id'], []).append(item)
    domains = []
    for declaration in declarations:
        domain_id = declaration.get('id')
        if not domain_id:
            continue
        records = observed.get(domain_id) or []
        unique = {json.dumps(item, sort_keys=True, separators=(',', ':')): item
                  for item in records}
        records = [unique[key] for key in sorted(unique)]
        observation_conflict = len(records) > 1

        def observed_values(key):
            return set(value for item in records for value in item.get(key) or [])

        declared_sets = {
            'entry': set(declaration.get('entries') or []),
            'input': set(declaration.get('inputs') or []),
            'file': set(declaration.get('files') or []),
            'operation_file': set(declaration.get('operation_files') or []),
            'file_authority': set(declaration.get('authority_paths') or []),
        }
        observed_sets = {
            'entry': observed_values('entries'),
            'input': observed_values('inputs'),
            'file': observed_values('files'),
            'operation_file': observed_values('operation_files'),
            'file_authority': {
                value.get('path') for item in records
                for value in item.get('authority_paths') or []
                if value.get('status') == 'complete' and value.get('path')},
        }
        coverage = {}
        for kind in ('entry', 'input', 'file', 'operation_file',
                     'file_authority'):
            missing = sorted(declared_sets[kind] - observed_sets[kind])
            unassigned = sorted(observed_sets[kind] - declared_sets[kind])
            coverage[kind] = {
                'complete': bool(records) and not observation_conflict and
                            not missing and not unassigned,
                'missing': missing, 'unassigned': unassigned}
        matching = [package for package in packages
                    if package.get('binary_package') in
                    set(declaration.get('packages') or [])]
        package_files = set().union(*(set(item.get('files') or [])
                                      for item in matching)) if matching else set()
        missing_owned = sorted(declared_sets['file'] - package_files)
        if missing_owned:
            coverage['file']['complete'] = False
            coverage['file']['missing_owned'] = missing_owned
        evidence_refs = sorted({value for item in records
                                for value in item.get('evidence_refs') or []})
        unknown = any(item.get('status', 'complete') != 'complete'
                      for item in records)
        work_evidence_complete = (bool(matching) and bool(evidence_refs) and
            not unknown and not observation_conflict and
            all(not coverage[kind]['missing'] for kind in
                ('entry', 'input', 'file', 'operation_file', 'file_authority')) and
            not missing_owned)
        complete = (bool(matching) and bool(evidence_refs) and not unknown and
                    not observation_conflict and
                    all(item['complete'] for item in coverage.values()))
        result = {
            'id': domain_id,
            'packages': sorted(declaration.get('packages') or []),
            'files': sorted(declared_sets['file']),
            'entries': sorted(declared_sets['entry']),
            'inputs': sorted(declared_sets['input']),
            'authority_paths': sorted(declared_sets['file_authority']),
            'operation_files': sorted(declared_sets['operation_file']),
            'interpreter': declaration.get('interpreter'),
            'elf_dependency_roots': sorted(
                declaration.get('elf_dependency_roots') or []),
            'selector_evidence': declaration.get('selector_evidence'),
            'coverage': coverage, 'complete': complete,
            'work_evidence_complete': work_evidence_complete,
            'disposition': declaration.get('disposition'),
            'evidence_refs': evidence_refs,
            'observation': {
                'entries': sorted(observed_sets['entry']),
                'inputs': sorted(observed_sets['input']),
                'files': sorted(observed_sets['file']),
                'operation_files': sorted({value for item in records for value in
                                           item.get('operation_files') or []}),
                'authority_paths': [value for item in records
                                    for value in item.get('authority_paths') or []],
                'evidence_refs': evidence_refs},
            'observation_records': records,
            'observation_conflict': observation_conflict,
            'observation_unknown': unknown,
            'unassigned_entries': coverage['entry']['unassigned'],
            'unassigned_inputs': coverage['input']['unassigned'],
            'unassigned_files': coverage['file']['unassigned'],
            'unassigned_operation_files': coverage['operation_file']['unassigned'],
            'unresolved_authority': sorted(
                set(declared_sets['file_authority']) -
                observed_sets['file_authority']),
        }
        domains.append(result)
    package_results = {}
    for package in packages:
        name = package.get('binary_package')
        if not name:
            continue
        current = package_results.setdefault(name, {
            'domains': [], 'complete': True, 'relevant_files': set(),
            'assigned_files': set(), 'owned_files': set()})
        relevant = (package['relevant_files'] if 'relevant_files' in package
                    else package.get('files') or [])
        current['relevant_files'].update(relevant)
        current['owned_files'].update(package.get('files') or [])
    for declaration, domain in zip(
            [item for item in declarations if item.get('id')], domains):
        for name in declaration.get('packages') or []:
            if name not in package_results:
                continue
            current = package_results[name]
            assigned = set(declaration.get('files') or []).intersection(
                current['owned_files'])
            if declaration.get('elf_dependency_roots') and not assigned:
                continue
            current['domains'].append(domain)
            current['assigned_files'].update(assigned)
            current['complete'] = current['complete'] and domain['complete']
    for current in package_results.values():
        relevant = current.pop('relevant_files')
        assigned = current.pop('assigned_files')
        current.pop('owned_files')
        current['unassigned_relevant_files'] = sorted(relevant - assigned)
        current['assigned_non_relevant_files'] = sorted(assigned - relevant)
        current['complete'] = (bool(current['domains']) and current['complete'] and
                               not current['unassigned_relevant_files'] and
                               not current['assigned_non_relevant_files'])
    return {'domains': domains, 'packages': package_results}


def observe_execution_domains(root: Path, packages: list[dict], declarations: list[dict],
                              services: list[dict], scheduled: list[dict]) -> list[dict]:
    """Collect bounded raw members; absence of an observable input stays unknown."""
    package_files = {}
    for package in packages:
        package_files.setdefault(package.get('binary_package'), set()).update(
            package.get('files') or [])
    current_services = {item.get('Id') for item in services
                        if item.get('ActiveState') == 'active' or
                        item.get('UnitFileState') in {'enabled', 'enabled-runtime'} or
                        item.get('activation_sources')}
    current_jobs = {str(item.get('Id') or item.get('path')) for item in scheduled}
    result = []
    for declaration in declarations:
        files = sorted(set(declaration.get('files') or []).intersection(
            set().union(*(package_files.get(name, set())
                          for name in declaration.get('packages') or []))))
        entries = sorted(entry for entry in declaration.get('entries') or []
                         if entry in current_services or entry in current_jobs)
        authority = []
        refs = []
        for path in declaration.get('authority_paths') or []:
            evidence = path_access_evidence(root / path.lstrip('/'))
            authority.append({'path': path, 'status': evidence['status'],
                              'evidence': evidence})
            refs.append('path-access:sha256:' + hashlib.sha256(json.dumps(
                evidence, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        result.append({
            'id': declaration['id'], 'entries': entries, 'inputs': [],
            'files': files, 'authority_paths': authority,
            'evidence_refs': refs,
        })
    return result


def derive_execution_domain_observations(declarations: list[dict], facts: dict) -> list[dict]:
    """Derive domain members from raw admission, service, listener, and file facts."""
    files = {item.get('path'): item for item in facts.get('files') or []
             if item.get('path')}
    services = {item.get('Id'): item for item in facts.get('services') or []
                if item.get('Id')}
    scheduled = {str(item.get('Id') or item.get('path')): item
                 for item in facts.get('scheduled') or []
                 if item.get('Id') or item.get('path')}
    results = []
    for declaration in declarations:
        entries = set()
        inputs = set()
        operation_files = set()
        refs = set(facts.get('evidence_refs') or [])
        snapshot_inputs_present = isinstance(
            facts.get('snapshot_artifact_inputs'), list)
        snapshot_inputs = []
        for artifact in facts.get('snapshot_artifact_inputs') or []:
            path = str(artifact.get('path') or '')
            expected = str(artifact.get('sha256') or '').lower()
            fact = files.get(path) or {}
            namespace = artifact.get('namespace') or {}
            complete = (
                namespace.get('kind') == 'host' and bool(namespace.get('host')) and
                Path(path).is_absolute() and '..' not in Path(path).parts and
                re.fullmatch(r'[0-9a-f]{64}', expected) is not None and
                artifact.get('artifact_id') == 'sha256:' + expected and
                fact.get('status') == 'complete' and
                fact.get('authority_status') == 'controlled' and
                str(fact.get('sha256') or '').lower() == expected)
            snapshot_inputs.append({
                'namespace': namespace, 'path': path, 'sha256': expected,
                'artifact_id': artifact.get('artifact_id'),
                'observed_sha256': fact.get('sha256'),
                'authority_status': fact.get('authority_status', 'unresolved'),
                'status': 'complete' if complete else 'incomplete',
            })
            refs.add('snapshot-artifact:' + json.dumps(
                [namespace, path, expected], sort_keys=True,
                separators=(',', ':')))
        for rule in declaration.get('entry_rules') or []:
            kind = rule.get('kind')
            if kind in {'forced_ssh_command', 'unrestricted_ssh_key'}:
                for account in facts.get('accounts') or []:
                    for record in (account.get('authorized_keys') or {}).get('records') or []:
                        if record.get('status') != 'parsed':
                            continue
                        if kind == 'unrestricted_ssh_key' and record.get(
                                'unrestricted_key_options') is True:
                            entries.add('ssh-key:' + account['name'] + ':unrestricted')
                        if kind == 'forced_ssh_command':
                            command = rule.get('command')
                            matched = record.get('forced_command') == command
                            if (not matched and record.get(
                                    'exact_repository_forced_options') is True and
                                    command == '/usr/local/libexec/homelab-agent-remote'):
                                matched = True
                            if matched:
                                suffix = rule.get('member_suffix', 'forced-broker')
                                entries.add('ssh-key:' + account['name'] + ':' + suffix)
            elif kind == 'ssh_password_pam':
                for context in facts.get('ssh_contexts') or []:
                    values = context.get('values') or {}
                    if (context.get('status', 'complete') == 'complete' and
                            values.get('passwordauthentication') == 'yes' and
                            values.get('usepam') == 'yes'):
                        entries.add('ssh-password-pam:' + context['user'] +
                                    ':unresolved')
            elif kind == 'service':
                service = services.get(rule.get('id'))
                if service and (service.get('ActiveState') == 'active' or
                        service.get('UnitFileState') in {'enabled', 'enabled-runtime'} or
                        service.get('activation_sources')):
                    entries.add(str(rule.get('member') or rule['id']))
                    operation_files.update(str(path) for path in
                                           service.get('executables') or [])
            elif kind == 'service_and_activators':
                service = services.get(rule.get('id'))
                if service and (service.get('ActiveState') == 'active' or
                        service.get('activation_sources')):
                    entries.add(str(rule.get('member') or rule['id']))
                    entries.update(str(item) for item in
                                   service.get('activation_sources') or [])
                    operation_files.update(str(path) for path in
                                           service.get('executables') or [])
            elif kind == 'scheduled':
                if rule.get('id') in scheduled:
                    entries.add(str(rule.get('member') or rule['id']))
            elif kind == 'listener':
                pattern = re.compile(str(rule.get('pattern') or ''))
                matches = [item for item in facts.get('listeners') or []
                           if pattern.search(str(item))]
                if matches:
                    entries.add(str(rule.get('member')))
        for rule in declaration.get('input_rules') or []:
            kind = rule.get('kind')
            if kind == 'verified_file_contracts':
                required = [files.get(path) for path in rule.get('paths') or []]
                sudo_rules = {value.get('known_rule') or value.get('command_class')
                              for account in facts.get('accounts') or []
                              if not rule.get('sudo_account') or
                              account.get('name') == rule.get('sudo_account')
                              for value in (account.get('sudo') or {}).get('rules') or []}
                sudo_complete = set(rule.get('sudo_commands') or []).issubset(
                    sudo_rules)
                artifact_authority_complete = (
                    not rule.get('require_snapshot_artifact_authority') or
                    (snapshot_inputs_present and all(
                        item['status'] == 'complete' for item in snapshot_inputs)))
                if required and sudo_complete and all(
                        item and item.get('status') == 'complete' and
                        item.get('contract_status') == 'matched'
                        for item in required) and artifact_authority_complete:
                    inputs.add(str(rule['member']))
            elif kind == 'current_service_contract':
                service = services.get(rule.get('service'))
                required = [files.get(path) for path in rule.get('paths') or []]
                current = service and (service.get('ActiveState') == 'active' or
                    service.get('activation_sources'))
                contracts = (not required or all(item and
                    item.get('status') == 'complete' and
                    item.get('contract_status') in {'matched', 'not-required'}
                    for item in required))
                if current and contracts:
                    inputs.update(str(item) for item in rule.get('members') or [])
            elif kind == 'listener_input':
                pattern = re.compile(str(rule.get('pattern') or ''))
                if any(pattern.search(str(item))
                       for item in facts.get('listeners') or []):
                    inputs.add(str(rule['member']))
        observed_files = sorted(path for path in declaration.get('files') or []
                                if files.get(path, {}).get('status') == 'complete')
        operation_files = sorted(path for path in operation_files
                                 if files.get(path, {}).get('status') == 'complete')
        authority = []
        for path in declaration.get('authority_paths') or []:
            fact = files.get(path)
            if not fact:
                continue
            value = {key: fact.get(key) for key in
                     ('path', 'sha256', 'contract_status', 'authority_status',
                      'authority') if key in fact}
            value['status'] = ('complete' if fact.get('status') == 'complete' and
                               fact.get('authority_status', 'controlled') ==
                               'controlled' and
                               fact.get('contract_status') != 'conflicting'
                               else 'incomplete')
            authority.append(value)
        refs.update('file:' + path + ':sha256:' + str(files[path].get('sha256') or '')
                    for path in sorted(files) if files[path].get('sha256'))
        results.append({
            'id': declaration['id'],
            'status': ('incomplete' if
                       (declaration.get('selector_evidence') or {}).get(
                           'status') == 'incomplete'
                       else facts.get('status', 'complete')),
            'entries': sorted(entries), 'inputs': sorted(inputs),
            'files': observed_files, 'operation_files': operation_files,
            'authority_paths': authority,
            'snapshot_artifact_inputs': snapshot_inputs,
            'evidence_refs': sorted(refs), 'claim_kind': 'derived',
            'derivation': {'rule': FINITE_EXECUTION_OBSERVATION_RULE,
                           'input_refs': sorted(refs)},
        })
    return results


def expand_execution_domains(declarations: list[dict], facts: dict) -> list[dict]:
    """Resolve declared finite selectors against current raw dependency facts."""
    expanded = json.loads(json.dumps(declarations))
    for declaration in expanded:
        roots = set(declaration.get('elf_dependency_roots') or [])
        packages = set(declaration.get('packages') or [])
        dependencies = (facts.get('elf_declared_dependencies') or
                        facts.get('elf_dependencies') or [])
        scans = (facts.get('elf_linkage_scans') or
                 facts.get('elf_dependency_scans') or [])
        selected = sorted({item['path'] for item in dependencies
                           if item.get('root') in roots and
                           item.get('package') in packages and
                           item.get('status') == 'complete' and item.get('path')})
        if roots:
            declaration['files'] = sorted(set(
                declaration.get('files') or []).union(selected))
            declaration['authority_paths'] = sorted(set(
                declaration.get('authority_paths') or []).union(selected))
            declaration['selector_evidence'] = {
                'kind': 'elf_declared_dependencies', 'roots': sorted(roots),
                'selected_files': selected,
                'status': ('complete' if roots and all(any(
                    item.get('root') == root and item.get('status') == 'complete'
                    for item in scans)
                    for root in roots) else 'incomplete'),
            }
    return expanded


def _bounded_command(argv: list[str]) -> dict:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        if len(result.stdout) > 256 * 1024:
            return {'status': 'incomplete', 'reason': 'output-limit'}
        return {'status': 'complete', 'returncode': result.returncode,
                'stdout': result.stdout}
    except (OSError, subprocess.SubprocessError):
        return {'status': 'incomplete', 'reason': 'command-failed'}


def _authorized_key_observation(path: Path, logical_path: str) -> dict:
    result = {'path': logical_path, 'status': 'complete', 'records': []}
    try:
        info = path.stat()
        if info.st_size > 64 * 1024:
            return {**result, 'status': 'incomplete', 'reason': 'file-size-limit'}
        raw = path.read_bytes()
    except FileNotFoundError:
        return {**result, 'status': 'absent'}
    except OSError:
        return {**result, 'status': 'incomplete', 'reason': 'unreadable'}
    result.update({'uid': info.st_uid, 'gid': info.st_gid,
                   'mode': oct(stat.S_IMODE(info.st_mode)),
                   'sha256': hashlib.sha256(raw).hexdigest()})
    key_pattern = re.compile(
        r'(?:^|\s)((?:sk-)?ssh-[^\s]+|(?:sk-)?ecdsa-[^\s]+)\s+')
    for number, line in enumerate(raw.decode(errors='replace').splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = key_pattern.search(line)
        if not match:
            result['records'].append({'line': number, 'status': 'unknown'})
            continue
        prefix = line[:match.start()].strip()
        command = re.search(r'(?:^|,)command="([^"]+)"(?:,|$)', prefix)
        result['records'].append({
            'line': number, 'status': 'parsed',
            'options_sha256': hashlib.sha256(prefix.encode()).hexdigest(),
            'unrestricted_key_options': not prefix,
            'forced_command': command.group(1) if command else None,
        })
    return result


def collect_execution_domain_facts(config: dict, services: list[dict],
                                   scheduled: list[dict], listeners: list[str],
                                   root: Path = Path('/'), *,
                                   snapshot_artifact_inputs: list[dict] | None = None
                                   ) -> dict:
    """Collect bounded raw facts used to derive current execution-domain members."""
    declarations = config.get('execution_domains') or []
    facts = {'schema': 1, 'kind': 'observation',
             'observed_at': datetime.now(UTC).isoformat(),
             'accounts': [], 'ssh_contexts': [], 'files': [],
             'services': services, 'scheduled': scheduled,
             'listeners': listeners, 'gaps': [],
             'snapshot_artifact_inputs': sorted(
                 json.loads(json.dumps(snapshot_artifact_inputs or [])),
                 key=lambda item: json.dumps(item, sort_keys=True,
                                              separators=(',', ':')))}
    if root == Path('/'):
        ldconfig = '/sbin/ldconfig'
        readelf = '/usr/bin/readelf'
        cache = _bounded_command([ldconfig, '-p']) if Path(ldconfig).is_file() else {
            'status': 'incomplete', 'stdout': ''}
        library_paths = {}
        for line in (cache.get('stdout') or '').splitlines():
            name, separator, path = line.strip().partition(' => ')
            if separator:
                library_paths.setdefault(name.split()[0], path)
        facts['elf_declared_dependencies'] = []
        facts['elf_linkage_scans'] = []
        for source in sorted({value for declaration in declarations
                              for value in declaration.get(
                                  'elf_dependency_roots') or []}):
            dynamic = _bounded_command([readelf, '-d', source])
            needed_names = sorted(set(re.findall(
                    r'\(NEEDED\).*Shared library: \[([^]]+)\]',
                    dynamic.get('stdout') or '')))
            dependencies = []
            for needed in needed_names:
                candidate = library_paths.get(needed)
                try:
                    path = str(Path(candidate).resolve(strict=True)) if candidate else None
                except OSError:
                    path = None
                owner = _bounded_command(['dpkg-query', '-S', path]) if path else {
                    'status': 'incomplete', 'stdout': ''}
                package = (owner.get('stdout') or '').partition(':')[0]
                item = {'kind': 'declared_dependency', 'root': source,
                        'needed': needed,
                        'loader_candidate': candidate, 'path': path,
                        'package': package,
                        'status': ('complete' if path and package and
                                   dynamic.get('status') == 'complete' and
                                   cache.get('status') == 'complete' and
                                   owner.get('returncode') == 0 else 'incomplete')}
                if item['status'] == 'complete':
                    try:
                        item['sha256'] = digest(Path(path))
                        item['authority'] = path_access_evidence(Path(path))
                        if item['authority']['status'] != 'complete':
                            item['status'] = 'incomplete'
                    except (OSError, ValueError):
                        item['status'] = 'incomplete'
                facts['elf_declared_dependencies'].append(item)
                dependencies.append(item)
            scan_complete = (dynamic.get('status') == 'complete' and
                             dynamic.get('returncode') == 0 and
                             cache.get('status') == 'complete' and
                             cache.get('returncode') == 0 and
                             bool(needed_names) and
                             all(item['status'] == 'complete'
                                 for item in dependencies))
            facts['elf_linkage_scans'].append({
                'root': source,
                'status': 'complete' if scan_complete else 'incomplete',
                'needed': needed_names,
                'resolved': len([item for item in dependencies
                                 if item['status'] == 'complete']),
                'semantics': 'declared-static-linkage-not-observed-loading',
            })
    else:
        facts['elf_declared_dependencies'] = []
        facts['elf_linkage_scans'] = []
    contracts = {}
    paths = set()
    for declaration in declarations:
        paths.update(declaration.get('files') or [])
        paths.update(declaration.get('operation_files') or [])
        paths.update(declaration.get('authority_paths') or [])
        for contract in declaration.get('file_contracts') or []:
            contracts.setdefault(contract['path'], []).append(contract)
            paths.add(contract['path'])
    paths.update(item['path'] for item in facts['snapshot_artifact_inputs']
                 if ((item.get('namespace') or {}).get('kind') == 'host' and
                     isinstance(item.get('path'), str) and
                     Path(item['path']).is_absolute()))
    for logical_path in sorted(paths):
        actual = root / logical_path.lstrip('/')
        access = path_access_evidence(actual)
        controlled = (access['status'] == 'complete' and
                      all(entry.get('uid') == 0 and
                          (entry.get('type') == 'symlink' or
                           not (int(entry.get('mode', '0'), 8) & 0o022))
                          for entry in access.get('entries') or []))
        item = {'path': logical_path, 'status': access['status'],
                'authority': access,
                'authority_status': 'controlled' if controlled else 'unresolved',
                'contract_status': 'not-required'}
        try:
            if actual.is_file():
                item['sha256'] = digest(actual)
                raw = actual.read_bytes() if actual.stat().st_size <= MAX_ACCESS_BYTES else b''
                matches = []
                for contract in contracts.get(logical_path, []):
                    expected = contract.get('expected_sha256')
                    literals = [value.encode() for value in
                                contract.get('required_literals') or []]
                    matches.append((not expected or expected == item['sha256']) and
                                   bool(expected or literals) and
                                   all(value in raw for value in literals))
                if matches:
                    item['contract_status'] = ('matched' if all(matches)
                                               else 'conflicting')
        except (OSError, ValueError):
            item['status'] = 'incomplete'
            facts['gaps'].append('execution-file-unreadable:' + logical_path)
        facts['files'].append(item)
    for dependency in facts['elf_declared_dependencies']:
        if not dependency.get('path') or any(
                item['path'] == dependency['path'] for item in facts['files']):
            continue
        authority = dependency.get('authority') or {}
        controlled = (authority.get('status') == 'complete' and
                      all(entry.get('uid') == 0 and
                          (entry.get('type') == 'symlink' or
                           not (int(entry.get('mode', '0'), 8) & 0o022))
                          for entry in authority.get('entries') or []))
        facts['files'].append({
            'path': dependency['path'], 'status': dependency['status'],
            'sha256': dependency.get('sha256'), 'authority': authority,
            'authority_status': 'controlled' if controlled else 'unresolved',
            'contract_status': 'not-required'})
    admission = config.get('execution_admission') or {}
    if root == Path('/'):
        for name in admission.get('accounts') or []:
            try:
                account = pwd.getpwnam(name)
                password = _bounded_command(['/usr/bin/passwd', '-S', name])
                status = (password.get('stdout') or '').split()
                item = {'name': name, 'uid': account.pw_uid, 'gid': account.pw_gid,
                        'groups': os.getgrouplist(name, account.pw_gid),
                        'home': account.pw_dir, 'shell': account.pw_shell,
                        'password_status': status[1] if len(status) > 1 else 'unknown'}
                for filename in ('authorized_keys', 'authorized_keys2'):
                    logical = str(Path(account.pw_dir) / '.ssh' / filename)
                    item[filename] = _authorized_key_observation(
                        Path(logical), logical)
                sudo = _bounded_command(['/usr/bin/sudo', '-n', '-l', '-U', name])
                rules = []
                for line in (sudo.get('stdout') or '').splitlines():
                    value = line.strip()
                    if value.startswith('('):
                        rules.append({'sha256': hashlib.sha256(value.encode()).hexdigest(),
                                      'command_class': value if value in set(
                                          admission.get('recognized_sudo_rules') or [])
                                                       else 'unrecognized'})
                item['sudo'] = {'status': sudo['status'],
                                'returncode': sudo.get('returncode'), 'rules': rules}
                facts['accounts'].append(item)
            except (KeyError, OSError):
                facts['gaps'].append('execution-account-unavailable:' + name)
        for context in admission.get('ssh_contexts') or []:
            argv = ['/usr/sbin/sshd', '-T', '-C',
                    'user=' + context['user'] + ',host=' + context['host'] +
                    ',addr=' + context['remote_address'] +
                    ',laddr=' + context['local_address'] +
                    ',lport=' + str(context['port'])]
            output = _bounded_command(argv)
            allowed = set(admission.get('ssh_fields') or [])
            values = {line.partition(' ')[0]: line.partition(' ')[2]
                      for line in (output.get('stdout') or '').splitlines()
                      if line.partition(' ')[0] in allowed}
            facts['ssh_contexts'].append({**context, 'status': output['status'],
                                          'returncode': output.get('returncode'),
                                          'values': values})
    elif admission:
        facts['gaps'].append('execution-admission-unavailable:alternate-root')
    identity = hashlib.sha256(json.dumps(facts, sort_keys=True,
                                         separators=(',', ':')).encode()).hexdigest()
    facts['evidence_refs'] = ['execution-domain-facts:sha256:' + identity]
    return facts


def package_consumer_evidence(root: Path, requests: list[dict], processes: list[dict],
                              services: list[dict], scheduled: list[dict], *,
                              namespace: dict, capabilities: list[dict] | None = None,
                              execution_domains: list[dict] | None = None,
                              execution_observations: list[dict] | None = None,
                              execution_facts: dict | None = None) -> list[dict]:
    """Bind package-owned paths to positive runtime or activation observations."""
    result = []
    packages = package_file_inventory(root, requests)
    for package in packages:
        profile = package_artifact_profile(root, package['files'])
        package['artifact_profile'] = profile
        package['relevant_files'] = profile['functional_files']
    capability_map = capability_bindings(packages, capabilities or [], root)
    effective_domains = expand_execution_domains(
        execution_domains or [], execution_facts or {})
    for package in packages:
        current_use_files = {path for domain in effective_domains
            if package['binary_package'] in (domain.get('packages') or [])
            for path in domain.get('files') or []
            if path in set(package.get('files') or [])}
        if any(package['binary_package'] in (domain.get('packages') or [])
               for domain in effective_domains):
            package['relevant_files'] = sorted(current_use_files)
    if execution_observations is None:
        execution_observations = (derive_execution_domain_observations(
            effective_domains, execution_facts) if execution_facts is not None
            else observe_execution_domains(
                root, packages, effective_domains, services, scheduled))
    domain_evidence = reconcile_execution_domains(
        packages, effective_domains, execution_observations)
    for package in packages:
        owned = set(package['files'])
        observations = []

        def file_evidence(path, captured=None):
            identity = dict(captured or {})
            identity['path'] = path
            candidate = root / path.lstrip('/')
            packaged_md5 = package.get('packaged_md5', {}).get(path)
            actual_md5 = None
            try:
                info = candidate.stat()
                expected_inode = identity.get('inode')
                expected_device = identity.get('device')
                actual_device = [os.major(info.st_dev), os.minor(info.st_dev)]
                if ((expected_inode is None or expected_inode == info.st_ino) and
                        (expected_device is None or expected_device == actual_device)):
                    identity.setdefault('inode', info.st_ino)
                    identity.setdefault('device', actual_device)
                    identity.setdefault('sha256', digest(candidate))
                    actual_md5 = digest(candidate, 'md5')
            except OSError:
                pass
            identity['packaged_md5'] = packaged_md5
            identity['actual_md5'] = actual_md5
            identity['replacement_status'] = (
                'unknown' if not packaged_md5 or not actual_md5 else
                'packaged' if packaged_md5 == actual_md5 else 'replaced')
            return identity

        for process in processes:
            identities = {item['path']: item for item in
                          process.get('loaded_file_identities', [])}
            if process.get('executable') in owned:
                identities.setdefault(process['executable'], {
                    'path': process['executable'], 'sha256': process.get('sha256'),
                    **(process.get('executable_identity') or {})})
            unit = _process_unit(process, services)
            for path in sorted(owned.intersection(identities)):
                observations.append({
                    'relation': 'loaded_file',
                    'claim_kind': 'derived',
                    'derivation': {'rule': PACKAGE_OBSERVATION_RULE,
                                   'input_refs': [
                                       'package-owned-path:' + path,
                                       'process-mapping:sha256:' + hashlib.sha256(
                                           json.dumps([
                                               path, identities[path].get('sha256'),
                                               process.get('executable'),
                                               process.get('sha256')],
                                               separators=(',', ':')).encode()).hexdigest()]},
                    'file': file_evidence(path, identities[path]),
                    'consumer': {
                        'kind': 'process', 'pid': process['pid'],
                        'start_ticks': process.get('start_ticks'),
                        'executable': process.get('executable'),
                        'executable_sha256': process.get('sha256'),
                        'service': unit.get('Id') if unit else None,
                        'privileges': process.get('privileges'),
                        'deployments': unit.get('deployments', []) if unit else
                            namespace.get('deployments', []),
                    }})
        for service in services:
            if (service.get('ActiveState') != 'active' and
                    service.get('UnitFileState') not in {'enabled', 'enabled-runtime'} and
                    not service.get('activation_sources')):
                continue
            relation = ('service_execution' if
                        (service.get('ActiveState') == 'active' or
                         service.get('UnitFileState') in {'enabled', 'enabled-runtime'})
                        else 'triggered_service_execution')
            for executable in sorted(owned.intersection(service.get('executables') or [])):
                observations.append({
                    'relation': relation,
                    'claim_kind': 'derived',
                    'derivation': {'rule': PACKAGE_OBSERVATION_RULE,
                                   'input_refs': [
                                       'package-owned-path:' + executable,
                                       'systemd-exec:' + str(service.get('Id'))]},
                    'file': file_evidence(executable),
                    'consumer': {'kind': 'service', 'id': service.get('Id'),
                                 'active_state': service.get('ActiveState'),
                                 'unit_file_state': service.get('UnitFileState'),
                                 'activation_sources': service.get('activation_sources', []),
                                 'deployments': service.get('deployments', [])}})
        for job in scheduled:
            for executable in sorted(owned.intersection(job.get('executables') or [])):
                observations.append({
                    'relation': 'scheduled_execution',
                    'claim_kind': 'derived',
                    'derivation': {'rule': PACKAGE_OBSERVATION_RULE,
                                   'input_refs': [
                                       'package-owned-path:' + executable,
                                       'scheduled-file:' + str(job['path'])]},
                    'file': file_evidence(executable),
                    'consumer': {'kind': 'job', 'id': job['path'],
                                 'deployments': job.get('deployments', [])}})
        slots = []
        for request in package.get('scanner_slots', []):
            for location in [request.get('location', '/')]:
                slots.append({
                    'installation': ('os' if namespace.get('kind') == 'host' else
                                     'container:' + namespace.get('container_name', '')),
                    'consumer_class': request.get('consumer_class', ''),
                    'ecosystem': request.get('ecosystem', ''),
                    'artifact_id': request.get('artifact_id', ''),
                    'binary_package': package['binary_package'],
                    'version': package['version'],
                    'architecture': package['architecture'],
                    'source_package': package['source_package'],
                    'source_version': package['source_version'],
                    'location': (('/:' + location) if namespace.get('kind') == 'host'
                                 else namespace.get('container_name', '') + ':' + location),
                })
        profile = package['artifact_profile']
        declared_capabilities = capability_map.get(package['binary_package'], [])
        package_domains = domain_evidence['packages'].get(package['binary_package'])
        if package_domains:
            package_domains = json.loads(json.dumps(package_domains))
            observed_consumers = set()
            for observation in observations:
                consumer = observation.get('consumer') or {}
                identifier = consumer.get('id') or consumer.get('service')
                if identifier:
                    observed_consumers.add(str(identifier))
                elif consumer.get('kind') == 'process' and consumer.get('executable'):
                    observed_consumers.add('process:' + consumer['executable'])
            for domain in package_domains['domains']:
                unassigned = sorted(observed_consumers - set(domain.get('entries') or []))
                if unassigned:
                    domain['unassigned_entries'] = sorted(set(
                        domain.get('unassigned_entries') or []).union(unassigned))
                    domain['coverage']['entry']['unassigned'] = domain[
                        'unassigned_entries']
                    domain['coverage']['entry']['complete'] = False
                    domain['complete'] = False
                    package_domains['complete'] = False
        unresolved_scheduled = []
        for job in scheduled:
            candidates = sorted(owned.intersection(
                job.get('unresolved_executables') or []))
            if not candidates:
                continue
            unresolved_scheduled.append({
                'kind': 'scheduled_execution', 'path': str(job.get('path')),
                'sha256': str(job.get('sha256') or ''),
                'reasons': sorted(job.get('unsupported') or []),
                'executables': candidates})
        if (not observations and profile['kind'] != 'development-headers' and
                not declared_capabilities and not package_domains and
                not any(item.get('vulnerable')
                        for item in package.get('scanner_slots', []))):
            continue
        result.append({
            'namespace': namespace, 'installed': {
                key: package[key] for key in ('manager', 'binary_package', 'version',
                                              'architecture', 'source_package',
                                              'source_version')},
            'slots': slots, 'file_count': len(package['files']),
            'files': package['files'],
            'file_inventory_sha256': package['file_inventory_sha256'],
            'artifact_profile': profile,
            'declared_capabilities': declared_capabilities,
            'execution_domains': (package_domains or {}).get('domains', []),
            'observations': observations,
            'consumer_coverage_dependencies': unresolved_scheduled,
            # Positive runtime observations alone remain open-world. Only an
            # exact, current finite-domain reconciliation can close the scope.
            'consumer_coverage_complete': bool(
                package_domains and package_domains.get('complete') is True),
        })
    return result


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


def discover(config: dict, proc: Path = Path('/proc'), reports: list[dict] | None = None,
             package_requests: dict | None = None,
             execution_facts: dict | None = None,
             filesystem_root: Path = Path('/')) -> dict:
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
            if unit.endswith('@.service'):
                continue
            try:
                item = unit_evidence(properties(unit))
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

    evidence['activated_units'] = []
    for unit_type in ('timer', 'socket', 'path'):
        try:
            declared = run([
                'systemctl', 'list-unit-files', '--type=' + unit_type,
                '--no-pager', '--no-legend']).splitlines()
            loaded = run([
                'systemctl', 'list-units', '--type=' + unit_type, '--all',
                '--no-pager', '--plain', '--no-legend']).splitlines()
            names = sorted({line.split()[0] for line in declared + loaded
                            if line.split() and
                            line.split()[0].endswith('.' + unit_type)})
            for name in names:
                if name.endswith('@.' + unit_type):
                    continue
                try:
                    unit = unit_evidence(properties(name))
                except (OSError, ValueError, RuntimeError,
                        subprocess.SubprocessError):
                    gaps.append('activated-unit-properties-failed:' +
                                unit_type + ':' + name)
                    continue
                if (unit.get('ActiveState') != 'active' and
                        unit.get('UnitFileState') not in {'enabled', 'enabled-runtime'}):
                    continue
                targets = (unit.get('Triggers') or '').split()
                owners = sorted(d['id'] for d in config['deployments']
                                if any(fnmatch.fnmatchcase(candidate, pattern)
                                       for candidate in [unit.get('Id', ''), *targets]
                                       for pattern in d.get('units', [])))
                unit['deployments'] = owners
                fragment = unit.get('FragmentPath')
                if fragment:
                    try:
                        unit['path'] = fragment
                        unit['sha256'] = fingerprint(Path(fragment))
                    except (OSError, ValueError):
                        gaps.append('activated-unit-file-unreadable:' + name)
                evidence['activated_units'].append(unit)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            gaps.append('activated-unit-discovery-failed:' + unit_type)
    activation_sources = {}
    for unit in evidence['activated_units']:
        for target in (unit.get('Triggers') or '').split():
            activation_sources.setdefault(target, []).append(unit.get('Id'))
    for service in evidence['services']:
        service['configured_activation_sources'] = sorted(set(
            (service.get('TriggeredBy') or '').split()))
        service['activation_sources'] = sorted(set(
            activation_sources.get(service.get('Id'), [])))

    try:
        evidence['processes'] = process_inventory(
            proc, (proc / 'self/ns/pid').stat().st_ino, fingerprint, gaps, 'host')
    except OSError:
        gaps.append('process-discovery-failed:host')
    for service in evidence['services']:
        service['execution_identity'] = service_execution_identity(service, evidence['processes'])
    try:
        evidence['listeners'] = run(['ss', '-H', '-lntup']).splitlines()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        gaps.append('listener-discovery-failed')

    container_processes = {}
    if shutil.which('docker'):
        try:
            ids = run(['docker', 'ps', '-aq', '--no-trunc']).split()
            for container in ids:
                template = '{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .State.Running}}\t{{json .Mounts}}\t{{json .HostConfig.PortBindings}}\t{{json .State.Pid}}\t{{json (index .Config.Labels "com.docker.compose.service")}}'
                values = [json.loads(value) for value in run(['docker', 'inspect', '--format', template, container]).strip().split('\t')]
                item = dict(zip(['id', 'name', 'image_id', 'running', 'mounts', 'ports',
                                 'main_pid', 'compose_service'], values, strict=True))
                if item['running']:
                    try:
                        item['executable_sha256'] = fingerprint(proc / str(item['main_pid']) / 'exe')
                    except (OSError, ValueError):
                        gaps.append('container-executable-unreadable:' + item['name'])
                item['changes'] = run(['docker', 'diff', container]).splitlines()
                owners = sorted(set(d['id'] for d in config['deployments'] if
                          any(fnmatch.fnmatchcase(item['name'].lstrip('/'), pattern)
                              for pattern in d.get('containers', [])) or
                          item.get('compose_service') in d.get('compose_services', [])))
                item['deployments'] = owners if len(owners) == 1 else []
                item['ambiguous_deployments'] = owners if len(owners) > 1 else []
                if not owners:
                    gaps.append('unclassified-container:' + item['name'])
                elif len(owners) > 1:
                    gaps.append('ambiguous-container-owner:' + item['name'])
                if item['mounts'] or item['changes']:
                    gaps.append('container-runtime-content-needs-assessment:' + item['name'])
                evidence['containers'].append(item)
                if item['running']:
                    try:
                        namespace_inode = (proc / str(item['main_pid']) / 'ns/pid').stat().st_ino
                        container_processes[item['id']] = process_inventory(
                            proc, namespace_inode, fingerprint, gaps,
                            'container:' + item['name'].lstrip('/'))
                        item['process_privileges'] = [{
                            'pid': process['pid'], 'start_ticks': process['start_ticks'],
                            'executable': process['executable'],
                            'privileges': process['privileges']}
                            for process in container_processes[item['id']]]
                    except OSError:
                        gaps.append('container-process-discovery-failed:' + item['name'])
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            gaps.append('container-discovery-failed')

    run_parts_cache = {}

    def select_run_parts(directory):
        if directory not in run_parts_cache:
            run_parts_cache[directory] = run([
                '/usr/bin/run-parts', '--test', '--report', directory
            ]).splitlines()
        return run_parts_cache[directory]

    for root in (Path('/etc/cron.d'), Path('/etc/cron.hourly'), Path('/etc/cron.daily'),
                 Path('/etc/cron.weekly'), Path('/etc/cron.monthly'),
                 Path('/var/spool/cron/crontabs')):
        try:
            for path in sorted(root.glob('*')):
                if path.is_file():
                    job, unsupported = scheduled_file(
                        path, filesystem_root=filesystem_root,
                        run_parts_selector=select_run_parts)
                    job['sha256'] = fingerprint(path)
                    evidence['scheduled_files'].append(job)
                    gaps.extend('scheduled-command-unsupported:' + str(path) + ':' + reason
                                for reason in unsupported)
        except (OSError, ValueError):
            gaps.append('scheduled-job-discovery-failed:' + str(root))
    if Path('/etc/crontab').is_file():
        try:
            job, unsupported = scheduled_file(
                Path('/etc/crontab'), filesystem_root=filesystem_root,
                run_parts_selector=select_run_parts)
            job['sha256'] = fingerprint(Path('/etc/crontab'))
            evidence['scheduled_files'].append(job)
            gaps.extend('scheduled-command-unsupported:/etc/crontab:' + reason
                        for reason in unsupported)
        except (OSError, ValueError):
            gaps.append('scheduled-job-discovery-failed:/etc/crontab')
    snapshot_inputs = scanner_snapshot_artifact_inputs(
        reports or [], config['host'])
    if execution_facts is None and config.get('execution_domains'):
        execution_facts = collect_execution_domain_facts(
            config, evidence['services'],
            [*evidence['scheduled_files'], *evidence['activated_units']],
            evidence.get('listeners') or [], filesystem_root,
            snapshot_artifact_inputs=snapshot_inputs)
    evidence['execution_domain_facts'] = execution_facts or {
        'schema': 1, 'kind': 'observation', 'status': 'not-configured'}
    requests = (package_requests if package_requests is not None else
                scanner_package_requests(reports or []))
    evidence['package_evidence'] = []
    try:
        evidence['package_evidence'].extend(package_consumer_evidence(
            filesystem_root, requests['host'], evidence['processes'], evidence['services'],
            [*evidence['scheduled_files'], *evidence['activated_units']],
            namespace={'kind': 'host', 'host': config['host']},
            capabilities=config.get('package_capabilities', []),
            execution_domains=config.get('execution_domains', []),
            execution_facts=execution_facts))
    except (OSError, ValueError):
        gaps.append('host-package-evidence-incomplete')
    image_requests = requests['images']
    for container in evidence['containers']:
        if not container.get('running') or container.get('image_id') not in image_requests:
            continue
        root = proc / str(container['main_pid']) / 'root'
        try:
            evidence['package_evidence'].extend(package_consumer_evidence(
                root, image_requests[container['image_id']],
                container_processes.get(container['id'], []), [], [], namespace={
                    'kind': 'container', 'host': config['host'],
                    'container_id': container['id'], 'container_name': container['name'].lstrip('/'),
                    'image_id': container['image_id'],
                    'deployments': container.get('deployments', [])}))
        except (OSError, ValueError):
            gaps.append('container-package-evidence-incomplete:' + container['name'])
    domain_records = {}
    for package in evidence['package_evidence']:
        for domain in package.get('execution_domains') or []:
            domain_records[domain['id']] = domain
    for declaration in config.get('execution_domains', []):
        if declaration['id'] not in domain_records:
            domain_records[declaration['id']] = {
                'id': declaration['id'], 'packages': declaration.get('packages', []),
                'files': declaration.get('files', []),
                'entries': declaration.get('entries', []),
                'inputs': declaration.get('inputs', []),
                'authority_paths': declaration.get('authority_paths', []),
                'coverage': {name: {'complete': False, 'missing': values,
                                    'unassigned': []}
                             for name, values in (
                                 ('entry', declaration.get('entries', [])),
                                 ('input', declaration.get('inputs', [])),
                                 ('file', declaration.get('files', [])),
                                 ('file_authority', declaration.get(
                                     'authority_paths', [])))},
                'complete': False,
                'disposition': declaration.get('disposition'),
                'evidence_refs': [],
            }
    evidence['execution_domains'] = [domain_records[key]
                                     for key in sorted(domain_records)]
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
    access_paths = {item['path'] for item in evidence['configuration_files']}
    for service in evidence['services']:
        if service.get('deployments'):
            access_paths.update(service.get('executables', []))
            if service.get('FragmentPath'):
                access_paths.add(service['FragmentPath'])
    evidence['path_access'] = []
    access_bytes = 0
    for path in sorted(access_paths)[:MAX_ACCESS_PATHS]:
        if not Path(path).is_absolute():
            gaps.append('path-access-incomplete:relative-path:' + path)
            continue
        item = path_access_evidence(Path(path))
        access_bytes += len(json.dumps(item, sort_keys=True).encode())
        if access_bytes > MAX_ACCESS_BYTES:
            gaps.append('path-access-coverage-incomplete:byte-limit')
            break
        evidence['path_access'].append(item)
    if len(access_paths) > MAX_ACCESS_PATHS:
        gaps.append('path-access-coverage-incomplete:selection-limit')
    gaps.extend('path-access-incomplete:' + item['path']
                for item in evidence['path_access'] if item['status'] != 'complete')
    evidence['gaps'] = sorted(set(gaps))
    evidence['relationships'] = []
    for service in evidence['services']:
        service_key = 'service:' + config['host'] + ':' + service['Id']
        for deployment in service.get('deployments', []):
            evidence['relationships'].append({
                'subject': 'deployment:' + config['host'] + ':' + deployment,
                'relation': 'RUNS_AS', 'object': service_key,
                'scope': 'runtime:' + config['host'] + ':' + deployment,
                'kind': 'observation', 'status': 'valid'})
        identity = service['execution_identity']
        if 'effective_uid' in identity and len(service.get('deployments', [])) == 1:
            evidence['relationships'].append({
                'subject': service_key, 'relation': 'EXECUTES_AS',
                'object': 'principal:' + config['host'] + ':uid:' + str(identity['effective_uid']),
                'scope': 'runtime:' + config['host'] + ':' + service['deployments'][0],
                'kind': 'derived', 'status': 'valid',
                'derivation': {'rule': EXECUTION_OBSERVATION_RULE,
                               'input_refs': identity['input_refs']}})
    for container in evidence['containers']:
        container_key = container_resource_key(config['host'], container)
        for deployment in container.get('deployments', []):
            evidence['relationships'].append({
                'subject': 'deployment:' + config['host'] + ':' + deployment,
                'relation': 'RUNS_AS', 'object': container_key,
                'scope': 'runtime:' + config['host'] + ':' + deployment,
                'kind': 'observation', 'status': 'valid'})
        for mount in container.get('mounts', []):
            source = mount.get('Source')
            if source:
                evidence['relationships'].append({
                    'subject': container_key, 'relation': 'MOUNTS',
                    'object': 'host-path:' + config['host'] + ':' + source,
                    'scope': 'runtime:' + config['host'] + ':mounts',
                    'kind': 'observation', 'status': 'valid'})
    evidence['relationship_coverage'] = []
    mapped = {relationship['subject'] for relationship in evidence['relationships']}
    for deployment in config['deployments']:
        scope = 'runtime:' + config['host'] + ':' + deployment['id']
        key = 'deployment:' + config['host'] + ':' + deployment['id']
        related_gaps = [gap for gap in evidence['gaps']
                        if gap.startswith(('service-discovery-failed',
                                           'container-discovery-failed',
                                           'process-unreadable',
                                           'listener-discovery-failed'))]
        complete = key in mapped and not related_gaps
        evidence['relationship_coverage'].append({
            'scope': scope, 'relationship': 'runtime_ownership',
            'complete': complete, 'status': 'valid' if complete else 'incomplete',
            'gaps': related_gaps if related_gaps else ([] if complete else ['deployment-unmapped'])})
    mount_scope = 'runtime:' + config['host'] + ':mounts'
    if any(item['scope'] == mount_scope for item in evidence['relationships']):
        mount_gaps = [gap for gap in evidence['gaps']
                      if gap.startswith('container-discovery-failed')]
        evidence['relationship_coverage'].append({
            'scope': mount_scope, 'relationship': 'mounts',
            'complete': not mount_gaps,
            'status': 'incomplete' if mount_gaps else 'valid',
            'gaps': mount_gaps})
    stable = {k: evidence[k] for k in ['containers', 'scheduled_files', 'activated_units',
                                       'configuration_files', 'kernel', 'package_evidence',
                                       'path_access', 'execution_domains',
                                       'execution_domain_facts']}
    stable['containers'] = [container_binding(c) for c in evidence['containers']]
    # Ignore scanner/SSH processes and transient OS units. Track the application
    # service generation, its executable, and its loaded-file set instead.
    tracked_services = [s for s in evidence['services']
                        if set(s.get('deployments', [])) - {'defensive-monitor'}]
    main_pids = {int(s.get('MainPID') or 0) for s in tracked_services}
    stable['services'] = [{key: service.get(key) for key in (
        'Id', 'FragmentPath', 'fragment_sha256', 'ControlGroup', 'UnitFileState',
        'executables', 'activation_sources', 'deployments', 'execution_settings')}
        for service in tracked_services]
    stable['execution_observations'] = [{
        'unit': service['Id'], 'settings': service['execution_settings'],
        'process_privileges': service['execution_identity'].get('observed'),
        'status': service['execution_identity']['status'],
        'differences': service['execution_identity']['differences'],
        'unknown_fields': service['execution_identity']['unknown_fields'],
        'identity_resolution': service['execution_identity']['identity_resolution'],
    } for service in tracked_services]
    stable['processes'] = sorted({(p['executable'], p['sha256'], tuple(p['loaded_files'])) for p in evidence['processes'] if p['pid'] in main_pids})
    stable['loaded_file_identities'] = [[{
        'path': item.get('path'), 'sha256': item.get('sha256')}
        for item in p['loaded_file_identities']]
        for p in evidence['processes'] if p['pid'] in main_pids]
    stable['listeners'] = sorted(re.sub(r'pid=\d+,fd=\d+', 'process', line) for line in evidence.get('listeners', []))
    evidence['runtime_sha256'] = stable_runtime_identity(stable)
    return evidence
