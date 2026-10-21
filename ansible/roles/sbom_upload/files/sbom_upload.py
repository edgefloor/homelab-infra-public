#!/usr/bin/env python3
"""Collect CycloneDX with Trivy and send it to Dependency-Track's standard API."""
import argparse
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
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import uuid
import tomllib
from datetime import datetime, timezone
from urllib.parse import quote


class CollectionError(RuntimeError):
    pass


def command(argv, timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Tool diagnostics and HTTP bodies are deliberately not copied into logs.
        raise CollectionError(Path(argv[0]).name + ' failed')
    return result.stdout


def docker_targets(retired=()):
    if not shutil.which('docker'):
        if Path('/var/run/docker.sock').exists():
            raise CollectionError('Docker socket exists but its CLI is unavailable')
        return []
    ids = command(['docker', 'ps', '--quiet']).split()
    if not ids:
        return []
    template = ('{"name":{{json .Name}},"image":{{json .Image}},'
                '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                '"service":{{json (index .Config.Labels "com.docker.compose.service")}}}')
    records = [json.loads(line) for line in command(['docker', 'inspect', '--format', template, *ids]).splitlines()]
    return image_scopes([item for item in records if item['name'].lstrip('/') not in retired])


def image_scopes(records):
    result = {}
    for item in records:
        name = ('compose/' + item['project'] + '/' + item['service']
                if item.get('project') and item.get('service') else item['name'].lstrip('/'))
        key = 'container/' + name
        image = item['image']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise CollectionError('running container has an invalid image identity')
        if key in result and result[key]['target'] != image:
            raise CollectionError('multiple running image revisions share a Compose service; retry after rollout')
        result[key] = {'name': key, 'kind': 'image', 'target': image, 'packages': 'os,library'}
    return [result[key] for key in sorted(result)]


def declared_scopes(config):
    scopes = [{'name': 'os', 'kind': 'rootfs', 'target': '/', 'packages': 'os'}]
    scopes += [{'name': 'binary' + path, 'kind': 'rootfs', 'target': path, 'packages': 'library'}
               for path in sorted(set(config['go_binaries']))]
    scopes += [{'name': 'library/' + item['deployment'], 'kind': 'rootfs',
                'target': item['path'], 'packages': 'library',
                'vendor_bom': config.get('vendor_boms', {}).get(item['deployment'])}
               for item in config['libraries']]
    names = [scope['name'] for scope in scopes]
    if len(names) != len(set(names)):
        raise CollectionError('duplicate declared software scope')
    attach_source_locks(config, scopes)
    return scopes


def attach_source_locks(config, scopes):
    for scope in scopes:
        source = config.get('source_locks', {}).get(scope['name'])
        if source:
            scope['source_lock'] = source


SOURCE_LIMITATIONS = ('Cargo.lock candidates associated with the pinned release source; '
                     'compiled membership is unverified. Includes development, optional and '
                     'other-platform dependencies. Git forks and workspace crates have no '
                     'crates.io package URL. Does not inventory native libraries or the Rust toolchain.')


def verified_source_lock_bytes(scope):
    source = scope['source_lock']
    path = Path(source['path'])
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 4 * 1024 * 1024:
        raise CollectionError('source lock is missing, oversized or not a regular file')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise CollectionError('source lock checksum differs from the reviewed revision')
    if not re.fullmatch('[0-9a-f]{40}', source['revision']):
        raise CollectionError('source association requires an immutable Git revision')
    if scope['kind'] == 'image':
        if scope['target'] != source['image_id']:
            raise CollectionError('running image differs from the reviewed source association')
    elif file_digest(scope['target']) != source['artifact_sha256']:
        raise CollectionError('installed binary differs from the reviewed source association')
    return raw


def verified_source_lock_bom(scope, output):
    """Publish source candidates, never infer that lock entries were compiled."""
    source = scope['source_lock']
    lock = tomllib.loads(verified_source_lock_bytes(scope).decode('utf-8'))
    packages = lock.get('package', [])
    if not 0 < len(packages) <= 20000:
        raise CollectionError('source lock has no bounded package inventory')
    components = []
    registry_count = 0
    for package in packages:
        name, version = package['name'], package['version']
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not isinstance(version, str) or not version:
            raise CollectionError('source lock contains an invalid Cargo package identity')
        origin = package.get('source', '')
        identity = hashlib.sha256((name + '\0' + version + '\0' + origin).encode()).hexdigest()
        component = {'type': 'library', 'bom-ref': 'cargo-lock:' + identity,
                     'name': name, 'version': version,
                     'description': 'Source-lock candidate; presence in the deployed executable is unverified.',
                     'properties': [{'name': 'homelab:inventory:evidence', 'value': 'source-lock-candidate'},
                                    {'name': 'homelab:cargo:source', 'value': origin or 'workspace'}]}
        if origin == 'registry+https://github.com/rust-lang/crates.io-index':
            checksum = package.get('checksum', '')
            if not re.fullmatch('[0-9a-f]{64}', checksum):
                raise CollectionError('registry source package lacks its crate checksum')
            component['purl'] = 'pkg:cargo/' + quote(name, safe='') + '@' + quote(version, safe='')
            component['hashes'] = [{'alg': 'SHA-256', 'content': checksum}]
            component['properties'].append({'name': 'homelab:cargo:checksum-kind', 'value': 'registry-crate-archive'})
            registry_count += 1
        elif origin.startswith('git+https://') and re.search(r'#[0-9a-f]{40}$', origin):
            component['externalReferences'] = [{'type': 'vcs', 'url': origin}]
        elif origin:
            raise CollectionError('source lock contains an unsupported package source')
        components.append(component)
    artifact = source['image_id'] if scope['kind'] == 'image' else 'sha256:' + source['artifact_sha256']
    properties = {
        'homelab:inventory:evidence': 'source-lock-candidates',
        'homelab:inventory:compiled-membership': 'unverified',
        'homelab:inventory:limitations': SOURCE_LIMITATIONS,
        'homelab:source:repository': source['repository'],
        'homelab:source:revision': source['revision'],
        'homelab:source:lock-sha256': source['sha256'],
        'homelab:source:lock-url': source['url'],
        'homelab:source:association': source['association'],
        'homelab:artifact:identity': artifact,
    }
    # Dependency-Track retains component properties but does not map BOM metadata
    # properties to project properties. Keep provenance visible after native import.
    for component in components:
        component['properties'].extend({'name': key, 'value': value}
                                       for key, value in properties.items()
                                       if key != 'homelab:inventory:evidence')
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'serialNumber': 'urn:uuid:' + str(uuid.uuid4()),
           'metadata': {'timestamp': datetime.now(timezone.utc).isoformat(),
                        'component': {'type': 'application', 'bom-ref': 'source-associated-release',
                                      'name': scope['name'] + ' source-lock candidates', 'version': source['release']},
                        'properties': [{'name': key, 'value': value} for key, value in properties.items()]},
           'components': components,
           'compositions': [{'aggregate': 'unknown', 'assemblies': ['source-associated-release']}]}
    output.write_text(json.dumps(bom, separators=(',', ':')))
    validate_bom(output)
    return {'mode': 'source-lock-candidates', 'compiled_membership': 'unverified',
            'components': len(components), 'registry_purls': registry_count,
            'source_revision': source['revision'], 'artifact_identity': artifact,
            'limitations': SOURCE_LIMITATIONS}


def trivy_command(config, scope, output, work):
    result = [config['trivy'], scope['kind'], '--format', 'cyclonedx', '--quiet',
              '--skip-version-check', '--offline-scan', '--parallel', '1',
              '--cache-dir', str(work / 'cache'), '--output', str(output),
              '--pkg-types', scope['packages'], '--timeout', str(config['scan_timeout_seconds']) + 's']
    if scope['name'] == 'os':
        for path in config['skip_dirs']:
            result.extend(['--skip-dirs', path])
    if scope['kind'] == 'image':
        result.extend(['--image-src', 'docker'])
    return result + [scope['target']]


def file_digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verified_vendor_bom(scope, output):
    """Use a publisher's pinned BOM only while its installed JAR set matches."""
    vendor = scope['vendor_bom']
    for path_key, checksum_key in (('path', 'sha256'), ('archive', 'archive_sha256')):
        if file_digest(vendor[path_key]) != vendor[checksum_key]:
            raise CollectionError('vendor BOM or release archive checksum does not match')
    validate_bom(Path(vendor['path']))
    bom = json.loads(Path(vendor['path']).read_text())
    if bom.get('metadata', {}).get('component', {}).get('version') != vendor['version']:
        raise CollectionError('vendor BOM version does not match the pinned release')
    root = Path(scope['target'])
    with tarfile.open(vendor['archive'], 'r:*') as archive:
        jars = [member for member in archive if member.name.lower().endswith('.jar')]
        expected = set()
        for member in jars:
            relative = Path(member.name)
            if not member.isfile() or relative.is_absolute() or '..' in relative.parts:
                raise CollectionError('release archive contains an unsafe JAR path')
            expected.add(relative.as_posix())
            installed = root / relative
            if installed.is_symlink() or not installed.is_file():
                raise CollectionError('installed JAR is missing or is not a regular file')
            with archive.extractfile(member) as source:
                if hashlib.file_digest(source, 'sha256').hexdigest() != file_digest(installed):
                    raise CollectionError('installed JAR differs from the pinned release')
        actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.suffix.lower() == '.jar'}
        if not expected or actual != expected:
            raise CollectionError('installed JAR set differs from the pinned release')
    shutil.copyfile(vendor['path'], output)


def scan(config, scope, output, work):
    if scope['kind'] != 'image':
        # Trivy's filesystem walker does not follow a symlink used as its root.
        # Preserve the logical scope name while scanning the installed release.
        scope = {**scope, 'target': str(Path(scope['target']).resolve(strict=True))}
    if scope.get('source_lock'):
        return verified_source_lock_bom(scope, output)
    if scope.get('vendor_bom'):
        try:
            verified_vendor_bom(scope, output)
        except tarfile.TarError as exc:
            raise CollectionError('pinned release archive could not be verified') from exc
        return
    def limit_file_size():
        resource.setrlimit(resource.RLIMIT_FSIZE, (config['cache_max_bytes'], config['cache_max_bytes']))
    environment = {**os.environ, 'TMPDIR': str(work / 'tmp'), 'GOMEMLIMIT': '256MiB'}
    started = time.monotonic()
    with (work / 'scanner.stderr').open('wb') as errors:
        process = subprocess.Popen(trivy_command(config, scope, output, work), stdout=subprocess.DEVNULL,
                                   stderr=errors, env=environment, start_new_session=True, preexec_fn=limit_file_size)
        try:
            while process.poll() is None:
                used = sum(path.stat().st_size for path in work.rglob('*') if path.is_file() and not path.is_symlink())
                if (used > config['cache_max_bytes'] or
                        shutil.disk_usage(work).free < config['minimum_free_bytes'] or
                        time.monotonic() - started > config['scan_timeout_seconds']):
                    raise CollectionError('scanner exceeded its disk or time budget')
                time.sleep(0.5)
            if process.returncode:
                raise CollectionError('Trivy scan failed')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    validate_bom(output)


def validate_bom(path):
    if not path.is_file() or not 0 < path.stat().st_size <= 64 * 1024 * 1024:
        raise CollectionError('missing or oversized CycloneDX output')
    value = json.loads(path.read_text())
    if value.get('bomFormat') != 'CycloneDX' or not isinstance(value.get('components'), list) or not value['components']:
        raise CollectionError('scan did not produce a nonempty CycloneDX inventory')
    return len(value['components'])


def api(config, suffix, form=()):
    argv = ['curl', '--silent', '--show-error', '--fail', '--connect-timeout', '15', '--max-time', '120',
            '--header', '@' + config['header_file']]
    for address in config.get('resolve', []):
        argv += ['--resolve', address]
    for key, value in form:
        argv += ['--form' if key == 'bom' else '--form-string', key + '=' + value]
    return json.loads(command(argv + [config['url'].rstrip('/') + '/api/v1/' + suffix], timeout=130))


def upload(config, scope, bom):
    project = 'homelab/' + config['system'] + '/' + scope['name']
    if scope.get('source_lock'):
        project += '/source-lock-candidates'
    if len(project) > 255:
        raise CollectionError('project name exceeds API limit')
    response = api(config, 'bom', [('autoCreate', 'true'), ('projectName', project),
                                  ('projectVersion', 'current'),
                                  ('parentUUID', str(uuid.UUID(config['parent_uuid']))),
                                  ('bom', '@' + str(bom))])
    token = str(uuid.UUID(response['token']))
    for _ in range(60):
        state = api(config, 'bom/token/' + token)
        if state.get('processing') is False:
            if state.get('status') == 'COMPLETED':
                return
            raise CollectionError('Dependency-Track did not successfully consume the upload')
        time.sleep(2)
    raise CollectionError('Dependency-Track has not finished consuming the upload')


def config_digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def collect(config):
    state = Path(config['state'])
    previous = json.loads(state.read_text()) if state.exists() else {}
    status = {'attempted_at': int(time.time()), 'config_digest': config_digest(config),
              'last_success': previous.get('last_success'), 'uploaded': [], 'failed': [], 'coverage': {}}
    scopes = declared_scopes(config)
    try:
        images = docker_targets(config.get('retired_containers', []))
    except (CollectionError, OSError, ValueError, subprocess.SubprocessError):
        images = None
        status['failed'].append('container-inventory')
    scopes.extend(dict(scope) for scope in images or [])
    attach_source_locks(config, scopes)
    for missing in set(config.get('source_locks', {})) - {scope['name'] for scope in scopes}:
        status['failed'].append('source-lock-scope-missing:' + missing)
    # No persistent scanner database, extracted layers, BOMs or credentials are left in this directory.
    cache = Path(config['cache_dir'])
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    # An interrupted systemd run may not execute Python's finally blocks. The service's
    # flock makes it safe to remove only this collector's abandoned work directories.
    for abandoned in cache.glob('run-*'):
        if abandoned.is_dir() and not abandoned.is_symlink():
            shutil.rmtree(abandoned)
    with tempfile.TemporaryDirectory(prefix='run-', dir=cache) as directory:
        work = Path(directory)
        (work / 'tmp').mkdir()
        for scope in scopes:
            output = work / 'bom.json'
            try:
                coverage = scan(config, scope, output, work)
                upload(config, scope, output)
                status['uploaded'].append(scope['name'])
                status['coverage'][scope['name']] = coverage or {'mode': 'artifact-inventory'}
            except (CollectionError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                status['failed'].append(scope['name'])
            finally:
                output.unlink(missing_ok=True)
        if images is not None:
            try:
                if docker_targets(config.get('retired_containers', [])) != images:
                    status['failed'].append('container-inventory-changed')
            except (CollectionError, OSError, ValueError, subprocess.SubprocessError):
                status['failed'].append('container-inventory')
    if not status['failed']:
        status['last_success'] = int(time.time())
    state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = state.with_suffix('.tmp')
    temporary.write_text(json.dumps(status, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(state)
    print('SBOM uploads: succeeded=' + str(len(status['uploaded'])) + ' failed=' + str(len(status['failed'])))
    return 1 if status['failed'] else 0


def fresh(config, now=None):
    try:
        state = json.loads(Path(config['state']).read_text())
        age = (time.time() if now is None else now) - state['last_success']
        current = not state['failed'] and state['config_digest'] == config_digest(config) and 0 <= age <= config['max_age_seconds']
        if current and config.get('source_locks'):
            scopes = declared_scopes(config)
            if any(name.startswith('container/') for name in config['source_locks']):
                scopes.extend(docker_targets(config.get('retired_containers', [])))
            attach_source_locks(config, scopes)
            sources = [scope for scope in scopes if scope.get('source_lock')]
            if {scope['name'] for scope in sources} != set(config['source_locks']):
                return False
            for scope in sources:
                verified_source_lock_bytes(scope)
        return current
    except (CollectionError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    address = urlsplit(config['url'])
    if address.scheme != 'https' and not (address.scheme == 'http' and address.hostname == '127.0.0.1'):
        raise CollectionError('API requires verified HTTPS or the restricted local SSH forward')
    header = Path(config['header_file']).lstat()
    if not stat.S_ISREG(header.st_mode) or header.st_uid != 0 or header.st_mode & 0o077:
        raise CollectionError('API header must be a root-owned private regular file')
    if args.check:
        current = fresh(config)
        message = 'SBOM collection is current' if current else 'SBOM coverage is missing, failed, changed, or older than 36 hours'
        if current and config.get('source_locks'):
            message += '; source-lock candidate scopes=' + str(len(config['source_locks'])) + ', compiled Rust membership unverified'
        print(message)
        return 0 if current else 1
    return collect(config)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (CollectionError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('SBOM collection failed; previous Dependency-Track inventories were retained')
        raise SystemExit(1)
