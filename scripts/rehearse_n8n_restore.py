#!/usr/bin/env python3
"""Rehearse an installed candidate using a private SQLite backup and no egress.

Run as root on the n8n host. The source database is opened read-only. The native
unpublish command disables workflows only in the disposable copy before startup.
The untouched database/config backup and a redacted receipt remain root-private.
"""
import argparse
from contextlib import closing
from datetime import UTC, datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid

SOURCE = Path('/var/lib/n8n/.n8n')
NODE = Path('/opt/node-v24.21.0-linux-x64/bin/node')
ISOLATION_CHECKS = {'production_state', 'production_config', 'production_process',
                    'capabilities', 'groups', 'network', 'identity', 'backup', 'disposable_state'}


def command(argv, timeout=10):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed: {argv[0]}')
    return result.stdout.strip()


def validate_release(value):
    release = Path(value).resolve(strict=True)
    if not release.is_relative_to('/opt/n8n/candidates'):
        raise ValueError('only a separately installed candidate is allowed')
    package = release / 'node_modules/n8n/package.json'
    if json.loads(package.read_text())['version'] not in {'2.43.7', '2.43.8'}:
        raise ValueError('this rehearsal was reviewed for n8n 2.43.7 and 2.43.8')
    return release


def service_identity():
    text = command(['systemctl', 'show', 'n8n.service', '-p', 'MainPID',
                    '-p', 'ActiveState', '-p', 'ActiveEnterTimestampMonotonic'])
    state = dict(line.split('=', 1) for line in text.splitlines())
    if state['ActiveState'] != 'active' or state['MainPID'] == '0':
        raise RuntimeError('production n8n must be healthy before and after rehearsal')
    state['release'] = str(Path('/opt/n8n/current').resolve(strict=True))
    return state


def inspect_database(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as connection:
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('SQLite integrity validation failed')
        counts = {name: connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                  for name, table in [('users', 'user'), ('workflows', 'workflow_entity'),
                                      ('credentials', 'credentials_entity'), ('migrations', 'migrations')]}
        counts['owners'] = connection.execute(
            'SELECT count(*) FROM user WHERE roleSlug = ?', ('global:owner',)).fetchone()[0]
        counts['active_workflows'] = connection.execute(
            'SELECT count(*) FROM workflow_entity WHERE active = 1 OR activeVersionId IS NOT NULL').fetchone()[0]
        hashes = {}
        for name, query in {
            'workflow_definitions': 'SELECT id,nodes,connections FROM workflow_entity ORDER BY id',
            'credentials': 'SELECT id,type,data FROM credentials_entity ORDER BY id',
            'account_authentication': 'SELECT id,password,roleSlug,disabled,mfaEnabled,mfaSecret,mfaRecoveryCodes FROM user ORDER BY id',
        }.items():
            rows = connection.execute(query).fetchall()
            hashes[name] = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    return {'integrity': 'ok', 'counts': counts, 'content_sha256': hashes}


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def create_rehearsal_account():
    name = 'n8n-rehearsal-' + uuid.uuid4().hex[:12]
    command(['useradd', '--system', '--no-create-home', '--user-group', '--home-dir',
             '/nonexistent', '--shell', '/usr/sbin/nologin', name])
    account = pwd.getpwnam(name)
    production = pwd.getpwnam('n8n')
    if (account.pw_uid in {0, production.pw_uid} or account.pw_gid in {0, production.pw_gid}
            or os.getgrouplist(name, account.pw_gid) != [account.pw_gid]):
        command(['userdel', name])
        raise RuntimeError('rehearsal account is not separate from production')
    return account


def remove_rehearsal_account(account):
    # Catch any descendants that escaped the original process group. This UID
    # was allocated only for this run, so it cannot target production processes.
    result = subprocess.run(['pkill', '-KILL', '-u', str(account.pw_uid)], capture_output=True)
    if result.returncode not in {0, 1}:
        raise RuntimeError('could not stop all rehearsal account processes')
    command(['userdel', account.pw_name])
    try:
        group = grp.getgrnam(account.pw_name)
    except KeyError:
        pass
    else:
        if group.gr_gid != account.pw_gid or group.gr_mem:
            raise RuntimeError('rehearsal group changed before cleanup')
        command(['groupdel', account.pw_name])


def isolated_command(directory, account, argv, environment=None):
    # Root creates loopback, then permanently drops the fresh UID's privileges.
    # The candidate inherits no supplementary groups, capabilities or service env.
    return ['unshare', '--net', '--', 'sh', '-c', 'ip link set lo up && exec "$@"',
            'n8n-rehearsal', 'setpriv', f'--reuid={account.pw_uid}', f'--regid={account.pw_gid}',
            '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all',
            '--ambient-caps=-all', 'env', '-i', 'HOME=' + str(directory),
            'PATH=/usr/bin:/bin', *(f'{key}={value}' for key, value in (environment or {}).items()), *argv]


def verify_isolation(directory, account, production_pid, backup):
    # Probe permissions without reading secret bytes or sending a real signal.
    probe = r'''
import json, os, socket, sys
from pathlib import Path
uid, gid, pid = map(int, sys.argv[1:4])
directory, backup = map(Path, sys.argv[4:6])
def denied(path, flags=os.O_RDONLY):
    try:
        fd = os.open(path, flags)
    except PermissionError:
        return True
    else:
        os.close(fd)
        return False
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
try:
    os.kill(pid, 0)
    signal_denied = False
except PermissionError:
    signal_denied = True
checks = {
 'identity': os.getuid() == os.geteuid() == uid and uid != 0 and os.getgid() == gid,
 'groups': os.getgroups() == [],
 'capabilities': all(int(status[name].strip(), 16) == 0 for name in ['CapEff','CapPrm','CapInh','CapBnd','CapAmb']) and status['NoNewPrivs'].strip() == '1',
 'production_state': all(denied(path) for path in ['/var/lib/n8n/.n8n/config','/var/lib/n8n/.n8n/database.sqlite']) and not os.access('/var/lib/n8n/.n8n', os.W_OK),
 'production_config': all(denied('/etc/n8n/' + name) for name in ['n8n.env','pangolin-auth.json']),
 'production_process': signal_denied and denied('/proc/' + str(pid) + '/environ'),
 'backup': denied(backup / 'config') and denied(backup / 'database.sqlite'),
 'network': [name for _, name in socket.if_nameindex()] == ['lo'],
 'disposable_state': os.access(directory / '.n8n/database.sqlite', os.R_OK | os.W_OK),
}
print(json.dumps(checks, sort_keys=True))
'''
    result = json.loads(command(isolated_command(directory, account,
                        ['/usr/bin/python3', '-c', probe, str(account.pw_uid), str(account.pw_gid),
                         str(production_pid), str(directory), str(backup)])))
    if set(result) != ISOLATION_CHECKS or not all(value is True for value in result.values()):
        raise RuntimeError('rehearsal isolation probe failed')
    return result


def candidate_command(release, directory, arguments, account):
    environment = {
        'HOME': str(directory), 'N8N_USER_FOLDER': str(directory),
        'PATH': f'{NODE.parent}:/usr/bin:/bin', 'NODE_ENV': 'production',
        'NODE_OPTIONS': '--max-old-space-size=1024', 'DB_TYPE': 'sqlite',
        'N8N_LISTEN_ADDRESS': '127.0.0.1', 'N8N_HOST': '127.0.0.1',
        'N8N_PORT': '15678', 'N8N_PROTOCOL': 'http', 'N8N_SECURE_COOKIE': 'false',
        'N8N_DISABLE_PRODUCTION_MAIN_PROCESS': 'true',
        'N8N_DIAGNOSTICS_ENABLED': 'false', 'N8N_VERSION_NOTIFICATIONS_ENABLED': 'false',
        'N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS': 'true',
        'N8N_RUNNERS_ENABLED': 'false', 'GENERIC_TIMEZONE': 'UTC', 'TZ': 'UTC',
        'NODES_EXCLUDE': json.dumps(['n8n-nodes-base.executeCommand',
                                     'n8n-nodes-base.localFileTrigger', 'n8n-nodes-base.git']),
        'N8N_DISABLED_MODULES': 'source-control,promotions',
    }
    return isolated_command(directory, account,
                            [str(NODE), str(release / 'node_modules/n8n/bin/n8n'), *arguments], environment)


def bounded_candidate(release, directory, arguments, log, account):
    with log.open('wb') as output:
        process = subprocess.Popen(candidate_command(release, directory, arguments, account),
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                   cwd=directory)
        try:
            if process.wait(timeout=120):
                raise RuntimeError(f'candidate command failed: {arguments[0]}')
        finally:
            stop(process)


def finalize_rehearsal(process, log_stream, account, directory, receipt, output):
    try:
        if process is not None:
            stop(process)
        if log_stream is not None:
            log_stream.close()
        try:
            if account is not None:
                remove_rehearsal_account(account)
                receipt['disposable_account_removed'] = True
        finally:
            shutil.rmtree(directory)
            receipt['disposable_runtime_removed'] = not directory.exists()
    except BaseException:
        # Functional checks do not certify success when cleanup fails or is interrupted.
        receipt['status'] = 'failed'
        raise
    finally:
        output.write_text(json.dumps(receipt, indent=2) + '\n')
        output.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--release', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('run this rehearsal as root on the n8n host')
    os.umask(0o077)
    release = validate_release(args.release)
    if shutil.disk_usage('/var').free < 4 * 1024**3:
        raise RuntimeError('at least four GiB of free space is required')
    original = service_identity()
    tag = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    backup = Path('/var/backups/n8n') / ('rehearsal-' + tag)
    backup.mkdir(parents=True, mode=0o700)
    backup.parent.chmod(0o700)
    receipt = {'schema': 1, 'application': 'n8n', 'candidate': str(release),
               'candidate_version': json.loads((release / 'node_modules/n8n/package.json').read_text())['version'],
               'candidate_lock_sha256': hashlib.sha256((release / 'package-lock.json').read_bytes()).hexdigest(),
               'candidate_manifest_sha256': hashlib.sha256((release / 'package.json').read_bytes()).hexdigest(),
               'observed_at': datetime.now(UTC).isoformat(), 'status': 'failed',
               'backup': str(backup), 'production_before': original,
               'disabled_nodes': ['n8n-nodes-base.executeCommand',
                                  'n8n-nodes-base.localFileTrigger', 'n8n-nodes-base.git'],
               'disabled_modules': ['source-control', 'promotions']}
    directory = Path(tempfile.mkdtemp(prefix='homelab-n8n-restore-'))
    process = None
    log_stream = None
    account = None
    try:
        started = time.monotonic()
        def progress(_status, _remaining, _total):
            if time.monotonic() - started > 30:
                raise TimeoutError('SQLite backup exceeded thirty seconds')
        with closing(sqlite3.connect((SOURCE / 'database.sqlite').as_uri() + '?mode=ro', uri=True, timeout=5)) as source:
            with closing(sqlite3.connect(backup / 'database.sqlite')) as destination:
                source.backup(destination, pages=256, progress=progress, sleep=0.05)
        config = json.loads((SOURCE / 'config').read_text())
        if not isinstance(config.get('encryptionKey'), str) or not config['encryptionKey']:
            raise ValueError('source encryption config is missing its key')
        (backup / 'config').write_text(json.dumps({'encryptionKey': config['encryptionKey']}))
        # Retain the matching service configuration for rollback, but never
        # source it into the isolated candidate's environment.
        service_backup = backup / 'service-config'
        service_backup.mkdir(mode=0o700)
        configuration = [Path('/etc/n8n') / name for name in
                         ['n8n.env', 'pangolin-auth.js', 'pangolin-auth.json']]
        configuration.append(Path('/etc/systemd/system/n8n.service'))
        for path in configuration:
            shutil.copy2(path, service_backup / path.name)
            (service_backup / path.name).chmod(0o600)
        receipt['rollback_configuration_files'] = [path.name for path in configuration]
        receipt['before'] = inspect_database(backup / 'database.sqlite')
        with (backup / 'database.sqlite').open('rb') as stream:
            receipt['backup_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        state = directory / '.n8n'
        state.mkdir(mode=0o700)
        for name in ['database.sqlite', 'config']:
            shutil.copy2(backup / name, state / name)
        account = create_rehearsal_account()
        for path in [directory, state, *state.iterdir()]:
            os.chown(path, account.pw_uid, account.pw_gid)
        receipt['isolation_checks'] = verify_isolation(directory, account, original['MainPID'], backup)
        receipt['rehearsal_uid'] = account.pw_uid
        bounded_candidate(release, directory, ['unpublish:workflow', '--all'], backup / 'unpublish.log', account)
        unpublished = inspect_database(state / 'database.sqlite')
        if unpublished['counts']['active_workflows']:
            raise RuntimeError('disposable workflows were not fully unpublished')
        receipt['disposable_workflows_unpublished'] = True
        export = directory / 'credentials.json'
        try:
            bounded_candidate(release, directory,
                              ['export:credentials', '--all', '--decrypted', '--output=' + str(export)],
                              backup / 'credential-export.log', account)
            if export.stat().st_size > 16 * 1024**2:
                raise RuntimeError('credential export exceeds the rehearsal limit')
            credentials = json.loads(export.read_text())
            if (len(credentials) != receipt['before']['counts']['credentials']
                    or any(not isinstance(item.get('data'), dict) for item in credentials)):
                raise RuntimeError('restored credentials could not all be decrypted')
            receipt['decrypted_credentials'] = len(credentials)
            del credentials
        finally:
            export.unlink(missing_ok=True)
        log_stream = (backup / 'startup.log').open('wb')
        process = subprocess.Popen(candidate_command(release, directory, ['start'], account),
                                   stdout=log_stream, stderr=subprocess.STDOUT, start_new_session=True,
                                   cwd=directory)
        for _attempt in range(45):
            if process.poll() is not None:
                raise RuntimeError('candidate exited before HTTP readiness')
            if os.readlink(f'/proc/{process.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
                time.sleep(0.1)
                continue
            interfaces = json.loads(command(['nsenter', '-t', str(process.pid), '-n', '--', 'ip', '-j', 'link']))
            if [item['ifname'] for item in interfaces] != ['lo']:
                raise RuntimeError('candidate has an external network interface')
            try:
                code = command(['nsenter', '-t', str(process.pid), '-n', '--', 'curl',
                                '--silent', '--show-error', '--max-time', '2', '--output', '/dev/null',
                                '--write-out', '%{http_code}', 'http://127.0.0.1:15678/healthz/readiness'])
                if code == '200':
                    receipt['http_readiness'] = 200
                    receipt['network_interfaces'] = ['lo']
                    break
            except RuntimeError:
                pass
            time.sleep(2)
        else:
            raise RuntimeError('candidate readiness deadline exceeded')
        stop(process)
        receipt['after'] = inspect_database(state / 'database.sqlite')
        for name in ['users', 'owners', 'workflows', 'credentials']:
            if receipt['before']['counts'][name] != receipt['after']['counts'][name]:
                raise RuntimeError(f'restored {name} count changed')
        if receipt['before']['content_sha256'] != receipt['after']['content_sha256']:
            raise RuntimeError('restored account, workflow, or credential content changed')
        if receipt['after']['counts']['active_workflows']:
            raise RuntimeError('a disposable workflow became active')
        if receipt['candidate_lock_sha256'] != hashlib.sha256((release / 'package-lock.json').read_bytes()).hexdigest():
            raise RuntimeError('candidate dependency lock changed during rehearsal')
        receipt['production_after'] = service_identity()
        if original != receipt['production_after']:
            raise RuntimeError('production service identity changed during rehearsal')
        receipt['production_database_after'] = inspect_database(SOURCE / 'database.sqlite')
        if receipt['production_database_after'] != receipt['before']:
            raise RuntimeError('production account, workflow, credential, or migration state changed during rehearsal')
        receipt['status'] = 'passed'
    finally:
        finalize_rehearsal(process, log_stream, account, directory, receipt, args.output)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
