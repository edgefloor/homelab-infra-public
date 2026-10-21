#!/usr/bin/env python3
"""Bootstrap Dependency-Track using its standard v1/v2 APIs on loopback only."""

import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


def save_private(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    if urlsplit(config['api_url']).hostname != '127.0.0.1':
        raise RuntimeError('Bootstrap requires the loopback API')
    credentials = Path(config['credentials_dir'])
    credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(credentials, 0o700)
    admin_path = credentials / 'admin.json'
    key_path = credentials / 'upload-key.json'
    changed = False
    if not admin_path.exists():
        save_private(admin_path, {
            'url': config['public_url'], 'username': 'admin',
            'password': secrets.token_urlsafe(36), 'initialized': False,
        })
        changed = True
    admin = json.loads(admin_path.read_text())
    opener = build_opener(ProxyHandler({}))

    def request(method, path, payload=None, form=False, token=None, key=None, allowed=(200,)):
        headers = {}
        data = None
        if payload is not None:
            data = (urlencode(payload) if form else json.dumps(payload)).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if key:
            headers['X-Api-Key'] = key
        req = Request(config['api_url'] + path, data=data, headers=headers, method=method)
        try:
            with opener.open(req, timeout=60) as response:
                status, body = response.status, response.read().decode()
        except HTTPError as error:
            status, body = error.code, error.read().decode()
        if status not in allowed:
            # API response bodies may contain credentials. Never include them in logs.
            raise RuntimeError(f'{method} {path} returned HTTP {status}')
        return status, body

    login = {'username': admin['username'], 'password': admin['password']}
    status, token = request('POST', '/v1/user/login', login, form=True, allowed=(200, 401))
    if status != 200:
        if admin.get('initialized'):
            raise RuntimeError('Saved administrator credentials no longer authenticate; refusing default-password fallback')
        request('POST', '/v1/user/forceChangePassword', {
            'username': 'admin', 'password': 'admin',
            'newPassword': admin['password'], 'confirmPassword': admin['password'],
        }, form=True)
        _, token = request('POST', '/v1/user/login', login, form=True)
        changed = True
    token = token.strip()
    # Verify the rotated credentials before recording success or exposing the frontend.
    request('GET', '/v1/user/self', token=token)
    if not admin.get('initialized'):
        admin['initialized'] = True
        save_private(admin_path, admin)
        changed = True

    # Central Trivy owns vulnerability feeds. Configure these before enabling
    # the task scheduler on first boot, since NVD otherwise mirrors immediately.
    disabled_extensions = [('vuln-data-source', name) for name in ('nvd', 'osv', 'github', 'jvn')]
    disabled_extensions.append(('vuln-analyzer', 'internal'))
    for point, name in disabled_extensions:
        path = f'/v2/extension-points/{point}/extensions/{name}/config'
        status, _ = request('PUT', path, {'config': {'enabled': False}},
                            token=token, allowed=(204, 304))
        changed = changed or status == 204

    trivy_secret = 'homelab-trivy'
    trivy_value = Path(config['trivy_token_path']).read_text().strip()
    if not trivy_value:
        raise RuntimeError('Central Trivy credential is empty')
    status, _ = request('GET', '/v2/secrets/' + trivy_secret, token=token, allowed=(200, 404))
    if status == 404:
        request('POST', '/v2/secrets', {
            'name': trivy_secret, 'value': trivy_value,
            'description': 'Existing central Trivy server',
        }, token=token, allowed=(201,))
        changed = True
    else:
        status, _ = request('PATCH', '/v2/secrets/' + trivy_secret,
                            {'value': trivy_value}, token=token, allowed=(204, 304))
        changed = changed or status == 204
    analyzer_path = '/v2/extension-points/vuln-analyzer/extensions/trivy/config'
    analyzer = {
        'enabled': True, 'apiUrl': config['trivy_url'], 'apiToken': trivy_secret,
        'ignoreUnfixed': False, 'scanLibrary': True, 'scanOs': True,
    }
    status, _ = request('PUT', analyzer_path, {'config': analyzer}, token=token, allowed=(204, 304))
    changed = changed or status == 204
    _, body = request('GET', analyzer_path, token=token)
    configured = json.loads(body)['config']
    if any(configured.get(field) != value for field, value in analyzer.items()):
        raise RuntimeError('Trivy analyzer configuration did not persist')

    account_path = '/v2/service-accounts/homelab-sbom'
    status, _ = request('GET', account_path, token=token, allowed=(200, 404))
    if status == 404:
        request('POST', '/v2/service-accounts', {'name': 'homelab-sbom'}, token=token, allowed=(201,))
        changed = True
    status, _ = request('PUT', '/v1/permission/user', {
        'username': 'svc:homelab-sbom', 'permissions': config['upload_permissions'],
    }, token=token, allowed=(200, 304))
    changed = changed or status == 200
    existing = json.loads(key_path.read_text()) if key_path.exists() else None
    renew = existing is None or existing['expires_at'] < (time.time() + 7 * 86400) * 1000
    if existing and not renew:
        status, _ = request('GET', '/v1/project?pageSize=1', key=existing['key'], allowed=(200, 401))
        renew = status == 401
    if renew:
        _, body = request('POST', account_path + '/api-keys', {
            'comment': 'Homelab SBOM uploads; managed by Ansible',
            'expires_in_days': config['api_key_days'],
        }, token=token, allowed=(201,))
        current = json.loads(body)
        current.update({'url': config['public_url'], 'service_account': 'homelab-sbom'})
        # Save before any later call: the plaintext key is returned only once.
        save_private(key_path, current)
        changed = True
    else:
        current = existing
    request('GET', '/v1/project?pageSize=1', key=current['key'])
    # No credentials or response bodies are printed, including on errors.
    print('changed' if changed else 'unchanged')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        # Deliberate RuntimeErrors contain only operation names/status or fixed text.
        print(f'Dependency-Track bootstrap failed: {error}; frontend must remain stopped', file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f'Dependency-Track bootstrap failed ({type(error).__name__}); frontend must remain stopped', file=sys.stderr)
        sys.exit(1)
