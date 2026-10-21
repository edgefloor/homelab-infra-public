"""Read-only target-side regression using a running container and retained scan evidence.

Run as root on the evidence target with CONTAINER and ABSOLUTE_EXECUTABLE arguments.
This performs no model request, vulnerability scan, image pull, or configuration change.
"""
import argparse
import importlib.machinery
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('container')
    parser.add_argument('executable')
    args = parser.parse_args()
    assert args.executable.startswith('/') and '..' not in Path(args.executable).parts
    gateway = importlib.machinery.SourceFileLoader('gateway', '/usr/local/libexec/homelab-evidence-gateway').load_module()
    live = json.loads(subprocess.check_output(['/usr/bin/docker', 'inspect', '--type=container', '--format',
                      '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}}}', args.container], text=True))
    assert live['running'] is True, 'Select a known running container'
    envelope = json.loads(Path('/var/lib/homelab-update-monitor/cve-state.incident-snapshot.json').read_text())
    snapshot = envelope['snapshot']
    finding = next(f for f in snapshot['findings'] if f['target'].lstrip('/') == args.executable.lstrip('/')
                   and f['artifact_id'] == live['image'] and any(c['id'] == live['id'] for c in f.get('containers', [])))
    result = gateway.snapshot_artifact('inspect_executable', {
        'snapshot_sha256': envelope['sha256'],
        'finding_sha256': gateway.object_sha256(finding),
        'container': args.container,
        'path': args.executable,
    })['result']
    assert result['status'] == 'success', result
    resolved = result['container_lookup']['resolved']
    assert resolved['id'] == live['id'] and resolved['image_id'] == live['image'] and resolved['running'] is True
    independent = subprocess.check_output(['/usr/bin/docker','exec',live['id'],'sha256sum',args.executable],text=True).split()[0]
    assert result['result']['sha256'] == independent, 'Extracted bytes differ from the running container file'
    assert gateway.docker_inventory()[live['id']]['running'] is True
    print(json.dumps({'status': 'passed', 'container': args.container, 'container_id': live['id'],
                      'image_id': live['image'], 'executable': args.executable, 'sha256': independent,
                      'observation_id': result['observation_id']}))


if __name__ == '__main__':
    main()
