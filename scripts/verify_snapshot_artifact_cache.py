"""Target-side acceptance: real analyzer, retained snapshot, independent cache reads.

Run as root with a known running container and its exact executable path.
No model is invoked, no image is pulled, and no application is restarted.
"""
import argparse
import importlib.machinery
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('container')
    parser.add_argument('path')
    args = parser.parse_args()
    gateway = importlib.machinery.SourceFileLoader('gateway', '/usr/local/libexec/homelab-evidence-gateway').load_module()
    envelope = json.loads((gateway.SCAN_STATE_DIR/'cve-state.incident-snapshot.json').read_text())
    finding = next(f for f in envelope['snapshot']['findings']
                   if '/'+f['target'].lstrip('/') == args.path
                   and any(c.get('name') == args.container for c in f.get('containers', [])))
    bound = {'snapshot_sha256': envelope['sha256'], 'finding_sha256': gateway.object_sha256(finding),
             'path': args.path, 'container': args.container, 'advisory': finding['id'], 'analyzer': 'govulncheck'}
    inspected = gateway.snapshot_artifact('inspect_executable', bound)['result']
    assert inspected['status'] == 'success', inspected
    first = gateway.snapshot_artifact('run_analyzer', bound)['result']
    assert first['status'] == 'success', first
    report = first['result']
    assert report.get('cache', {}).get('eligible'), report
    assert report['sha256'] == inspected['result']['sha256']
    second = gateway.snapshot_artifact('run_analyzer', bound)['result']
    assert second['status'] == 'success', second
    reused = second['result']
    assert reused['reused_analysis'] and reused.get('shared_provenance'), reused
    assert reused['sha256'] == report['sha256']
    assert reused['deployment_exposure'] == 'not_assessed'
    print(json.dumps({'status': 'passed', 'advisory': finding['id'], 'identity': reused['cache']['identity'],
                      'evidence_level': reused['evidence_level'], 'shared_provenance': reused['shared_provenance'],
                      'observations': [inspected['observation_id'], first['observation_id'], second['observation_id']]}))


if __name__ == '__main__':
    main()
