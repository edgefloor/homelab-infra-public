"""Target-side acceptance of independent symbol proof and immutable image reads.

Runs no model and never imports or executes a candidate image. Downloads a bounded
copy of the already deployed image to temporary storage, then checks its identity.
"""
import importlib.machinery
import json
from pathlib import Path
import sys

sys.path.insert(0, '/usr/local/libexec')
gateway = importlib.machinery.SourceFileLoader('gateway', '/usr/local/libexec/homelab-evidence-gateway').load_module()
envelope = json.loads((gateway.SCAN_STATE_DIR/'cve-state.incident-snapshot.json').read_text())
finding = next(f for f in envelope['snapshot']['findings']
               if f['id'] == 'GHSA-gcjh-h69q-9w9g' and f['target'].lstrip('/') == 'usr/bin/caddy'
               and any(c.get('name') == 'nerocd-edge-1' for c in f.get('containers', [])))
bound = {'snapshot_sha256': envelope['sha256'], 'finding_sha256': gateway.object_sha256(finding),
         'path': '/usr/bin/caddy', 'container': 'nerocd-edge-1', 'advisory': finding['id'], 'analyzer': 'govulncheck'}
before = gateway.docker_inventory()
temporary_before = set(Path('/tmp').glob('homelab-replacement-*'))
proof = gateway.snapshot_artifact('prove_symbols', {**bound, 'symbols': ['main.main', 'homelab.nonexistent']})['result']
assert proof['status'] == 'success', proof
symbols = proof['result']['symbols']
assert symbols[0]['status'] == 'present_in_function_table', proof
assert symbols[1]['status'] == 'not_observed', proof
candidate = sys.argv[1] if len(sys.argv) > 1 else 'sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
verified = gateway.snapshot_artifact('verify_replacement', {**bound, 'candidate': candidate})['result']
assert verified['status'] == 'success', verified
report = verified['result']
assert report['status'] == 'observed', report
assert report['baseline']['sha256'] == proof['result']['sha256'], report
assert report['comparison']['verified_fix'] is False, report
if candidate.startswith('sha256:'):
    assert report['comparison']['status'] == 'same_executable', report
assert set(Path('/tmp').glob('homelab-replacement-*')) == temporary_before
after = gateway.docker_inventory()
assert before == after, 'Container identity, process, or runtime state changed during acceptance'
print(json.dumps({'status': 'passed', 'symbol_proof': proof['result'],
                  'replacement': {k: report[k] for k in ('comparison', 'candidate_identity')},
                  'executable_sha256': {k: report[k]['sha256'] for k in ('baseline', 'candidate')},
                  'temporary_storage_clean': True, 'containers_unchanged': True, 'model_calls': 0}))
