"""Run as zag-ops with its evidence environment. Real reads, no model or job."""
import json
import sys

sys.path.insert(0, '/usr/local/lib/zag-ops')
from investigation_evidence import EvidenceBudget, assessment
from zag_ops_worker import evidence_tool


def find(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for field, child in value.items():
            if field == 'arguments':
                continue  # Requested symbols are not observed symbol records.
            found = find(child, key)
            if found is not None:
                return found
    return None


charges = []
budget = EvidenceBudget(lambda kind, amount: charges.append((kind, amount)))
coverage = json.loads(evidence_tool({'target': 'nerocd', 'operation': 'deployment_coverage',
                                   'arguments': {'advisory': 'GHSA-gcjh-h69q-9w9g'}}, budget))
findings = find(coverage, 'matching_findings')
assert findings, coverage
finding = next(f for f in findings if f['target'].lstrip('/') == 'usr/bin/caddy')
bound = {**finding['binding'], 'path': '/usr/bin/caddy', 'container': 'nerocd-edge-1',
         'advisory': finding['id'], 'analyzer': 'govulncheck'}
analyzed = json.loads(evidence_tool({'target': 'nerocd', 'operation': 'run_analyzer', 'arguments': bound}, budget))
assert find(analyzed, 'reused_analysis') is True, analyzed
assert find(analyzed, 'evidence_level') == 'symbol', analyzed
official = json.loads(evidence_tool({'target': 'nerocd', 'operation': 'advisory_record',
                                   'arguments': {'advisory': finding['id']}}, budget))
assert find(official, 'source') == 'https://api.osv.dev/v1/vulns/'+finding['id'], official
proof = json.loads(evidence_tool({'target': 'nerocd', 'operation': 'prove_symbols',
                                 'arguments': {**bound, 'symbols': ['main.main', 'homelab.nonexistent']}}, budget))
assert find(proof, 'method') == 'elf_go_pclntab_v1', proof
assert find(proof, 'symbols')[0]['status'] == 'present_in_function_table', proof
assert find(proof, 'symbols')[1]['status'] == 'not_observed', proof
replacement = json.loads(evidence_tool({'target': 'nerocd', 'operation': 'verify_replacement',
                                       'arguments': {**bound, 'candidate': 'latest'}}, budget))
comparison = find(replacement, 'comparison')
assert comparison['status'] in {'same_executable', 'match_retained', 'match_removed', 'no_demonstrated_improvement'}, replacement
assert comparison['verified_fix'] is False, replacement
hashes = find(replacement, 'artifact_sha256')
assert all(len(hashes[k]) == 64 for k in ('baseline', 'candidate')), replacement
if hashes['baseline'] == hashes['candidate']:
    assert comparison['status'] == 'same_executable', replacement
claim = {'claim': 'The exact artifact has a symbol-level analyzer report. Runtime exposure was not assessed by this check.',
         'source': 'nerocd', 'scope': finding['scope'], 'classification': 'visibility_gap',
         'confidence': 'high', 'visibility_gap': 'Process residency, feature configuration and attacker reachability not checked.',
         'references': [analyzed['sha256'], official['sha256']]}
report = assessment(json.dumps({'summary': 'Read-only tool acceptance, not an incident verdict.', 'claims': [claim]}),
                    budget, {'nerocd': {finding['scope']}})
assert report['complete'] and len(report['evidence']) == 5
assert sum(n for kind,n in charges if kind == 'evidence') == 20000
print(json.dumps({'status': 'passed', 'tool_reads': 5, 'evidence_reserved': 20000,
                  'shared_reuse': True, 'symbol_proof': True, 'replacement_comparison': comparison,
                  'journal_valid': report['complete'], 'model_calls': 0}))
