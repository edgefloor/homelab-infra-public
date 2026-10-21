"""Test real source upload against the authenticated API without network or agents."""
import importlib.util
import copy
import hashlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'ansible/roles/vulnerability_incidents/files'))
from incident_store import IncidentStore
from cve_lifecycle import installation_resource_key
from incident_service import IncidentAPI

spec = importlib.util.spec_from_file_location('snapshot', ROOT/'ansible/roles/update_monitor/files/homelab_incident_snapshot.py')
SNAP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SNAP)


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = IncidentStore(self.root/'db')
        self.settings = {'source': 'caddy', 'generation': 'one', 'token': 'source-key'}
        self.api = IncidentAPI(self.store, {'caddy': {**self.settings, 'role': 'source'},
                                          'reader': {'role': 'reader', 'token': 'read-key'}})
        self.reports = [{'Results': [{'Type': 'debian', 'Target': '/', 'Vulnerabilities': [
            {'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libssl', 'Severity': 'MEDIUM', 'InstalledVersion': '1'}]}]}]

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def send(self, settings, payload):
        return self.api.call('Bearer ' + settings['token'], payload)

    def test_source_snapshot_includes_medium_and_retries_lost_ack_once(self):
        delivered = False
        def send(settings, payload):
            nonlocal delivered
            value = self.send(settings, payload)
            if payload['action'] == 'commit' and not delivered:
                delivered = True
                raise RuntimeError('lost acknowledgement')
            return value
        path = self.root/'outbox.json'
        with self.assertRaises(RuntimeError):
            SNAP.publish(self.reports, {}, {}, path, self.settings, send)
        self.assertIsNotNone(json.loads(path.read_text())['pending'])
        self.assertFalse((self.root/'outbox.incident-snapshot.json').exists())
        SNAP.deliver_pending(path, self.settings, send)
        self.assertIsNone(json.loads(path.read_text())['pending'])
        self.assertEqual(self.store.stats()['scans'], 1)
        incident = self.store.get_incident(self.store.list_incidents()[0]['id'])
        self.assertEqual(incident['occurrences'][0]['finding']['severity'], 'MEDIUM')
        accepted = json.loads((self.root/'outbox.incident-snapshot.json').read_text())
        self.assertEqual(accepted['snapshot']['findings'][0]['severity'], 'MEDIUM')
        self.assertEqual(accepted['sha256'], self.store.db.execute('SELECT hash FROM scans').fetchone()[0])

    def test_shared_image_findings_keep_only_their_own_container_binding(self):
        report = {'_homelab_runtime': {'image_id': 'sha256:'+'a'*64,
                  'containers': [{'id': '1'*64, 'name': 'first'}, {'id': '2'*64, 'name': 'second'}]},
                  'Results': [{'Type': 'gobinary', 'Class': 'lang-pkgs', 'Target': 'usr/bin/app', 'Packages': [],
                               'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'stdlib'}]}]}
        findings, _, _ = SNAP.snapshot_findings([report])
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertEqual(len(finding['containers']), 1)
            self.assertTrue(finding['location'].startswith(finding['containers'][0]['name']+':'))

    def test_runtime_slot_identity_does_not_change_with_owner_classification(self):
        report = {'_homelab_runtime': {
            'image_id': 'sha256:' + 'a' * 64,
            'containers': [{'id': '1' * 64, 'name': 'web', 'running': True,
                            'compose_service': 'web'}]},
            'Results': [{'Type': 'gobinary', 'Class': 'lang-pkgs',
                         'Target': '/usr/bin/web', 'Packages': [],
                         'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1200',
                             'PkgName': 'stdlib', 'InstalledVersion': 'v1.2.3'}]}]}
        unclassified, _, _ = SNAP.snapshot_findings([report], {'deployments': []})
        classified, _, _ = SNAP.snapshot_findings([report], {'deployments': [{
            'id': 'web', 'compose_services': ['web']}]})

        self.assertEqual('container:web', unclassified[0]['installation'])
        self.assertEqual(unclassified[0]['installation'], classified[0]['installation'])
        self.assertEqual([], unclassified[0]['consumer_deployments'])
        self.assertEqual(['web'], classified[0]['consumer_deployments'])

    def test_runtime_os_package_records_exact_owner_without_claiming_consumption(self):
        report = {'_homelab_runtime': {
            'image_id': 'sha256:' + 'a' * 64,
            'containers': [{'id': '1' * 64, 'name': 'nerocd-server-1',
                            'running': True, 'compose_service': 'server'}]},
            'Results': [{'Type': 'alpine', 'Class': 'os-pkgs', 'Target': '/',
                         'Packages': [{'Name': 'zlib', 'Version': '1.3.1-r2'}],
                         'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1202',
                             'PkgName': 'zlib', 'InstalledVersion': '1.3.1-r2',
                             'FixedVersion': '1.3.1-r3'}]}]}
        findings, _, packages = SNAP.snapshot_findings([report], {
            'deployments': [{'id': 'nerocd', 'compose_services': ['server']}]})

        self.assertEqual('container:nerocd-server-1', findings[0]['installation'])
        self.assertEqual(['nerocd'], findings[0]['owner_deployments'])
        self.assertEqual([], findings[0].get('consumer_deployments', []))
        self.assertEqual(['nerocd'], packages[0]['owner_deployments'])

    def test_ambiguous_container_owner_does_not_create_consumer_paths(self):
        report = {'_homelab_runtime': {
            'image_id': 'sha256:' + 'a' * 64,
            'containers': [{'id': '1' * 64, 'name': 'shared', 'running': False,
                            'compose_service': 'shared'}]},
            'Results': [{'Type': 'gobinary', 'Class': 'lang-pkgs',
                         'Target': '/usr/bin/shared', 'Packages': [],
                         'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1200',
                             'PkgName': 'stdlib', 'InstalledVersion': 'v1.2.3'}]}]}
        inventory = {'deployments': [
            {'id': 'edge', 'compose_services': ['shared']},
            {'id': 'db', 'compose_services': ['shared']}]
        }
        findings, _, _ = SNAP.snapshot_findings([report], inventory)
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'a' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': []}}, inventory, findings)

        self.assertEqual([], findings[0]['consumer_deployments'])
        self.assertEqual(['db', 'edge'], findings[0]['ambiguous_deployments'])
        self.assertEqual([], findings[0]['owner_deployments'])
        self.assertFalse(any(item['relation'] in {'CONSUMED_BY', 'OWNED_BY'}
                             for item in graph['assertions']))
        package_coverage = next(item for item in graph['coverage']
                                if item['relationship'] == 'package_consumer')
        self.assertFalse(package_coverage['complete'])

    def test_removed_consumer_path_is_explicitly_withdrawn(self):
        finding = {
            'installation': 'container:web', 'ecosystem': 'gobinary',
            'package': 'stdlib', 'binary_package': 'stdlib',
            'installed': 'v1.2.3', 'architecture': 'amd64',
            'source_package': 'go', 'source_version': 'v1.2.3',
            'artifact_id': 'sha256:' + 'a' * 64,
            'location': 'web:/usr/bin/web', 'scope': 'container:web:web',
            'consumer_class': 'runtime-language',
            'consumer_deployments': ['web']}
        discovery = {'discovery': {'runtime_sha256': 'a' * 64, 'gaps': [],
            'relationships': [], 'relationship_coverage': [],
            'package_evidence': []}}
        previous = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), discovery,
            {'deployments': [{'id': 'web'}]}, [finding])
        ambiguous = {**finding, 'consumer_deployments': [],
                     'ambiguous_deployments': ['web', 'edge']}

        current = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time(), discovery,
            {'deployments': [{'id': 'web'}, {'id': 'edge'}]}, [ambiguous],
            previous_graph=previous)

        withdrawn = [item for item in current['assertions']
                     if item['relation'] == 'CONSUMED_BY']
        self.assertEqual(1, len(withdrawn))
        self.assertEqual('withdrawn', withdrawn[0]['status'])

    def test_only_running_language_package_slots_bind_to_their_deployment(self):
        report = {'_homelab_runtime': {
            'image_id': 'sha256:' + 'a' * 64,
            'containers': [
                {'id': '1' * 64, 'name': 'web-running', 'running': True},
                {'id': '2' * 64, 'name': 'web-stopped', 'running': False},
            ]}, 'Results': [{
                'Type': 'node-pkg', 'Class': 'lang-pkgs', 'Target': '/app',
                'Packages': [], 'Vulnerabilities': [{
                    'VulnerabilityID': 'CVE-2026-1200',
                    'PkgName': 'decoder', 'InstalledVersion': '1'}]}, {
                'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
                'Packages': [], 'Vulnerabilities': [{
                    'VulnerabilityID': 'CVE-2026-1201',
                    'PkgName': 'libc6', 'InstalledVersion': '1'}]}]}
        inventory = {'deployments': [{
            'id': 'web', 'containers': ['web-*']}]}
        findings, _, _ = SNAP.snapshot_findings([report], inventory)
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(),
            {'discovery': {'runtime_sha256': 'a' * 64, 'gaps': [],
                           'relationships': [], 'relationship_coverage': []}},
            inventory, findings)
        edges = {(item['subject'], item.get('object_key'))
                 for item in graph['assertions']
                 if item['relation'] == 'CONSUMED_BY'}
        scopes = {item['scope']: item for item in graph['coverage']
                  if item['relationship'] == 'package_consumer'}
        by_key = {SNAP.installation_resource_key(
            'host', *(finding[field] for field in
                      ('installation', 'ecosystem', 'package', 'location'))): finding
                  for finding in findings}
        running = next(key for key, finding in by_key.items()
                       if finding['package'] == 'decoder' and
                       finding['location'].startswith('web-running:'))
        stopped = next(key for key, finding in by_key.items()
                       if finding['package'] == 'decoder' and
                       finding['location'].startswith('web-stopped:'))
        os_package = next(key for key, finding in by_key.items()
                          if finding['package'] == 'libc6' and
                          finding['location'].startswith('web-running:'))
        self.assertIn((running, 'deployment:host:web'), edges)
        self.assertNotIn((stopped, 'deployment:host:web'), edges)
        self.assertNotIn((os_package, 'deployment:host:web'), edges)
        self.assertEqual(['web'], by_key[running]['owner_deployments'])
        self.assertEqual(['web'], by_key[stopped]['owner_deployments'])
        self.assertEqual(['web'], by_key[running]['consumer_deployments'])
        self.assertEqual([], by_key[stopped]['consumer_deployments'])
        self.assertTrue(scopes[SNAP.consumer_scope(
            'host', by_key[running])]['complete'])
        self.assertFalse(scopes[SNAP.consumer_scope(
            'host', by_key[stopped])]['complete'])
        self.assertFalse(scopes[SNAP.consumer_scope(
            'host', by_key[os_package])]['complete'])

    def test_consumer_coverage_is_package_scoped_and_version_stable(self):
        findings = [{
            'installation': 'host-os', 'ecosystem': 'debian',
            'package': package, 'binary_package': package,
            'installed': '1', 'location': '/', 'scope': 'host',
            'architecture': 'amd64', 'source_package': package,
            'source_version': '1',
            'consumer_class': 'host-os', 'consumer_deployments': [],
        } for package in ('libc6', 'openssl')]
        evidence = [{
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{
                'installation': finding['installation'],
                'consumer_class': finding['consumer_class'],
                'ecosystem': finding['ecosystem'], 'artifact_id': '',
                'binary_package': finding['package'], 'version': '1',
                'architecture': 'amd64', 'source_package': finding['package'],
                'source_version': '1',
                'location': finding['location']}],
            'installed': {'binary_package': finding['package'], 'version': '1'},
            'files': [], 'file_inventory_sha256': finding['package'],
            'consumer_coverage_complete': finding['package'] == 'libc6',
            'execution_domains': [], 'observations': []}
            for finding in findings]
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(),
            {'discovery': {'runtime_sha256': 'a' * 64, 'gaps': [],
                           'relationships': [], 'relationship_coverage': [],
                           'package_evidence': evidence}},
            {'deployments': []}, findings)
        package_coverage = [item for item in graph['coverage']
                            if item['relationship'] == 'package_consumer']

        current = [item for item in package_coverage
                   if item['status'] != 'withdrawn']
        self.assertEqual(2, len(current))
        self.assertEqual(2, len({item['scope'] for item in current}))
        by_scope = {item['scope']: item for item in current}
        libc_scope = SNAP.consumer_scope('host', findings[0])
        openssl_scope = SNAP.consumer_scope('host', findings[1])
        self.assertTrue(by_scope[libc_scope]['complete'])
        self.assertFalse(by_scope[openssl_scope]['complete'])
        legacy = next(item for item in package_coverage
                      if item['scope'] == 'consumer:host:host:host-os')
        self.assertEqual('withdrawn', legacy['status'])

        upgraded = copy.deepcopy(findings)
        upgraded[0]['installed'] = '2'
        self.assertEqual(libc_scope, SNAP.consumer_scope('host', upgraded[0]))
        upgraded_evidence = copy.deepcopy(evidence)
        upgraded_evidence[0]['slots'][0]['version'] = '2'
        upgraded_evidence[0]['installed']['version'] = '2'
        upgraded_graph = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time() + 1,
            {'discovery': {'runtime_sha256': 'b' * 64, 'gaps': [],
                           'relationships': [], 'relationship_coverage': [],
                           'package_evidence': upgraded_evidence}},
            {'deployments': []}, upgraded)
        upgraded_scopes = {item['scope'] for item in upgraded_graph['coverage']
                           if item['relationship'] == 'package_consumer' and
                           item['status'] != 'withdrawn'}
        self.assertIn(libc_scope, upgraded_scopes)

    def test_shared_consumer_discovery_failure_is_a_separate_dependency(self):
        finding = {
            'installation': 'host-os', 'ecosystem': 'debian',
            'package': 'binutils', 'binary_package': 'binutils',
            'installed': '1', 'location': '/', 'scope': 'host',
            'architecture': 'amd64', 'source_package': 'binutils',
            'source_version': '1',
            'consumer_class': 'host-os', 'consumer_deployments': []}
        domain = {
            'id': 'administrative-binutils', 'packages': ['binutils'],
            'files': [], 'entries': [], 'inputs': [], 'authority_paths': [],
            'operation_files': [],
            'disposition': 'administrative_input_boundary',
            'complete': True, 'work_evidence_complete': False,
            'evidence_refs': ['receipt:administrative'],
            'observation': {'files': [], 'entries': [], 'inputs': [],
                'operation_files': [], 'authority_paths': [],
                'evidence_refs': ['receipt:administrative']},
            'coverage': {name: {'complete': True, 'missing': [],
                                'unassigned': []} for name in
                ('entry', 'input', 'file', 'operation_file',
                 'file_authority')}}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'host-os', 'consumer_class': 'host-os',
                'ecosystem': 'debian', 'artifact_id': '',
                'binary_package': 'binutils', 'version': '1',
                'architecture': 'amd64', 'source_package': 'binutils',
                'source_version': '1',
                'location': '/'}],
            'installed': {'binary_package': 'binutils', 'version': '1'},
            'files': [], 'file_inventory_sha256': 'a' * 64,
            'consumer_coverage_complete': True,
            'execution_domains': [domain], 'observations': []}]
        scheduler_gap = (
            'scheduled-command-unsupported:/var/spool/cron/crontabs/'
            'operator:1:unsupported-command')
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'a' * 64,
                'gaps': [scheduler_gap],
                'relationships': [], 'relationship_coverage': [],
                'scheduled_files': [{
                    'path': '/var/spool/cron/crontabs/operator',
                    'sha256': '9' * 64, 'executables': [],
                    'unresolved_executables': ['/bin/true'],
                    'unsupported': ['1:unsupported-command']}],
                'package_evidence': package_evidence,
                'execution_domains': [domain]}},
            {'deployments': []}, [finding])

        package_scope = SNAP.consumer_scope('host', finding)
        package_coverage = next(item for item in graph['coverage']
            if item['scope'] == package_scope and
            item['relationship'] == 'package_consumer')
        discovery_coverage = next(item for item in graph['coverage']
            if item['relationship'] == 'consumer_discovery')
        resource = next(item for item in graph['resources']
                        if item['resource_key'].startswith('installation:'))
        self.assertTrue(package_coverage['complete'])
        self.assertFalse(discovery_coverage['complete'])
        self.assertIn(discovery_coverage['scope'],
                      resource['properties']['consumer_dependency_scopes'])
        self.store.lifecycle.stage_graph_change(
            graph['change_id'], resources=graph['resources'],
            evidence=graph['evidence'], assertions=graph['assertions'],
            coverage=graph['coverage'])
        self.store.lifecycle.acknowledge_graph_change(graph['change_id'])
        incident = self.store._incident('CVE-2026-8250')
        occurrence = 'occ-unresolved-second-pipeline-command'
        self.store.lifecycle.add_occurrence(
            incident, occurrence, resource['resource_key'], service='host-os',
            host='host', deployment='/')
        decision = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('gap', decision['result'])
        self.assertEqual('missing_relationship_coverage', decision['reason'])
        self.assertIn(discovery_coverage['scope'], decision['missing_scopes'])

    def test_legacy_host_consumer_coverage_cannot_mask_package_scope(self):
        finding = {
            'installation': 'host-os', 'ecosystem': 'debian',
            'package': 'binutils', 'binary_package': 'binutils',
            'installed': '1', 'location': '/', 'scope': 'host',
            'architecture': 'amd64', 'source_package': 'binutils',
            'source_version': '1', 'consumer_class': 'host-os',
            'consumer_deployments': []}
        package = {
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'host-os', 'consumer_class': 'host-os',
                'ecosystem': 'debian', 'artifact_id': '',
                'binary_package': 'binutils', 'version': '1',
                'architecture': 'amd64', 'source_package': 'binutils',
                'source_version': '1', 'location': '/'}],
            'installed': {'binary_package': 'binutils', 'version': '1'},
            'files': [], 'file_inventory_sha256': 'a' * 64,
            'consumer_coverage_complete': True,
            'execution_domains': [], 'observations': []}
        resource = SNAP.installation_resource_key(
            'host', 'host-os', 'debian', 'binutils', '/')

        first = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'a' * 64, 'gaps': [],
                'relationships': [], 'relationship_coverage': [],
                'package_evidence': [package]}}, {'deployments': []}, [finding])
        legacy_scope = SNAP.legacy_consumer_scope('host', finding)
        package_scope = SNAP.consumer_scope('host', finding)
        legacy = copy.deepcopy(first)
        legacy['resources'][0]['properties']['consumer_scope'] = legacy_scope
        legacy['resources'].append({
            'resource_key': 'execution-domain:host:legacy',
            'kind': 'execution-domain', 'name': 'host:legacy',
            'properties': {'source': 'host'}})
        legacy['assertions'].append({
            'logical_key': 'runtime:legacy-consumer-edge',
            'version': 'legacy:1', 'subject': resource,
            'relation': 'CURRENT_DOMAIN',
            'object_key': 'execution-domain:host:legacy', 'value': True,
            'kind': 'derived', 'scope': legacy_scope, 'source': 'host',
            'provenance': 'derived:legacy:runtime:a',
            'evidence_id': legacy['evidence'][0]['id'],
            'valid_from': time.time(), 'valid_until': time.time() + 100,
            'status': 'valid', 'derivation': {
                'rule': 'legacy', 'input_refs': ['legacy'],
                'input_evidence_ids': [legacy['evidence'][0]['id']]}})
        legacy['coverage'] = [item for item in legacy['coverage']
                              if item['relationship'] != 'package_consumer']
        legacy['coverage'].append({
            'logical_key': 'runtime-coverage:' + hashlib.sha256(
                SNAP.canonical(['host', legacy_scope,
                                'package_consumer'])).hexdigest(),
            'version': 'legacy:1', 'scope': legacy_scope,
            'relationship': 'package_consumer', 'producer': 'host',
            'complete': True, 'status': 'valid',
            'valid_from': time.time(), 'valid_until': time.time() + 100,
            'evidence_id': legacy['evidence'][0]['id']})
        self.store.lifecycle.stage_graph_change(
            legacy['change_id'], resources=legacy['resources'],
            evidence=legacy['evidence'], assertions=legacy['assertions'],
            coverage=legacy['coverage'])
        self.store.lifecycle.acknowledge_graph_change(legacy['change_id'])
        incident = self.store._incident('CVE-2026-8300')
        occurrence = 'occ-legacy-consumer'
        self.store.lifecycle.add_occurrence(
            incident, occurrence, resource, service='host-os', host='host',
            deployment='/')
        initial = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertNotEqual('gap', initial['result'])

        incomplete = copy.deepcopy(package)
        incomplete['consumer_coverage_complete'] = False
        current = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time() + 1, {'discovery': {
                'runtime_sha256': 'b' * 64, 'gaps': [],
                'relationships': [], 'relationship_coverage': [],
                'package_evidence': [incomplete]}}, {'deployments': []},
            [finding], previous_graph=legacy)
        self.store.lifecycle.stage_graph_change(
            current['change_id'], resources=current['resources'],
            evidence=current['evidence'], assertions=current['assertions'],
            coverage=current['coverage'])
        self.store.lifecycle.acknowledge_graph_change(current['change_id'])

        self.assertIsNone(self.store.db.execute(
            'SELECT id FROM lifecycle_decisions WHERE occurrence=? AND current=1',
            (occurrence,)).fetchone())
        decision = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v2',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('gap', decision['result'])
        self.assertIn(package_scope, decision['missing_scopes'])
        self.assertNotIn(legacy_scope, self.store.lifecycle.decision(
            decision['id'])['dependency_scopes'])
        retired = self.store.db.execute(
            '''SELECT status,complete FROM lifecycle_coverage
               WHERE scope=? AND current=1''', (legacy_scope,)).fetchone()
        self.assertEqual(('withdrawn', 0), tuple(retired))

    def test_os_package_uses_owned_file_chain_without_claiming_complete_coverage(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian', 'package': 'libssl3t64',
            'binary_package': 'libssl3t64', 'installed': '3.5.1-1',
            'architecture': 'amd64', 'source_package': 'openssl',
            'source_version': '3.5.1-1', 'artifact_id': '',
            'location': '/:host', 'scope': 'os:/', 'consumer_class': 'host-os'}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'host'},
            'slot': {'installation': 'os', 'consumer_class': 'host-os',
                     'ecosystem': 'debian', 'artifact_id': '',
                     'binary_package': 'libssl3t64', 'version': '3.5.1-1',
                     'architecture': 'amd64', 'source_package': 'openssl',
                     'source_version': '3.5.1-1', 'location': '/:host'},
            'installed': {'manager': 'dpkg', 'binary_package': 'libssl3t64',
                          'version': '3.5.1-1', 'architecture': 'amd64',
                          'source_package': 'openssl', 'source_version': '3.5.1-1'},
            'file_inventory_sha256': 'c' * 64, 'consumer_coverage_complete': False,
            'observations': [{'file': {
                'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3',
                'sha256': 'd' * 64, 'inode': 9},
                'consumer': {'kind': 'process', 'pid': 8, 'start_ticks': '12',
                             'executable': '/usr/bin/app', 'executable_sha256': 'e' * 64,
                             'service': 'app.service', 'deployments': ['web']}}]}]
        package_evidence[0]['observations'] *= 2
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': package_evidence}},
            {'deployments': [{'id': 'web'}]}, [finding])

        relations = {item['relation'] for item in graph['assertions']}
        self.assertTrue({'OWNS_FILE', 'LOADED_BY', 'RUNS_UNDER', 'OWNED_BY'} <= relations)
        logical_keys = [item['logical_key'] for item in graph['assertions']]
        self.assertEqual(len(logical_keys), len(set(logical_keys)))
        package_coverage = next(item for item in graph['coverage']
                                if item['relationship'] == 'package_consumer')
        self.assertFalse(package_coverage['complete'])
        binding = graph['evidence'][0]['content']['installation_bindings'][0]
        self.assertEqual(['web'], binding['deployments'])
        self.assertEqual('openssl', next(item for item in graph['resources']
            if item['kind'] == 'package-file')['properties']['installed_package']['source_package'])
        owned = next(item for item in graph['assertions']
                     if item['relation'] == 'OWNS_FILE')
        self.assertEqual('derived', owned['kind'])
        self.assertEqual('package-consumer-derivation/v3',
                         owned['derivation']['rule'])
        self.assertEqual([graph['evidence'][0]['id']],
                         owned['derivation']['input_evidence_ids'])
        self.assertTrue(owned['derivation']['input_refs'])

    def test_shared_runtime_ownership_is_not_repeated_per_package_scope(self):
        def finding(package, path):
            return {
                'installation': 'os', 'ecosystem': 'debian',
                'package': package, 'binary_package': package,
                'installed': '1', 'architecture': 'amd64',
                'source_package': package, 'source_version': '1',
                'artifact_id': '', 'location': '/:' + path,
                'scope': 'os:/', 'consumer_class': 'host-os'}

        findings = [finding('libone', '/usr/lib/libone.so'),
                    finding('libtwo', '/usr/lib/libtwo.so')]
        package_evidence = []
        for index, item in enumerate(findings):
            package_evidence.append({
                'namespace': {'kind': 'host', 'host': 'host'},
                'slot': SNAP.package_slot(item),
                'installed': {'manager': 'dpkg',
                              'binary_package': item['package'],
                              'version': '1', 'architecture': 'amd64',
                              'source_package': item['package'],
                              'source_version': '1'},
                'file_inventory_sha256': str(index + 1) * 64,
                'consumer_coverage_complete': False,
                'observations': [{'file': {
                    'path': item['location'].removeprefix('/:'),
                    'sha256': str(index + 3) * 64},
                    'derivation': {'input_refs': [
                        'package-observation:' + item['package']]},
                    'consumer': {'kind': 'process', 'pid': 8,
                                 'start_ticks': '12',
                                 'executable': '/usr/bin/app',
                                 'executable_sha256': 'e' * 64,
                                 'service': 'app.service',
                                 'deployments': ['web']}}]})
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [],
                'package_evidence': package_evidence}},
            {'deployments': [{'id': 'web'}]}, findings)

        assertions = graph['assertions']
        shared_scope = 'consumer-discovery:host:host'
        self.assertEqual(2, sum(item['relation'] == 'OWNS_FILE'
                                for item in assertions))
        self.assertEqual(2, sum(item['relation'] == 'LOADED_BY'
                                for item in assertions))
        for relation in ('RUNS_UNDER', 'OWNED_BY'):
            matches = [item for item in assertions
                       if item['relation'] == relation]
            self.assertEqual(1, len(matches))
            self.assertEqual(shared_scope, matches[0]['scope'])
            self.assertEqual(
                ['package-observation:libone', 'package-observation:libtwo'],
                matches[0]['derivation']['input_refs'])
        package_scopes = {SNAP.consumer_scope('host', item)
                          for item in findings}
        self.assertEqual(package_scopes, {
            item['scope'] for item in assertions
            if item['relation'] in {'OWNS_FILE', 'LOADED_BY'}})
        for item in findings:
            resource_key = SNAP.installation_resource_key(
                'host', *(item.get(field, '') for field in
                          ('installation', 'ecosystem', 'package', 'location')))
            resource = next(value for value in graph['resources']
                            if value['resource_key'] == resource_key)
            self.assertIn(shared_scope,
                          resource['properties']['consumer_dependency_scopes'])
        evidence_relationships = graph['evidence'][0]['content']['relationships']
        self.assertEqual(len(evidence_relationships), len({
            SNAP.canonical(item) for item in evidence_relationships}))
        removed = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time() + 1, {'discovery': {
                'runtime_sha256': 'a' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': []}},
            {'deployments': [{'id': 'web'}]}, findings,
            previous_graph=graph)
        for relation in ('RUNS_UNDER', 'OWNED_BY'):
            withdrawn = [item for item in removed['assertions']
                         if item['relation'] == relation]
            self.assertEqual(1, len(withdrawn))
            self.assertEqual('withdrawn', withdrawn[0]['status'])
            self.assertEqual(shared_scope, withdrawn[0]['scope'])

    def test_complete_execution_domain_emits_separate_derived_disposition(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian', 'package': 'binutils',
            'binary_package': 'binutils', 'installed': '2.44-3',
            'architecture': 'amd64', 'source_package': 'binutils',
            'source_version': '2.44-3', 'artifact_id': '',
            'location': '/:host', 'scope': 'os:/', 'consumer_class': 'host-os'}
        domain = {
            'id': 'native-elf-inspection', 'packages': ['binutils'],
            'files': ['/usr/bin/readelf'], 'entries': ['forced-broker'],
            'inputs': ['accepted-installed-artifact'],
            'authority_paths': ['/usr/bin/readelf'],
            'operation_files': ['/usr/local/libexec/inspect'],
            'interpreter': '/usr/bin/readelf',
            'disposition': 'administrative_input_boundary',
            'evidence_refs': ['receipt:broker-v2'], 'complete': True,
            'observation': {'entries': ['forced-broker'],
                            'inputs': ['accepted-installed-artifact'],
                            'files': ['/usr/bin/readelf'],
                            'operation_files': ['/usr/local/libexec/inspect'],
                            'authority_paths': [{'path': '/usr/bin/readelf',
                                                 'status': 'complete'}],
                            'evidence_refs': ['receipt:broker-v2']},
            'coverage': {name: {'complete': True, 'missing': [], 'unassigned': []}
                         for name in ('entry', 'input', 'file', 'file_authority')}}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'os', 'consumer_class': 'host-os',
                'ecosystem': 'debian', 'artifact_id': '',
                'binary_package': 'binutils', 'version': '2.44-3',
                'architecture': 'amd64', 'source_package': 'binutils',
                'source_version': '2.44-3', 'location': '/:host'}],
            'installed': {'manager': 'dpkg', 'binary_package': 'binutils',
                'version': '2.44-3', 'architecture': 'amd64',
                'source_package': 'binutils', 'source_version': '2.44-3'},
            'files': ['/usr/bin/readelf'], 'file_inventory_sha256': 'c' * 64,
            'consumer_coverage_complete': True, 'execution_domains': [domain],
            'observations': []}]

        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': package_evidence,
                'execution_domains': [domain]}}, {'deployments': []}, [finding])

        disposition = next(item for item in graph['assertions']
                           if item['relation'] == 'WORK_DISPOSITION')
        self.assertEqual('administrative_input_boundary', disposition['value'])
        self.assertEqual('derived', disposition['kind'])
        relations = {item['relation'] for item in graph['assertions']}
        self.assertTrue({'CURRENT_DOMAIN', 'OWNS_FILE', 'PARSES_WITH',
                         'ENTERED_BY', 'ADMITS_INPUT', 'EXECUTES_FILE',
                         'INTERPRETED_BY'} <= relations)
        domain_coverage = [item for item in graph['coverage']
                           if item['scope'].startswith('current-domain:')]
        self.assertEqual(6, len(domain_coverage))
        self.assertTrue(all(item['complete'] for item in domain_coverage))
        raw = graph['evidence'][0]['content']['input_observations']
        self.assertEqual([domain], raw['execution_domains'])

        resource = SNAP.installation_resource_key(
            'host', 'os', 'debian', 'binutils', '/:host')
        occurrence = 'occ-finite-domain'
        for key in ('change_id',):
            self.assertIn(key, graph)
        self.store.lifecycle.stage_graph_change(
            graph['change_id'], resources=graph['resources'],
            evidence=graph['evidence'], assertions=graph['assertions'],
            coverage=graph['coverage'])
        self.store.lifecycle.acknowledge_graph_change(graph['change_id'])
        self.store.lifecycle.add_occurrence(
            self.incident if hasattr(self, 'incident') else
            self.store._incident('CVE-2026-8100'), occurrence, resource,
            service='os', host='host', deployment='os')
        incident = self.store.db.execute(
            'SELECT incident FROM lifecycle_occurrences WHERE id=?',
            (occurrence,)).fetchone()[0]
        first = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('quiet', first['result'])

        changed_domain = copy.deepcopy(domain)
        changed_domain['complete'] = False
        changed_domain['coverage']['input'] = {
            'complete': False, 'missing': [], 'unassigned': ['https-download']}
        changed_package = copy.deepcopy(package_evidence)
        changed_package[0]['consumer_coverage_complete'] = False
        changed_package[0]['execution_domains'] = [changed_domain]
        changed = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time() + 1, {'discovery': {
                'runtime_sha256': 'e' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': changed_package,
                'execution_domains': [changed_domain]}}, {'deployments': []},
            [finding], previous_graph=graph)
        self.store.lifecycle.stage_graph_change(
            changed['change_id'], resources=changed['resources'],
            evidence=changed['evidence'], assertions=changed['assertions'],
            coverage=changed['coverage'])
        self.store.lifecycle.acknowledge_graph_change(changed['change_id'])

        self.assertIsNone(self.store.db.execute(
            'SELECT id FROM lifecycle_decisions WHERE occurrence=? AND current=1',
            (occurrence,)).fetchone())
        second = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v2',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('gap', second['result'])
        self.assertEqual('missing_relationship_coverage', second['reason'])

        removed_without_renewal = copy.deepcopy(domain)
        removed_without_renewal['complete'] = False
        removed_without_renewal['evidence_refs'] = []
        removed_package = copy.deepcopy(package_evidence)
        removed_package[0]['consumer_coverage_complete'] = False
        removed_package[0]['execution_domains'] = [removed_without_renewal]
        removed = SNAP.lifecycle_graph(
            'host', 'one', 3, time.time() + 2, {'discovery': {
                'runtime_sha256': 'd' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': removed_package,
                'execution_domains': [removed_without_renewal]}},
            {'deployments': []}, [finding], previous_graph=changed)
        self.store.lifecycle.stage_graph_change(
            removed['change_id'], resources=removed['resources'],
            evidence=removed['evidence'], assertions=removed['assertions'],
            coverage=removed['coverage'])
        self.store.lifecycle.acknowledge_graph_change(removed['change_id'])
        third = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v3',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('gap', third['result'])

    def test_same_disposition_in_distinct_domains_has_distinct_identity(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian', 'package': 'binutils',
            'binary_package': 'binutils', 'installed': '2.44-3',
            'architecture': 'amd64', 'source_package': 'binutils',
            'source_version': '2.44-3', 'artifact_id': '',
            'location': '/:host', 'scope': 'os:/', 'consumer_class': 'host-os'}

        def domain(name):
            return {
                'id': name, 'packages': ['binutils'], 'files': [],
                'entries': [], 'inputs': [], 'authority_paths': [],
                'disposition': 'requires_work', 'evidence_refs': ['receipt:one'],
                'complete': True,
                'observation': {'entries': [], 'inputs': [], 'files': [],
                                'authority_paths': [],
                                'evidence_refs': ['receipt:one']},
                'coverage': {kind: {'complete': True, 'missing': [],
                                    'unassigned': []}
                             for kind in ('entry', 'input', 'file',
                                          'file_authority')}}

        domains = [domain('forced-broker'), domain('ssh-preauthentication')]
        package = {
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'os', 'consumer_class': 'host-os',
                       'ecosystem': 'debian', 'artifact_id': '',
                       'binary_package': 'binutils', 'version': '2.44-3',
                       'architecture': 'amd64', 'source_package': 'binutils',
                       'source_version': '2.44-3', 'location': '/:host'}],
            'installed': {'manager': 'dpkg', 'binary_package': 'binutils',
                          'version': '2.44-3', 'architecture': 'amd64',
                          'source_package': 'binutils',
                          'source_version': '2.44-3'},
            'files': [], 'file_inventory_sha256': 'c' * 64,
            'consumer_coverage_complete': True,
            'execution_domains': domains, 'observations': []}

        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': [package],
                'execution_domains': domains}}, {'deployments': []}, [finding])
        dispositions = [item for item in graph['assertions']
                        if item['relation'] == 'WORK_DISPOSITION']

        self.assertEqual(2, len(dispositions))
        self.assertEqual(2, len({item['logical_key'] for item in dispositions}))
        self.assertEqual(2, len({item['scope'] for item in dispositions}))

    def test_shared_domain_does_not_assign_foreign_manifest_file(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian',
            'package': 'libbinutils', 'binary_package': 'libbinutils',
            'installed': '2.44-3', 'architecture': 'amd64',
            'source_package': 'binutils', 'source_version': '2.44-3',
            'artifact_id': '', 'location': '/:host', 'scope': 'os:/',
            'consumer_class': 'host-os'}
        foreign = '/usr/lib/x86_64-linux-gnu/libctf-nobfd.so.0.0.0'
        domain = {
            'id': 'native-elf-declared-dependencies',
            'packages': ['libbinutils', 'libctf-nobfd0'],
            'files': [foreign], 'entries': ['configured-readelf-inspection'],
            'inputs': ['accepted-installed-artifact'], 'authority_paths': [foreign],
            'elf_dependency_roots': ['/usr/bin/readelf'],
            'disposition': 'administrative_input_boundary',
            'complete': True, 'work_evidence_complete': False,
            'evidence_refs': ['linkage:one'],
            'observation': {'files': [foreign], 'entries': [
                'configured-readelf-inspection'],
                'inputs': ['accepted-installed-artifact'],
                'authority_paths': [{'path': foreign, 'status': 'complete'}],
                'evidence_refs': ['linkage:one']},
            'coverage': {name: {'complete': True, 'missing': [], 'unassigned': []}
                         for name in ('entry', 'input', 'file', 'operation_file',
                                      'file_authority')}}
        package = {
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'os', 'consumer_class': 'host-os',
                       'ecosystem': 'debian', 'artifact_id': '',
                       'binary_package': 'libbinutils', 'version': '2.44-3',
                       'architecture': 'amd64', 'source_package': 'binutils',
                       'source_version': '2.44-3', 'location': '/:host'}],
            'installed': {'manager': 'dpkg', 'binary_package': 'libbinutils',
                          'version': '2.44-3', 'architecture': 'amd64',
                          'source_package': 'binutils',
                          'source_version': '2.44-3'},
            'files': ['/usr/lib/x86_64-linux-gnu/libbfd-2.44-system.so'],
            'file_inventory_sha256': 'c' * 64,
            'consumer_coverage_complete': False,
            'execution_domains': [domain], 'observations': []}

        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': [package],
                'execution_domains': [domain]}}, {'deployments': []}, [finding])

        self.assertFalse(any(item['relation'] in {
            'CURRENT_DOMAIN', 'OWNS_FILE', 'DECLARES_DEPENDENCY'}
            for item in graph['assertions']))

        owned_package = copy.deepcopy(package)
        owned_package['installed']['binary_package'] = 'libctf-nobfd0'
        owned_package['slots'][0]['binary_package'] = 'libctf-nobfd0'
        owned_package['files'] = [foreign]
        owned_finding = {**finding, 'package': 'libctf-nobfd0',
                         'binary_package': 'libctf-nobfd0'}
        owned_graph = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time(), {'discovery': {
                'runtime_sha256': 'e' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': [owned_package],
                'execution_domains': [domain]}}, {'deployments': []},
            [owned_finding])
        relations = {item['relation'] for item in owned_graph['assertions']}
        self.assertIn('DECLARES_DEPENDENCY', relations)
        self.assertNotIn('PARSES_WITH', relations)

    def test_positive_work_path_does_not_require_unrelated_membership(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian', 'package': 'binutils',
            'binary_package': 'binutils', 'installed': '2.44-3',
            'architecture': 'amd64', 'source_package': 'binutils',
            'source_version': '2.44-3', 'artifact_id': '',
            'location': '/:host', 'scope': 'os:/', 'consumer_class': 'host-os'}
        domain = {
            'id': 'external-elf-inspection', 'packages': ['binutils'],
            'files': ['/usr/bin/readelf'], 'entries': ['broker-operation'],
            'inputs': ['caller-supplied-elf'],
            'authority_paths': ['/usr/bin/readelf'],
            'disposition': 'requires_work', 'complete': False,
            'work_evidence_complete': True, 'evidence_refs': ['request:one'],
            'observation': {'files': ['/usr/bin/readelf'],
                'entries': ['broker-operation'], 'inputs': ['caller-supplied-elf'],
                'authority_paths': [{'path': '/usr/bin/readelf',
                                     'status': 'complete'}],
                'evidence_refs': ['request:one']},
            'coverage': {name: {'complete': name != 'membership',
                               'missing': [], 'unassigned': []}
                         for name in ('entry', 'input', 'file', 'operation_file',
                                      'file_authority')}}
        package = {
            'namespace': {'kind': 'host', 'host': 'host'},
            'slots': [{'installation': 'os', 'consumer_class': 'host-os',
                       'ecosystem': 'debian', 'artifact_id': '',
                       'binary_package': 'binutils', 'version': '2.44-3',
                       'architecture': 'amd64', 'source_package': 'binutils',
                       'source_version': '2.44-3', 'location': '/:host'}],
            'installed': {'manager': 'dpkg', 'binary_package': 'binutils',
                          'version': '2.44-3', 'architecture': 'amd64',
                          'source_package': 'binutils',
                          'source_version': '2.44-3'},
            'files': ['/usr/bin/readelf', '/usr/bin/objdump'],
            'file_inventory_sha256': 'c' * 64,
            'consumer_coverage_complete': False,
            'consumer_coverage_dependencies': [{
                'kind': 'scheduled_execution',
                'path': '/var/spool/cron/crontabs/operator',
                'sha256': '9' * 64,
                'reasons': ['1:unsupported-command'],
                'executables': ['/usr/bin/readelf']}],
            'execution_domains': [domain], 'observations': []}

        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': [package],
                'execution_domains': [domain]}}, {'deployments': []}, [finding])

        disposition = next(item for item in graph['assertions']
                           if item['relation'] == 'WORK_DISPOSITION')
        self.assertEqual('requires_work', disposition['value'])

        resource = SNAP.installation_resource_key(
            'host', 'os', 'debian', 'binutils', '/:host')
        occurrence = 'occ-positive-work'
        self.store.lifecycle.stage_graph_change(
            graph['change_id'], resources=graph['resources'],
            evidence=graph['evidence'], assertions=graph['assertions'],
            coverage=graph['coverage'])
        self.store.lifecycle.acknowledge_graph_change(graph['change_id'])
        incident = self.store._incident('CVE-2026-8200')
        self.store.lifecycle.add_occurrence(
            incident, occurrence, resource, service='os', host='host',
            deployment='os')
        positive = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('work', positive['result'])
        self.assertTrue(any(scope.startswith('scheduled-discovery:')
                            for scope in positive['missing_scopes']))

        removed_domain = copy.deepcopy(domain)
        removed_domain['work_evidence_complete'] = False
        removed_domain['observation']['inputs'] = []
        removed_domain['coverage']['input'] = {
            'complete': False, 'missing': ['caller-supplied-elf'],
            'unassigned': []}
        removed_package = copy.deepcopy(package)
        removed_package['execution_domains'] = [removed_domain]
        removed = SNAP.lifecycle_graph(
            'host', 'one', 2, time.time() + 1, {'discovery': {
                'runtime_sha256': 'e' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': [removed_package],
                'execution_domains': [removed_domain]}}, {'deployments': []},
            [finding], previous_graph=graph)
        self.store.lifecycle.stage_graph_change(
            removed['change_id'], resources=removed['resources'],
            evidence=removed['evidence'], assertions=removed['assertions'],
            coverage=removed['coverage'])
        self.store.lifecycle.acknowledge_graph_change(removed['change_id'])
        negative = self.store.lifecycle.evaluate(
            incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v2',
            dependency_scopes=self.store.lifecycle.dependency_scopes(occurrence))
        self.assertEqual('gap', negative['result'])

    def test_debian_release_fields_reconstruct_exact_package_identity(self):
        report = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
            'Packages': [{'Name': 'libacl1', 'Version': '2.3.2', 'Release': '2+b1',
                          'SrcName': 'acl', 'SrcVersion': '2.3.2', 'SrcRelease': '2',
                          'Identifier': {
                              'UID': 'pkg-1',
                              'PURL': ('pkg:deb/debian/libacl1@2.3.2-2%2Bb1'
                                       '?arch=amd64&distro=debian-13.6')}}],
            'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1234',
                'PkgName': 'libacl1', 'InstalledVersion': '2.3.2-2+b1',
                'Severity': 'MEDIUM', 'PkgIdentifier': {'UID': 'pkg-1'}}]}]}
        findings, _, packages = SNAP.snapshot_findings([report])

        self.assertEqual(1, len(findings))
        self.assertEqual(1, len(packages))
        for item in (findings[0], packages[0]):
            self.assertEqual('2.3.2-2+b1', item['installed'])
            self.assertEqual('amd64', item['architecture'])
            self.assertEqual('acl', item['source_package'])
            self.assertEqual('2.3.2-2', item['source_version'])
            self.assertEqual(
                'pkg:deb/debian/libacl1@2.3.2-2%2Bb1?arch=amd64&distro=debian-13.6',
                item['purl'])
            self.assertEqual('native-package-identity/v1',
                             item['package_identity_derivation']['rule'])
            self.assertEqual('2.3.2',
                             item['package_identity_derivation']['facts']['version'])

        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'caddy'},
            'slot': {'installation': 'os', 'consumer_class': 'host-os',
                     'ecosystem': 'debian', 'artifact_id': '',
                     'binary_package': 'libacl1', 'version': '2.3.2-2+b1',
                     'architecture': 'amd64', 'source_package': 'acl',
                     'source_version': '2.3.2-2', 'location': '/:/'},
            'installed': {'manager': 'dpkg', 'binary_package': 'libacl1',
                          'version': '2.3.2-2+b1', 'architecture': 'amd64',
                          'source_package': 'acl', 'source_version': '2.3.2-2'},
            'file_inventory_sha256': 'c' * 64, 'consumer_coverage_complete': False,
            'observations': [{'file': {'path': '/usr/lib/libacl.so.1',
                                       'sha256': 'd' * 64},
                              'consumer': {'kind': 'process', 'pid': 2,
                                  'start_ticks': '10', 'executable': '/usr/bin/caddy',
                                  'executable_sha256': 'e' * 64,
                                  'service': 'caddy.service',
                                  'deployments': ['caddy']}}]}]
        graph = SNAP.lifecycle_graph(
            'caddy', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': package_evidence}},
            {'deployments': [{'id': 'caddy'}]}, findings)
        self.assertIn('OWNS_FILE', {item['relation'] for item in graph['assertions']})

    def test_ambiguous_native_package_metadata_is_not_guessed(self):
        packages = [
            {'Name': 'libacl1', 'Version': '2.3.2', 'Release': '2+b1',
             'SrcName': 'acl', 'SrcVersion': '2.3.2', 'SrcRelease': '2',
             'Identifier': {'PURL':
                 f'pkg:deb/debian/libacl1@2.3.2-2%2Bb1?arch={architecture}'}}
            for architecture in ('amd64', 'arm64')]
        report = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
            'Packages': packages, 'Vulnerabilities': [{
                'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libacl1',
                'InstalledVersion': '2.3.2-2+b1', 'Severity': 'MEDIUM'}]}]}

        findings, _, _ = SNAP.snapshot_findings([report])

        self.assertEqual('', findings[0]['architecture'])
        self.assertEqual('', findings[0]['source_package'])
        self.assertEqual('', findings[0]['source_version'])
        self.assertEqual('', findings[0]['purl'])
        self.assertEqual('ambiguous', findings[0]['package_identity_status'])

    def test_native_purl_epoch_qualifier_is_part_of_installed_version(self):
        identity = SNAP.native_package_identity({
            'Name': 'libepoch', 'Version': '1.2', 'Release': '3', 'Epoch': 1,
            'SrcName': 'epoch', 'SrcVersion': '1.2', 'SrcRelease': '3',
            'SrcEpoch': 1, 'Identifier': {'PURL':
                'pkg:deb/debian/libepoch@1.2-3?arch=amd64&epoch=1'}})

        self.assertEqual('1:1.2-3', identity['installed'])
        self.assertEqual('1:1.2-3', identity['source_version'])

    def test_package_observations_require_exact_consumer_class_and_artifact(self):
        finding = {
            'installation': 'container:web', 'ecosystem': 'python-pkg',
            'package': 'libfoo', 'binary_package': 'libfoo', 'installed': '1.0',
            'location': 'web:/app/libfoo.py', 'scope': 'container:web:web',
            'consumer_class': 'runtime-language', 'artifact_id': 'sha256:' + 'a' * 64,
            'containers': [{'id': '1' * 64, 'name': 'web'}],
            'consumer_deployments': ['web']}
        unrelated = [{
            'namespace': {'kind': 'host', 'host': 'host'},
            'scanner': {'name': 'libfoo', 'version': '1.0'},
            'slot': {'installation': 'os', 'consumer_class': 'host-os',
                     'ecosystem': 'debian', 'artifact_id': '',
                     'binary_package': 'libfoo', 'version': '1.0',
                     'architecture': 'amd64', 'source_package': 'libfoo',
                     'source_version': '1.0'},
            'installed': {'manager': 'dpkg', 'binary_package': 'libfoo',
                          'version': '1.0', 'architecture': 'amd64',
                          'source_package': 'libfoo', 'source_version': '1.0'},
            'file_inventory_sha256': 'c' * 64, 'consumer_coverage_complete': False,
            'observations': [{'file': {'path': '/usr/lib/libfoo.so',
                                       'sha256': 'd' * 64},
                              'consumer': {'kind': 'process', 'pid': 1,
                                           'deployments': ['edge']}}]}]
        graph = SNAP.lifecycle_graph(
            'host', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': unrelated}},
            {'deployments': [{'id': 'web'}, {'id': 'edge'}]}, [finding])

        self.assertFalse(any(item['relation'] == 'OWNS_FILE'
                             for item in graph['assertions']))
        binding = graph['evidence'][0]['content']['installation_bindings'][0]
        self.assertEqual(0, binding['package_evidence_records'])
        self.assertEqual(['web'], binding['deployments'])

    def test_positive_os_relationship_survives_advisory_disappearance(self):
        report = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
            'Packages': [{'Name': 'libssl3', 'Version': '3.0',
                          'SrcName': 'openssl', 'SrcVersion': '3.0',
                          'Identifier': {'PURL': 'pkg:deb/debian/libssl3@3.0?arch=amd64'}}],
            'Vulnerabilities': []}]}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'caddy'},
            'slot': {'installation': 'os', 'consumer_class': 'host-os',
                     'ecosystem': 'debian', 'artifact_id': '',
                     'binary_package': 'libssl3', 'version': '3.0',
                     'architecture': 'amd64', 'source_package': 'openssl',
                     'source_version': '3.0', 'location': '/:/'},
            'installed': {'manager': 'dpkg', 'binary_package': 'libssl3',
                          'version': '3.0', 'architecture': 'amd64',
                          'source_package': 'openssl', 'source_version': '3.0'},
            'file_inventory_sha256': 'c' * 64, 'consumer_coverage_complete': False,
            'observations': [{'file': {'path': '/usr/lib/libssl.so.3',
                                       'sha256': 'd' * 64},
                              'consumer': {'kind': 'process', 'pid': 2,
                                  'start_ticks': '10', 'executable': '/usr/bin/web',
                                  'executable_sha256': 'e' * 64,
                                  'service': 'web.service', 'deployments': ['web']}}]}]
        coverage = {'discovery': {'runtime_sha256': 'f' * 64, 'gaps': [],
            'relationships': [], 'relationship_coverage': [],
            'package_evidence': package_evidence}}
        SNAP.publish([report], coverage, {'deployments': [{'id': 'web'}]},
                     self.root / 'persistent-outbox.json', self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        package_resource = SNAP.installation_resource_key(
            'caddy', 'os', 'debian', 'libssl3', '/:/')
        relations = self.store.lifecycle.relationships(package_resource)['relationships']
        self.assertIn('OWNS_FILE', {item['relation'] for item in relations})
        report['Results'][0]['Vulnerabilities'] = [{
            'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libssl3',
            'InstalledVersion': '3.0', 'Severity': 'MEDIUM'}]
        SNAP.publish([report], coverage, {'deployments': [{'id': 'web'}]},
                     self.root / 'persistent-outbox.json', self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        report['Results'][0]['Vulnerabilities'] = []
        SNAP.publish([report], coverage, {'deployments': [{'id': 'web'}]},
                     self.root / 'persistent-outbox.json', self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])

        relations = self.store.lifecycle.relationships(package_resource)['relationships']
        self.assertIn('OWNS_FILE', {item['relation'] for item in relations})

    def test_unchanged_split_version_package_does_not_become_a_deployed_fix(self):
        package = {'Name': 'libacl1', 'Version': '2.3.2', 'Release': '2+b1',
                   'SrcName': 'acl', 'SrcVersion': '2.3.2', 'SrcRelease': '2',
                   'Identifier': {'PURL':
                       ('pkg:deb/debian/libacl1@2.3.2-2%2Bb1'
                        '?arch=amd64&distro=debian-13.6')}}
        result = {'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
                  'Packages': [package], 'Vulnerabilities': [{
                      'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libacl1',
                      'InstalledVersion': '2.3.2-2+b1', 'Severity': 'MEDIUM'}]}
        report = {'Results': [result]}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'caddy'},
            'slot': {'installation': 'os', 'consumer_class': 'host-os',
                     'ecosystem': 'debian', 'artifact_id': '',
                     'binary_package': 'libacl1', 'version': '2.3.2-2+b1',
                     'architecture': 'amd64', 'source_package': 'acl',
                     'source_version': '2.3.2-2', 'location': '/:/'},
            'installed': {'manager': 'dpkg', 'binary_package': 'libacl1',
                          'version': '2.3.2-2+b1', 'architecture': 'amd64',
                          'source_package': 'acl', 'source_version': '2.3.2-2'},
            'file_inventory_sha256': 'c' * 64, 'consumer_coverage_complete': False,
            'observations': [{'file': {'path': '/usr/lib/libacl.so.1',
                                       'sha256': 'd' * 64},
                              'consumer': {'kind': 'process', 'pid': 2,
                                  'start_ticks': '10', 'executable': '/usr/bin/caddy',
                                  'executable_sha256': 'e' * 64,
                                  'service': 'caddy.service',
                                  'deployments': ['caddy']}}]}]
        coverage = {'discovery': {'runtime_sha256': 'f' * 64, 'gaps': [],
            'relationships': [], 'relationship_coverage': [],
            'package_evidence': package_evidence}}
        outbox = self.root / 'native-version-outbox.json'

        SNAP.publish([report], coverage, {'deployments': [{'id': 'caddy'}]},
                     outbox, self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        result['Vulnerabilities'] = []
        SNAP.publish([report], coverage, {'deployments': [{'id': 'caddy'}]},
                     outbox, self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])

        occurrence = self.store.db.execute(
            'SELECT * FROM occurrences WHERE source=?', ('caddy',)).fetchone()
        self.assertEqual('unknown', occurrence['state'])
        retained = json.loads(occurrence['finding'])
        self.assertEqual('2.3.2-2+b1', retained['installed'])
        self.assertEqual('amd64', retained['architecture'])
        dispositions = self.store.db.execute("""SELECT a.value
            FROM lifecycle_assertions a
            JOIN lifecycle_assertion_occurrences ao ON ao.assertion=a.id
            WHERE ao.occurrence=? AND a.current=1
                AND a.relation='BUILD_DISPOSITION' AND a.status='valid'""",
            (occurrence['id'],)).fetchall()
        self.assertEqual([], dispositions)
        package_resource = SNAP.installation_resource_key(
            'caddy', 'os', 'debian', 'libacl1', '/:/')
        relations = self.store.lifecycle.relationships(package_resource)['relationships']
        self.assertIn('OWNS_FILE', {item['relation'] for item in relations})

    def test_absent_advisory_does_not_guess_between_multiarch_slots(self):
        vulnerable = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs',
            'Target': '/', 'Packages': [], 'Vulnerabilities': [{
                'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libacl1',
                'InstalledVersion': '2.3.2-2+b1', 'Severity': 'MEDIUM'}]}]}
        packages = [
            {'Name': 'libacl1', 'Version': '2.3.2', 'Release': '2+b1',
             'SrcName': 'acl', 'SrcVersion': '2.3.2', 'SrcRelease': '2',
             'Identifier': {'PURL':
                 f'pkg:deb/debian/libacl1@2.3.2-2%2Bb1?arch={architecture}'}}
            for architecture in ('amd64', 'arm64')]
        quiet = {'Results': [{'Type': 'debian', 'Class': 'os-pkgs',
            'Target': '/', 'Packages': packages, 'Vulnerabilities': []}]}
        outbox = self.root / 'multiarch-outbox.json'

        SNAP.publish([vulnerable], {}, {}, outbox, self.settings, self.send)
        SNAP.publish([quiet], {}, {}, outbox, self.settings, self.send)

        occurrence = self.store.db.execute(
            'SELECT * FROM occurrences WHERE source=?', ('caddy',)).fetchone()
        retained = json.loads(occurrence['finding'])
        self.assertEqual('unknown', occurrence['state'])
        self.assertEqual('', retained['architecture'])
        self.assertEqual('', retained['source_package'])
        self.assertEqual('', retained['source_version'])
        self.assertEqual('', retained['purl'])
        self.assertEqual('ambiguous', retained['package_identity_status'])

    def test_absent_advisory_refreshes_mutable_artifact_identity(self):
        package = {'Name': 'libacl1', 'Version': '2.3.2', 'Release': '2+b1',
                   'SrcName': 'acl', 'SrcVersion': '2.3.2', 'SrcRelease': '2',
                   'Identifier': {'PURL':
                       'pkg:deb/debian/libacl1@2.3.2-2%2Bb1?arch=amd64'}}

        def report(image_id, vulnerabilities):
            return {'_homelab_runtime': {
                'image_id': image_id,
                'containers': [{'id': image_id.removeprefix('sha256:'),
                                'name': 'web', 'running': True}]},
                'Results': [{'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
                             'Packages': [package],
                             'Vulnerabilities': vulnerabilities}]}

        finding = {'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'libacl1',
                   'InstalledVersion': '2.3.2-2+b1', 'Severity': 'MEDIUM'}
        first_image = 'sha256:' + 'a' * 64
        second_image = 'sha256:' + 'b' * 64
        outbox = self.root / 'artifact-refresh-outbox.json'

        SNAP.publish([report(first_image, [finding])], {}, {}, outbox,
                     self.settings, self.send)
        SNAP.publish([report(second_image, [])], {}, {}, outbox,
                     self.settings, self.send)

        occurrence = self.store.db.execute(
            'SELECT * FROM occurrences WHERE source=?', ('caddy',)).fetchone()
        retained = json.loads(occurrence['finding'])
        self.assertEqual('unknown', occurrence['state'])
        self.assertEqual(second_image, retained['artifact_id'])
        self.assertEqual('runtime-os', retained['consumer_class'])

    def test_process_relationship_identity_survives_process_restart(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian', 'package': 'app',
            'binary_package': 'app', 'installed': '1', 'architecture': 'amd64',
            'source_package': 'app', 'source_version': '1', 'artifact_id': '',
            'location': '/:/', 'scope': 'os:/', 'consumer_class': 'host-os'}

        def graph(pid, start_ticks):
            evidence = [{
                'namespace': {'kind': 'host', 'host': 'host'},
                'slot': SNAP.package_slot(finding),
                'installed': {'manager': 'dpkg', 'binary_package': 'app',
                              'version': '1', 'architecture': 'amd64',
                              'source_package': 'app', 'source_version': '1'},
                'file_inventory_sha256': 'c' * 64,
                'consumer_coverage_complete': False,
                'observations': [{'relation': 'loaded_file',
                    'file': {'path': '/usr/bin/app', 'sha256': 'd' * 64},
                    'consumer': {'kind': 'process', 'pid': pid,
                                 'start_ticks': start_ticks,
                                 'executable': '/usr/bin/app',
                                 'executable_sha256': 'd' * 64,
                                 'service': 'app.service',
                                 'deployments': ['app']}}]}]
            return SNAP.lifecycle_graph(
                'host', 'one', 1, time.time(), {'discovery': {
                    'runtime_sha256': 'f' * 64, 'gaps': [],
                    'relationships': [], 'relationship_coverage': [],
                    'package_evidence': evidence}},
                {'deployments': [{'id': 'app'}]}, [finding])

        before = graph(100, '20')
        after = graph(200, '30')
        before_loaded = next(item for item in before['assertions']
                             if item['relation'] == 'LOADED_BY')
        after_loaded = next(item for item in after['assertions']
                            if item['relation'] == 'LOADED_BY')

        self.assertEqual(before_loaded['object_key'], after_loaded['object_key'])
        self.assertEqual(before_loaded['logical_key'], after_loaded['logical_key'])

    def test_complete_header_package_does_not_imply_an_exclusion(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian',
            'package': 'linux-libc-dev', 'binary_package': 'linux-libc-dev',
            'installed': '6.1', 'architecture': 'amd64',
            'source_package': 'linux', 'source_version': '6.1',
            'artifact_id': '', 'location': '/:/', 'scope': 'os:/',
            'consumer_class': 'host-os'}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'media'},
            'slot': SNAP.package_slot(finding),
            'installed': {'manager': 'dpkg', 'binary_package': 'linux-libc-dev',
                          'version': '6.1', 'architecture': 'amd64',
                          'source_package': 'linux', 'source_version': '6.1'},
            'file_inventory_sha256': 'c' * 64,
            'artifact_profile': {'kind': 'development-headers',
                                 'classification_complete': True},
            'declared_capabilities': [], 'observations': [],
            'consumer_coverage_complete': False}]
        graph = SNAP.lifecycle_graph(
            'media', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'kernel': '6.1.0-running',
                'gaps': [], 'relationships': [], 'relationship_coverage': [],
                'package_evidence': package_evidence}},
            {'deployments': []}, [finding])

        coverage = next(item for item in graph['coverage']
                        if item['relationship'] == 'package_consumer')
        binding = graph['evidence'][0]['content']['installation_bindings'][0]
        self.assertFalse(any(item['relation'] == 'CONSTRAINT_EXCLUDES'
                             for item in graph['assertions']))
        self.assertFalse(coverage['complete'])
        self.assertEqual('6.1.0-running', binding['running_kernel'])

    def test_header_package_is_available_on_declared_build_environment(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian',
            'package': 'linux-libc-dev', 'binary_package': 'linux-libc-dev',
            'installed': '6.1', 'architecture': 'amd64',
            'source_package': 'linux', 'source_version': '6.1',
            'artifact_id': '', 'location': '/:/', 'scope': 'os:/',
            'consumer_class': 'host-os'}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'plan-runner'},
            'slot': SNAP.package_slot(finding),
            'installed': {'manager': 'dpkg', 'binary_package': 'linux-libc-dev',
                          'version': '6.1', 'architecture': 'amd64',
                          'source_package': 'linux', 'source_version': '6.1'},
            'file_inventory_sha256': 'c' * 64,
            'artifact_profile': {'kind': 'development-headers',
                                 'classification_complete': True},
            'declared_capabilities': [], 'observations': [],
            'consumer_coverage_complete': False}]
        graph = SNAP.lifecycle_graph(
            'plan-runner', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': package_evidence}},
            {'deployments': [{'id': 'plan-runner'}],
             'build_consumers': ['plan-runner']}, [finding])

        self.assertTrue(any(item['relation'] == 'AVAILABLE_TO' and
                            item['object_key'] == 'deployment:plan-runner:plan-runner'
                            for item in graph['assertions']))
        self.assertFalse(any(item['relation'] == 'CONSUMED_BY'
                             for item in graph['assertions']))
        self.assertFalse(any(item['relation'] == 'CONSTRAINT_EXCLUDES'
                             for item in graph['assertions']))

    def test_declared_package_capability_is_auditable_and_complete(self):
        finding = {
            'installation': 'os', 'ecosystem': 'debian',
            'package': 'libbinutils', 'binary_package': 'libbinutils',
            'installed': '2.40', 'architecture': 'amd64',
            'source_package': 'binutils', 'source_version': '2.40',
            'artifact_id': '', 'location': '/:/', 'scope': 'os:/',
            'consumer_class': 'host-os'}
        capability = {
            'id': 'diagnostic-artifact-inspection',
            'applications': ['diagnostic-agent'],
            'evidence': ['gateway.py'], 'required_executables': ['/usr/bin/readelf'],
            'dependency_path': ['binutils', 'libbinutils']}
        package_evidence = [{
            'namespace': {'kind': 'host', 'host': 'media'},
            'slot': SNAP.package_slot(finding),
            'installed': {'manager': 'dpkg', 'binary_package': 'libbinutils',
                          'version': '2.40', 'architecture': 'amd64',
                          'source_package': 'binutils', 'source_version': '2.40'},
            'file_inventory_sha256': 'c' * 64,
            'artifact_profile': {'kind': 'runtime-or-command',
                                 'classification_complete': True},
            'declared_capabilities': [capability], 'observations': [],
            'consumer_coverage_complete': False}]
        graph = SNAP.lifecycle_graph(
            'media', 'one', 1, time.time(), {'discovery': {
                'runtime_sha256': 'f' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': [], 'package_evidence': package_evidence}},
            {'deployments': []}, [finding])

        relations = {item['relation'] for item in graph['assertions']}
        capability_resource = next(item for item in graph['resources']
                                   if item['kind'] == 'command-capability')
        capability_coverage = next(item for item in graph['coverage']
                                   if item['relationship'] == 'package_capability')
        self.assertTrue({'AVAILABLE_TO', 'USED_BY'} <= relations)
        self.assertNotIn('CONSTRAINT_EXCLUDES', relations)
        self.assertEqual(['binutils', 'libbinutils'],
                         capability_resource['properties']['dependency_path'])
        self.assertTrue(capability_coverage['complete'])
        package_coverage = next(item for item in graph['coverage']
                                if item['relationship'] == 'package_consumer')
        self.assertFalse(package_coverage['complete'])

    def test_failed_next_upload_preserves_last_acknowledged_snapshot(self):
        path = self.root/'outbox.json'
        SNAP.publish(self.reports, {}, {}, path, self.settings, self.send)
        accepted_path = self.root/'outbox.incident-snapshot.json'
        before = accepted_path.read_bytes()
        def offline(*_):
            raise OSError('offline')
        with self.assertRaises(OSError):
            SNAP.publish([], {}, {}, path, self.settings, offline)
        self.assertEqual(accepted_path.read_bytes(), before)


    def test_source_cannot_query_or_impersonate_another_host(self):
        with self.assertRaises(PermissionError):
            self.api.call('Bearer source-key', {'action': 'list'})
        with self.assertRaises(PermissionError):
            self.api.call('Bearer source-key', {'action': 'commit', 'manifest': {'source': 'other', 'generation': 'one'}})
        with self.assertRaises(PermissionError):
            self.api.call('Bearer read-key', {'action': 'claim'})

    def test_health_stats_do_not_expand_full_source_inventory(self):
        SNAP.publish(self.reports, {}, {}, self.root/'outbox.json', self.settings, self.send)
        response = self.api.call('Bearer read-key', {'action': 'stats'})
        self.assertEqual(response['stats']['sources'], 1)
        self.assertEqual(set(response['sources'][0]), {'id', 'sequence', 'received', 'observed'})

    def test_retired_worker_credential_cannot_charge_evidence(self):
        self.api.credentials['worker'] = {'role': 'worker', 'token': 'work-key'}
        SNAP.publish(self.reports, {}, {}, self.root/'outbox.json', self.settings, self.send)
        self.store.request_investigation(self.store.list_incidents()[0]['id'], '$manual')
        job = self.store.claim_job()
        payload = {'action': 'work_budget', 'job': job['id'], 'fence': job['fence'],
                   'budget_kind': 'evidence', 'amount': 100}
        for credential in ('work-key', 'read-key', 'source-key'):
            with self.assertRaises(PermissionError):
                self.api.call('Bearer ' + credential, payload)

    def test_partial_chunk_upload_never_becomes_scan_evidence(self):
        path = self.root/'outbox.json'
        def stop_before_commit(settings, payload):
            if payload['action'] == 'commit':
                raise RuntimeError('interrupted')
            return self.send(settings, payload)
        with self.assertRaises(RuntimeError):
            SNAP.publish(self.reports, {}, {}, path, self.settings, stop_before_commit)
        self.assertEqual(self.store.stats()['incidents'], 0)
        self.assertEqual(self.store.stats()['scans'], 0)

    def test_manual_conversation_no_longer_admits_custom_jobs(self):
        self.api.credentials['operator']={'role':'operator','token':'operator-key'}
        self.reports[0]['Results'][0]['Vulnerabilities'].append({
            'VulnerabilityID':'CVE-2026-5678','PkgName':'other','Severity':'HIGH','InstalledVersion':'1'})
        SNAP.publish(self.reports, {}, {}, self.root/'outbox.json', self.settings, self.send)
        def request(identifier):
            return self.api.call('Bearer operator-key',{
                'action':'request','incident':identifier,'request_id':'same-user-message'})
        with self.assertRaises(PermissionError):
            request('CVE-2026-1234')
        with self.assertRaises(PermissionError):
            request('CVE-2026-5678')
        self.assertEqual(self.store.stats()['jobs'],0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM outbox WHERE incident=?',
            (self.store.get_incident('CVE-2026-5678')['id'],)).fetchone()[0],0)

    def test_unknown_library_coverage_never_clears_prior_occurrence(self):
        path = self.root/'outbox.json'
        SNAP.publish(self.reports, {}, {}, path, self.settings, self.send)
        SNAP.publish([], {}, {}, path, self.settings, self.send)
        incident = self.store.get_incident(self.store.list_incidents()[0]['id'])
        self.assertEqual(incident['occurrences'][0]['state'], 'unknown')

    def test_current_exact_package_slot_classifies_retained_legacy_finding(self):
        path = self.root / 'legacy-outbox.json'
        report = {'_homelab_runtime': {'image_id': 'sha256:' + 'a' * 64,
                  'containers': [{'id': '1' * 64, 'name': 'web', 'running': True}]},
                  'Results': [{'Type': 'gobinary', 'Class': 'lang-pkgs',
                               'Target': '/usr/bin/web', 'Packages': [{
                                   'Name': 'stdlib', 'Version': 'v1.2.3',
                                   'FilePath': '/usr/bin/web'}],
                               'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-9999',
                                   'PkgName': 'stdlib', 'InstalledVersion': 'v1.2.3'}]}]}
        inventory = {'deployments': [{'id': 'web', 'containers': ['web']}]}
        SNAP.publish([report], {}, inventory, path, self.settings, self.send)
        row = self.store.db.execute('SELECT id,finding FROM occurrences').fetchone()
        legacy = json.loads(row['finding'])
        legacy.pop('consumer_class')
        self.store.db.execute('UPDATE occurrences SET finding=? WHERE id=?',
                              (json.dumps(legacy, sort_keys=True, separators=(',', ':')), row['id']))
        report['Results'][0]['Vulnerabilities'] = []
        SNAP.publish([report], {}, inventory, path, self.settings, self.send)

        retained = self.store.get_incident('CVE-2026-9999')['occurrences'][0]
        self.assertEqual('unknown', retained['state'])
        self.assertEqual('runtime-language', retained['finding']['consumer_class'])
        self.assertEqual('current_package_slot',
                         retained['finding']['consumer_class_evidence']['kind'])

    def test_retained_occurrence_uses_current_exact_provisioning_owner(self):
        path = self.root / 'owner-refresh-outbox.json'
        report = {'_homelab_runtime': {
            'image_id': 'sha256:' + 'a' * 64,
            'containers': [{'id': '1' * 64, 'name': 'web', 'running': True,
                            'compose_service': 'web'}]},
            'Results': [{'Type': 'alpine', 'Class': 'os-pkgs', 'Target': '/',
                'Packages': [{'Name': 'zlib', 'Version': '1.3.1-r2'}],
                'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-9997',
                    'PkgName': 'zlib', 'InstalledVersion': '1.3.1-r2',
                    'FixedVersion': '1.3.1-r3'}]}]}
        old_inventory = {'deployments': [
            {'id': 'owner-old', 'compose_services': ['web']}]}
        new_inventory = {'deployments': [
            {'id': 'owner-new', 'compose_services': ['web']}]}
        SNAP.publish([report], {}, old_inventory, path, self.settings, self.send)
        report['Results'][0]['Vulnerabilities'] = []
        SNAP.publish([report], {}, new_inventory, path, self.settings, self.send)

        retained = self.store.get_incident('CVE-2026-9997')['occurrences'][0]
        self.assertEqual('unknown', retained['state'])
        self.assertEqual(['owner-new'], retained['finding']['owner_deployments'])
        opportunity = {
            'installation': 'container:web', 'ecosystem': 'alpine',
            'package': 'zlib', 'candidate': '0.3.24', 'installed': '0.3.23',
            'available': True, 'source': 'configured-release-channel',
            'channel': 'stable', 'platform': 'linux-amd64',
            'provenance': 'fixture', 'observed_at': time.time(), 'reason': '',
        }
        receipt = {'collector': 'fixture', 'status': 'complete',
                   'observed_at': time.time(),
                   'source_snapshot': {'sequence': 2}, 'missing': []}
        old = self.store.lifecycle.begin_provisioning_cycle(
            'retained-owner-old', 'ansible:owner-old', ['caddy'],
            ['deployment:owner-old'],
            [{**opportunity, 'owner_installation': 'deployment:owner-old'}],
            receipt)
        new = self.store.lifecycle.begin_provisioning_cycle(
            'retained-owner-new', 'ansible:owner-new', ['caddy'],
            ['deployment:owner-new'],
            [{**opportunity, 'owner_installation': 'deployment:owner-new'}],
            receipt)

        self.assertEqual([], old['candidates'])
        self.assertEqual(1, len(new['candidates']))
        self.assertEqual([retained['id']], new['candidates'][0]['occurrences'])

    def test_different_package_location_does_not_classify_retained_finding(self):
        finding = {
            'id': 'CVE-2026-9998', 'installation': 'deployment:legacy',
            'scope': 'container:web:web', 'ecosystem': 'gobinary',
            'package': 'stdlib', 'location': 'web:/usr/bin/old',
            'installed': 'v1.2.3', 'fixed': '', 'severity': 'HIGH'}
        first = {'schema': 1, 'source': 'caddy', 'generation': 'one',
                 'sequence': 1, 'observed_at': time.time(),
                 'findings': [finding], 'packages': [],
                 'complete_scopes': [], 'coverage': {}}
        current = {**finding, 'installation': 'container:web',
                   'location': 'web:/usr/bin/current',
                   'consumer_class': 'runtime-language'}
        second = {'schema': 1, 'source': 'caddy', 'generation': 'one',
                  'sequence': 2, 'observed_at': time.time(),
                  'findings': [], 'packages': [current],
                  'complete_scopes': [], 'coverage': {}}

        self.store.ingest(first)
        self.store.ingest(second)

        retained = self.store.get_incident('CVE-2026-9998')['occurrences'][0]
        self.assertNotIn('consumer_class', retained['finding'])
        self.assertNotIn('consumer_class_evidence', retained['finding'])

    def test_duplicate_installation_identities_retire_to_audited_survivor(self):
        def snapshot(sequence, installation):
            finding = {
                'id': 'CVE-2026-7000', 'installation': installation,
                'scope': 'container:web:web', 'ecosystem': 'gobinary',
                'package': 'stdlib', 'location': 'web:/usr/bin/web',
                'installed': 'v1.2.3', 'fixed': '', 'severity': 'HIGH',
                'consumer_class': 'runtime-language'}
            return {'schema': 1, 'source': 'caddy', 'generation': 'one',
                    'sequence': sequence, 'observed_at': time.time(),
                    'findings': [finding], 'packages': [{
                        key: finding[key] for key in
                        ('installation', 'ecosystem', 'package', 'location', 'installed')}],
                    'complete_scopes': [finding['scope']], 'coverage': {}}

        self.store.ingest(snapshot(1, 'deployment:old-owner'))
        survivor = self.store.db.execute('SELECT * FROM occurrences').fetchone()
        incident = survivor['incident']
        work = self.store.lifecycle.ensure_work(incident, 'fixture', 'fixture:work')
        self.store.lifecycle.set_link(work['id'], 'thread', 'thread-root')
        duplicate_id = 'f' * 64
        duplicate_finding = json.loads(survivor['finding'])
        duplicate_finding['installation'] = 'deployment:new-owner'
        duplicate_identity = ['caddy', 'deployment:new-owner', 'gobinary',
                              'stdlib', 'web:/usr/bin/web']
        self.store.db.execute('INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)', (
            duplicate_id, incident, 'caddy', survivor['scope'],
            json.dumps(duplicate_identity, separators=(',', ':')),
            survivor['state'], json.dumps(duplicate_finding, sort_keys=True,
                                           separators=(',', ':')),
            survivor['material'], survivor['observed'] + 1, 2))
        self.store.lifecycle.add_occurrence(
            incident, duplicate_id,
            installation_resource_key('caddy', 'deployment:new-owner', 'gobinary',
                                      'stdlib', 'web:/usr/bin/web'),
            service='deployment:new-owner', host='caddy',
            deployment='web:/usr/bin/web')

        self.store.ingest(snapshot(3, 'container:web'))

        active = self.store.db.execute(
            "SELECT id FROM occurrences WHERE state!='retired'").fetchall()
        self.assertEqual([survivor['id']], [row['id'] for row in active])
        migration = self.store.db.execute(
            'SELECT old_occurrence,current_occurrence,evidence FROM occurrence_identity_migrations').fetchone()
        self.assertEqual(duplicate_id, migration['old_occurrence'])
        self.assertEqual(survivor['id'], migration['current_occurrence'])
        self.assertEqual('thread-root', self.store.lifecycle.work(work['id'])['thread'])
        self.assertEqual(0, self.store.db.execute(
            'SELECT active FROM lifecycle_occurrences WHERE id=?',
            (duplicate_id,)).fetchone()[0])

    def test_runtime_discovery_stages_scoped_graph_and_links_deployment_identity(self):
        report = {'_homelab_library': {
            'deployment': 'web', 'path': '/srv/web', 'status': 'covered'},
            'Results': [{'Type': 'gobinary', 'Target': '/srv/web/app',
                'Packages': [{'Name': 'stdlib', 'Version': '1',
                              'FilePath': '/srv/web/app'}],
                'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-4321',
                    'PkgName': 'stdlib', 'InstalledVersion': '1'}]}]}
        coverage = {'discovery': {
            'runtime_sha256': 'a' * 64, 'gaps': [],
            'relationships': [{
                'subject': 'deployment:caddy:web', 'relation': 'RUNS_AS',
                'object': 'service:caddy:web.service',
                'scope': 'runtime:caddy:web', 'kind': 'observation',
                'status': 'valid'}],
            'relationship_coverage': [{
                'scope': 'runtime:caddy:web',
                'relationship': 'runtime_ownership', 'complete': True,
                'status': 'valid', 'gaps': []}]}}
        inventory = {'deployments': [{'id': 'web'}]}
        SNAP.publish([report], coverage, inventory, self.root/'runtime-outbox.json',
                     self.settings, self.send)
        occurrence = self.store.db.execute(
            "SELECT * FROM lifecycle_occurrences").fetchone()
        package_resource = installation_resource_key(
            'caddy', 'deployment:web', 'gobinary', 'stdlib',
            '/srv/web:/srv/web/app')
        self.assertEqual(package_resource, occurrence['resource_key'])
        change = self.store.lifecycle.pending_graph_change()
        self.assertTrue(change['id'].startswith('runtime:caddy:one:'))
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        relationships = self.store.lifecycle.relationships(
            package_resource)['relationships']
        self.assertEqual({'BUILD_DISPOSITION', 'CONSUMED_BY'},
                         {item['relation'] for item in relationships})
        decisions = self.store.lifecycle.evaluate_all()
        self.assertEqual('pending', decisions[0]['result'])
        self.assertEqual([
                         'consumer-discovery:caddy:host',
                         'consumer:caddy:' + package_resource,
                         'runtime:caddy:web',
                         'scanner:caddy:' + occurrence['id']],
                         self.store.lifecycle.decision(
                             decisions[0]['id'])['dependency_scopes'])

    def test_runtime_graph_covers_every_relationship_scope(self):
        coverage = {'discovery': {
            'runtime_sha256': 'd' * 64, 'gaps': [],
            'relationships': [{
                'subject': 'container:caddy:one', 'relation': 'MOUNTS',
                'object': 'host-path:caddy:/srv/data',
                'scope': 'runtime:caddy:mounts', 'kind': 'observation',
                'status': 'valid'}],
            'relationship_coverage': [{
                'scope': 'runtime:caddy:web',
                'relationship': 'runtime_ownership', 'complete': True,
                'status': 'valid', 'gaps': []}]}}
        graph = SNAP.lifecycle_graph(
            'caddy', 'one', 1, time.time(), coverage,
            {'deployments': [{'id': 'web'}]})

        covered = {item['scope']: item for item in graph['coverage']}
        self.assertIn('runtime:caddy:mounts', covered)
        self.assertTrue(covered['runtime:caddy:mounts']['complete'])

    def test_later_clean_package_observation_closes_only_after_graph_evaluation(self):
        def report(version, vulnerable):
            result = {'Type': 'gobinary', 'Target': '/srv/web/app',
                      'Packages': [{'Name': 'stdlib', 'Version': version,
                                    'FilePath': '/srv/web/app'}]}
            result['Vulnerabilities'] = ([{
                'VulnerabilityID': 'CVE-2026-8765', 'PkgName': 'stdlib',
                'InstalledVersion': version}] if vulnerable else [])
            return {'_homelab_library': {
                'deployment': 'web', 'path': '/srv/web', 'status': 'covered'},
                'Results': [result]}

        def runtime(identity):
            return {'discovery': {
                'runtime_sha256': identity, 'gaps': [],
                'relationships': [{
                    'subject': 'deployment:caddy:web', 'relation': 'RUNS_AS',
                    'object': 'service:caddy:web.service',
                    'scope': 'runtime:caddy:web', 'kind': 'observation',
                    'status': 'valid'}],
                'relationship_coverage': [{
                    'scope': 'runtime:caddy:web',
                    'relationship': 'runtime_ownership', 'complete': True,
                    'status': 'valid', 'gaps': []}]}}

        inventory = {'deployments': [{'id': 'web'}]}
        path = self.root/'resolution-outbox.json'
        SNAP.publish([report('1', True)], runtime('b' * 64), inventory, path,
                     self.settings, self.send)
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        occurrence = self.store.db.execute(
            "SELECT * FROM lifecycle_occurrences").fetchone()
        app = 'application:web'
        path_scope = 'paths:' + app
        self.store.lifecycle.stage_graph_change(
            'fixture-targetable-web', resources=[{
                'resource_key': app, 'kind': 'application', 'name': 'web'}],
            evidence=[{
                'id': 'fixture-targetable-web-evidence', 'kind': 'declaration',
                'scope': path_scope, 'source': 'fixture',
                'provenance': 'fixture:routes', 'status': 'complete',
                'content': {'targetable': True}}], assertions=[{
                'logical_key': 'fixture-targetable-web', 'version': 'one',
                'subject': app, 'relation': 'TARGETABLE_PATH', 'value': True,
                'kind': 'declaration', 'scope': path_scope, 'source': 'fixture',
                'provenance': 'fixture:routes',
                'evidence_id': 'fixture-targetable-web-evidence'}], coverage=[{
                'logical_key': 'fixture-targetable-web-coverage',
                'version': 'one', 'scope': path_scope,
                'relationship': 'ingress', 'producer': 'fixture',
                'complete': True, 'status': 'valid',
                'evidence_id': 'fixture-targetable-web-evidence'}])
        self.store.lifecycle.acknowledge_graph_change('fixture-targetable-web')
        first = self.store.lifecycle.evaluate_all()[0]
        self.assertEqual('work', first['result'])
        work = self.store.lifecycle.work(
            self.store.get_incident('CVE-2026-8765')['id'])
        self.assertNotEqual('closed', work['state'])

        SNAP.publish([report('2', False)], runtime('c' * 64), inventory, path,
                     self.settings, self.send)
        self.assertNotEqual('closed', self.store.lifecycle.work(work['id'])['state'])
        while change := self.store.lifecycle.pending_graph_change():
            self.store.lifecycle.acknowledge_graph_change(change['id'])
        decisions = self.store.lifecycle.evaluate_all()
        self.assertEqual('quiet', decisions[0]['result'])
        self.assertEqual('closed', self.store.lifecycle.work(work['id'])['state'])


if __name__ == '__main__':
    unittest.main()
