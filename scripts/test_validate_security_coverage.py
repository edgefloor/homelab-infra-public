import copy
import unittest

import yaml

from build_security_config import compile_configs, compile_lifecycle_graph
from cve_coverage_report import expected_systems
from validate_security_coverage import ROOT, validate, validate_relationships


class SecurityCoverageTests(unittest.TestCase):
    def setUp(self):
        self.contract = yaml.safe_load((ROOT / "inventory/security-coverage.yml").read_text())
        self.relationships = yaml.safe_load(
            (ROOT / "inventory/security-relationships.yml").read_text())
        self.apps = {yaml.safe_load(p.read_text())["id"] for p in (ROOT / "apps").glob("*.yml")}
        self.systems = set(expected_systems(
            yaml.safe_load((ROOT / "ansible/inventory/hosts.yml").read_text()),
            yaml.safe_load((ROOT / "inventory/workloads.yml").read_text())))

    def test_compiler_preserves_declared_hosts_deployments_and_adapters(self):
        configs = compile_configs()
        self.assertEqual(set(configs), self.systems)
        profiles = {**self.contract['applications'], **self.contract['additional_deployments']}
        expected = {(host, name): set(profile['adapters'])
                    for name, profile in profiles.items() for host in profile['targets']}
        actual = {(host, deployment['id']): set(deployment['adapters'])
                  for host, config in configs.items() for deployment in config['deployments']
                  if deployment['id'] in profiles}
        self.assertEqual(actual, expected)
        self.assertEqual(['plan-runner'], configs['plan-runner']['build_consumers'])
        self.assertTrue(all(not capability.get('constraint_excludes')
            for config in configs.values()
            for capability in config['package_capabilities']))

    def test_network_ops_runtime_config_includes_finite_execution_domains(self):
        configs = compile_configs()
        domains = {item['id']: item for item in
                   configs['network-ops']['execution_domains']}

        self.assertIn('native-elf-inspection', domains)
        self.assertEqual(['/usr/bin/readelf',
                          '/usr/bin/x86_64-linux-gnu-readelf'],
                         domains['native-elf-inspection']['files'])
        self.assertIn('native-elf-declared-dependencies', domains)
        self.assertNotIn('native-elf-loaded-libraries', domains)
        self.assertNotIn('operator-binutils-tools', domains)
        self.assertEqual('administrative_input_boundary',
                         domains['forced-evidence-broker']['disposition'])
        gateway = next(item for item in
                       domains['native-elf-inspection']['file_contracts']
                       if item['path'] ==
                       '/usr/local/libexec/homelab-evidence-gateway')
        self.assertEqual(gateway['source_sha256'], gateway['expected_sha256'])
        self.assertEqual('python3.13-minimal',
                         domains['cloudflare-ddns-update']['packages'][0])
        self.assertEqual('/usr/local/libexec/cloudflare-ddns',
                         domains['cloudflare-ddns-update']['operation_files'][0])
        self.assertEqual('/usr/bin/python3.13',
                         domains['cloudflare-ddns-update']['interpreter'])
        self.assertEqual([], configs['caddy']['execution_domains'])

    def test_package_mapping_rollout_stages_the_complete_incident_runtime(self):
        path = ROOT / 'ansible/playbooks/cve-source-observations-full.yml'
        text = path.read_text()
        playbook = yaml.safe_load(text)
        refresh = next(play for play in playbook
                       if play['name'].startswith('Refresh package-consumer'))
        artifacts = refresh['vars']['mapping_collector_artifacts']
        self.assertEqual({
            ('homelab_cve_monitor.py', 'homelab-cve-monitor', '0755'),
            ('homelab_deployment_inventory.py',
             'homelab_deployment_inventory.py', '0644'),
            ('homelab_incident_snapshot.py',
             'homelab_incident_snapshot.py', '0644'),
            ('homelab_update_opportunities.py',
             'homelab-update-opportunities', '0755'),
        }, {(item['source'], item['destination'], item['mode'])
            for item in artifacts})
        tasks = {task['name']: task for task in refresh['tasks']}
        compile_script = tasks['Verify the deployed collectors compile'][
            'ansible.builtin.command']['argv'][-1]
        self.assertIn('/usr/local/libexec/homelab-update-opportunities',
                      compile_script)
        hashes = tasks['Read deployed collector hashes']
        self.assertEqual('{{ mapping_collector_artifacts }}', hashes['loop'])
        verification = tasks['Verify deployed collector hashes']
        self.assertEqual('{{ mapping_collector_hashes.results }}',
                         verification['loop'])
        self.assertRegex(text, r"item\.item\.source,\s+rstrip=False\)")
        self.assertGreaterEqual(text.count('cve_lifecycle.py'), 4)
        self.assertIn('new_cve_lifecycle.py', text)
        self.assertIn('Verify deployed incident runtime hashes', text)
        self.assertIn("relationship['derivation']", text)

    def test_shared_gap_runtime_rollout_includes_helix_adapter(self):
        path = ROOT / 'ansible/playbooks/cve-source-observations-runtime.yml'
        play = yaml.safe_load(path.read_text())[0]
        tasks = {task['name']: task for task in play['tasks']}
        required = {'incident_store.py', 'cve_lifecycle.py',
                    'helix_lifecycle.py'}

        for name in ('Back up the deployed incident runtime modules',
                     'Stage the reviewed incident runtime modules'):
            self.assertEqual(required, set(tasks[name]['loop']))
        compile_script = tasks[
            'Verify staged incident modules compile before pausing ingestion'][
                'ansible.builtin.command']['argv'][-2]
        self.assertIn("'helix_lifecycle.py'", compile_script)

        install = tasks[
            'Install the reviewed lifecycle runtime with ingestion paused']
        install_tasks = {task['name']: task for task in install['block']}
        self.assertEqual(required, set(install_tasks[
            'Install the reviewed incident runtime modules']['loop']))
        self.assertEqual(required, set(install_tasks[
            'Read deployed incident runtime hashes']['loop']))
        restore_tasks = {task['name']: task for task in install['rescue']
                         if 'name' in task}
        self.assertEqual(required, set(restore_tasks[
            'Restore the previous runtime after a failed install']['loop']))

    def test_lifecycle_graph_separates_declared_routes_from_derived_claims(self):
        graph = compile_lifecycle_graph()
        routes = yaml.safe_load((ROOT / 'inventory/routes.yml').read_text())['homelab_routing']['routes']
        route_nodes = [r for r in graph['resources'] if r['kind'] == 'route']
        self.assertEqual({r['id'] for r in routes},
                         {r['resource_key'].removeprefix('route:') for r in route_nodes})
        self.assertGreater(len(route_nodes), 2)
        exceptions = [a for a in graph['assertions'] if a['relation'] == 'AUTH_EXCEPTION']
        expected = [r for r in routes if any(rule.get('enabled') and rule.get('action') == 'allow'
                    for rule in r.get('pangolin', {}).get('policy_rules', []))]
        self.assertEqual(len(expected), len(exceptions))
        declared = [a for a in graph['assertions']
                    if a['relation'] in {'EXPOSES', 'ROUTES_TO'}]
        derived = [a for a in graph['assertions']
                   if a['relation'] in {'TARGETABLE_PATH',
                                        'AUTHENTICATION_REQUIRED',
                                        'AUTH_EXCEPTION', 'SOURCE_RESTRICTION'} and
                   a['source'] == 'inventory/routes.yml']
        self.assertTrue(all(a['kind'] == 'declaration' for a in declared))
        self.assertTrue(all(a['kind'] == 'derived' for a in derived))
        self.assertTrue(all(a['derivation']['rule'] ==
                            'infrastructure-route-derivation/v3'
                            for a in derived))
        self.assertTrue(all(a['derivation']['input_evidence_ids'] ==
                            [graph['evidence'][0]['id']] for a in derived))
        self.assertTrue(graph['evidence'][0]['provenance'].startswith('sha256:'))

    def test_new_app_requires_profile(self):
        with self.assertRaisesRegex(ValueError, "application coverage drift"):
            validate(self.contract, self.apps | {"new-app"}, self.systems)

    def test_every_deployment_has_an_input_mapping(self):
        validate_relationships(self.contract, self.relationships)
        changed = copy.deepcopy(self.contract)
        changed['additional_deployments']['new-service'] = {
            'targets': ['caddy'], 'adapters': ['go_binary']}
        with self.assertRaisesRegex(ValueError, 'input relationship drift'):
            validate_relationships(changed, self.relationships)

    def test_input_mapping_rejects_unknown_relationship_targets(self):
        changed = copy.deepcopy(self.relationships)
        changed['applications']['caddy']['inputs'][0]['source'] = \
            'not-a-recorded-source'
        with self.assertRaisesRegex(ValueError, 'unknown input source'):
            validate_relationships(self.contract, changed)

    def test_lifecycle_graph_contains_indirect_input_paths_and_coverage(self):
        graph = compile_lifecycle_graph()
        edges = {(item['subject'], item['relation'], item.get('object_key'))
                 for item in graph['assertions']}
        self.assertIn(('application:crowdsec', 'CONSUMES_LOGS_FROM',
                       'application:caddy'), edges)
        self.assertIn(('application:plan-runner', 'RECEIVES_JOBS_FROM',
                       'input-source:github-actions'), edges)
        covered = {item['scope']: item['complete'] for item in graph['coverage']}
        self.assertTrue(covered['input-paths:application:crowdsec'])
        self.assertFalse(covered['input-paths:application:next-plaid'])

    def test_new_system_cannot_disappear(self):
        with self.assertRaisesRegex(ValueError, "systems missing"):
            validate(self.contract, self.apps, self.systems | {"new-host"})

    def test_target_typo_rejected(self):
        next(iter(self.contract["applications"].values()))["targets"] = ["undeclared-test-host"]
        with self.assertRaisesRegex(ValueError, "unknown target"):
            validate(self.contract, self.apps, self.systems)

    def test_requirement_missing_rejected(self):
        next(iter(self.contract["applications"].values()))["adapters"] = []
        with self.assertRaisesRegex(ValueError, "missing targets or required adapters"):
            validate(self.contract, self.apps, self.systems)

    def test_autonomy_cannot_be_enabled_without_executor_contract(self):
        for field in ("patching_enabled", "emergency_measures_enabled"):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                contract["autonomy"][field] = True
                with self.assertRaisesRegex(ValueError, "no authorized executor"):
                    validate(contract, self.apps, self.systems)

    def test_recovery_cannot_be_omitted(self):
        del self.contract["layers"]["recovery"]
        with self.assertRaisesRegex(ValueError, "seven evidence layers"):
            validate(self.contract, self.apps, self.systems)
