#!/usr/bin/env python3
"""Compile per-host discovery requirements; generated files contain no secrets."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml

from cve_coverage_report import expected_systems
from validate_security_coverage import ROOT, validate, validate_relationships
from validate_infrastructure_ownership import collect_ansible_hosts


def compile_configs(root: Path = ROOT) -> dict:
    def read(path):
        return yaml.safe_load((root / path).read_text())
    contract = read('inventory/security-coverage.yml')
    runtime = read('inventory/security-runtime.yml')
    managed_hosts, _ = collect_ansible_hosts(read('ansible/inventory/hosts.yml'))
    manifests = {value['id']: value for value in (yaml.safe_load(p.read_text()) for p in (root / 'apps').glob('*.yml'))}
    systems = set(expected_systems(read('ansible/inventory/hosts.yml'), read('inventory/workloads.yml')))
    validate(contract, set(manifests), systems)
    validate_relationships(contract, read('inventory/security-relationships.yml'))
    if set(runtime['systems']) != systems:
        raise ValueError('runtime scan configuration must account for every system')
    result = {host: {'schema': 1, 'host': host, 'deployments': [], **runtime['systems'][host]} for host in sorted(systems)}
    for name, profile in {**contract['applications'], **contract['additional_deployments']}.items():
        manifest = manifests.get(name, {})
        for host in profile['targets']:
            result[host]['deployments'].append({
                'id': name, 'adapters': profile['adapters'],
                'units': manifest.get('health', {}).get('expected_units', runtime['additional_units'].get(name, [])),
                'containers': runtime['containers'].get(name, []),
                'compose_services': runtime.get('container_services', {}).get(name, []),
                'owner': 'homelab', 'deployment_method': manifest.get('runtime', 'external_or_operational'),
                'declared_upstream': manifest.get('upstream', {}),
                'health': manifest.get('health', {}),
                'required_layers': list(contract['layers']),
            })
    for host, config in result.items():
        config['package_capabilities'] = []
        for declaration in runtime.get('package_capabilities', []):
            capability = {**declaration,
                          'applications': list(declaration.get('applications', []))}
            config['package_capabilities'].append(capability)
        config['execution_domains'] = []
        for declaration in runtime.get('execution_domains', []):
            targets = declaration.get('hosts') or []
            if host not in targets:
                continue
            required_lists = ('packages', 'files', 'entries', 'inputs',
                              'authority_paths')
            if (not declaration.get('id') or
                    declaration.get('disposition') not in
                    {'administrative_input_boundary', 'requires_work'} or
                    any(not isinstance(declaration.get(key), list)
                        for key in required_lists) or
                    any(not Path(path).is_absolute()
                        for key in ('files', 'operation_files', 'authority_paths',
                                    'elf_dependency_roots')
                        for path in declaration.get(key, []))):
                raise ValueError('invalid execution domain declaration')
            if (not isinstance(declaration.get('operation_files', []), list) or
                    not isinstance(declaration.get('elf_dependency_roots', []), list) or
                    (declaration.get('interpreter') and
                     not Path(declaration['interpreter']).is_absolute())):
                raise ValueError('invalid execution domain declaration')
            compiled = {key: value for key, value in declaration.items()
                        if key != 'hosts'}
            compiled['file_contracts'] = []
            for file_contract in declaration.get('file_contracts', []):
                file_contract = dict(file_contract)
                source = file_contract.get('source')
                if source:
                    source_path = root / source
                    if (not source_path.is_file() or
                            root.resolve() not in source_path.resolve().parents):
                        raise ValueError('invalid execution file contract source')
                    file_contract['source_sha256'] = hashlib.sha256(
                        source_path.read_bytes()).hexdigest()
                    file_contract['expected_sha256'] = file_contract['source_sha256']
                compiled['file_contracts'].append(file_contract)
            config['execution_domains'].append(compiled)
        config['execution_admission'] = dict(
            runtime.get('execution_admission', {}).get(host, {}))
        config['build_consumers'] = list(
            runtime.get('build_consumers', {}).get(host, []))
        config['configuration_roots'] = managed_hosts.get(host, {}).get('homelab_agent_evidence_config_roots',
            ['/etc/systemd/system', *({'firecrawl': ['/opt/firecrawl'], 'eu-law-db': ['/etc/postgresql']}.get(host, []))])
        config['expected_systems'] = sorted(systems)
        if host == 'proxmox':
            config['expected_guest_ids'] = {str(w['id']): w['name'] for w in read('inventory/workloads.yml')['inventory']['workloads']}
            # No external guest scanner or evidence endpoint is enrolled.
            config['external_guests'] = []
        config['deployments'].append({'id': 'defensive-monitor', 'adapters': ['python_runtime', 'source_identity', 'go_binary'],
                                     'units': ['homelab-cve-monitor.service'] + (['homelab-scan-watchdog.service'] if host in managed_hosts else []) + ['homelab-release-monitor.service', 'homelab-defense-recovery.service'],
                                     'containers': [], 'compose_services': [],
                                     'owner': 'homelab', 'deployment_method': 'native_systemd',
                                     'required_layers': list(contract['layers'])})
        deployments = {d['id'] for d in config['deployments']}
        for scan in config.get('libraries', []):
            if scan['deployment'] not in deployments or not Path(scan['path']).is_absolute() or '..' in Path(scan['path']).parts or not scan['types']:
                raise ValueError(f'invalid library scan on {host}')
    return result


def compile_lifecycle_graph(root: Path = ROOT) -> dict:
    """Compile declared routes and application input relationships."""
    model_version = 'infrastructure-graph/v3'
    route_derivation_rule = 'infrastructure-route-derivation/v3'
    route_path = root / 'inventory/routes.yml'
    relationship_path = root / 'inventory/security-relationships.yml'
    route_raw = route_path.read_bytes()
    relationship_raw = relationship_path.read_bytes()
    routing = yaml.safe_load(route_raw)['homelab_routing']
    relationship_inventory = yaml.safe_load(relationship_raw)
    contract = yaml.safe_load((root / 'inventory/security-coverage.yml').read_text())
    validate_relationships(contract, relationship_inventory)
    route_revision = hashlib.sha256(route_raw).hexdigest()
    relationship_revision = hashlib.sha256(relationship_raw).hexdigest()
    revision = hashlib.sha256(
        model_version.encode() + b'\0' + route_raw + b'\0' +
        relationship_raw).hexdigest()
    route_record_version = model_version + ':' + route_revision
    relationship_record_version = model_version + ':' + relationship_revision
    evidence_id = 'evidence_routes_' + route_revision
    relationship_evidence_id = 'evidence_relationships_' + relationship_revision
    resources = []
    assertions = []
    coverage = []
    seen = set()

    def resource(key, kind, name, **properties):
        if key not in seen:
            resources.append({'resource_key': key, 'kind': kind, 'name': name,
                              'properties': properties})
            seen.add(key)

    application_aliases = {
        'matrix': 'tuwunel', 'pangolin-dashboard': 'pangolin',
        'router': 'physical-router', 'apex': 'caddy', 'proxmox': 'hypervisor',
        'helix': 'helix-cve',
    }
    for route in routing['routes']:
        route_key = 'route:' + route['id']
        edge_key = 'edge:' + route['public_target']
        application = application_aliases.get(route['id'], route['id'])
        consumer_key = 'application:' + application
        scope = 'declared-routes:' + consumer_key
        resource(route_key, 'route', route['hostname'], route_id=route['id'])
        resource(edge_key, 'edge', route['public_target'])
        resource(consumer_key, 'application', application)

        def assertion(suffix, subject, relation, value, object_key=None,
                      derivation_refs=()):
            item = {
                'logical_key': 'route:' + route['id'] + ':' + suffix,
                'version': route_record_version, 'subject': subject,
                'relation': relation,
                'object_key': object_key, 'value': value, 'kind': 'declaration',
                'scope': scope, 'source': 'inventory/routes.yml',
                'provenance': 'sha256:' + route_revision, 'evidence_id': evidence_id,
            }
            if derivation_refs:
                item['kind'] = 'derived'
                item['provenance'] = ('derived:' + route_derivation_rule +
                                      ':sha256:' + route_revision)
                item['derivation'] = {
                    'rule': route_derivation_rule,
                    'input_evidence_ids': [evidence_id],
                    'input_refs': list(derivation_refs),
                }
            assertions.append(item)

        assertion('edge', edge_key, 'EXPOSES', True, route_key)
        assertion('consumer', route_key, 'ROUTES_TO', True, consumer_key)
        assertion('targetable', consumer_key, 'TARGETABLE_PATH',
                  route['public_target'] in {'home_dynamic', 'pangolin_vps'}, route_key,
                  ['inventory/routes.yml#route:' + route['id'] + ':public_target'])
        pangolin = route.get('pangolin', {})
        assertion('authentication', consumer_key, 'AUTHENTICATION_REQUIRED',
                  bool(pangolin.get('roles') or pangolin.get('auto_login_idp')), route_key,
                  ['inventory/routes.yml#route:' + route['id'] + ':pangolin-auth'])
        exceptions = [rule for rule in pangolin.get('policy_rules', [])
                      if rule.get('enabled') and rule.get('action') == 'allow']
        if exceptions:
            assertion('auth-exceptions', consumer_key, 'AUTH_EXCEPTION', True, route_key,
                      ['inventory/routes.yml#route:' + route['id'] + ':policy_rules'])
        if route.get('caddy', {}).get('internal_source_only'):
            assertion('source-restriction', consumer_key, 'SOURCE_RESTRICTION',
                      'declared_internal_only', route_key,
                      ['inventory/routes.yml#route:' + route['id'] +
                       ':caddy.internal_source_only'])
        coverage.append({
            'logical_key': 'coverage:' + scope,
            'version': route_record_version,
            'scope': scope, 'relationship': 'declared_route_membership',
            'producer': 'build_security_config.py', 'complete': True,
            'status': 'valid', 'evidence_id': evidence_id,
        })
    for name, source in relationship_inventory['input_sources'].items():
        source_key = 'input-source:' + name
        scope = 'input-source:' + name
        resource(source_key, 'input-source', name, evidence=source['evidence'])
        assertions.append({
            'logical_key': 'input-source:' + name,
            'version': relationship_record_version, 'subject': source_key,
            'relation': 'TARGETABLE_PATH', 'value': source['targetable'],
            'kind': 'declaration', 'scope': scope,
            'source': 'inventory/security-relationships.yml',
            'provenance': 'sha256:' + relationship_revision,
            'evidence_id': relationship_evidence_id,
        })
        coverage.append({
            'logical_key': 'coverage:' + scope,
            'version': relationship_record_version, 'scope': scope,
            'relationship': 'targetability',
            'producer': 'build_security_config.py', 'complete': True,
            'status': 'valid', 'evidence_id': relationship_evidence_id,
        })
    for name, mapping in relationship_inventory['applications'].items():
        app_key = 'application:' + name
        scope = 'input-paths:' + app_key
        resource(app_key, 'application', name)
        assertions.append({
            'logical_key': 'input-map:' + name,
            'version': relationship_record_version,
            'subject': app_key, 'relation': 'INPUT_PATHS_DECLARED',
            'value': True, 'kind': 'declaration', 'scope': scope,
            'source': 'inventory/security-relationships.yml',
            'provenance': 'sha256:' + relationship_revision,
            'evidence_id': relationship_evidence_id,
        })
        for index, item in enumerate(mapping['inputs']):
            if 'source' in item:
                object_key = 'input-source:' + item['source']
                resource(object_key, 'input-source', item['source'])
            else:
                object_key = 'application:' + item['application']
                resource(object_key, 'application', item['application'])
            assertions.append({
                'logical_key': 'input-map:' + name + ':' + str(index),
                'version': relationship_record_version, 'subject': app_key,
                'relation': item['relation'].upper(), 'object_key': object_key,
                'value': True, 'kind': 'declaration', 'scope': scope,
                'source': 'inventory/security-relationships.yml',
                'provenance': 'sha256:' + relationship_revision,
                'evidence_id': relationship_evidence_id,
            })
        coverage.append({
            'logical_key': 'coverage:' + scope,
            'version': relationship_record_version, 'scope': scope,
            'relationship': 'application_inputs',
            'producer': 'build_security_config.py',
            'complete': mapping['complete'],
            'status': 'valid' if mapping['complete'] else 'incomplete',
            'evidence_id': relationship_evidence_id,
        })
    return {
        'change_id': 'relationships:' + revision,
        'resources': resources,
        'evidence': [{
            'id': evidence_id, 'kind': 'declaration',
            'scope': 'inventory/routes.yml', 'source': 'inventory/routes.yml',
            'provenance': 'sha256:' + route_revision, 'status': 'complete',
            'content': route_raw.decode(),
        }, {
            'id': relationship_evidence_id, 'kind': 'declaration',
            'scope': 'inventory/security-relationships.yml',
            'source': 'inventory/security-relationships.yml',
            'provenance': 'sha256:' + relationship_revision,
            'status': 'complete', 'content': relationship_raw.decode(),
        }],
        'assertions': assertions,
        'coverage': coverage,
    }




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    configs = compile_configs()
    for host, config in configs.items():
        path = args.output / (host + '.json')
        path.write_text(json.dumps(config, indent=2) + '\n')
        path.chmod(0o600)
    inventory, _ = collect_ansible_hosts(yaml.safe_load((ROOT / 'ansible/inventory/hosts.yml').read_text()))
    targets = {name: {'host': values['ansible_host'], 'display_name': values.get('beszel_agent_system_name', name),
                      'services': values.get('homelab_agent_units', {})} for name, values in inventory.items()}
    for guest in configs['proxmox']['external_guests']:
        units = {unit.removesuffix('.service'): unit for deployment in configs[guest['name']]['deployments']
                 for unit in deployment.get('units', []) if not any(c in unit for c in '*?[')}
        path = args.output / (guest['name'] + '-units.json')
        path.write_text(json.dumps(units) + '\n')
        path.chmod(0o600)
    (args.output / 'agent-targets.json').write_text(json.dumps(targets, indent=2) + '\n')
    (args.output / 'agent-targets.json').chmod(0o600)
    (args.output / 'lifecycle-graph.json').write_text(
        json.dumps(compile_lifecycle_graph(), indent=2) + '\n')
    (args.output / 'lifecycle-graph.json').chmod(0o600)
    print('compiled deployment discovery requirements')


if __name__ == '__main__':
    main()
