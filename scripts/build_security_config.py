#!/usr/bin/env python3
"""Compile per-host discovery requirements; generated files contain no secrets."""
import argparse
import json
from pathlib import Path

import yaml

from cve_coverage_report import expected_systems
from validate_security_coverage import ROOT, validate
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
                'owner': 'homelab', 'deployment_method': manifest.get('runtime', 'external_or_operational'),
                'declared_upstream': manifest.get('upstream', {}),
                'health': manifest.get('health', {}),
                'required_layers': list(contract['layers']),
            })
    for host, config in result.items():
        config['configuration_roots'] = managed_hosts.get(host, {}).get('homelab_agent_evidence_config_roots',
            ['/etc/systemd/system', *({'firecrawl': ['/opt/firecrawl'], 'eu-law-db': ['/etc/postgresql']}.get(host, []))])
        config['expected_systems'] = sorted(systems)
        if host == 'proxmox':
            config['expected_guest_ids'] = {str(w['id']): w['name'] for w in read('inventory/workloads.yml')['inventory']['workloads']}
            config['external_guests'] = [{'id': w['id'], 'name': w['name']} for w in read('inventory/workloads.yml')['inventory']['workloads']
                                        if w['name'] in {'next-plaid', 'firecrawl', 'eu-law-db'}]
        config['deployments'].append({'id': 'defensive-monitor', 'adapters': ['python_runtime', 'source_identity', 'go_binary'],
                                     'units': ['homelab-cve-monitor.service', 'homelab-release-monitor.service', 'homelab-defense-recovery.service'],
                                     'containers': [], 'owner': 'homelab', 'deployment_method': 'native_systemd',
                                     'required_layers': list(contract['layers'])})
        deployments = {d['id'] for d in config['deployments']}
        for scan in config.get('libraries', []):
            if scan['deployment'] not in deployments or not Path(scan['path']).is_absolute() or '..' in Path(scan['path']).parts or not scan['types']:
                raise ValueError(f'invalid library scan on {host}')
    return result


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
        targets[guest['name']] = {'host': inventory['proxmox']['ansible_host'], 'proxy_guest': guest['id'],
                                 'display_name': guest['name'], 'services': units, 'restart_allowed': False}
        path = args.output / (guest['name'] + '-units.json')
        path.write_text(json.dumps(units) + '\n')
        path.chmod(0o600)
    (args.output / 'agent-targets.json').write_text(json.dumps(targets, indent=2) + '\n')
    (args.output / 'agent-targets.json').chmod(0o600)
    print('compiled deployment discovery requirements')


if __name__ == '__main__':
    main()
