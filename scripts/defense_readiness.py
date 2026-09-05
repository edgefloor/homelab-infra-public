#!/usr/bin/env python3
"""Evaluate every deployment requirement. Observations never imply action approval."""
import argparse
import json
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from build_security_config import compile_configs
from cve_coverage_report import fresh, load

TYPE_ADAPTERS = {'python_installed': 'python-pkg', 'node_installed': 'node-pkg',
                 'dotnet_deps': 'dotnet-core', 'rust_artifact_sbom': 'rustbinary'}


def assess(config: dict, state: dict, status: dict, now: datetime) -> dict:
    valid = (status.get('status') == 'complete' and fresh(status.get('observed_at'), now)
             and fresh(state.get('updated_at'), now))
    coverage = state.get('coverage', {}) if valid else {}
    discovery = coverage.get('discovery', {})
    valid = valid and discovery.get('config_sha256') == hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    if not valid:
        coverage, discovery = {}, {}
    services = discovery.get('services', [])
    processes = discovery.get('processes', [])
    deployments = []
    for deployment in config['deployments']:
        name = deployment['id']
        scans = [s for s in coverage.get('libraries', []) if s['deployment'] == name]
        owned_services = [s for s in services if name in s.get('deployments', [])]
        pids = {int(s.get('MainPID') or 0) for s in owned_services}
        running = [p for p in processes if p['pid'] in pids]
        containers = [c for c in discovery.get('containers', []) if name in c.get('deployments', [])]
        images = [image for image in coverage.get('docker_images', [])
                  if any(c['image_id'] == image.get('image_id') for c in containers)]
        adapters = {}
        for adapter in deployment['adapters']:
            result = {'status': 'unknown', 'reason': 'no current evidence for this required adapter'}
            if not valid:
                result['reason'] = 'scan missing, failed, or stale'
            elif adapter == 'os_packages' and coverage.get('os_packages'):
                result = {'status': 'covered', 'reason': 'OS package database scanned; running-library identity is separate'}
            elif adapter in TYPE_ADAPTERS:
                selected = [s for s in scans if TYPE_ADAPTERS[adapter] in s.get('required_types', [])]
                analyzed = [s for s in selected if TYPE_ADAPTERS[adapter] in s.get('identified_types', [])]
                result = {'status': 'covered' if selected and len(selected) == len(analyzed) else ('failed' if any(s['status'] == 'failed' for s in selected) else 'unsupported'),
                          'reason': 'installed artifact inventory analyzed' if analyzed else 'no installed artifact inventory identified',
                          'paths': [s['path'] for s in selected],
                          'package_count': sum(sum(p['type'] == TYPE_ADAPTERS[adapter] for p in s['packages']) for s in analyzed)}
            elif adapter == 'container_image' and containers:
                ids = {image.get('image_id') for image in images}
                missing = [c['name'] for c in containers if c['image_id'] not in ids]
                result = {'status': 'partial' if missing else 'covered', 'reason': 'image contents scanned; mounts and writable layers are separate', 'unscanned_containers': missing}
            elif adapter == 'go_binary':
                matched = [g for g in coverage.get('native_go', []) if any(p['sha256'] == g['sha256'] for p in running)]
                result = {'status': 'covered' if matched else 'unknown',
                          'reason': 'scanned Go digest matches service executable' if matched else 'no scanned Go digest bound to this service',
                          'paths': [g['path'] for g in matched]}
            elif adapter == 'running_kernel' and discovery.get('kernel'):
                result = {'status': 'partial', 'reason': 'running release identified; advisory and loaded module correlation remains required', 'release': discovery['kernel']}
            elif adapter in {'native_libraries', 'runtime_mounts'} and discovery:
                result = {'status': 'partial', 'reason': 'runtime files and mounts discovered; content and advisory assessment remain required'}
            adapters[adapter] = result
        gaps = [adapter for adapter, result in adapters.items() if result['status'] != 'covered']
        layers = {
            'platform': {'status': 'partial' if coverage.get('os_packages') else 'unknown', 'reason': 'OS scan does not establish running kernel, driver, and runtime coverage'},
            'application': {'status': 'unknown', 'reason': 'declared upstream version is not a verified deployed version or vendor advisory check'},
            'dependencies': {'status': 'partial' if any(a['status'] == 'covered' for a in adapters.values()) else 'unknown', 'missing_adapters': gaps},
            'runtime': {'status': 'partial' if running or containers else 'unknown', 'reason': 'snapshot requires content binding and revalidation before a change'},
            'exposure': {'status': 'partial' if discovery.get('listeners') else 'unknown', 'reason': 'listeners observed; route and exploit-precondition assessment required'},
            'provenance': {'status': 'unknown', 'reason': 'build attestation bound to the deployed artifact is required'},
            'recovery': {'status': 'unknown', 'reason': 'candidate-specific restore rehearsal and health checks are required'},
        }
        deployments.append({'id': name, 'adapters': adapters, 'layers': layers,
                            'automatic_patch_eligible': False, 'automatic_emergency_eligible': False})
    return {'schema': 1, 'host': config['host'], 'observed_at': state.get('updated_at'),
            'scan_current': valid, 'discovery_gaps': discovery.get('gaps', ['discovery evidence missing']),
            'runtime_sha256': discovery.get('runtime_sha256'), 'deployments': deployments}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    now = datetime.now(UTC)
    hosts = [assess(config, load(args.directory / f'{name}.json'), load(args.directory / f'{name}.status.json'), now)
             for name, config in compile_configs().items()]
    report = {'schema': 1, 'generated_at': now.isoformat(), 'hosts': hosts}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    args.output.chmod(0o600)
    lines = ['# Deployment defense readiness', '', '| System | Current scan | Deployments | Required adapters with evidence | Discovery gaps |', '| --- | --- | ---: | ---: | ---: |']
    for host in hosts:
        adapters = [a for d in host['deployments'] for a in d['adapters'].values()]
        lines.append(f"| {host['host']} | {'Yes' if host['scan_current'] else 'Unknown'} | {len(host['deployments'])} | {sum(a['status'] == 'covered' for a in adapters)}/{len(adapters)} | {len(host['discovery_gaps'])} |")
    lines += ['', 'Counts describe explicit adapter evidence, not a safety score. Every deployment retains its missing evidence layers in the JSON report. Automatic changes are disabled.', '']
    markdown = args.output.with_suffix('.md')
    markdown.write_text('\n'.join(lines))
    markdown.chmod(0o600)
    print(f'{len(hosts)} systems evaluated; {sum(h["scan_current"] for h in hosts)} current scans; automatic changes disabled')


if __name__ == '__main__':
    main()
