#!/usr/bin/env python3
"""Validated client for the forced-command homelab agent endpoints."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import sys
from pathlib import Path


CONFIG = Path(os.environ.get("HOMELAB_AGENT_CONFIG", "/etc/homelab-investigator/targets.json"))
KEY = Path(os.environ.get('HOMELAB_AGENT_KEY', '/var/lib/homelab-investigator/.ssh/id_ed25519'))
KNOWN_HOSTS = Path(os.environ.get('HOMELAB_AGENT_KNOWN_HOSTS', '/var/lib/homelab-investigator/.ssh/known_hosts'))
MAX_EVIDENCE_REQUEST = 128 * 1024


def targets() -> dict[str, dict[str, object]]:
    value = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("target map is not an object")
    return value


def run_remote(
    target: dict[str, object],
    remote_command: list[str],
    timeout: int,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    host = str(target["host"])
    if target.get('proxy_guest'):
        input_text = json.dumps({'guest': target['proxy_guest'], 'command': remote_command, 'input': input_text or ''})
        remote_command = ['guest-proxy']
        timeout += 30
    return subprocess.run(
        [
            "/usr/bin/ssh", "-F", "/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-i",
            str(KEY),
            f"homelab-agent@{host}",
            *remote_command,
        ],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def invoke(
    target: dict[str, object],
    remote_command: list[str],
    timeout: int,
    input_text: str | None = None,
) -> int:
    completed = run_remote(target, remote_command, timeout, input_text)
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


def evidence_request(
    target: dict[str, object], payload: dict[str, object], timeout: int
) -> int:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    if len(raw) > MAX_EVIDENCE_REQUEST:
        raise ValueError("evidence request exceeds size limit")
    return invoke(target, ["evidence"], timeout, raw.decode("utf-8"))


def alert_store_target(
    config: dict[str, dict[str, object]],
) -> dict[str, object]:
    matches = [
        target for target in config.values()
        if isinstance(target.get("services"), dict)
        and "matrix-alerts" in target["services"]
    ]
    if len(matches) != 1:
        raise RuntimeError("expected exactly one deterministic alert store target")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("list")
    alerts_parser = subparsers.add_parser(
        'alerts', help='Read complete deterministic alert records from the Matrix bridge'
    )
    alerts_subparsers = alerts_parser.add_subparsers(dest='alerts_action', required=True)
    alerts_list = alerts_subparsers.add_parser('list')
    alerts_list.add_argument('--kind', default='')
    alerts_list.add_argument('--contains', default='')
    alerts_list.add_argument('--since', default='')
    alerts_list.add_argument('--limit', type=int, default=10)
    alerts_get = alerts_subparsers.add_parser('get')
    alerts_get.add_argument('record_id')
    coverage_parser = subparsers.add_parser('coverage')
    coverage_parser.add_argument('--advisory', default='')
    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("target")
    snapshot_parser.add_argument("service", nargs="?")
    observe_parser = subparsers.add_parser('observe', help='Read operational evidence on any managed target; no scanner finding required')
    observe_parser.add_argument('target')
    observe_parser.add_argument('operation')
    observe_parser.add_argument('arguments', nargs='?', default='{}', help='JSON object; see docs/cve-verification.md')
    bound_parser = subparsers.add_parser('snapshot-artifact', help='Inspect an artifact selected from acknowledged deployment coverage')
    bound_parser.add_argument('target')
    bound_parser.add_argument('operation', choices=['extract_file', 'inspect_executable', 'run_analyzer', 'prove_symbols', 'verify_replacement'])
    bound_parser.add_argument('arguments', help='JSON with snapshot_sha256, finding_sha256 and exact path')
    args = parser.parse_args()

    config = targets()
    if args.action == "list":
        print(json.dumps(config, separators=(",", ":")))
        return 0

    if args.action == 'alerts':
        if args.alerts_action == 'get':
            request_body = {'action': 'get', 'record_id': args.record_id}
        else:
            request_body = {
                'action': 'list',
                'kind': args.kind,
                'contains': args.contains,
                'limit': args.limit,
            }
            if args.since:
                request_body['since'] = args.since
        return invoke(
            alert_store_target(config), ['alerts'], 30,
            json.dumps(request_body, separators=(',', ':')),
        )

    if args.action == 'coverage':
        payload = json.dumps({'advisory': args.advisory, 'include_external': False})
        def query(item):
            name, target = item
            argv = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'UpdateHostKeys=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={KNOWN_HOSTS}',
                    '-i', str(KEY), f"homelab-agent@{target['host']}", 'coverage']
            try:
                result = subprocess.run(argv, input=payload, capture_output=True, text=True, timeout=125)
                if result.returncode or len(result.stdout) > 128 * 1024:
                    raise ValueError('coverage transport failed')
                return json.loads(result.stdout)['hosts']
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                return [{'host': name, 'status': 'unknown', 'reason': 'coverage transport failed'}]
        with ThreadPoolExecutor(max_workers=4) as pool:
            direct = {name: target for name, target in config.items() if not target.get('proxy_guest')}
            results = list(pool.map(query, direct.items()))
        expected = json.loads((CONFIG.parent / 'coverage-systems.json').read_text())
        merged = {}
        for host in [host for result in results for host in result]:
            if host['host'] not in config:
                continue
            if host['host'] not in merged or host['status'] == 'unknown':
                merged[host['host']] = host
        for name in expected:
            merged.setdefault(name, {'host': name, 'status': 'unknown', 'reason': 'coverage source missing from fleet response'})
        print(json.dumps({'expected_systems': expected, 'hosts': list(merged.values())}))
        return 0

    if args.target not in config:
        parser.error("unknown target")
    target = config[args.target]
    services = target.get("services", {})
    if not isinstance(services, dict):
        raise RuntimeError("target service map is not an object")

    if args.action == 'observe':
        return evidence_request(target, {'action': 'observe', 'operation': args.operation,
                                         'arguments': json.loads(args.arguments)}, 360)

    if args.action == 'snapshot-artifact':
        return evidence_request(target, {'action': 'snapshot_artifact', 'operation': args.operation,
                                         'arguments': json.loads(args.arguments)}, 360)

    if args.action == "snapshot":
        if args.service is not None and args.service not in services:
            parser.error("unknown service")
        command = ["snapshot"] + ([args.service] if args.service else [])
        return invoke(target, command, 90)

    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1) from exc
