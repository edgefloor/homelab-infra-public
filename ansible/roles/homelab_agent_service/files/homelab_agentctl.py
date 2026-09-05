#!/usr/bin/env python3
"""Validated client for the forced-command homelab agent endpoints."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
from pathlib import Path


CONFIG = Path("/etc/homelab-agent/targets.json")
KEY = Path("/var/lib/homelab-agent/.ssh/id_ed25519")
MAX_EVIDENCE_REQUEST = 128 * 1024


def targets() -> dict[str, dict[str, object]]:
    value = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("target map is not an object")
    return value


def invoke(
    target: dict[str, object],
    remote_command: list[str],
    timeout: int,
    input_text: str | None = None,
) -> int:
    host = str(target["host"])
    if target.get('proxy_guest'):
        input_text = json.dumps({'guest': target['proxy_guest'], 'command': remote_command, 'input': input_text or ''})
        remote_command = ['guest-proxy']
        timeout += 30
    completed = subprocess.run(
        [
            "/usr/bin/ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
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


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("list")
    coverage_parser = subparsers.add_parser('coverage')
    coverage_parser.add_argument('--advisory', default='')
    defense_parser = subparsers.add_parser('defense')
    defense_parser.add_argument('target')
    defense_parser.add_argument('mode', choices=['prepare', 'execute'])
    defense_parser.add_argument('name')
    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("target")
    snapshot_parser.add_argument("service", nargs="?")
    restart_parser = subparsers.add_parser("restart")
    restart_parser.add_argument("target")
    restart_parser.add_argument("service")
    evidence_open_parser = subparsers.add_parser("evidence-open")
    evidence_open_parser.add_argument("target")
    evidence_call_parser = subparsers.add_parser("evidence-call")
    evidence_call_parser.add_argument("target")
    evidence_call_parser.add_argument("token")
    evidence_call_parser.add_argument("operation")
    evidence_close_parser = subparsers.add_parser("evidence-close")
    evidence_close_parser.add_argument("target")
    evidence_close_parser.add_argument("token")
    args = parser.parse_args()

    config = targets()
    if args.action == "list":
        print(json.dumps(config, separators=(",", ":")))
        return 0

    if args.action == 'coverage':
        payload = json.dumps({'advisory': args.advisory})
        def query(item):
            name, target = item
            argv = ['/usr/bin/sudo', '-n', '/usr/local/libexec/homelab-coverage-read'] if name == 'plan-runner' else [
                '/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
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
            results = list(pool.map(query, {**direct, 'plan-runner': {}}.items()))
        expected = json.loads((CONFIG.parent / 'coverage-systems.json').read_text())
        merged = {}
        for host in [host for result in results for host in result]:
            if host['host'] not in merged or host['status'] == 'unknown':
                merged[host['host']] = host
        for name in expected:
            merged.setdefault(name, {'host': name, 'status': 'unknown', 'reason': 'coverage source missing from fleet response'})
        print(json.dumps({'expected_systems': expected, 'hosts': list(merged.values())}))
        return 0

    if args.target not in config:
        parser.error("unknown target")
    target = config[args.target]
    if args.action == 'defense':
        return invoke(target, ['defense'], 610, json.dumps({'mode': args.mode, 'action': args.name}))
    services = target.get("services", {})
    if not isinstance(services, dict):
        raise RuntimeError("target service map is not an object")

    if args.action == "snapshot":
        if args.service is not None and args.service not in services:
            parser.error("unknown service")
        command = ["snapshot"] + ([args.service] if args.service else [])
        return invoke(target, command, 90)

    if args.action == "evidence-open":
        scope = json.load(sys.stdin)
        return evidence_request(target, {"action": "open", "scope": scope}, 60)

    if args.action == "evidence-call":
        arguments = json.load(sys.stdin)
        if not isinstance(arguments, dict):
            raise ValueError("evidence arguments must be an object")
        return evidence_request(
            target,
            {
                "action": "invoke",
                "token": args.token,
                "operation": args.operation,
                "arguments": arguments,
            },
            360,
        )

    if args.action == "evidence-close":
        return evidence_request(target, {"action": "close", "token": args.token}, 30)

    if args.service not in services:
        parser.error("unknown service")
    if target.get('restart_allowed') is False:
        parser.error('direct restarts are not exposed for this target; defensive changes require named root policy')
    return invoke(target, ["restart", args.service], 120)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1) from exc
