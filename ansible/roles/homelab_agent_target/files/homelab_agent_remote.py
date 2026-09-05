#!/usr/bin/env python3
"""Forced SSH command exposing only service inspection and mapped restarts."""

from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


UNIT_FILE = Path("/etc/homelab-agent/units.json")
MAX_LOG_LINES = 80
MAX_EVIDENCE_REQUEST = 128 * 1024
EVIDENCE_GATEWAY = "/usr/local/libexec/homelab-evidence-gateway"


def run(argv: list[str], *, timeout: int = 30) -> dict[str, object]:
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": argv[0],
        "returncode": completed.returncode,
        "stdout": completed.stdout[-16000:].strip(),
        "stderr": completed.stderr[-4000:].strip(),
    }


def load_units() -> dict[str, str]:
    value = json.loads(UNIT_FILE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("unit map is not an object")
    units: dict[str, str] = {}
    for alias, unit in value.items():
        if not isinstance(alias, str) or not isinstance(unit, str):
            raise RuntimeError("unit map contains a non-string entry")
        units[alias] = unit
    return units


def inspect_unit(alias: str, unit: str) -> dict[str, object]:
    active = run(["/usr/bin/systemctl", "is-active", unit], timeout=10)
    properties = run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,Result,ExecMainStatus,NRestarts",
        ],
        timeout=10,
    )
    logs = run(
        [
            "/usr/bin/journalctl",
            "--unit",
            unit,
            "--lines",
            str(MAX_LOG_LINES),
            "--since",
            "-30 min",
            "--no-pager",
            "--output",
            "short-iso",
        ],
        timeout=20,
    )
    return {
        "alias": alias,
        "unit": unit,
        "active": active,
        "properties": properties,
        "logs": logs,
    }


def snapshot(units: dict[str, str], alias: str | None) -> dict[str, object]:
    selected = units if alias is None else {alias: units[alias]}
    return {
        "host": run(["/usr/bin/hostname"]),
        "uptime": run(["/usr/bin/uptime", "-p"]),
        "memory": run(["/usr/bin/free", "-h"]),
        "filesystems": run(["/usr/bin/df", "-h", "-x", "tmpfs", "-x", "devtmpfs"]),
        "failed_units": run(
            ["/usr/bin/systemctl", "--failed", "--no-pager", "--plain"]
        ),
        "services": [inspect_unit(name, unit) for name, unit in selected.items()],
    }


def main() -> int:
    units = load_units()
    command = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if not command:
        print(json.dumps({"error": "missing command"}))
        return 2

    action = command[0]
    alias = command[1] if len(command) == 2 else None
    root_prefix = [] if os.geteuid() == 0 else ['/usr/bin/sudo', '-n']
    if action == 'guest-proxy' and len(command) == 1:
        raw = sys.stdin.buffer.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError('guest request exceeds limit')
        completed = subprocess.run([*root_prefix, '/usr/local/libexec/homelab-guest-agent'],
                                   input=raw, capture_output=True, timeout=660)
        sys.stdout.buffer.write(completed.stdout)
        return completed.returncode
    if action == 'coverage' and len(command) == 1:
        raw = sys.stdin.buffer.read(256)
        completed = subprocess.run([*root_prefix, '/usr/local/libexec/homelab-coverage-read'],
                                   input=raw, capture_output=True, timeout=120)
        sys.stdout.buffer.write(completed.stdout)
        return completed.returncode
    if action == 'defense' and len(command) == 1:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('defense request exceeds limit')
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {'mode', 'action'} or payload['mode'] not in {'prepare', 'execute'}:
            raise ValueError('invalid defense request')
        completed = subprocess.run([*root_prefix, '/usr/local/libexec/homelab-defense'],
                                   input=json.dumps(payload), capture_output=True, text=True, timeout=600)
        if completed.stdout:
            print(completed.stdout.strip())
        return completed.returncode
    if action == "snapshot" and len(command) in (1, 2):
        if alias is not None and alias not in units:
            print(json.dumps({"error": "unknown service alias"}))
            return 2
        print(json.dumps(snapshot(units, alias), separators=(",", ":")))
        return 0

    if action == "restart" and alias is not None and alias in units:
        result = run(
            ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", units[alias]],
            timeout=90,
        )
        result["service"] = alias
        result["after"] = inspect_unit(alias, units[alias])
        print(json.dumps(result, separators=(",", ":")))
        return int(result["returncode"])

    if action == "evidence" and len(command) in (1, 2):
        try:
            if alias is None:
                raw = sys.stdin.buffer.read(MAX_EVIDENCE_REQUEST + 1)
            else:
                # Accept the previous controller during the gateway-first rollout.
                encoded = alias.encode("ascii")
                if len(encoded) > MAX_EVIDENCE_REQUEST * 2:
                    raise ValueError("encoded evidence request is too large")
                raw = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
            if len(raw) > MAX_EVIDENCE_REQUEST:
                raise ValueError("evidence request is too large")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("evidence request is not an object")
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return 2
        completed = subprocess.run(
            [*root_prefix, EVIDENCE_GATEWAY],
            input=json.dumps(payload, separators=(",", ":")),
            capture_output=True,
            text=True,
            timeout=360,
            check=False,
        )
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr[-4000:])
        return completed.returncode

    print(json.dumps({"error": "command is not allowed"}))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(1) from exc
