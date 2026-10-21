#!/usr/bin/env python3
"""Capability-scoped, read-only evidence gateway for homelab investigations."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import secrets
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import threading
import urllib.request
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Any

POLICY_FILE = Path("/etc/homelab-agent/evidence-policy.json")
UNIT_FILE = Path("/etc/homelab-agent/units.json")
CAPABILITY_DIR = Path("/run/homelab-evidence-gateway")
SCAN_STATE_DIR = Path('/var/lib/homelab-update-monitor')
INCIDENT_CONFIG = Path('/etc/homelab-update-monitor/incident.json')
MAX_SCAN_AGE = 36 * 3600
CAPABILITY_TTL = 1800
MAX_REQUEST_BYTES = 128 * 1024
MAX_CALLS = 160
MAX_RESULT_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_EXTRACT_BYTES = 64 * 1024
MAX_ANALYZER_BYTES = 8 * 1024 * 1024
GOVULNCHECK = Path('/usr/local/bin/govulncheck')
SYMBOL_PROOF = Path('/usr/local/libexec/homelab-go-symbol-proof')
GO_VULN_DB = 'https://vuln.go.dev'
ANALYZER_ADAPTER_VERSION = 2
GOVULNCHECK_OPTIONS = ('-format', 'json', '-mode', 'binary', '-scan', 'symbol', '-db', GO_VULN_DB)
OPERATIONS = {
    'prove_symbols',
    'verify_replacement',
    'advisory_record',
    "list_processes",
    "list_listeners",
    "inspect_executable",
    "read_proc_maps",
    "extract_file",
    "container_metadata",
    "package_info",
    "read_config",
    "service_state",
    "run_analyzer",
    "discover_config",
    "deployment_coverage",
    "network_state",
    "firewall_query",
}
ARTIFACT_OPERATIONS = {"extract_file", "inspect_executable", "run_analyzer", 'prove_symbols', 'verify_replacement'}
# Operational reads are authorized by the installed host policy, not by a scanner
# finding. Artifact extraction and analysis still require a bound artifact identity.
OBSERVATIONS = OPERATIONS - ARTIFACT_OPERATIONS
DENIED_PATH = re.compile(
    r"(^|/)(?:priv|secrets?|credentials?|\.ssh|\.aws)(/|$)|"
    r"(^|/)(?:\.env(?:\..*)?|shadow|gshadow|passwd-|id_(?:rsa|ecdsa|ed25519)|"
    r"[^/]*\.(?:key|pem)|[^/]*(?:secret|token|credential|password|private[_-]?key|key[_-]?pair)[^/]*)$",
    re.IGNORECASE,
)
SECRET_LINE = re.compile(
    r"(?i)^(?P<prefix>\s*[^#\n:=]*(?:secret|token|password|credential|"
    r"private[_-]?key|api[_-]?key|access[_-]?key)"
    r"[^#\n:=]*\s*[:=]\s*)(?P<value>.*)$"
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}")
CVE_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+|GO-\d{4}-\d+)", re.I)
NFT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@+\-]{0,127}")
NFT_FAMILIES = {"ip", "ip6", "inet", "arp", "bridge", "netdev"}


def bounded_run(
    argv: list[str], timeout: int = 30, input_text: str | None = None
) -> dict[str, Any]:
    if input_text is not None:
        raise ValueError("Evidence commands do not accept input scripts")
    result = limited_output_run(argv, timeout, MAX_RESULT_BYTES)
    return {
        "returncode": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "truncated": result["overflow"] or result["timed_out"],
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            total += len(chunk)
            if total > 256 * 1024 * 1024:
                raise ValueError("Artifact grew beyond the analysis limit")
            digest.update(chunk)
    return digest.hexdigest()


def limited_output_run(
    argv: list[str],
    timeout: int,
    byte_limit: int,
    *,
    disk_root: Path | None = None,
    disk_limit: int = 0,
) -> dict[str, Any]:
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=(
            {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(disk_root),
                "TMPDIR": str(disk_root),
                "GOTELEMETRY": "off",
            }
            if disk_root
            else {**os.environ, "GOTELEMETRY": "off"}
        ),
        cwd=str(disk_root) if disk_root else None,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("analyzer pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    overflow = False
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if (
                disk_root
                and sum(p.stat().st_size for p in disk_root.rglob("*") if p.is_file())
                > disk_limit
            ):
                overflow = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            if remaining <= 0:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            for key, _mask in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                if sum(len(value) for value in buffers.values()) > byte_limit:
                    overflow = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
            if overflow:
                break
        returncode = process.wait(timeout=10)
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()
    return {
        "returncode": returncode,
        "stdout": bytes(buffers["stdout"]).decode(errors="replace"),
        "stderr": bytes(buffers["stderr"][:8192]).decode(errors="replace"),
        "overflow": overflow,
        "timed_out": timed_out,
    }


def parse_json_stream(value: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    messages: list[dict[str, Any]] = []
    position = 0
    while position < len(value):
        while position < len(value) and value[position].isspace():
            position += 1
        if position >= len(value):
            break
        message, position = decoder.raw_decode(value, position)
        if not isinstance(message, dict) or len(message) != 1:
            raise ValueError('Analyzer stream contains an invalid message')
        messages.append(message)
    return messages


def summarize_govulncheck(value: str, advisory: str) -> dict[str, Any]:
    messages = parse_json_stream(value)
    if not messages or not isinstance(messages[0].get('config'), dict):
        raise ValueError('Analyzer returned no initial configuration')
    config = messages[0]['config']
    mode, scan_level = config.get('scan_mode'), config.get('scan_level')
    if (config.get('protocol_version') != 'v1.0.0' or mode not in {'binary', 'source'}
            or scan_level not in {'module', 'package', 'symbol'}):
        raise ValueError('Unsupported analyzer protocol, mode, or scan level')
    if sum('config' in m for m in messages) != 1:
        raise ValueError('Conflicting analyzer configurations')
    sboms = [m['SBOM'] for m in messages if 'SBOM' in m]
    if (len(sboms) != 1 or not isinstance(sboms[0], dict)
            or not isinstance(sboms[0].get('modules'), list) or not sboms[0]['modules']):
        raise ValueError('Analyzer returned no module inventory')
    if any(not isinstance(m, dict) or not isinstance(m.get('path'), str) or not m['path']
           for m in sboms[0]['modules']):
        raise ValueError('Invalid analyzer module inventory')
    warnings = []
    for message in messages:
        key = next(iter(message))
        if key not in {'config', 'SBOM', 'osv', 'finding', 'progress'} or not isinstance(message[key], dict):
            raise ValueError('Unsupported analyzer message')
        if key == 'progress':
            progress = str(message[key].get('message') or '')
            if 'warning' in progress.lower():
                warnings.append(progress[:1000])
        if key == 'finding':
            finding = message[key]
            trace = finding.get('trace')
            if (not isinstance(finding.get('osv'), str) or not finding['osv']
                    or not isinstance(trace, list) or not trace
                    or any(not isinstance(f, dict) or not isinstance(f.get('module'), str) or not f['module'] for f in trace)):
                raise ValueError('Invalid analyzer finding trace')
            for frame in trace:
                if any(k in frame and not isinstance(frame[k], str) for k in ('version', 'package', 'function', 'receiver')):
                    raise ValueError('Invalid analyzer trace field')
            if mode == 'binary' and len(trace) != 1:
                raise ValueError('Binary analysis cannot establish a call trace')
    advisory_upper = advisory.upper()
    matched_osvs: dict[str, dict[str, Any]] = {}
    all_osvs = set()
    for message in messages:
        osv = message.get("osv")
        if osv is None:
            continue
        if (not isinstance(osv.get('id'), str) or not osv['id']
                or not isinstance(osv.get('aliases', []), list)
                or any(not isinstance(a, str) for a in osv.get('aliases', []))):
            raise ValueError('Invalid advisory identity')
        all_osvs.add(osv['id'])
        identifiers = {str(osv["id"]).upper()} | {
            str(alias).upper() for alias in osv.get("aliases") or []
        }
        if advisory_upper in identifiers:
            matched_osvs[str(osv["id"])] = osv
    if any(m['finding']['osv'] not in all_osvs for m in messages if 'finding' in m):
        raise ValueError('Finding refers to an advisory missing from the stream')

    levels: list[str] = []
    symbols: set[str] = set()
    packages: set[str] = set()
    modules: set[str] = set()
    versions: dict[tuple[str, str, str], dict] = {}
    call_paths = []
    for message in messages:
        finding = message.get("finding")
        if not isinstance(finding, dict) or str(finding.get("osv")) not in matched_osvs:
            continue
        trace = finding.get("trace") or []
        # The protocol orders traces from the vulnerable symbol to the entry point.
        frame = trace[0]
        if frame.get("module") and frame.get("version"):
            key = (frame["module"], frame["version"], finding.get("fixed_version", ""))
            versions[key] = dict(zip(("module", "installed", "fixed"), key))
        if frame.get("function"):
            levels.append("symbol")
            package = str(frame.get("package") or "")
            function = str(frame["function"])
            receiver = str(frame.get("receiver") or "")
            symbol = ".".join(filter(None, (package, receiver, function)))
            symbols.add(symbol)
            if mode == 'source' and len(trace) > 1 and all(f.get('function') for f in trace):
                levels.append('call_path')
                call_paths.append([{k: f[k] for k in ('module', 'version', 'package', 'function', 'receiver') if k in f}
                                   for f in trace[:20]])
        elif frame.get("package"):
            levels.append("package")
            packages.add(str(frame["package"]))
        elif frame.get("module"):
            levels.append("module")
            modules.add(str(frame["module"]))
    evidence_level = next(
        (
            level
            for level in ("call_path", "symbol", "package", "module")
            if level in levels
        ),
        "none",
    )
    status = evidence_level + '_reported' if evidence_level != 'none' else 'not_reported'
    interpretation = {
        'call_path_reported': 'Static source analysis reported a path to an affected symbol. Deployment reachability is not established.',
        'symbol_reported': 'The analyzer reported an affected symbol. This does not establish runtime invocation or exposure.',
        'package_reported': 'The analyzer reported an affected package. Deeper evidence is not established.',
        'module_reported': 'The analyzer reported an affected module version. Package and symbol presence are not established.',
        'not_reported': 'The analyzer reported no matching finding at this scan level. This is not a safety verdict.',
    }[status]
    depth = {'module': 1, 'package': 2, 'symbol': 3, 'call_path': 4, 'none': 0}
    checks = {level: 'reported' if depth[evidence_level] >= depth[level] else
              'not_reported' if depth[scan_level] >= depth[level] else 'not_checked'
              for level in ('module', 'package', 'symbol')}
    checks['call_path'] = 'reported' if evidence_level == 'call_path' else (
        'not_reported' if mode == 'source' and scan_level == 'symbol' else 'not_checked')
    advisories = [
        {
            "id": osv_id,
            "aliases": osv.get("aliases") or [],
            "summary": str(osv.get("summary") or "")[:2000],
            "details": str(osv.get("details") or "")[:4000],
            'modified': osv.get('modified'),
            'withdrawn': osv.get('withdrawn'),
            'sha256': hashlib.sha256(json.dumps(osv, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        }
        for osv_id, osv in matched_osvs.items()
    ]
    return {
        "status": status,
        'evidence_level': evidence_level,
        'checks': checks,
        'artifact_applicability': 'not_established',
        'deployment_exposure': 'not_assessed',
        'compromise_evidence': 'not_assessed',
        'replacement_verification': 'not_assessed',
        'analysis_config': {k: config.get(k) for k in ('protocol_version', 'scanner_name', 'scanner_version',
                           'scan_mode', 'scan_level', 'db', 'db_last_modified')},
        "interpretation": interpretation,
        "advisories": advisories,
        "symbols": sorted(symbols)[:100],
        "packages": sorted(packages)[:100],
        "modules": sorted(modules)[:100],
        "affected_versions": list(versions.values())[:100],
        'call_paths': call_paths[:20],
        'warnings': warnings[:20],
        "truncated": any(
            len(items) > 100 for items in (symbols, packages, modules, versions)
        ) or len(call_paths) > 20 or len(warnings) > 20 or any(len(m['finding']['trace']) > 20 for m in messages if 'finding' in m),
        "limitations": [
            'Binary mode does not compute call paths. Symbol reports may use a conservative fallback when binary symbol extraction is incomplete; this wrapper does not independently verify symbol provenance.',
            'Missing reports do not prove absence. Reflection, unsafe code, incomplete build metadata, and analyzer limitations can leave visibility gaps.',
            'Listed fixed versions are advisory metadata, not verified replacement artifacts. Exit code 0 in JSON mode is not a vulnerability verdict.'
        ],
    }


def audit(event: dict[str, Any]) -> None:
    record = json.dumps(
        {"time": int(time.time()), **event}, separators=(",", ":"), sort_keys=True
    )
    subprocess.run(
        [
            "/usr/bin/systemd-cat",
            "--identifier=homelab-evidence-gateway",
            "--priority=info",
        ],
        input=record + "\n",
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )


def read_json_file(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not a JSON object")
    return value


def safe_identifier(value: Any, label: str) -> str:
    text = str(value or "")
    if not IDENTIFIER.fullmatch(text):
        raise ValueError(f"invalid {label}")
    return text


def safe_absolute_path(value: Any, label: str = "path") -> str:
    text = str(value or "")
    path = Path(text)
    if not text.startswith("/") or ".." in path.parts or len(text) > 1024:
        raise ValueError(f"invalid {label}")
    return str(path)


class ContainerLookupError(ValueError):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.details = {'code': code, 'runtime': 'docker', **details}


def docker_lookup(argv, stage, timeout):
    lookup = {'stage': stage, 'argv': argv[:48], 'omitted_arguments': max(0, len(argv)-48)}
    try:
        result = bounded_run(argv, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ContainerLookupError('runtime_lookup_failed', 'Docker lookup could not execute', lookup=lookup) from exc
    if result['returncode'] != 0 or result.get('truncated'):
        raise ContainerLookupError('runtime_lookup_failed', 'Docker lookup failed or returned incomplete output',
                                   lookup=lookup, returncode=result['returncode'], truncated=bool(result.get('truncated')))
    return result['stdout'], lookup


def docker_inventory(*, include_stopped=False) -> dict[str, dict]:
    if not Path("/usr/bin/docker").exists():
        if include_stopped:
            raise ContainerLookupError('runtime_lookup_failed', 'Docker runtime is unavailable',
                                       lookup={'stage': 'runtime', 'executable': '/usr/bin/docker'})
        return {}
    listed, lookup = docker_lookup(['/usr/bin/docker', 'ps', '--all', '--quiet', '--no-trunc'], 'list', 20)
    ids = listed.splitlines()
    if any(not re.fullmatch('[0-9a-f]{64}', value) for value in ids) or len(set(ids)) != len(ids):
        raise ContainerLookupError('runtime_lookup_failed', 'Invalid Docker container inventory', lookup=lookup)
    if not ids:
        return {}
    # Select only non-secret identity/state fields. Never return Config.Env.
    template = ('{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},'
                '"image_ref":{{json .Config.Image}},"running":{{json .State.Running}},'
                '"state":{{json .State.Status}},"pid":{{json .State.Pid}}}')
    inspected, lookup = docker_lookup(['/usr/bin/docker', 'inspect', '--type=container', '--format', template, *ids], 'inspect', 30)
    try:
        records = [json.loads(line) for line in inspected.splitlines()]
        if len(records) != len(ids) or {r['id'] for r in records} != set(ids):
            raise ValueError('partial inventory')
        for item in records:
            if (not isinstance(item['name'], str) or not item['name'] or
                    not re.fullmatch('sha256:[0-9a-f]{64}', item['image_id']) or
                    type(item['running']) is not bool or type(item['pid']) is not int or item['pid'] < 0 or
                    (item['running'] and item['pid'] == 0) or
                    not isinstance(item['state'], str) or not isinstance(item['image_ref'], str)):
                raise ValueError('invalid identity/state record')
    except (ValueError, KeyError, TypeError) as exc:
        raise ContainerLookupError('runtime_lookup_failed', 'Invalid or partial Docker inspection output', lookup=lookup) from exc
    inventory = {}
    for item in records:
        if not include_stopped and not item['running']:
            continue
        item = {**item, 'name': item['name'].lstrip('/'), 'short_id': item['id'][:12]}
        for key in (item["id"], item["short_id"], item["name"]):
            if key in inventory and inventory[key]['id'] != item['id']:
                raise ContainerLookupError('runtime_lookup_failed', 'Ambiguous Docker identity', lookup=lookup)
            inventory[key] = item
    return inventory


def resolve_container(inventory, requested, artifact_id='', *, stage='bind'):
    requested = {key: str(requested.get(key) or '')[:256] for key in ('id', 'name')}
    candidate = inventory.get(requested['id']) or inventory.get(requested['name'].lstrip('/'))
    details = {'requested': requested, 'lookup': {'stage': stage, 'method': 'full-id, short-id, then name'},
               'resolved': candidate}
    if candidate is None:
        raise ContainerLookupError('not_found', 'Reported container was not found in the Docker inventory', **details)
    if requested['id'] and requested['id'] not in (candidate['id'], candidate['short_id']):
        raise ContainerLookupError('identity_changed', 'Running container identity no longer matches the alert', **details)
    if not candidate.get('running', True):
        raise ContainerLookupError('not_running', 'Resolved container is not running', **details)
    if artifact_id and candidate['image_id'] != artifact_id:
        raise ContainerLookupError('identity_changed', 'Running container image no longer matches the alert', **details)
    return candidate


def normalized_scope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 2:
        raise ValueError("scope must be a schema-2 finding object")
    groups = value.get("groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 20:
        raise ValueError("scope must contain 1-20 finding groups")

    inventory = None
    containers: dict[str, dict[str, str]] = {}
    packages: set[str] = set()
    advisories: set[str] = set()
    artifacts: set[str] = set()
    reported_files: set[str] = set()
    bindings: list[dict[str, Any]] = []
    occurrence_count = 0

    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("finding group is not an object")
        advisory = safe_identifier(group.get("id"), "advisory identifier")
        package = safe_identifier(group.get("package"), "package")
        advisories.add(advisory)
        packages.add(package)
        occurrences = group.get("occurrences") or []
        if not isinstance(occurrences, list):
            raise ValueError("occurrences must be a list")
        occurrence_count += len(occurrences)
        if occurrence_count > 40:
            raise ValueError("scope contains more than 40 occurrences")
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                raise ValueError("occurrence is not an object")
            artifact = str(occurrence.get("artifact") or "host rootfs")
            artifact_id = str(occurrence.get("artifact_id") or "")
            artifacts.add(artifact)
            for digest in occurrence.get("repo_digests") or []:
                artifacts.add(str(digest))
            reported = occurrence.get("reported_file")
            if reported:
                reported_files.add(safe_absolute_path(reported, "reported file"))
            for requested in occurrence.get("containers") or []:
                if not isinstance(requested, dict):
                    raise ValueError("container scope is not an object")
                if inventory is None:
                    try:
                        inventory = docker_inventory(include_stopped=True)
                    except ContainerLookupError as exc:
                        exc.details['requested'] = {k: str(requested.get(k) or '')[:256] for k in ('id','name')}
                        raise
                candidate = resolve_container(inventory, requested, artifact_id)
                containers[candidate["name"]] = candidate
                bindings.append(
                    {
                        "container_id": candidate["id"],
                        "advisory": advisory,
                        "package": package,
                        "artifact": artifact,
                        "reported_file": reported,
                    }
                )
            if not occurrence.get("containers"):
                bindings.append(
                    {
                        "container_id": None,
                        "advisory": advisory,
                        "package": package,
                        "artifact": artifact,
                        "artifact_id": artifact_id,
                        "reported_file": reported,
                    }
                )

    policy = read_json_file(POLICY_FILE)
    config_roots = [
        safe_absolute_path(path, "configuration root")
        for path in policy.get("config_roots", [])
    ]
    config_files = [
        safe_absolute_path(path, "configuration file")
        for path in policy.get("config_files", [])
    ]
    return {
        "schema": 2,
        "bindings": bindings,
        "discovered_files": {},
        "analyzer_cache": {},
        "candidate_cache": {},
        "containers": list(containers.values()),
        "packages": sorted(packages),
        "advisories": sorted(advisories),
        "artifacts": sorted(artifacts),
        "reported_files": sorted(reported_files),
        "config_roots": config_roots,
        "config_files": config_files,
        "services": sorted(read_json_file(UNIT_FILE)),
    }


def capability_path(token: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("invalid capability token")
    return CAPABILITY_DIR / (hashlib.sha256(token.encode()).hexdigest() + ".json")


def open_capability(scope: Any, *, operational: bool = False) -> dict[str, Any]:
    CAPABILITY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CAPABILITY_DIR, 0o700)
    token = secrets.token_hex(32)
    policy = read_json_file(POLICY_FILE)
    if operational:
        normalized = {
            "operational": True, "bindings": [], "advisories": [], "packages": [],
            "containers": list({c['id']: c for c in docker_inventory().values()}.values()),
            "config_roots": policy.get("config_roots", []),
            "config_files": policy.get("config_files", []),
            "services": sorted(read_json_file(UNIT_FILE)), "discovered_files": {},
        }
    else:
        normalized = normalized_scope(scope)
    path_count = len(scope.get("deployed_paths") or normalized["containers"]) or 1
    calls = min(
        int(policy.get("max_calls", MAX_CALLS)),
        8 + 4 * len(normalized["advisories"]) + 8 * path_count,
    )
    total_bytes = min(
        int(policy.get("max_total_bytes", MAX_TOTAL_BYTES)), calls * MAX_RESULT_BYTES
    )
    ttl = min(int(policy.get("max_seconds", CAPABILITY_TTL)), 600 + 300 * path_count)
    if calls < 1 or total_bytes < MAX_RESULT_BYTES or ttl < 30:
        raise ValueError("Invalid evidence resource policy")
    capability = {
        "schema": 2,
        "created": int(time.time()),
        "expires": int(time.time()) + ttl,
        "calls": 0,
        "bytes": 0,
        "pending": {},
        "cache": {},
        "scope": normalized,
        "limits": {"calls": calls, "total_bytes": total_bytes},
    }
    path = capability_path(token)
    path.write_text(json.dumps(capability, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    audit({"action": "open", "capability": path.stem[:16], "status": "ok"})
    return {
        "protocol": 2,
        "token": token,
        "expires_at": capability["expires"],
        "operations": sorted(OPERATIONS),
        "limits": capability["limits"],
        "config_roots": normalized["config_roots"],
        "services": normalized["services"],
    }


def scoped_container(
    scope: dict[str, Any], value: Any, *, optional: bool = False
) -> dict[str, str] | None:
    if value in (None, "") and optional:
        return None
    requested = str(value or "")
    for container in scope["containers"]:
        if requested in (container["name"], container["id"], container["short_id"]):
            return container
    raise ContainerLookupError('policy_denied', 'container is outside the capability scope', requested={'container': requested[:256]})


def container_argv(container: dict[str, str] | None, argv: list[str]) -> list[str]:
    return ["/usr/bin/docker", "exec", container["id"], *argv] if container else argv


def process_ids(container: dict[str, str] | None) -> list[int]:
    if container:
        result = bounded_run(
            ["/usr/bin/docker", "top", container["id"], "-eo", "pid"], 20
        )
        require_command(result)
        values = result["stdout"].splitlines()[1:]
    else:
        values = [path.name for path in Path("/proc").glob("[0-9]*")]
    return [int(value.strip()) for value in values if value.strip().isdigit()][:200]


def allowed_reported_file(
    scope: dict[str, Any], value: Any, container: dict | None = None
) -> str:
    path = safe_absolute_path(value)
    identity = container["id"] if container else None
    allowed = {
        b["reported_file"]
        for b in scope.get("bindings", [])
        if b["container_id"] == identity
    }
    allowed.update(scope.get("discovered_files", {}).get(identity or "host", []))
    if not scope.get("bindings"):
        allowed.update(scope["reported_files"])
    if DENIED_PATH.search(path) or path not in allowed:
        raise ContainerLookupError('policy_denied', 'file is outside the reported artifact scope',
                                   runtime='docker' if container else 'host', requested={'path': path, 'container_id': identity})
    return path


def copy_container_file(
    container: dict[str, str],
    path: str,
    destination: Path,
    max_bytes: int = 256 * 1024 * 1024,
) -> None:
    # Stream one regular tar member, without unpacking paths or following a symlink.
    # Docker need not find a shell, stat, or other utilities inside a minimal image.
    process = subprocess.Popen(
        ["/usr/bin/docker", "cp", f"{container['id']}:{path}", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            member = archive.next()
            if not member or not member.isfile() or member.size > max_bytes:
                raise ValueError("Reported artifact is not a bounded regular file")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Container file extraction failed")
            with destination.open("xb") as output:
                while chunk := stream.read(64 * 1024):
                    output.write(chunk)
            if archive.next() is not None:
                raise ValueError("Container extraction returned more than one file")
        if process.wait(timeout=5) != 0:
            raise ValueError("Container file extraction failed")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()


def host_binary_digests(scope: dict, path: str) -> set[str]:
    expected = {b.get("artifact_id", "") for b in scope.get("bindings", [])
                if b.get("container_id") is None and b.get("reported_file") == path}
    expected = {value.removeprefix('sha256:') for value in expected
                if re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', value)}
    return expected


def validate_host_binary(scope: dict, path: str, digest: str) -> None:
    expected = host_binary_digests(scope, path)
    if expected and expected != {digest}:
        raise ValueError("Host executable changed since the scan; fresh detection is required")


def open_bound_host_file(path: str) -> int:
    """Resolve links through pinned directories; never let open follow a link.

    Only digest-bound captures use this traversal. The caller verifies the
    captured digest before exposing bytes to any parser.
    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open('/', directory_flags)
    pending = path.split('/')
    links = steps = 0
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                              value.st_mtime_ns, value.st_ctime_ns)
    try:
        while pending:
            name = pending.pop(0)
            steps += 1
            if steps > 1024:
                raise ValueError('Artifact path exceeds traversal limit')
            if name in ('', '.'):
                continue
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                links += 1
                if links > 40:
                    raise ValueError('Artifact path exceeds symlink limit')
                target = os.readlink(name, dir_fd=directory)
                if identity(before) != identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
                    raise ValueError('Artifact path changed during capture')
                if target.startswith('/'):
                    root = os.open('/', directory_flags)
                    os.close(directory)
                    directory = root
                pending = target.split('/') + pending
                continue
            flags = directory_flags if pending else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            descriptor = os.open(name, flags, dir_fd=directory)
            if identity(before) != identity(os.fstat(descriptor)):
                os.close(descriptor)
                raise ValueError('Artifact path changed during capture')
            if not pending:
                return descriptor
            os.close(directory)
            directory = descriptor
        raise ValueError('Artifact path does not select a regular file')
    finally:
        os.close(directory)


def capture_host_file(path: str, destination: Path,
                      max_bytes: int = 256 * 1024 * 1024,
                      expected_digests: set[str] | None = None) -> str:
    """Copy one stable host file so its digest and metadata use identical bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = open_bound_host_file(path) if expected_digests else os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError("Reported artifact is not a bounded regular file")
        digest = hashlib.sha256()
        copied = 0
        with destination.open("xb") as output:
            while chunk := os.read(descriptor, 64 * 1024):
                copied += len(chunk)
                if copied > max_bytes:
                    raise ValueError("Reported artifact is not a bounded regular file")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or copied != after.st_size:
            raise ValueError("Host executable changed during capture; fresh evidence is required")
        captured = digest.hexdigest()
        if expected_digests and expected_digests != {captured}:
            raise ValueError('Host executable changed since the scan; fresh detection is required')
        if file_sha256(destination) != captured:
            raise ValueError("Host executable capture failed its digest check")
        return captured
    finally:
        os.close(descriptor)


def inspect_executable(
    scope: dict[str, Any], arguments: dict[str, Any]
) -> dict[str, Any]:
    container = scoped_container(scope, arguments.get("container"), optional=True)
    path = allowed_reported_file(scope, arguments.get("path"), container)
    with tempfile.TemporaryDirectory(prefix="homelab-evidence-") as directory:
        local = Path(directory) / "artifact"
        if container:
            copy_container_file(container, path, local)
        else:
            digest = capture_host_file(path, local, expected_digests=host_binary_digests(scope, path))
        if local.is_symlink() or not local.is_file():
            raise ValueError("reported executable is not a regular file")
        if local.stat().st_size > 256 * 1024 * 1024:
            raise ValueError("Executable exceeds analysis size limit")
        digest = file_sha256(local) if container else digest
        if not container:
            validate_host_binary(scope, path, digest)
        file_result = bounded_run(["/usr/bin/file", "-Lb", str(local)], 20)
        require_command(file_result)
        dynamic = bounded_run(["/usr/bin/readelf", "-d", str(local)], 20)
        needed = [
            line.strip()
            for line in dynamic["stdout"].splitlines()
            if "(NEEDED)" in line or "(INTERP)" in line
        ][:100]
        return {
            "path": path,
            "sha256": digest,
            "format": file_result["stdout"].strip(),
            "dynamic_dependencies": needed,
            "linkage_status": "success"
            if dynamic["returncode"] == 0
            else "unavailable",
            "go_build": go_build_info(local, scope, container, path, digest),
            "limitations": [
                "Static symbol presence does not prove runtime invocation."
            ],
        }


def prove_symbols(scope, arguments):
    symbols = arguments.get('symbols')
    if (not isinstance(symbols, list) or not 1 <= len(symbols) <= 20
            or any(not isinstance(s, str) or not 0 < len(s) <= 512 or '\x00' in s for s in symbols)):
        raise ValueError('provide one to twenty exact Go symbol names')
    container = scoped_container(scope, arguments.get('container'), optional=True)
    path = allowed_reported_file(scope, arguments.get('path'), container)
    with tempfile.TemporaryDirectory(prefix='homelab-symbol-proof-') as directory:
        local = Path(directory)/'artifact'
        if container:
            copy_container_file(container, path, local)
        else:
            local = Path(path)
        digest = file_sha256(local)
        if not container:
            validate_host_binary(scope, path, digest)
        result = bounded_run([str(SYMBOL_PROOF), str(local), *symbols], 20)
        require_command(result)
        report = json.loads(result['stdout'])
        if report.get('sha256') != digest or file_sha256(local) != digest:
            raise ValueError('symbol evidence does not match the bound executable')
        return {**report, 'reader_sha256': file_sha256(SYMBOL_PROOF), 'deployment_exposure': 'not_assessed'}


def compare_replacement(baseline, candidate):
    result = {'verified_fix': False, 'deployment_exposure': 'not_assessed',
              'limitations': ['Comparison verifies artifact evidence, not runtime safety, compatibility, or absence of other vulnerabilities.']}
    if baseline.get('sha256') and baseline.get('sha256') == candidate.get('sha256'):
        return {**result, 'status': 'same_executable', 'reason': 'The candidate contains exactly the same executable bytes. This is not a binary remediation.'}
    valid = {'not_reported', 'module_reported', 'package_reported', 'symbol_reported'}
    if baseline.get('status') not in valid or candidate.get('status') not in valid:
        return {**result, 'status': 'visibility_gap', 'reason': 'Both artifacts need valid analyzer evidence.'}
    before = baseline.get('cache', {}).get('identity')
    after = candidate.get('cache', {}).get('identity')
    if not before or not after or {k:v for k,v in before.items() if k != 'executable_sha256'} != {k:v for k,v in after.items() if k != 'executable_sha256'}:
        return {**result, 'status': 'visibility_gap', 'reason': 'Analyzer or advisory database revisions differ.'}
    if candidate['status'] != 'not_reported':
        return {**result, 'status': 'match_retained', 'reason': 'The replacement still has an analyzer report for this advisory.'}
    return {**result, 'status': 'match_removed' if baseline['status'] != 'not_reported' else 'no_demonstrated_improvement',
            'reason': 'The exact candidate has no report at the checked analyzer level. This alone is not a safety verdict.'}


def verify_replacement(scope, arguments):
    from artifact_replacement import fetch
    container = scoped_container(scope, arguments.get('container'))
    path = allowed_reported_file(scope, arguments.get('path'), container)
    platform = bounded_run(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Os}}/{{.Architecture}}', container['image_id']], 20)
    require_command(platform)
    if platform['stdout'].strip() != 'linux/amd64':
        raise ValueError('replacement comparison currently requires a linux/amd64 deployment')
    baseline = run_analyzer(scope, {**arguments, 'analyzer': 'govulncheck'})
    if not baseline.get('sha256'):
        return {'status': 'unavailable', 'reason': 'Current artifact analysis is unavailable', 'baseline': baseline}
    with tempfile.TemporaryDirectory(prefix='homelab-replacement-') as directory:
        local, provenance = fetch(container['image_ref'], arguments.get('candidate', 'latest'), path,
                                  Path(directory), limited_output_run)
        candidate_sha = file_sha256(local)
        candidate_scope = {'containers': [], 'advisories': scope['advisories'], 'bindings': [
            {'container_id': None, 'reported_file': str(local), 'artifact_id': candidate_sha}]}
        candidate = run_analyzer(candidate_scope, {'path': str(local), 'advisory': arguments['advisory'], 'analyzer': 'govulncheck'})
        comparison = compare_replacement(baseline, candidate)
        def compact(report):
            result = {k:report[k] for k in ('sha256', 'status', 'evidence_level', 'checks', 'analysis_config', 'cache', 'limitations') if k in report}
            result['go_build'] = {k:v for k,v in report.get('go_build', {}).items() if k != 'modules'}
            return result
        return {'status': 'observed', 'comparison': comparison, 'candidate_identity': provenance,
                'artifact_sha256': {'baseline': baseline['sha256'], 'candidate': candidate_sha},
                'baseline': compact(baseline), 'candidate': compact(candidate),
                'storage': 'temporary image layers and executable removed when the request exits'}


def configuration_locations(scope: dict, container: dict) -> list[dict]:
    """Map approved host configuration to this container's actual bind mounts."""
    result = bounded_run(
        ["/usr/bin/docker", "inspect", "--format", "{{json .Mounts}}", container["id"]],
        20,
    )
    require_command(result)
    locations = []
    roots = [Path(p).resolve() for p in scope["config_roots"]]
    for mount in json.loads(result["stdout"]):
        if mount.get("Type") != "bind":
            continue
        source = Path(safe_absolute_path(mount.get("Source")))
        destination = safe_absolute_path(mount.get("Destination"))
        if DENIED_PATH.search(str(source)) or DENIED_PATH.search(destination):
            continue
        resolved = source.resolve()
        if not any(resolved.is_relative_to(root) for root in roots):
            continue
        if not resolved.is_file() and not resolved.is_dir():
            continue
        locations.append(
            {
                "path": destination,
                "source": str(source),
                "kind": "file" if resolved.is_file() else "directory",
            }
        )
    return locations


def startup_configuration(container: dict) -> dict:
    result = bounded_run(
        [
            "/usr/bin/docker",
            "inspect",
            "--format",
            "{{json .Path}}\t{{json .Args}}",
            container["id"],
        ],
        20,
    )
    require_command(result)
    executable, raw = result["stdout"].strip().split("\t", 1)
    arguments = json.loads(raw)
    paths = []
    for index, value in enumerate(arguments):
        for option in ("--config", "-config", "--config-file"):
            path = (
                arguments[index + 1]
                if value == option and index + 1 < len(arguments)
                else value[len(option) + 1 :]
                if value.startswith(option + "=")
                else ""
            )
            if path.startswith("/") and not DENIED_PATH.search(path):
                paths.append(safe_absolute_path(path))
    return {
        "executable": json.loads(executable),
        "configuration_paths": paths,
        "resume_requested": "--resume" in arguments,
        "meaning": "Configuration arguments passed at container startup; other arguments are not disclosed.",
    }


def parse_go_build_info(blob: bytes) -> dict:
    """Read Go 1.18+ inline build metadata, never executing the target binary."""
    if len(blob) < 32 or not blob.startswith(b"\xff Go buildinf:") or not blob[15] & 2:
        raise ValueError("No supported inline Go build metadata")
    position = 32

    def text():
        nonlocal position
        size = 0
        for shift in range(0, 70, 7):
            if position >= len(blob):
                raise ValueError("Incomplete Go build metadata")
            value = blob[position]
            position += 1
            size |= (value & 127) << shift
            if not value & 128:
                break
        else:
            raise ValueError("Invalid Go metadata length")
        if size > 1024 * 1024 or position + size > len(blob):
            raise ValueError("Go metadata exceeds section bounds")
        result = blob[position : position + size]
        position += size
        return result

    version = text().decode("utf-8")
    framed = text()
    if not version.startswith("go1.") or len(framed) < 33 or framed[-17:-16] != b"\n":
        raise ValueError("Invalid Go module metadata")
    lines = framed[16:-16].decode("utf-8").splitlines()
    modules, settings, main, package = [], {}, {}, ""
    previous = None
    for line in lines:
        parts = line.split("\t")
        if parts[0] == "path" and len(parts) == 2:
            package = parts[1]
        elif parts[0] in ("mod", "dep") and len(parts) >= 3:
            previous = {"path": parts[1], "version": parts[2]}
            if parts[0] == "mod":
                main = previous
            else:
                modules.append(previous)
        elif parts[0] == "=>" and previous is not None:
            previous["replaced"] = True
        elif parts[0] == "build" and len(parts) == 2 and "=" in parts[1]:
            key, value = parts[1].split("=", 1)
            if key in {"CGO_ENABLED", "GOOS", "GOARCH", "vcs.revision", "vcs.modified"}:
                settings[key] = value
    if len(modules) > 500:
        raise ValueError("Go module metadata exceeds supported size")
    return {
        "status": "available",
        "go_version": version,
        "package": package,
        "main": main,
        "modules": modules,
        "settings": settings,
    }


def go_build_info(
    local: Path, scope: dict, container: dict | None, path: str, digest: str
) -> dict:
    sections = bounded_run(["/usr/bin/readelf", "-SW", str(local)], 20)
    match = re.search(
        r"\.go\.buildinfo\s+PROGBITS\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
        sections["stdout"],
    )
    if sections["returncode"] or sections.get("truncated") or not match:
        return {"status": "unavailable", "reason": "No readable Go build-info section"}
    offset, size = (int(v, 16) for v in match.groups())
    if size > 1024 * 1024 or offset + size > local.stat().st_size:
        return {"status": "unavailable", "reason": "Invalid Go section bounds"}
    try:
        with local.open("rb") as handle:
            handle.seek(offset)
            build = parse_go_build_info(handle.read(size))
    except (ValueError, UnicodeError) as exc:
        return {"status": "unavailable", "reason": str(exc)}
    identity = (container["id"] if container else "host") + ":" + path
    scope.setdefault("binary_metadata", {})[identity] = {**build, "sha256": digest}
    return build


def package_commands(package: str) -> list[tuple[str, list[str]]]:
    return [
        (
            "debian",
            ["/usr/bin/dpkg-query", "-W", "-f=${Status} ${Version}\\n", package],
        ),
        ("files", ["/usr/bin/dpkg-query", "-L", package]),
        ("dependencies", ["/usr/bin/apt-cache", "depends", package]),
        ("installed_reverse_dependencies", ["/usr/bin/apt-cache", "--installed", "rdepends", package]),
        ("manually_installed", ["/usr/bin/apt-mark", "showmanual", package]),
        ("alpine", ["/sbin/apk", "info", "-a", package]),
        ("rpm", ["/usr/bin/rpm", "-qi", package]),
    ]


def package_info(scope: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    package = safe_identifier(arguments.get("package"), "package")
    if not scope.get("operational") and package not in scope["packages"]:
        raise ValueError("package is outside the capability scope")
    container = scoped_container(scope, arguments.get("container"), optional=True)
    results: dict[str, Any] = {}
    for name, command in package_commands(package):
        try:
            result = bounded_run(container_argv(container, command), 30)
        except FileNotFoundError:
            continue
        if result["returncode"] == 0 and not result.get("truncated"):
            results[name] = result["stdout"].splitlines()[:200]
    return results or {
        "status": "unavailable",
        "reason": "no supported package manager matched",
    }


def read_config(scope: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    path = safe_absolute_path(arguments.get("path"))
    if DENIED_PATH.search(path):
        raise ValueError("credential-like paths are never readable")
    container = scoped_container(scope, arguments.get("container"), optional=True)
    locations = configuration_locations(scope, container) if container else []
    roots = [Path(root) for root in scope["config_roots"]]
    approved_files = set(scope.get("config_files", []))

    def allowed(value, *, resolved=False):
        if approved_files:
            if container:
                mounted = [item for item in locations if value == item["path"] or (
                    item["kind"] == "directory" and Path(value).is_relative_to(item["path"])
                )]
                if not mounted:
                    return False
                # A more specific bind mount can shadow a directory mount.
                item = max(mounted, key=lambda location: len(Path(location["path"]).parts))
                host_path = Path(item["source"]) / Path(value).relative_to(item["path"])
                return any(
                    not Path(approved).is_symlink()
                    and host_path == Path(approved)
                    and host_path.resolve() == Path(approved).resolve()
                    for approved in approved_files
                )
            if not resolved:
                return value in approved_files
            return any(not Path(item).is_symlink() and
                       Path(value) == Path(item).resolve() for item in approved_files)
        checked_roots = [root.resolve() for root in roots] if resolved else roots
        return any(Path(value).is_relative_to(root) for root in checked_roots) or any(
            value == item["path"]
            or (
                item["kind"] == "directory" and Path(value).is_relative_to(item["path"])
            )
            for item in locations
        )

    if not allowed(path):
        raise ValueError(
            "configuration path is outside the approved roots and mounted configuration"
        )
    if container:
        resolved = bounded_run(
            [
                "/usr/bin/docker",
                "exec",
                container["id"],
                "/usr/bin/readlink",
                "-f",
                path,
            ],
            20,
        )["stdout"].strip()
        if not resolved or not allowed(resolved) or DENIED_PATH.search(resolved):
            raise ValueError("configuration symlink escapes the allow-listed roots")
        with tempfile.TemporaryDirectory(prefix="homelab-config-") as directory:
            local = Path(directory) / "config"
            copy_container_file(container, resolved, local, MAX_CONFIG_BYTES)
            content = local.read_text(encoding="utf-8", errors="replace")
        truncated = False
    else:
        resolved_path = Path(path).resolve(strict=True)
        if not allowed(str(resolved_path), resolved=True) or DENIED_PATH.search(str(resolved_path)):
            raise ValueError("configuration symlink escapes the allow-listed roots")
        with resolved_path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
            truncated = len(raw) > MAX_CONFIG_BYTES
            content = raw[:MAX_CONFIG_BYTES].decode("utf-8", errors="replace")
    redacted = []
    redacted_indent: int | None = None
    redacted_private_key = False
    for line in content.splitlines():
        if redacted_private_key:
            if "-----END " in line and "PRIVATE KEY-----" in line:
                redacted_private_key = False
            continue
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            redacted.append("[REDACTED PRIVATE KEY]")
            redacted_private_key = not ("-----END " in line and "PRIVATE KEY-----" in line)
            continue
        indent = len(line) - len(line.lstrip())
        if redacted_indent is not None:
            if not line.strip() or indent > redacted_indent:
                continue
            redacted_indent = None
        match = SECRET_LINE.match(line)
        if match:
            value = match.group("value").strip().rstrip(",")
            redacted.append(match.group("prefix") + "[REDACTED]")
            if value in {"", "|", ">", "|-", ">-", "|+", ">+"}:
                redacted_indent = indent
        else:
            redacted.append(line)
    return {
        "path": path,
        "content": "\n".join(redacted),
        "truncated": truncated,
    }


def govulncheck_database_revision() -> dict | None:
    """Read only the fixed public metadata endpoint, never a caller-selected URL."""
    url = GO_VULN_DB + '/index/db.json'
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.geturl() != url:
                return None
            raw = response.read(8193)
        if len(raw) > 8192:
            return None
        value = json.loads(raw)
        modified = value.get('modified') if isinstance(value, dict) else None
        if not isinstance(modified, str) or not modified.endswith('Z'):
            return None
        datetime.fromisoformat(modified.replace('Z', '+00:00'))
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'modified': modified, 'sha256': hashlib.sha256(canonical).hexdigest()}
    except (OSError, ValueError):
        return None


def analyzer_cache_identity(digest: str, advisory: str, analyzer_digest: str, revision: dict) -> dict:
    # Exact executable bytes carry platform and build properties. Container names,
    # paths, process state, and exposure are deliberately not reusable binary facts.
    return {'executable_sha256': digest, 'advisory': advisory,
            'analyzer_sha256': analyzer_digest, 'adapter_version': ANALYZER_ADAPTER_VERSION,
            'options': list(GOVULNCHECK_OPTIONS), 'database': {'url': GO_VULN_DB, **revision}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('evidence service redirects are not permitted')


def shared_cache_call(action, identity, **values):
    settings = read_json_file(INCIDENT_CONFIG)
    payload = {'kind': 'incident_api', 'action': 'artifact_cache_'+action, 'identity': identity, **values}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 70*1024:
        raise ValueError('shared evidence request exceeds limit')
    req = urllib.request.Request(settings['url'], data=raw, headers={
        'Authorization': 'Bearer '+settings['token'], 'Content-Type': 'application/json',
        'X-Homelab-Incident-API': '1'})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=5) as response:
        data = response.read(70*1024+1)
    if len(data) > 70*1024:
        raise ValueError('shared evidence response exceeds limit')
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError('invalid shared evidence response')
    return result


@contextmanager
def shared_analysis(identity):
    lease = None
    enabled = identity is not None and INCIDENT_CONFIG.is_file()
    try:
        response = shared_cache_call('acquire', identity) if enabled else {'status': 'local'}
        lease = response.get('lease') if response.get('status') == 'acquired' else None
        yield response
    finally:
        if lease:
            try:
                shared_cache_call('release', identity, lease=lease)
            except (OSError, ValueError):
                pass  # Published or expired leases are already fenced; crashes expire too.


def run_analyzer(scope: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    analyzer = str(arguments.get("analyzer") or "")
    if analyzer != "govulncheck":
        raise ValueError("analyzer is not allow-listed")
    container = scoped_container(scope, arguments.get("container"), optional=True)
    path = allowed_reported_file(scope, arguments.get("path"), container)
    advisory = safe_identifier(arguments.get("advisory"), "advisory identifier")
    if advisory not in scope["advisories"]:
        raise ValueError("advisory is outside the capability scope")
    with tempfile.TemporaryDirectory(prefix="homelab-evidence-") as directory:
        local = Path(directory) / "artifact"
        if container:
            copy_container_file(container, path, local)
        else:
            capture_host_file(path, local, expected_digests=host_binary_digests(scope, path))
        if (
            local.is_symlink()
            or not local.is_file()
            or local.stat().st_size > 256 * 1024 * 1024
        ):
            raise ValueError("Analyzer input is not a bounded regular file")
        digest = file_sha256(local)
        if not container:
            validate_host_binary(scope, path, digest)
        build = go_build_info(local, scope, container, path, digest)
        if not GOVULNCHECK.exists():
            return {"status": "unavailable", "reason": "govulncheck is not installed"}
        analyzer_digest = file_sha256(GOVULNCHECK)
        revision = govulncheck_database_revision()
        identity = analyzer_cache_identity(digest, advisory, analyzer_digest, revision) if revision else None
        cache_key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest() if identity else None
        cached = scope.get('analyzer_cache', {}).get(cache_key) if cache_key else None
        if cached and cached.get('cache', {}).get('identity') == identity:
            if file_sha256(local) != digest or file_sha256(GOVULNCHECK) != analyzer_digest:
                return {'status': 'unavailable', 'reason': 'Executable or analyzer changed during cache validation'}
            return {**cached, 'executable': path, 'go_build': build, 'reused_analysis': True}
        try:
            with shared_analysis(identity) as shared:
                if shared['status'] == 'hit':
                    cached = shared['report']
                    if (cached.get('cache', {}).get('identity') != identity
                            or cached.get('sha256') != digest
                            or cached.get('deployment_exposure') != 'not_assessed'
                            or file_sha256(local) != digest or file_sha256(GOVULNCHECK) != analyzer_digest):
                        return {'status': 'unavailable', 'reason': 'shared artifact identity validation failed'}
                    return {**cached, 'executable': path, 'go_build': build, 'reused_analysis': True,
                            'shared_provenance': {k: shared[k] for k in ('publisher', 'generation', 'published_at', 'expires')}}
                if shared['status'] not in {'acquired', 'local'}:
                    return {'status': 'unavailable', 'reason': shared.get('reason', 'shared analysis unavailable')}
                result = analyze_executable(local, path, digest, build, analyzer, analyzer_digest, advisory, revision, identity)
                if result.get('cache', {}).get('eligible'):
                    stored = {k: v for k, v in result.items() if k not in {'executable', 'go_build'}}
                    if len(json.dumps(stored).encode()) > 64*1024:
                        result['cache'].update(eligible=False, reason='report exceeds cache admission limit')
                    else:
                        cache = scope.setdefault('analyzer_cache', {})
                        if len(cache) >= 16:
                            cache.pop(next(iter(cache)))
                        cache[cache_key] = stored
                        if shared['status'] == 'acquired':
                            stored['cache']['storage'] = 'shared'
                            publication = shared_cache_call('publish', identity, lease=shared['lease'], report=stored)
                            if publication.get('status') != 'saved':
                                raise ValueError('shared publication was not acknowledged')
                return result
        except (OSError, ValueError, KeyError) as exc:
            return {'status': 'unavailable', 'reason': 'shared analysis or publication failed; no duplicate work scheduled',
                    'limitations': [type(exc).__name__]}


def analyze_executable(local, path, digest, build, analyzer, analyzer_digest, advisory, revision, identity):
    result = limited_output_run(
        [str(GOVULNCHECK), *GOVULNCHECK_OPTIONS, str(local)],
        300,
        MAX_ANALYZER_BYTES,
    )
    if result["timed_out"]:
        return {
            "status": "unavailable",
            "reason": "govulncheck exceeded its execution limit",
        }
    if result["overflow"]:
        return {
            "status": "unavailable",
            "reason": "govulncheck exceeded its output limit",
        }
    if result["returncode"] not in (0, 3):
        return {
            "status": "unavailable",
            "reason": (result["stderr"] or "govulncheck failed")[-2000:],
        }
    try:
        summary = summarize_govulncheck(result["stdout"], advisory)
        config = summary['analysis_config']
        if config['scan_mode'] != 'binary' or config['scan_level'] != 'symbol' or config['db'] != GO_VULN_DB:
            raise ValueError('Analyzer configuration does not match the requested binary analysis')
    except ValueError as exc:
        return {
            "status": "unavailable",
            "reason": f"invalid govulncheck output: {exc}",
        }
    if file_sha256(local) != digest or file_sha256(GOVULNCHECK) != analyzer_digest:
        return {'status': 'unavailable', 'reason': 'Executable or analyzer changed during analysis'}
    after_revision = govulncheck_database_revision()
    eligible = bool(revision and revision == after_revision
                    and config['db_last_modified'] == revision['modified']
                    and config['scanner_name'] == 'govulncheck' and config['scanner_version']
                    and not summary['truncated'] and not summary['warnings'])
    result = {
        "sha256": digest,
        "analysis_timestamp": time.time(),
        "analyzer": analyzer,
        "advisory": advisory,
        "executable": path,
        "go_build": build,
        'reused_analysis': False,
        'cache': {'eligible': eligible, 'identity': identity,
                  'scope': 'artifact_only', 'storage': 'capability_local',
                  'reason': 'matching analyzer and database revision' if eligible else
                  'reuse disabled: missing, changed, or inconsistent provenance, warnings, or incomplete output'},
        **summary,
    }
    if not eligible:
        result['limitations'].append('This result is not reusable as current evidence; database freshness or analysis completeness was not verified.')
    return result


def require_command(result: dict) -> None:
    if result["returncode"] != 0 or result.get("truncated"):
        raise RuntimeError("Observation command failed or returned incomplete output")


def read_json_observation(label: str, argv: list[str]) -> dict | list:
    result = bounded_run(argv, 20)
    if result.get("truncated"):
        raise RuntimeError(f"{label} exceeded its observation budget")
    if result["returncode"] != 0:
        reason = (result.get("stderr") or f"{label} failed")[-2000:]
        raise RuntimeError(reason)
    try:
        value = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, (dict, list)):
        raise RuntimeError(f"{label} returned an unsupported JSON value")
    return value


def split_nft_document(document: dict | list) -> tuple[dict, list[dict]]:
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        raise RuntimeError("nft returned an invalid JSON document")
    metainfo = {}
    objects = []
    for item in document["nftables"]:
        if not isinstance(item, dict):
            raise RuntimeError("nft returned an invalid object")
        if "metainfo" in item and isinstance(item["metainfo"], dict):
            metainfo = item["metainfo"]
        else:
            objects.append(item)
    return metainfo, objects


def nft_name(arguments: dict, key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not NFT_NAME.fullmatch(value):
        raise ValueError(f"invalid nft {key}")
    return value


def firewall_query(arguments: dict) -> dict:
    allowed = {"family", "table", "chain", "set", "address"}
    if set(arguments) - allowed:
        raise ValueError("unsupported firewall query argument")
    if not arguments:
        documents = {}
        metainfo = {}
        for plural, singular in (
            ("tables", "table"),
            ("chains", "chain"),
            ("sets", "set"),
        ):
            document = read_json_observation(
                f"nft {plural}",
                ["/usr/sbin/nft", "-j", "-t", "list", plural],
            )
            current_metainfo, objects = split_nft_document(document)
            if not metainfo:
                metainfo = current_metainfo
            documents[plural] = [
                item[singular] for item in objects if isinstance(item.get(singular), dict)
            ]
        return {"query": "inventory", "metainfo": metainfo, **documents}

    family = nft_name(arguments, "family")
    table = nft_name(arguments, "table")
    if family not in NFT_FAMILIES:
        raise ValueError("unsupported nft family")
    chain = arguments.get("chain")
    set_name = arguments.get("set")
    address = arguments.get("address")
    if chain is not None and set_name is not None:
        raise ValueError("select either one chain or one set")
    if address is not None and set_name is None:
        raise ValueError("an address query requires a set")

    selection = {"family": family, "table": table}
    if chain is not None:
        selection["chain"] = nft_name(arguments, "chain")
        query = "chain"
        noun = ["chain", family, table, selection["chain"]]
    elif set_name is not None:
        selection["set"] = nft_name(arguments, "set")
        query = "set"
        noun = ["set", family, table, selection["set"]]
    else:
        query = "table"
        noun = ["table", family, table]

    document = read_json_observation(
        f"nft {query}",
        ["/usr/sbin/nft", "-j", "-t", "list", *noun],
    )
    metainfo, objects = split_nft_document(document)
    if address is None:
        return {
            "query": query,
            "selection": selection,
            "metainfo": metainfo,
            "objects": objects,
        }

    sets = [item["set"] for item in objects if isinstance(item.get("set"), dict)]
    if len(sets) != 1:
        raise RuntimeError("nft did not return the selected set metadata")
    set_type = sets[0].get("type")
    if set_type not in {"ipv4_addr", "ipv6_addr"}:
        raise ValueError("address lookup requires an IPv4 or IPv6 address set")
    if not isinstance(address, str):
        raise ValueError("invalid firewall address")
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("invalid firewall address") from exc
    expected_version = 4 if set_type == "ipv4_addr" else 6
    if parsed_address.version != expected_version:
        raise ValueError(f"address does not match the selected {set_type} set")
    canonical_address = str(parsed_address)
    probe = bounded_run(
        [
            "/usr/sbin/nft", "-j", "get", "element", family, table,
            selection["set"], "{", canonical_address, "}",
        ],
        20,
    )
    if probe.get("truncated"):
        raise RuntimeError("nft address lookup exceeded its observation budget")
    if probe["returncode"] == 0:
        present = True
    elif probe["returncode"] == 1 and "No such file or directory" in probe.get("stderr", ""):
        present = False
    else:
        raise RuntimeError((probe.get("stderr") or "nft address lookup failed")[-2000:])
    selection["address"] = canonical_address
    return {
        "query": "set_address",
        "selection": selection,
        "set": sets[0],
        "present": present,
        "details": probe.get("stdout", "").strip(),
    }


def discover_config(scope: dict, arguments: dict) -> dict:
    root = safe_absolute_path(arguments.get("root"))
    container = scoped_container(scope, arguments.get("container"), optional=True)
    locations = configuration_locations(scope, container) if container else []
    mapped = [item for item in locations if Path(item["path"]).is_relative_to(root)]
    if mapped:
        return {
            "paths": [item["path"] for item in mapped],
            "locations": mapped,
            "truncated": False,
        }
    if root not in scope["config_roots"] or DENIED_PATH.search(root):
        raise ValueError(
            "Configuration discovery requires an approved root or configuration mount"
        )
    # Do not follow symlinks or return credential-like paths.
    result = bounded_run(
        container_argv(
            container, ["/usr/bin/find", root, "-maxdepth", "3", "-type", "f"]
        ),
        20,
    )
    require_command(result)
    approved_files = set(scope.get("config_files", [])) if not container else set()
    paths = [p for p in result["stdout"].splitlines()
             if not DENIED_PATH.search(p) and (not approved_files or p in approved_files)]
    return {"paths": paths[:100], "truncated": len(paths) > 100}


def advisory_record(arguments):
    advisory = arguments.get('advisory')
    if not isinstance(advisory, str) or not CVE_ID.fullmatch(advisory):
        raise ValueError('invalid advisory identifier')
    if set(arguments) - {'advisory', 'part', 'offset'}:
        raise ValueError('unsupported advisory argument')
    part, offset = arguments.get('part', 'details'), arguments.get('offset', 0)
    if part not in {'details', 'affected', 'references'} or type(offset) is not int or not 0 <= offset <= 100000:
        raise ValueError('invalid advisory section')
    url = 'https://api.osv.dev/v1/vulns/'+advisory
    with urllib.request.build_opener(NoRedirect).open(url, timeout=10) as response:
        raw = response.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError('advisory record exceeds limit')
    record = json.loads(raw)
    if record.get('id') != advisory:
        raise ValueError('advisory identity mismatch')
    content = record.get(part, '' if part == 'details' else [])
    if part == 'details':
        if not isinstance(content, str):
            raise ValueError('invalid advisory details')
        selected, end = content[offset:offset+1800], offset+1800
    else:
        if not isinstance(content, list):
            raise ValueError('invalid advisory section')
        selected, end = content[offset:offset+3], offset+3
    return {'status': 'observed', 'source': url, 'advisory': advisory, 'sha256': object_sha256(record),
            'modified': record.get('modified'), 'withdrawn': record.get('withdrawn'),
            'summary': str(record.get('summary', ''))[:500], 'part': part, 'offset': offset,
            'content': selected, 'next_offset': end if end < len(content) else None,
            'limitations': ['Advisory prerequisites require interpretation against the exact artifact. This record does not establish deployment exposure.']}


def deployment_coverage(scope: dict, arguments: dict) -> dict:
    advisory = arguments.get('advisory', '')
    if advisory and (not isinstance(advisory, str) or not CVE_ID.fullmatch(advisory)):
        raise ValueError('invalid advisory')
    if set(arguments) - {'advisory'}:
        raise ValueError('unsupported coverage argument')
    advisories = {advisory.upper()} if advisory else {b['advisory'].upper() for b in scope['bindings']}
    accepted = SCAN_STATE_DIR / 'cve-state.incident-snapshot.json'
    provenance = None
    if accepted.exists():
        if accepted.stat().st_size > 32 * 1024 * 1024 + 1024:
            raise ValueError('accepted scan evidence exceeds limit')
        envelope = json.loads(accepted.read_text())
        state = envelope['snapshot']
        raw = json.dumps(state, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if state.get('schema') != 1 or hashlib.sha256(raw).hexdigest() != envelope.get('sha256'):
            raise ValueError('accepted snapshot integrity check failed')
        if INCIDENT_CONFIG.exists():
            settings = json.loads(INCIDENT_CONFIG.read_text())
            if (state['source'], state['generation']) != (settings['source'], settings['generation']):
                raise ValueError('accepted snapshot belongs to another source generation')
        observed = state['observed_at']
        if type(observed) not in (int, float) or not 0 < observed <= time.time()+300:
            raise ValueError('invalid snapshot observation time')
        findings = state['findings']
        if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
            raise ValueError('invalid snapshot findings')
        status_path = SCAN_STATE_DIR/'cve-state.status.json'
        status = json.loads(status_path.read_text()) if status_path.exists() else {'status': 'unknown'}
        fresh = time.time()-observed <= MAX_SCAN_AGE
        coverage = state.get('coverage', {})
        matching = [f for f in findings if str(f.get('id', '')).upper() in advisories]
        matching = [{**f, 'containers': snapshot_containers(f), 'binding': {'snapshot_sha256': envelope['sha256'],
                     'finding_sha256': object_sha256(f)}} for f in matching]
        complete = set(state['complete_scopes'])
        scopes_complete = bool(complete) and all(f.get('scope') in complete for f in matching)
        overall = 'complete' if fresh and scopes_complete and status.get('status') == 'complete' else 'unknown'
        provenance = {k: state[k] for k in ('source', 'generation', 'sequence')}
        provenance.update(sha256=envelope['sha256'], fresh=fresh, basis='acknowledged_incident_snapshot')
        limitations = ['No match in this scan does not prove a deployed fix. Inventory retirement and incident history remain separate evidence.']
    else:
        if INCIDENT_CONFIG.exists():
            return {'status': 'unknown', 'reason': 'no acknowledged incident snapshot', 'matching_findings': [],
                    'limitations': ['Legacy notification state is severity-filtered and is not incident evidence.']}
        choices = [SCAN_STATE_DIR/'cve-state.json', SCAN_STATE_DIR/'coverage-audit.json']
        available = [p for p in choices if p.is_file()]
        if not available:
            return {'status': 'unknown', 'reason': 'no deployment scan evidence'}
        path = max(available, key=lambda p: p.stat().st_mtime_ns)
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('deployment evidence exceeds limit')
        state = json.loads(path.read_text())
        status = json.loads(path.with_suffix('.status.json').read_text())
        coverage = state.get('coverage', {})
        observed = state.get('updated_at')
        matching = [f for f in state.get('findings', {}).values() if str(f.get('id', '')).upper() in advisories]
        overall = 'unknown'
        limitations = ['Legacy evidence includes only HIGH and CRITICAL findings. No match cannot establish absence.']
    discovery = coverage.get('discovery', {})
    return {'status': overall, 'scan_status': status, 'observed_at': observed,
            'snapshot': provenance, 'runtime_sha256': discovery.get('runtime_sha256'),
            'discovery_gaps': discovery.get('gaps', ['runtime discovery missing']),
            'requirements': coverage.get('requirements', []),
            'libraries': [{k: item.get(k) for k in ('deployment', 'path', 'status', 'reason', 'identified_types')}
                          for item in coverage.get('libraries', [])],
            'matching_findings': matching, 'matching_count': len(matching),
            'limitations': limitations + coverage.get('limitations', [])}


def invoke_operation(
    scope: dict[str, Any], operation: str, arguments: dict[str, Any]
) -> Any:
    if operation == 'prove_symbols':
        return prove_symbols(scope, arguments)
    if operation == 'verify_replacement':
        return verify_replacement(scope, arguments)
    if operation == 'advisory_record':
        return advisory_record(arguments)
    if operation == 'network_state':
        if arguments:
            raise ValueError('network_state does not accept arguments')
        addresses = read_json_observation(
            'network addresses', ['/usr/sbin/ip', '-j', 'address']
        )
        routes = read_json_observation(
            'network routes', ['/usr/sbin/ip', '-j', 'route']
        )
        if not isinstance(addresses, list) or not isinstance(routes, list):
            raise RuntimeError('ip returned an invalid JSON document')
        return {'addresses': addresses, 'routes': routes}
    if operation == 'firewall_query':
        return firewall_query(arguments)
    if operation == 'deployment_coverage':
        return deployment_coverage(scope, arguments)
    if operation == "discover_config":
        return discover_config(scope, arguments)
    if operation == "list_processes":
        container = scoped_container(scope, arguments.get("container"), optional=True)
        processes = []
        missed = False
        for pid in process_ids(container):
            proc = Path("/proc") / str(pid)
            try:
                processes.append(
                    {
                        "pid": pid,
                        "exe": os.readlink(proc / "exe"),
                    }
                )
            except OSError:
                missed = True
        return {
            "processes": processes[:100],
            "truncated": missed or len(processes) > 100,
        }
    if operation == "list_listeners":
        container = scoped_container(scope, arguments.get("container"), optional=True)
        if container:
            pids = process_ids(container)
            if not pids:
                return {
                    "status": "unavailable",
                    "reason": "No running container process was found.",
                }
            result = bounded_run(
                [
                    "/usr/bin/nsenter",
                    "--target",
                    str(pids[0]),
                    "--net",
                    "/usr/bin/ss",
                    "-H",
                    "-lntup",
                ],
                20,
            )
        else:
            result = bounded_run(["/usr/bin/ss", "-H", "-lntup"], 20)
        lines = result["stdout"].splitlines()
        require_command(result)
        return {"listeners": lines[:100], "truncated": len(lines) > 100}
    if operation == "inspect_executable":
        return inspect_executable(scope, arguments)
    if operation == "read_proc_maps":
        container = scoped_container(scope, arguments.get("container"), optional=True)
        pid = int(arguments.get("pid"))
        if pid not in process_ids(container):
            raise ValueError("process is outside the capability scope")
        lines = (
            (Path("/proc") / str(pid) / "maps").read_text(errors="replace").splitlines()
        )
        return {"pid": pid, "maps": lines[:500], "truncated": len(lines) > 500}
    if operation == "extract_file":
        container = scoped_container(scope, arguments.get("container"), optional=True)
        path = allowed_reported_file(scope, arguments.get("path"), container)
        with tempfile.TemporaryDirectory(prefix="homelab-evidence-") as directory:
            local = Path(directory) / "artifact"
            if container:
                copy_container_file(container, path, local)
            else:
                expected = host_binary_digests(scope, path)
                if not expected:
                    raise ValueError("Host artifact lacks a scanner-bound digest")
                capture_host_file(path, local, expected_digests=expected)
            if local.is_symlink() or not local.is_file():
                raise ValueError("Reported file is not a regular file")
            size = local.stat().st_size
            if size > MAX_EXTRACT_BYTES:
                return {
                    "status": "too_large",
                    "path": path,
                    "size": size,
                    "limit": MAX_EXTRACT_BYTES,
                }
            data = local.read_bytes()
            return {
                "path": path,
                "size": size,
                "sha256": hashlib.sha256(data).hexdigest(),
                "base64": base64.b64encode(data).decode(),
            }
    if operation == "container_metadata":
        container = scoped_container(scope, arguments.get("container"))
        result = bounded_run(
            [
                "/usr/bin/docker",
                "inspect",
                "--format",
                "{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .State}}\t{{json .NetworkSettings.Networks}}\t{{json .NetworkSettings.Ports}}",
                container["id"],
            ],
            20,
        )
        require_command(result)
        return {
            "metadata": result["stdout"],
            "configuration": configuration_locations(scope, container),
            "startup_configuration": startup_configuration(container),
        }
    if operation == "package_info":
        return package_info(scope, arguments)
    if operation == "read_config":
        return read_config(scope, arguments)
    if operation == "run_analyzer":
        return run_analyzer(scope, arguments)
    if operation == "service_state":
        alias = str(arguments.get("service") or "")
        units = read_json_file(UNIT_FILE)
        if alias not in scope["services"] or alias not in units:
            raise ValueError("service is outside the capability scope")
        unit = str(units[alias])
        return {
            "state": bounded_run(
                [
                    "/usr/bin/systemctl",
                    "show",
                    unit,
                    "--property=ActiveState,SubState,Result,ExecMainStatus,NRestarts,FragmentPath",
                ],
                20,
            ),
            "logs": bounded_run(
                [
                    "/usr/bin/journalctl",
                    "--unit",
                    unit,
                    "--lines",
                    "80",
                    "--since",
                    "-30 min",
                    "--no-pager",
                    "--output",
                    "short-iso",
                ],
                30,
            ),
        }
    raise ValueError("unknown evidence operation")


def redact_result(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if re.search(
                    r"(?i)password|secret|token|credential|private.key|"
                    r"api.key|access.key",
                    key,
                )
                else redact_result(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_result(item) for item in value]
    if isinstance(value, str):
        return re.sub(
            r"(?i)((?:password|secret|token|credential|authorization)\s*[=:]\s*)[^\s,;]+",
            r"\1[REDACTED]",
            value,
        )
    return value


def result_incomplete(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("truncated") or value.get("returncode", 0)) or any(
            result_incomplete(v) for v in value.values()
        )
    if isinstance(value, list):
        return any(result_incomplete(v) for v in value)
    return False


def remaining(capability: dict) -> dict:
    return {
        "calls": max(0, capability["limits"]["calls"] - capability["calls"]),
        "bytes": max(
            0,
            capability["limits"]["total_bytes"]
            - capability["bytes"]
            - len(capability["pending"]) * MAX_RESULT_BYTES,
        ),
        "seconds": max(0, capability["expires"] - int(time.time())),
    }


def write_capability(handle, capability: dict) -> None:
    handle.seek(0)
    json.dump(capability, handle, separators=(",", ":"))
    handle.truncate()
    handle.flush()


@contextmanager
def operation_deadline(seconds: int):
    # The installed gateway handles one invocation per process. Threaded test callers
    # retain their own bounded mocked operations because Python signals are main-thread only.
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def expired(_signum, _frame):
        raise TimeoutError("Evidence operation exceeded its deadline")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.01, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def invoke_capability(token: str, operation: str, arguments: Any) -> dict[str, Any]:
    if operation not in OPERATIONS or not isinstance(arguments, dict):
        raise ValueError("Invalid evidence operation or arguments")
    path = capability_path(token)
    observation_id = secrets.token_hex(16)
    receipt = {
        "protocol": 2,
        "observation_id": observation_id,
        "operation": operation,
        "arguments": arguments,
        "timestamp": time.time(),
        "status": "failed",
        "identity": {},
        "result": {},
        "truncated": False,
        "limitations": [],
        "remaining": {},
    }
    reserved = False
    slot = None
    try:
        with path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            capability = json.load(handle)
            if capability.get("schema") != 2:
                raise ValueError("Evidence protocol mismatch; reopen capability")
            scope = capability["scope"]
            requested = arguments.get("container")
            container = next(
                (
                    item
                    for item in scope["containers"]
                    if requested in (item["id"], item["short_id"], item["name"])
                ),
                None,
            )
            receipt["identity"] = {
                "container_id": container["id"] if container else None,
                "artifact_id": container["image_id"] if container else None,
            }
            # A crashed process cannot reserve capacity indefinitely. Attempts remain charged.
            capability["pending"] = {
                key: end
                for key, end in capability["pending"].items()
                if end > time.time()
            }
            receipt["remaining"] = remaining(capability)
            if not receipt["remaining"]["seconds"]:
                raise ValueError("Capability expired")
            if (
                not receipt["remaining"]["calls"]
                or receipt["remaining"]["bytes"] < MAX_RESULT_BYTES
            ):
                raise ValueError("Investigation resource budget exhausted")
            capability["calls"] += 1
            capability["pending"][observation_id] = time.time() + 390
            write_capability(handle, capability)
            reserved = True
        with operation_deadline(min(330, receipt["remaining"]["seconds"])):
            if requested and container is None:
                raise ContainerLookupError('policy_denied', 'Container is outside the capability scope', requested={'container': str(requested)[:256]})
            category = (
                "analyzer"
                if operation in {'run_analyzer', 'verify_replacement', 'prove_symbols'}
                else "read"
            )
            for index in range(1 if category == "analyzer" else 2):
                candidate = (CAPABILITY_DIR / f"{category}-{index}.lock").open("a")
                try:
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    slot = candidate
                    break
                except BlockingIOError:
                    candidate.close()
            if slot is None:
                raise ValueError(
                    "Target evidence capacity is busy; retry after an active operation finishes"
                )
            if container:
                current = resolve_container(docker_inventory(include_stopped=True), container, container['image_id'], stage='before_operation')
                receipt['container_lookup'] = {'runtime': 'docker', 'requested': {'id': container['id'], 'name': container['name']}, 'resolved': current}
            result = invoke_operation(scope, operation, arguments)
            incomplete = result_incomplete(result)
            receipt.update(
                result=redact_result(result),
                truncated=incomplete,
                status="unavailable"
                if result.get("status") in {"unavailable", "too_large"}
                else "success",
                limitations=result.get("limitations", []),
            )
            if incomplete:
                receipt["status"] = "incomplete"
            if len(json.dumps(receipt).encode()) > MAX_RESULT_BYTES - 2048:
                raise ValueError("Observation exceeded its output budget")
            # Detect replacement during a slow operation as well as before it.
            if container:
                resolve_container(docker_inventory(include_stopped=True), container, container['image_id'], stage='after_operation')
    except Exception as exc:
        receipt.update(status="failed", result={}, limitations=[str(exc)[:500]])
        if isinstance(exc, ContainerLookupError):
            receipt['failure'] = exc.details
    finally:
        if slot:
            slot.close()
        if reserved:
            try:
                with path.open("r+", encoding="utf-8") as handle:
                    fcntl.flock(handle, fcntl.LOCK_EX)
                    capability = json.load(handle)
                    capability["pending"].pop(observation_id, None)
                    if capability["expires"] < time.time():
                        receipt.update(
                            status="failed",
                            result={},
                            limitations=["Capability expired during observation"],
                        )
                    capability["bytes"] += (
                        (len(json.dumps(receipt).encode()) + 2047) // 1024
                    ) * 1024
                    if receipt["status"] == "success" and operation == "list_processes":
                        identity = receipt["identity"].get("container_id") or "host"
                        capability["scope"]["discovered_files"][identity] = [
                            p["exe"]
                            for p in receipt["result"]["processes"]
                            if not DENIED_PATH.search(p["exe"])
                        ]
                    for cache_name in (
                        "analyzer_cache",
                        "candidate_cache",
                        "binary_metadata",
                    ):
                        capability["scope"].setdefault(cache_name, {}).update(
                            scope.get(cache_name, {})
                        )
                        if cache_name == 'analyzer_cache':
                            merged = capability['scope'][cache_name]
                            for old in sorted(merged, key=lambda k: merged[k].get('analysis_timestamp', 0))[:-16]:
                                del merged[old]
                    receipt["remaining"] = remaining(capability)
                    write_capability(handle, capability)
            except FileNotFoundError:
                receipt.update(
                    status="failed",
                    result={},
                    limitations=["Capability was revoked during observation"],
                )
    receipt["duration_ms"] = round((time.time() - receipt["timestamp"]) * 1000)
    receipt = redact_result(receipt)
    audit(
        {
            "action": "invoke",
            "operation": operation,
            "status": receipt["status"],
            "observation_id": observation_id,
            "duration_ms": receipt["duration_ms"],
        }
    )
    return {"operation": operation, "result": receipt}


def close_capability(token: str) -> dict[str, Any]:
    path = capability_path(token)
    path.unlink(missing_ok=True)
    audit({"action": "close", "capability": path.stem[:16], "status": "ok"})
    return {"closed": True}


def object_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def snapshot_containers(finding):
    # Older snapshots copied every image user into each occurrence. Bind only
    # the container whose component is named by this occurrence's location.
    return [c for c in finding.get('containers', [])
            if c.get('name') and str(finding.get('location', '')).startswith(c['name'].lstrip('/')+':')]


def snapshot_artifact(operation, arguments):
    """The caller selects evidence, never supplies a scanner authorization scope."""
    if operation not in {'extract_file', 'inspect_executable', 'run_analyzer', 'prove_symbols', 'verify_replacement'} or not isinstance(arguments, dict):
        raise ValueError('unsupported snapshot artifact read')
    if set(arguments) - {'snapshot_sha256', 'finding_sha256', 'path', 'container', 'advisory', 'analyzer', 'symbols', 'candidate'}:
        raise ValueError('unsupported artifact argument')
    accepted = SCAN_STATE_DIR/'cve-state.incident-snapshot.json'
    if not accepted.is_file():
        raise ValueError(
            'accepted snapshot binding is unavailable; refresh deployment coverage')
    if accepted.stat().st_size > 32*1024*1024+1024:
        raise ValueError('accepted scan exceeds limit')
    envelope = json.loads(accepted.read_text())
    snapshot = envelope['snapshot']
    settings = read_json_file(INCIDENT_CONFIG)
    if (snapshot.get('schema') != 1 or object_sha256(snapshot) != envelope.get('sha256')
            or envelope['sha256'] != arguments.get('snapshot_sha256')
            or (snapshot['source'], snapshot['generation']) != (settings['source'], settings['generation'])
            or not -300 <= time.time()-snapshot['observed_at'] <= MAX_SCAN_AGE):
        raise ValueError('snapshot binding is stale or invalid; refresh deployment coverage')
    matches = [f for f in snapshot['findings'] if object_sha256(f) == arguments.get('finding_sha256')]
    if len(matches) != 1:
        raise ValueError('finding is not uniquely bound to the acknowledged snapshot')
    finding = matches[0]
    path = safe_absolute_path(arguments.get('path'))
    if path == '/' or path != '/' + str(finding.get('target', '')).lstrip('/'):
        raise ValueError('path is not the exact scanner-reported artifact')
    containers = snapshot_containers(finding)
    requested = arguments.get('container')
    if finding.get('containers'):
        containers = [c for c in containers if requested in (c.get('id'), c.get('name'))]
        if len(containers) != 1:
            raise ValueError('select one container recorded in this finding')
    elif requested or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', finding.get('artifact_id', '')):
        raise ValueError('host artifact lacks a scanner-bound executable hash')
    if arguments.get('advisory', finding['id']) != finding['id']:
        raise ValueError('advisory differs from the selected finding')
    scope = {'schema': 2, 'groups': [{'id': finding['id'], 'package': finding['package'],
             'occurrences': [{'artifact': 'acknowledged-snapshot', 'artifact_id': finding['artifact_id'],
                              'reported_file': path, 'containers': containers}]}]}
    args = {k: v for k, v in arguments.items() if k not in {'snapshot_sha256', 'finding_sha256'}}
    result = artifact_investigation(scope, operation, args)
    result['snapshot_binding'] = {k: arguments[k] for k in ('snapshot_sha256', 'finding_sha256')}
    return result


def artifact_investigation(
    scope: Any, operation: str, arguments: Any
) -> dict[str, Any]:
    if operation not in ARTIFACT_OPERATIONS or not isinstance(arguments, dict):
        raise ValueError("unsupported artifact operation")
    opened = open_capability(scope)
    try:
        result = invoke_capability(opened["token"], operation, arguments)
        receipt = result.get("result")
        if isinstance(receipt, dict):
            receipt.pop("remaining", None)
        return result
    finally:
        close_capability(opened["token"])


def observe(operation: str, arguments: Any) -> dict[str, Any]:
    if operation not in OBSERVATIONS or not isinstance(arguments, dict):
        raise ValueError('unsupported operational read')
    opened = open_capability({}, operational=True)
    try:
        return invoke_capability(opened['token'], operation, arguments)
    finally:
        close_capability(opened['token'])


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("request must be an object")
    action = payload.get("action")
    if action == "observe":
        result = observe(payload.get('operation'), payload.get('arguments', {}))
    elif action == 'snapshot_artifact':
        result = snapshot_artifact(payload.get('operation'), payload.get('arguments', {}))
    else:
        raise ValueError("unsupported action")
    print(json.dumps({"ok": True, "result": result}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as exc:
        audit({"action": "error", "status": "error", "reason": str(exc)[:500]})
        response = {"ok": False, "error": str(exc)}
        if isinstance(exc, ContainerLookupError):
            response['failure'] = exc.details
        print(json.dumps(response, separators=(",", ":")))
        raise SystemExit(1) from exc
