#!/usr/bin/env python3
"""Ephemeral MCP adapter for one target-bound evidence capability."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import secrets
import fcntl
import re
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations


AGENTCTL = "/usr/local/bin/homelab-agentctl"
CONTEXT = Path("/etc/homelab-agent/repository-context")
MAX_REPOSITORY_MATCHES = 20
TARGET = os.environ["HOMELAB_EVIDENCE_TARGET"]
TOKEN = os.environ["HOMELAB_EVIDENCE_TOKEN"]
RECORD_DIR = Path(os.environ["HOMELAB_EVIDENCE_RECORD_DIR"])
DEADLINE = float(os.environ["HOMELAB_EVIDENCE_DEADLINE"])
LOGGER = logging.getLogger("homelab-evidence-mcp")
mcp = FastMCP("Homelab evidence")
READ_ONLY_CLOSED = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
READ_ONLY_OPEN = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


def save_receipt(receipt: dict) -> dict:
    if receipt.get("protocol") != 2:
        raise ValueError("Evidence gateway protocol mismatch")
    directory = RECORD_DIR / "receipts"
    if not re.fullmatch(r"[a-f0-9]{32}", str(receipt.get("observation_id", ""))):
        raise ValueError("Invalid gateway observation identifier")
    encoded = json.dumps(receipt, separators=(",", ":")).encode()
    if len(encoded) > 128 * 1024:
        raise ValueError("Observation exceeds the per-call storage limit")
    with (RECORD_DIR / "receipts.lock").open("a") as lock:
        os.chmod(RECORD_DIR / "receipts.lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        files = list(directory.glob("*.json"))
        if (
            len(files) >= 240
            or sum(p.stat().st_size for p in files) + len(encoded) > 16 * 1024 * 1024
        ):
            raise ValueError("Investigation receipt storage limit reached")
        temporary = directory / (secrets.token_hex(16) + ".tmp")
        try:
            with temporary.open("xb") as handle:
                os.chmod(temporary, 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(directory / (receipt["observation_id"] + ".json"))
        finally:
            temporary.unlink(missing_ok=True)
    return receipt


def failed_receipt(operation: str, arguments: dict, reason: str) -> dict:
    scope = json.loads((RECORD_DIR / "record.json").read_text())["scope"]
    identity = {}
    for path in scope["deployed_paths"]:
        container = path.get("container")
        if container and arguments.get("container") in (
            container["id"],
            container.get("name"),
        ):
            identity = {
                "container_id": container["id"],
                "artifact_id": path["artifact_id"],
            }
    return {
        "protocol": 2,
        "observation_id": secrets.token_hex(16),
        "operation": operation,
        "arguments": arguments,
        "timestamp": time.time(),
        "identity": identity,
        "status": "failed",
        "result": {},
        "truncated": False,
        "limitations": [reason],
        "remaining": {"seconds": max(0, int(DEADLINE - time.time()))},
    }


def remote(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        if time.time() >= DEADLINE:
            raise RuntimeError("Investigation deadline reached")
        completed = subprocess.run(
            [AGENTCTL, "evidence-call", TARGET, TOKEN, operation],
            input=json.dumps(arguments, separators=(",", ":")),
            capture_output=True,
            text=True,
            timeout=min(370, max(1, DEADLINE - time.time())),
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("Evidence transport failed; no observation was obtained")
        payload = json.loads(completed.stdout)
        if not payload.get("ok"):
            raise RuntimeError("Evidence gateway rejected the request")
        receipt = payload["result"]["result"]
        if receipt.get("protocol") != 2:
            raise RuntimeError("Evidence gateway protocol mismatch")
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        receipt = failed_receipt(operation, arguments, str(exc))
    return save_receipt(receipt)


@mcp.tool(annotations=READ_ONLY_CLOSED)
def fleet_deployment_coverage(advisory: str = '') -> dict[str, Any]:
    """Correlate an advisory across all deployment systems, including the controller and external LXCs. Missing or stale scans remain unknown; matches do not establish exploitability."""
    completed = subprocess.run([AGENTCTL, 'coverage', '--advisory', advisory], capture_output=True, text=True, timeout=400)
    if completed.returncode or len(completed.stdout) > 512 * 1024:
        return {'status': 'unknown', 'reason': 'fleet coverage query failed or exceeded limit'}
    value = json.loads(completed.stdout)
    # Supplemental fleet context is retained separately: it must not masquerade
    # as a runtime observation bound to the current installation's capability.
    path = RECORD_DIR / 'fleet-coverage.json'
    path.write_text(json.dumps({'observed_at': time.time(), 'advisory': advisory, 'result': value}))
    path.chmod(0o600)
    return value


@mcp.tool(annotations=READ_ONLY_CLOSED)
def prepare_defensive_action(action: str) -> dict[str, Any]:
    """Check a named, root-policy action against live identity and recovery evidence. Does not execute it. Missing policy is a blocker."""
    completed = subprocess.run([AGENTCTL, 'defense', TARGET, 'prepare', action],
                               capture_output=True, text=True, timeout=100, check=False)
    if completed.returncode:
        return {'eligible': False, 'blockers': ['action policy or evidence validation failed']}
    return json.loads(completed.stdout)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False))
def execute_defensive_action(action: str) -> dict[str, Any]:
    """Execute only a named action explicitly enabled by root policy with current verification and tested recovery. Cannot supply commands, paths, candidates, or approval evidence. Initially no actions are enabled."""
    completed = subprocess.run([AGENTCTL, 'defense', TARGET, 'execute', action],
                               capture_output=True, text=True, timeout=620, check=False)
    if completed.returncode:
        return {'status': 'blocked_or_recovered', 'result': json.loads(completed.stdout) if completed.stdout.strip() else {}}
    return json.loads(completed.stdout)


@mcp.tool(annotations=READ_ONLY_CLOSED)
def deployment_coverage() -> dict[str, Any]:
    """Read this target's latest deployment coverage, gaps, runtime identity and matching advisory occurrences. Check timestamps; a complete scan is not proof of complete coverage."""
    return remote('deployment_coverage', {})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def list_processes(container: str = "") -> dict[str, Any]:
    """List bounded process identity and executable paths on the target or one scoped container."""
    return remote("list_processes", {"container": container})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def list_listeners(container: str = "") -> dict[str, Any]:
    """List listening TCP/UDP sockets, optionally restricted to one scoped container."""
    return remote("list_listeners", {"container": container})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def inspect_executable(path: str, container: str = "") -> dict[str, Any]:
    """Inspect format, digest, linkage and declared libraries for a reported executable."""
    return remote("inspect_executable", {"container": container, "path": path})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def read_proc_maps(pid: int, container: str = "") -> dict[str, Any]:
    """Read bounded /proc mappings for a process inside the capability scope."""
    return remote("read_proc_maps", {"container": container, "pid": pid})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def extract_reported_file(path: str, container: str = "") -> dict[str, Any]:
    """Extract a small scanner-reported file; larger files return metadata and a size limit."""
    return remote("extract_file", {"container": container, "path": path})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def inspect_container(container: str) -> dict[str, Any]:
    """Read selected non-secret runtime, network and image metadata for a scoped container."""
    return remote("container_metadata", {"container": container})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def query_package(package: str, container: str = "") -> dict[str, Any]:
    """Query ownership, installed version, files and dependencies for a reported package."""
    return remote("package_info", {"container": container, "package": package})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def read_configuration(path: str, container: str = "") -> dict[str, Any]:
    """Read an allow-listed configuration file with credential paths denied and values redacted."""
    return remote("read_config", {"container": container, "path": path})


@mcp.tool(annotations=READ_ONLY_CLOSED)
def inspect_service(service: str) -> dict[str, Any]:
    """Read state and recent logs for an inventory-mapped service without changing it."""
    return remote("service_state", {"service": service})


@mcp.tool(annotations=READ_ONLY_OPEN)
def retrieve_official_advisory(advisory: str) -> dict[str, Any]:
    """Retrieve the scoped CVE record or OSV advisory, with reference indices for follow-up."""
    return remote("official_advisory", {"advisory": advisory})


@mcp.tool(annotations=READ_ONLY_OPEN)
def list_upstream_releases(artifact: str) -> dict[str, Any]:
    """List recent public registry tags for a scoped artifact; patch contents remain unverified."""
    return remote("upstream_releases", {"artifact": artifact})


@mcp.tool(annotations=READ_ONLY_OPEN)
def run_govulncheck(path: str, advisory: str, container: str = "") -> dict[str, Any]:
    """Analyze a Go executable: affected dependency versions, symbols, build settings, and provenance. No binary download is needed."""
    return remote(
        "run_analyzer",
        {
            "analyzer": "govulncheck",
            "container": container,
            "path": path,
            "advisory": advisory,
        },
    )


@mcp.tool(annotations=READ_ONLY_OPEN)
def read_dependency_source(
    executable: str,
    module: str,
    path: str,
    container: str = "",
    query: str = "",
    start_line: int = 1,
) -> dict[str, Any]:
    """Read source at a version observed in this executable's Go build metadata. Inspect/analyze the executable first. Use module 'stdlib' and a path such as 'net/lookup.go', or a declared module and repository-relative path. A literal query returns matching code with context; start_line pages results. Use this to connect configured behavior to affected functions, not to infer execution from symbol presence."""
    return remote(
        "dependency_source",
        {
            "executable": executable,
            "module": module,
            "path": path,
            "container": container,
            "query": query,
            "start_line": start_line,
        },
    )


@mcp.tool(annotations=READ_ONLY_OPEN)
def retrieve_advisory_reference(advisory: str, reference_index: int) -> dict[str, Any]:
    """Read a vendor or patch reference by its index in the scoped official advisory."""
    return remote(
        "advisory_reference", {"advisory": advisory, "reference_index": reference_index}
    )


@mcp.tool(annotations=READ_ONLY_CLOSED)
def discover_configuration(root: str, container: str = "") -> dict[str, Any]:
    """List non-secret configuration paths under a policy-approved root, without following symlinks."""
    return remote("discover_config", {"root": root, "container": container})


@mcp.tool(annotations=READ_ONLY_OPEN)
def verify_candidate_image(
    artifact: str, tag: str, advisory: str, package: str, container: str
) -> dict[str, Any]:
    """Resolve and scan a same-repository replacement without running it. A tag alone proves no fix."""
    return remote(
        "verify_candidate",
        {
            "artifact": artifact,
            "tag": tag,
            "advisory": advisory,
            "package": package,
            "container": container,
        },
    )


@mcp.tool(annotations=READ_ONLY_CLOSED)
def search_deployment_repository(query: str) -> dict[str, Any]:
    """Search intended deployment state, returning source-local line numbers and nearby context."""
    import re

    args = {"query": query}
    try:
        term = query.strip().casefold()
        if not 3 <= len(term) <= 80 or any(ord(c) < 32 for c in term):
            raise ValueError("query must contain 3-80 printable characters")
        if time.time() >= DEADLINE:
            raise ValueError("Investigation deadline reached")
        files: dict[str, list[str]] = {}
        current = "snapshot"
        for line in CONTEXT.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("# "):
                current = line[2:]
            else:
                files.setdefault(current, []).append(line)
        matches = []
        for source, lines in files.items():
            for number, line in enumerate(lines):
                if term in line.casefold():
                    context = [
                        {
                            "line": i + 1,
                            "text": re.sub(
                                r"(?i)((?:password|secret|token|credential)\s*[:=]\s*).+",
                                r"\1[REDACTED]",
                                lines[i],
                            ),
                        }
                        for i in range(max(0, number - 3), min(len(lines), number + 4))
                    ]
                    matches.append(
                        {"source": source, "line": number + 1, "context": context}
                    )
        receipt = failed_receipt("repository_search", args, "")
        receipt.update(
            status="success",
            result={"matches": matches[:MAX_REPOSITORY_MATCHES]},
            truncated=len(matches) > MAX_REPOSITORY_MATCHES,
            limitations=["Repository context is intended state, not runtime evidence."],
        )
        if receipt["truncated"]:
            receipt["status"] = "incomplete"
    except (OSError, ValueError) as exc:
        receipt = failed_receipt("repository_search", args, str(exc))
    return save_receipt(receipt)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    mcp.run()
