#!/usr/bin/env python3
"""Capability-scoped, read-only evidence gateway for homelab investigations."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import secrets
import subprocess
import sys
import tempfile
import tarfile
import time
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib import parse

from homelab_evidence_sources import (
    public_get,
    advisory_reference,
    release_tags,
    verify_candidate,
)


POLICY_FILE = Path("/etc/homelab-agent/evidence-policy.json")
UNIT_FILE = Path("/etc/homelab-agent/units.json")
CAPABILITY_DIR = Path("/run/homelab-evidence-gateway")
CAPABILITY_TTL = 1800
MAX_REQUEST_BYTES = 128 * 1024
MAX_CALLS = 160
MAX_RESULT_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_EXTRACT_BYTES = 64 * 1024
MAX_ANALYZER_BYTES = 8 * 1024 * 1024
OPERATIONS = {
    "list_processes",
    "list_listeners",
    "inspect_executable",
    "read_proc_maps",
    "extract_file",
    "container_metadata",
    "package_info",
    "read_config",
    "service_state",
    "official_advisory",
    "upstream_releases",
    "run_analyzer",
    "advisory_reference",
    "discover_config",
    "verify_candidate",
    "dependency_source",
    "deployment_coverage",
}
DENIED_PATH = re.compile(
    r"(^|/)(?:\.env(?:\..*)?|shadow|gshadow|passwd-|id_(?:rsa|ecdsa|ed25519)|"
    r"[^/]*(?:secret|token|credential|password|private[_-]?key)[^/]*)$",
    re.IGNORECASE,
)
SECRET_LINE = re.compile(
    r"(?i)^(?P<prefix>\s*[^#\n:=]*(?:secret|token|password|credential|private[_-]?key)"
    r"[^#\n:=]*\s*[:=]\s*)(?P<value>.*)$"
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}")
CVE_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+|GO-\d{4}-\d+)", re.I)


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
        if isinstance(message, dict):
            messages.append(message)
    return messages


def summarize_govulncheck(value: str, advisory: str) -> dict[str, Any]:
    messages = parse_json_stream(value)
    if not messages:
        raise ValueError("Analyzer returned no analysis metadata")
    advisory_upper = advisory.upper()
    matched_osvs: dict[str, dict[str, Any]] = {}
    for message in messages:
        osv = message.get("osv")
        if not isinstance(osv, dict) or not osv.get("id"):
            continue
        identifiers = {str(osv["id"]).upper()} | {
            str(alias).upper() for alias in osv.get("aliases") or []
        }
        if advisory_upper in identifiers:
            matched_osvs[str(osv["id"])] = osv

    levels: list[str] = []
    symbols: set[str] = set()
    packages: set[str] = set()
    modules: set[str] = set()
    versions: dict[tuple[str, str, str], dict] = {}
    for message in messages:
        finding = message.get("finding")
        if not isinstance(finding, dict) or str(finding.get("osv")) not in matched_osvs:
            continue
        trace = finding.get("trace") or []
        frame = trace[-1] if trace and isinstance(trace[-1], dict) else {}
        if frame.get("module") and frame.get("version"):
            key = (frame["module"], frame["version"], finding.get("fixed_version", ""))
            versions[key] = dict(zip(("module", "installed", "fixed"), key))
        if frame.get("function"):
            levels.append("symbol_present")
            package = str(frame.get("package") or "")
            function = str(frame["function"])
            receiver = str(frame.get("receiver") or "")
            symbol = ".".join(filter(None, (package, receiver, function)))
            symbols.add(symbol)
        elif frame.get("package"):
            levels.append("package_present")
            packages.add(str(frame["package"]))
        elif frame.get("module"):
            levels.append("module_present")
            modules.add(str(frame["module"]))
    status = next(
        (
            level
            for level in ("symbol_present", "package_present", "module_present")
            if level in levels
        ),
        "not_reported",
    )
    interpretation = {
        "symbol_present": "The affected symbol was found in the executable.",
        "package_present": (
            "The affected package was found, but no affected symbol was found in the executable."
        ),
        "module_present": (
            "The affected module was found, but no affected package or symbol was found in the executable."
        ),
        "not_reported": "The advisory was not reported for the executable.",
    }[status]
    advisories = [
        {
            "id": osv_id,
            "aliases": osv.get("aliases") or [],
            "summary": str(osv.get("summary") or "")[:2000],
            "details": str(osv.get("details") or "")[:4000],
        }
        for osv_id, osv in matched_osvs.items()
    ]
    return {
        "status": status,
        "interpretation": interpretation,
        "advisories": advisories,
        "symbols": sorted(symbols)[:100],
        "packages": sorted(packages)[:100],
        "modules": sorted(modules)[:100],
        "affected_versions": list(versions.values())[:100],
        "truncated": any(
            len(items) > 100 for items in (symbols, packages, modules, versions)
        ),
        "limitations": [
            "Binary symbol presence does not prove runtime invocation. Missing symbols or unreported advisories do not prove absence when build or symbol metadata is incomplete."
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


def docker_inventory() -> dict[str, dict[str, str]]:
    if not Path("/usr/bin/docker").exists():
        return {}
    containers = bounded_run(["/usr/bin/docker", "ps", "--quiet"], timeout=20)
    ids = [value for value in containers["stdout"].splitlines() if value]
    if containers["returncode"] != 0 or not ids:
        return {}
    inspected = bounded_run(
        [
            "/usr/bin/docker",
            "inspect",
            "--format",
            "{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .Config.Image}}",
            *ids,
        ],
        timeout=30,
    )
    inventory: dict[str, dict[str, str]] = {}
    for line in inspected["stdout"].splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        container_id, name, image_id, image_ref = [
            str(json.loads(v) or "") for v in fields
        ]
        item = {
            "id": container_id,
            "short_id": container_id[:12],
            "name": name.lstrip("/"),
            "image_id": image_id,
            "image_ref": image_ref,
        }
        for key in (item["id"], item["short_id"], item["name"]):
            inventory[key] = item
    return inventory


def normalized_scope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 2:
        raise ValueError("scope must be a schema-2 finding object")
    groups = value.get("groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 20:
        raise ValueError("scope must contain 1-20 finding groups")

    inventory = docker_inventory()
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
                candidate = inventory.get(
                    str(requested.get("id") or "")
                ) or inventory.get(str(requested.get("name") or ""))
                if candidate is None:
                    raise ValueError("reported container is not currently running")
                if requested.get("id") and candidate["id"] != requested["id"]:
                    raise ValueError(
                        "running container identity no longer matches the alert"
                    )
                if artifact_id and candidate["image_id"] != artifact_id:
                    raise ValueError(
                        "running container image no longer matches the alert"
                    )
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
        "services": sorted(read_json_file(UNIT_FILE)),
    }


def capability_path(token: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("invalid capability token")
    return CAPABILITY_DIR / (hashlib.sha256(token.encode()).hexdigest() + ".json")


def open_capability(scope: Any) -> dict[str, Any]:
    CAPABILITY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CAPABILITY_DIR, 0o700)
    token = secrets.token_hex(32)
    normalized = normalized_scope(scope)
    policy = read_json_file(POLICY_FILE)
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
    raise ValueError("container is outside the capability scope")


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
        raise ValueError("file is outside the reported artifact scope")
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


def validate_host_binary(scope: dict, path: str, digest: str) -> None:
    expected = {b.get("artifact_id", "") for b in scope.get("bindings", [])
                if b.get("container_id") is None and b.get("reported_file") == path}
    expected = {value for value in expected if value.startswith("sha256:")}
    if expected and expected != {"sha256:" + digest}:
        raise ValueError("Host executable changed since the scan; fresh detection is required")


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
            local = Path(path)
        if local.is_symlink() or not local.is_file():
            raise ValueError("reported executable is not a regular file")
        if local.stat().st_size > 256 * 1024 * 1024:
            raise ValueError("Executable exceeds analysis size limit")
        digest = file_sha256(local)
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


def dependency_source(scope: dict, arguments: dict) -> dict:
    """Source for a module/version observed in the scoped executable's build metadata."""
    container = scoped_container(scope, arguments.get("container"), optional=True)
    executable = allowed_reported_file(scope, arguments.get("executable"), container)
    identity = (container["id"] if container else "host") + ":" + executable
    build = scope.get("binary_metadata", {}).get(identity)
    if not build:
        raise ValueError(
            "Inspect or analyze this executable before reading its dependency source"
        )
    module = str(arguments.get("module") or "")
    if module == "stdlib":
        repository, revision, prefix = "golang/go", build["go_version"], "src/"
    else:
        dependency = next(
            (m for m in [build["main"], *build["modules"]] if m.get("path") == module),
            None,
        )
        if not dependency or dependency.get("replaced"):
            raise ValueError(
                "Module is not an unmodified declared dependency of this executable"
            )
        revision, prefix = dependency["version"], ""
        if module.startswith("golang.org/x/"):
            repository = "golang/" + module.split("/")[2]
            tail = module.split("/")[3:]
        elif module.startswith("github.com/"):
            parts = module.split("/")
            repository = "/".join(parts[1:3])
            tail = parts[3:]
        else:
            raise ValueError("No source adapter for this module host")
        if tail and re.fullmatch(r"v\d+", tail[-1]):
            tail = tail[:-1]
        if any(
            not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", part) for part in tail
        ):
            raise ValueError("Invalid module source directory")
        prefix = "/".join(tail) + "/" if tail else ""
        if (
            revision == "(devel)"
            and dependency is build["main"]
            and build["settings"].get("vcs.modified") == "false"
        ):
            revision = build["settings"].get("vcs.revision", "")
    if not re.fullmatch(
        r"(?:go)?v?\d+\.\d+\.\d+(?:[-.+][A-Za-z0-9.-]+)?|[a-f0-9]{40}", revision
    ):
        raise ValueError("No supported exact source revision for this binary")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid source repository")
    pseudo = re.fullmatch(r"v\d+\.\d+\.\d+-(?:0\.)?\d{14}-([a-f0-9]{12})", revision)
    if pseudo:
        revision = pseudo[1]
    elif module != "stdlib" and prefix and revision.startswith("v"):
        revision = prefix + revision
    relative = str(arguments.get("path") or "")
    if (
        not relative
        or relative.startswith("/")
        or ".." in Path(relative).parts
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", relative)
    ):
        raise ValueError("Invalid dependency source path")
    query = str(arguments.get("query") or "")
    start = arguments.get("start_line", 1)
    if type(start) is not int or start < 1 or len(query) > 200:
        raise ValueError("Invalid source selection")
    url = (
        "https://raw.githubusercontent.com/"
        + repository
        + "/"
        + revision
        + "/"
        + prefix
        + relative
    )
    raw, _ = public_get(url, maximum=1024 * 1024)
    lines = raw.decode("utf-8").splitlines()
    if query:
        hits = [i for i, line in enumerate(lines) if i + 1 >= start and query in line]
        selected = sorted(
            {j for i in hits[:4] for j in range(max(0, i - 8), min(len(lines), i + 32))}
        )
    else:
        selected = list(range(start - 1, min(len(lines), start + 119)))
    return {
        "url": url,
        "module": module,
        "revision": revision,
        "binary_sha256": build["sha256"],
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "total_lines": len(lines),
        "lines": [{"line": i + 1, "text": lines[i]} for i in selected],
        "more_matches": len(hits) > 4 if query else False,
        "limitations": [
            "Source matches the binary's declared version; this does not establish a reproducible build or runtime invocation."
        ],
    }


def package_commands(package: str) -> list[tuple[str, list[str]]]:
    return [
        (
            "debian",
            ["/usr/bin/dpkg-query", "-W", "-f=${Status} ${Version}\\n", package],
        ),
        ("files", ["/usr/bin/dpkg-query", "-L", package]),
        ("dependencies", ["/usr/bin/apt-cache", "depends", package]),
        ("alpine", ["/sbin/apk", "info", "-a", package]),
        ("rpm", ["/usr/bin/rpm", "-qi", package]),
    ]


def package_info(scope: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    package = safe_identifier(arguments.get("package"), "package")
    if package not in scope["packages"]:
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

    def allowed(value):
        return any(Path(value).is_relative_to(root) for root in roots) or any(
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
        if not any(resolved_path.is_relative_to(root.resolve()) for root in roots):
            raise ValueError("configuration symlink escapes the allow-listed roots")
        with resolved_path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
            truncated = len(raw) > MAX_CONFIG_BYTES
            content = raw[:MAX_CONFIG_BYTES].decode("utf-8", errors="replace")
    redacted = []
    redacted_indent: int | None = None
    for line in content.splitlines():
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
            local = Path(path)
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
        cache_key = digest + ":" + advisory
        cached = scope.get("analyzer_cache", {}).get(cache_key)
        if cached:
            return {**cached, "executable": path, "reused_analysis": True}
        if not Path("/usr/local/bin/govulncheck").exists():
            return {"status": "unavailable", "reason": "govulncheck is not installed"}
        result = limited_output_run(
            [
                "/usr/local/bin/govulncheck",
                "-format",
                "json",
                "-mode",
                "binary",
                str(local),
            ],
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
                "reason": "govulncheck exceeded its input limit",
            }
        if result["returncode"] not in (0, 3):
            return {
                "status": "unavailable",
                "reason": (result["stderr"] or "govulncheck failed")[-2000:],
            }
        try:
            summary = summarize_govulncheck(result["stdout"], advisory)
        except ValueError as exc:
            return {
                "status": "unavailable",
                "reason": f"invalid govulncheck output: {exc}",
            }
        result = {
            "sha256": digest,
            "analysis_timestamp": time.time(),
            "analyzer": analyzer,
            "advisory": advisory,
            "executable": path,
            "go_build": build,
            **summary,
        }
        scope.setdefault("analyzer_cache", {})[cache_key] = result
        return result


def official_advisory(
    scope: dict[str, Any], arguments: dict[str, Any]
) -> dict[str, Any]:
    advisory = str(arguments.get("advisory") or "").upper()
    if advisory not in {
        value.upper() for value in scope["advisories"]
    } or not CVE_ID.fullmatch(advisory):
        raise ValueError("advisory is outside the capability scope")
    if advisory.startswith("CVE-"):
        source = "CVE Record"
        url = "https://cveawg.mitre.org/api/cve/" + parse.quote(advisory, safe="-")
    else:
        source = "OSV"
        url = "https://api.osv.dev/v1/vulns/" + parse.quote(advisory, safe="-")
    try:
        raw, _headers = public_get(url, maximum=MAX_RESULT_BYTES)
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "reason": str(exc)}
    if len(raw) > MAX_RESULT_BYTES:
        return {
            "status": "unavailable",
            "reason": "official advisory exceeded output limit",
        }
    payload = json.loads(raw)
    if advisory.startswith("CVE-"):
        cna = payload.get("containers", {}).get("cna", {})
        return {
            "source": source,
            "url": url,
            "id": payload.get("cveMetadata", {}).get("cveId", advisory),
            "state": payload.get("cveMetadata", {}).get("state"),
            "descriptions": (cna.get("descriptions") or [])[:10],
            "problem_types": (cna.get("problemTypes") or [])[:10],
            "affected": (cna.get("affected") or [])[:20],
            "references": (cna.get("references") or [])[:20],
        }
    return {
        "source": source,
        "url": url,
        "id": payload.get("id", advisory),
        "aliases": payload.get("aliases") or [],
        "summary": str(payload.get("summary") or "")[:2000],
        "details": str(payload.get("details") or "")[:4000],
        "affected": (payload.get("affected") or [])[:20],
        "references": (payload.get("references") or [])[:20],
    }


def artifact_repository(artifact: str) -> str:
    unpinned = artifact.split("@sha256:", 1)[0]
    without_registry = unpinned.removeprefix("docker.io/")
    slash = without_registry.rfind("/")
    colon = without_registry.rfind(":")
    if colon > slash:
        return without_registry[:colon]
    return without_registry


def artifact_aliases(artifact: str) -> set[str]:
    unpinned = artifact.split("@sha256:", 1)[0]
    without_registry = unpinned.removeprefix("docker.io/")
    repository = artifact_repository(artifact)
    aliases = {artifact, unpinned, without_registry, repository}
    aliases.update(value.rsplit("/", 1)[-1] for value in list(aliases))
    return aliases


def scoped_artifact(scope: dict, requested: str) -> str:
    matches = [
        candidate
        for candidate in scope["artifacts"]
        if requested in artifact_aliases(candidate)
    ]
    if len({artifact_repository(candidate) for candidate in matches}) != 1:
        raise ValueError("artifact is outside the capability scope")
    return matches[0]


def upstream_releases(scope: dict, arguments: dict) -> dict:
    return release_tags(scoped_artifact(scope, str(arguments.get("artifact") or "")))


def require_command(result: dict) -> None:
    if result["returncode"] != 0 or result.get("truncated"):
        raise RuntimeError("Observation command failed or returned incomplete output")


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
    paths = [p for p in result["stdout"].splitlines() if not DENIED_PATH.search(p)]
    return {"paths": paths[:100], "truncated": len(paths) > 100}


def invoke_operation(
    scope: dict[str, Any], operation: str, arguments: dict[str, Any]
) -> Any:
    if operation == 'deployment_coverage':
        root = Path('/var/lib/homelab-update-monitor')
        choices = [root / 'cve-state.json', root / 'coverage-audit.json']
        available = [p for p in choices if p.is_file()]
        if not available:
            return {'status': 'unknown', 'reason': 'no deployment scan evidence'}
        path = max(available, key=lambda p: p.stat().st_mtime_ns)
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('deployment evidence exceeds limit')
        state = json.loads(path.read_text())
        status = json.loads(path.with_suffix('.status.json').read_text())
        coverage = state.get('coverage', {})
        discovery = coverage.get('discovery', {})
        advisories = {b['advisory'] for b in scope['bindings']}
        return {'status': status, 'observed_at': state.get('updated_at'),
                'scope': 'this host only; correlate other deployments separately',
                'runtime_sha256': discovery.get('runtime_sha256'),
                'discovery_gaps': discovery.get('gaps', ['runtime discovery missing']),
                'requirements': coverage.get('requirements', []),
                'libraries': [{k: item.get(k) for k in ('deployment', 'path', 'status', 'reason', 'identified_types')}
                              for item in coverage.get('libraries', [])],
                'matching_findings': [f for f in state.get('findings', {}).values() if f.get('id') in advisories],
                'limitations': coverage.get('limitations', [])}
    if operation == "advisory_reference":
        return advisory_reference(scope, arguments, official_advisory)
    if operation == "discover_config":
        return discover_config(scope, arguments)
    if operation == "dependency_source":
        return dependency_source(scope, arguments)
    if operation == "verify_candidate":
        container = scoped_container(scope, arguments.get("container"))
        artifact = scoped_artifact(scope, str(arguments.get("artifact") or ""))
        if not any(
            b["container_id"] == container["id"]
            and b["advisory"] == arguments.get("advisory")
            and b["package"] == arguments.get("package")
            and artifact_repository(b["artifact"]) == artifact_repository(artifact)
            for b in scope["bindings"]
        ):
            raise ValueError("Candidate does not match this deployed finding")
        return verify_candidate(
            scope, arguments, artifact, container, bounded_run, limited_output_run
        )
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
                local = Path(path)
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
    if operation == "official_advisory":
        return official_advisory(scope, arguments)
    if operation == "upstream_releases":
        return upstream_releases(scope, arguments)
    if operation == "run_analyzer":
        return run_analyzer(scope, arguments)
    raise ValueError("unknown evidence operation")


def redact_result(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if re.search(r"(?i)password|secret|token|credential|private.key", key)
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
                raise ValueError("Container is outside the capability scope")
            category = (
                "analyzer"
                if operation in {"run_analyzer", "verify_candidate"}
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
                current = next(
                    (
                        item
                        for item in docker_inventory().values()
                        if item["id"] == container["id"]
                    ),
                    None,
                )
                if not current or current["image_id"] != container["image_id"]:
                    raise ValueError(
                        "Deployment changed since this capability was opened"
                    )
            cache_key = hashlib.sha256(
                json.dumps([operation, arguments], sort_keys=True).encode()
            ).hexdigest()
            cached = (
                capability["cache"].get(cache_key)
                if operation in {"official_advisory", "advisory_reference"}
                else None
            )
            result = cached or invoke_operation(scope, operation, arguments)
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
            if container and not next(
                (
                    item
                    for item in docker_inventory().values()
                    if item["id"] == container["id"]
                ),
                None,
            ):
                raise ValueError("Deployment changed during observation")
    except Exception as exc:
        receipt.update(status="failed", result={}, limitations=[str(exc)[:500]])
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
                    if receipt["status"] == "success" and operation in {
                        "official_advisory",
                        "advisory_reference",
                    }:
                        capability["cache"][cache_key] = receipt["result"]
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


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("request must be an object")
    action = payload.get("action")
    if action == "open":
        result = open_capability(payload.get("scope"))
    elif action == "invoke":
        result = invoke_capability(
            str(payload.get("token") or ""),
            str(payload.get("operation") or ""),
            payload.get("arguments") or {},
        )
    elif action == "close":
        result = close_capability(str(payload.get("token") or ""))
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
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        raise SystemExit(1) from exc
