#!/usr/bin/env python3
"""Scan deployed artifacts and report high/critical findings and coverage failures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request


SEVERITIES = {"HIGH", "CRITICAL"}
MAX_MESSAGE_FINDINGS = 20
MAX_FINDING_GROUPS = 20
MAX_FINDING_OCCURRENCES = 40
FINDING_IDENTITY_FIELDS = ("id", "package", "installed", "fixed", "severity", "target")
SKIP_DIRS = (
    "/data",
    "/dev",
    "/media",
    "/mnt",
    "/proc",
    "/run",
    "/storage",
    "/sys",
    "/var/lib/containerd",
    "/var/lib/docker",
    "/var/lib/lxc",
    "/var/lib/lxcfs",
)


def read_credential(name: str) -> str:
    credential_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credential_directory:
        raise RuntimeError("CREDENTIALS_DIRECTORY is not set")
    value = (Path(credential_directory) / name).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"credential {name!r} is empty")
    return value


def run_json(command: list[str], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=output_dir, prefix="trivy-", suffix=".json", delete=False
    ) as handle:
        report_path = Path(handle.name)
    try:
        completed = subprocess.run(
            [*command, "--format", "json", "--output", str(report_path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=7200,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip().splitlines()[-1:]
            raise RuntimeError(
                f"Trivy exited with {completed.returncode}: "
                f"{detail[0] if detail else 'no diagnostic'}"
            )
        return json.loads(report_path.read_text(encoding="utf-8"))
    finally:
        report_path.unlink(missing_ok=True)


def trivy_scan_command(trivy: str, cache: Path, scan_type: str) -> list[str]:
    return [
        trivy,
        scan_type,
        "--cache-dir",
        str(cache),
        "--quiet",
        "--scanners",
        "vuln",
        "--severity",
        "HIGH,CRITICAL",
    ]


def scan_go_binary(trivy: str, cache: Path, state_dir: Path, path: Path) -> dict[str, Any]:
    """Scan an explicitly managed executable, requiring actual analyzer coverage."""
    if not path.is_absolute():
        raise ValueError("managed Go binary paths must be absolute")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > 256 * 1024 * 1024:
        raise RuntimeError(f"managed Go binary is not a bounded regular file: {path}")
    with resolved.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    # `fs` disables compiled-language analysis in Trivy 0.74. `rootfs` also
    # accepts a single file, so caches and unrelated host trees stay out of scope.
    report = run_json(
        [*trivy_scan_command(trivy, cache, "rootfs"), "--pkg-types", "library",
         "--list-all-pkgs", str(resolved)], state_dir,
    )
    with resolved.open("rb") as handle:
        after = hashlib.file_digest(handle, "sha256").hexdigest()
    if path.resolve(strict=True) != resolved or digest != after:
        raise RuntimeError(f"managed Go binary changed during its scan: {path}")
    results = [item for item in report.get("Results") or [] if item.get("Type") == "gobinary"]
    packages = [package for item in results for package in item.get("Packages") or []]
    versions = sorted({str(p.get("Version")) for p in packages if p.get("Name") == "stdlib" and p.get("Version")})
    if len(results) != 1 or not versions:
        raise RuntimeError(f"Trivy did not identify Go dependencies in {path}; coverage is unknown")
    # Single-file scans report only a basename. Preserve the real host path for
    # subsequent evidence requests; never turn 'caddy' into '/caddy'.
    results[0]["Target"] = str(resolved)
    report["Results"] = results
    report["ArtifactName"] = f"host executable {path}"
    report["_homelab_host_binary"] = {
        "path": str(path), "resolved_path": str(resolved), "sha256": digest,
        "go_versions": versions, "package_count": len(packages),
        "packages": [{"name": p.get("Name"), "version": p.get("Version")} for p in packages],
    }
    return report


def scan_reports(
    trivy: str, cache: Path, state_dir: Path, go_binaries: list[Path] | None = None,
    libraries: list[dict] | None = None,
) -> list[dict[str, Any]]:
    # OS packages, explicitly managed native Go binaries, and Docker images have
    # distinct coverage. An empty OS result says nothing about embedded libraries.
    rootfs = [*trivy_scan_command(trivy, cache, "rootfs"), "--pkg-types", "os"]
    for path in SKIP_DIRS:
        rootfs.extend(["--skip-dirs", path])
    rootfs.append("/")
    reports = [run_json(rootfs, state_dir)]
    reports[0]["_homelab_scan_kind"] = "os"

    for path in sorted(set(go_binaries or [])):
        reports.append(scan_go_binary(trivy, cache, state_dir, path))

    for spec in libraries or []:
        reports.append(scan_library(trivy, cache, state_dir, spec))

    for runtime in docker_runtime_images():
        report = run_json(
            trivy_scan_command(trivy, cache, "image") + ["--list-all-pkgs", runtime["image_id"]],
            state_dir,
        )
        report["_homelab_runtime"] = runtime
        reports.append(report)
    return reports


def scan_library(trivy: str, cache: Path, state_dir: Path, spec: dict) -> dict:
    from homelab_deployment_inventory import metadata_inventory

    path = Path(spec['path'])
    item = {'deployment': spec['deployment'], 'path': str(path), 'required_types': spec['types'],
            'status': 'failed', 'packages': [], 'reason': 'scan failed'}
    report = {'_homelab_library': item, 'Results': []}
    try:
        if not path.is_absolute():
            raise ValueError('library path must be absolute')
        before = metadata_inventory(path)
        report = run_json([*trivy_scan_command(trivy, cache, 'rootfs'), '--pkg-types', 'library',
                           '--list-all-pkgs', before['resolved_path']], state_dir)
        after = metadata_inventory(path)
        if before != after:
            raise ValueError('installed metadata changed during scan')
        item['identity'] = before
        file_identities = {str(Path(p['path']).resolve()): p['sha256'] for p in before['files']}
        identified = set()
        for result in report.get('Results') or []:
            packages = result.get('Packages') or []
            if packages:
                identified.add(result.get('Type'))
            target = result.get('Target', '')
            if target:
                scan_root = Path(before['resolved_path'])
                candidate = scan_root if scan_root.is_file() else scan_root / target
                candidate = candidate.resolve()
                if candidate != scan_root and not candidate.is_relative_to(scan_root):
                    raise ValueError('scanner target escaped the declared library root')
                if candidate.is_file():
                    result['Target'] = str(candidate)
            if result.get('Type') in {'gobinary', 'rustbinary'}:
                binary_path = str(Path(result.get('Target', '')).resolve())
                if binary_path in file_identities:
                    result['_homelab_binary_sha256'] = file_identities[binary_path]
            item['packages'].extend({'name': p.get('Name'), 'version': p.get('Version'),
                                     'type': result.get('Type')} for p in packages)
        missing = sorted(set(spec['types']) - identified)
        item['status'] = 'partial' if missing else 'covered'
        item['reason'] = 'missing analyzers: ' + ', '.join(missing) if missing else 'installed package metadata analyzed'
        item['identified_types'] = sorted(identified)
        report['ArtifactName'] = 'host application ' + spec['deployment']
        report['_homelab_library'] = item
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # Preserve other deployments' evidence and retain this explicit failure.
        report = {'_homelab_library': item, 'Results': []}
    return report


def docker_runtime_images() -> list[dict[str, Any]]:
    """Return each exact running Docker image once, without retaining container secrets."""
    if not shutil.which("docker"):
        return []
    containers = subprocess.run(
        ["docker", "ps", "--quiet"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    ids = sorted(set(filter(None, containers.stdout.splitlines())))
    if containers.returncode != 0:
        raise RuntimeError("Docker runtime inventory failed; container coverage is unknown")
    if not ids:
        return []
    inspected = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            '{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .Config.Image}}',
            *ids,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if inspected.returncode != 0:
        raise RuntimeError("Docker image inspection failed; container coverage is unknown")

    images: dict[str, dict[str, Any]] = {}
    for line in inspected.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise RuntimeError("Docker returned an incomplete container identity")
        try:
            container_id, name, image_id, configured_ref = (
                str(json.loads(field) or "") for field in fields
            )
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError("Docker returned an invalid container identity") from None
        if not image_id or not container_id:
            raise RuntimeError("Docker returned an empty container identity")
        configured_ref = configured_ref or image_id
        item = images.setdefault(
            image_id,
            {
                "image_id": image_id,
                "configured_refs": [],
                "containers": [],
            },
        )
        if configured_ref not in item["configured_refs"]:
            item["configured_refs"].append(configured_ref)
        item["containers"].append(
            {
                "id": container_id,
                "name": name.lstrip("/"),
            }
        )
    if sum(len(image["containers"]) for image in images.values()) != len(ids):
        raise RuntimeError("Docker inventory changed or was incomplete; scan must be retried")
    return [images[key] for key in sorted(images)]


def finding_key(finding: dict[str, Any]) -> str:
    # Keep the original state identity stable when display-only metadata is added.
    identity = {key: finding[key] for key in FINDING_IDENTITY_FIELDS}
    stable = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(stable.encode()).hexdigest()


def runtime_identity(finding: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return (str(finding.get("artifact_id") or "") + str(finding.get('runtime_sha256') or ''), tuple(sorted(
        str(c.get("id") or "") for c in finding.get("containers") or []
    )))


def canonical_artifact_label(value: str) -> str:
    return artifact_label(value).removeprefix("docker.io/")


def canonicalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(finding)
    target = str(normalized.get("target") or "")
    artifact = str(normalized.get("artifact") or "")
    if (
        artifact
        and artifact != "host rootfs"
        and (normalized.get("result_class") == "os-pkgs" or target.startswith("sha256:"))
        and "(" in target
    ):
        normalized["target"] = (
            canonical_artifact_label(artifact) + " (" + target.split("(", 1)[1]
        )
    return normalized


def extract_findings(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    for report in reports:
        runtime = (
            report.get("_homelab_runtime")
            if isinstance(report.get("_homelab_runtime"), dict)
            else {}
        )
        configured_refs = runtime.get("configured_refs") or []
        artifact = str(
            configured_refs[0] if configured_refs else report.get("ArtifactName") or "host rootfs"
        )
        metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
        for result in report.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or "unknown")
            result_class = str(result.get("Class") or "unknown")
            if runtime and result_class == "os-pkgs":
                os_metadata = metadata.get("OS") if isinstance(metadata.get("OS"), dict) else {}
                os_label = " ".join(
                    filter(
                        None,
                        [str(os_metadata.get("Family") or ""), str(os_metadata.get("Name") or "")],
                    )
                )
                repo_tags = metadata.get("RepoTags") or []
                image_label = canonical_artifact_label(
                    str(repo_tags[0] if repo_tags else artifact)
                )
                target = f"{image_label} ({os_label})" if os_label else image_label
            for vulnerability in result.get("Vulnerabilities") or []:
                if not isinstance(vulnerability, dict):
                    continue
                severity = str(vulnerability.get("Severity") or "UNKNOWN").upper()
                fixed = str(vulnerability.get("FixedVersion") or "").strip()
                if severity not in SEVERITIES:
                    continue
                finding = {
                    "id": str(vulnerability.get("VulnerabilityID") or "unknown"),
                    "package": str(vulnerability.get("PkgName") or "unknown"),
                    "installed": str(vulnerability.get("InstalledVersion") or "unknown"),
                    "fixed": fixed,
                    "severity": severity,
                    "target": target,
                    "artifact": artifact,
                    "artifact_type": str(report.get("ArtifactType") or "rootfs"),
                    "artifact_id": str(
                        metadata.get("ImageID") or runtime.get("image_id")
                        or ("sha256:" + report["_homelab_host_binary"]["sha256"]
                            if report.get("_homelab_host_binary") else "")
                    ),
                    "repo_digests": [str(value) for value in metadata.get("RepoDigests") or []][:5],
                    "containers": runtime.get("containers") or [],
                    "result_class": result_class,
                    "result_type": str(result.get("Type") or "unknown"),
                }
                if report.get('_homelab_library'):
                    identity = report['_homelab_library'].get('identity', {})
                    finding['deployment'] = report['_homelab_library']['deployment']
                    finding['artifact_id'] = 'inventory-sha256:' + identity.get('sha256', '')
                    if result.get('_homelab_binary_sha256'):
                        finding['artifact_id'] = 'sha256:' + result['_homelab_binary_sha256']
                finding = canonicalize_finding(finding)
                findings[finding_key(finding)] = finding
    return findings


def load_state(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise RuntimeError("unsupported CVE monitor state")
    return data


def save_state(
    path: Path, findings: dict[str, dict[str, Any]],
    native_coverage: list[dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
) -> None:
    data = {
        "schema": 1,
        "updated_at": datetime.now(UTC).isoformat(),
        "findings": findings,
        "native_go_coverage": native_coverage or [],
        "coverage": coverage or {},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def artifact_label(value: str) -> str:
    return value.split("@sha256:", 1)[0]


def format_findings(new: list[dict[str, Any]], total: int) -> str:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for finding in new:
        key = (
            finding["severity"],
            finding["id"],
            finding["package"],
            finding["fixed"],
        )
        groups.setdefault(key, []).append(finding)

    critical = sum(key[0] == "CRITICAL" for key in groups)
    group_noun = "group" if len(groups) == 1 else "groups"
    critical_noun = "group" if critical == 1 else "groups"
    occurrence_noun = "occurrence" if len(new) == 1 else "occurrences"
    lines = [
        f"{len(groups)} new high/critical vulnerability {group_noun} "
        f"({len(new)} {occurrence_noun}; {critical} critical {critical_noun}); "
        f"{total} raw findings tracked"
    ]
    ordered_groups = sorted(
        groups.items(),
        key=lambda item: (item[0][0] != "CRITICAL", item[0][1], item[0][2]),
    )
    for (severity, vulnerability_id, package, fixed), occurrences in ordered_groups[
        :MAX_MESSAGE_FINDINGS
    ]:
        locations: dict[tuple[str, str], int] = {}
        for finding in occurrences:
            location = (
                artifact_label(finding.get("artifact", "host rootfs")),
                finding["installed"],
            )
            locations[location] = locations.get(location, 0) + 1
        summaries = []
        for (artifact, installed), count in sorted(locations.items()):
            count_text = f", {count} binaries" if count > 1 else ""
            summaries.append(f"{artifact} {installed}{count_text}")
        lines.append(
            f"- {severity} {vulnerability_id} in {package} -> {fixed or 'no published fix'}; "
            + "; ".join(summaries)
        )
    if len(groups) > MAX_MESSAGE_FINDINGS:
        lines.append(f"- and {len(groups) - MAX_MESSAGE_FINDINGS} more groups")
    return "\n".join(lines)


def build_finding_context(
    new: list[dict[str, Any]], coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for finding in new[:MAX_FINDING_OCCURRENCES]:
        key = (
            finding["severity"],
            finding["id"],
            finding["package"],
            finding["fixed"],
        )
        group = groups.setdefault(
            key,
            {
                "id": finding["id"],
                "package": finding["package"],
                "installed": [],
                "fixed": finding["fixed"],
                "severity": finding["severity"],
                "occurrences": [],
            },
        )
        if finding["installed"] not in group["installed"]:
            group["installed"].append(finding["installed"])
            group["installed"].sort()
        target = str(finding.get("target") or "")
        reported_file = (
            "/" + target.lstrip("/")
            if finding.get("result_type") == "gobinary" or (finding.get('result_class') == 'lang-pkgs' and target.startswith('/'))
            else None
        )
        group["occurrences"].append(
            {
                "artifact": finding.get("artifact"),
                "artifact_type": finding.get("artifact_type"),
                "artifact_id": finding.get("artifact_id"),
                "repo_digests": finding.get("repo_digests"),
                "containers": finding.get("containers"),
                "reported_file": reported_file,
                "coverage_status": finding.get('coverage_status', 'current'),
                "target": target,
                "result_class": finding.get("result_class"),
                "result_type": finding.get("result_type"),
                "installed": finding.get("installed"),
            }
        )
    result = {
        "schema": 2,
        "generated_at": datetime.now(UTC).isoformat(),
        "groups": list(groups.values())[:MAX_FINDING_GROUPS],
        "truncated": len(new) > MAX_FINDING_OCCURRENCES or len(groups) > MAX_FINDING_GROUPS,
        "total_occurrences": len(new),
        "included_occurrences": sum(len(g["occurrences"]) for g in list(groups.values())[:MAX_FINDING_GROUPS]),
    }
    for group in result["groups"]:
        group["occurrence_count"] = len(group["occurrences"])
    if coverage is not None:
        result["coverage"] = {
            "scope": "this host only",
            "os_packages": coverage.get("os_packages", False),
            "native_go_paths": [p["path"] for p in coverage.get("native_go", [])],
            "docker_image_count": len(coverage.get("docker_images", [])),
            "limitations": coverage.get("limitations", []),
            "library_scans": [{k: item[k] for k in ('deployment', 'path', 'status', 'reason')}
                              for item in coverage.get('libraries', [])],
            "discovery_gap_count": len(coverage.get('discovery', {}).get('gaps', [])),
        }
    return result


def scan_coverage(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep dependency inventories even when they produce no vulnerability matches."""
    images = []
    for report in reports:
        if not report.get("_homelab_runtime"):
            continue
        images.append({
            **report["_homelab_runtime"],
            "go_binaries": [{
                "path": "/" + str(result.get("Target", "")).lstrip("/"),
                "packages": [{"name": p.get("Name"), "version": p.get("Version")}
                             for p in result.get("Packages") or []],
            } for result in report.get("Results") or [] if result.get("Type") == "gobinary"],
        })
    return {
        "os_packages": any(r.get("_homelab_scan_kind") == "os" for r in reports),
        "native_go": [r["_homelab_host_binary"] for r in reports if r.get("_homelab_host_binary")],
        "docker_images": images,
        "libraries": [r['_homelab_library'] for r in reports if r.get('_homelab_library')],
        "limitations": [
            "Native dependency coverage includes declared Go executables and explicitly reported library analyzers; unsupported types remain gaps.",
            "Container results describe image contents, not writable-layer or mounted replacements.",
            "Dependency matches do not establish runtime reachability or exploitation.",
        ],
    }


def finding_batches(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Keep one advisory per investigation and never silently discard the tail."""
    advisories: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        advisories.setdefault(finding["id"], []).append(finding)
    batches = []
    for advisory in sorted(advisories):
        batch: list[dict[str, Any]] = []
        groups: set[tuple[str, str, str]] = set()
        for finding in advisories[advisory]:
            key = (finding["package"], finding["severity"], finding["fixed"])
            if len(batch) == MAX_FINDING_OCCURRENCES or (key not in groups and len(groups) == MAX_FINDING_GROUPS):
                batches.append(batch)
                batch, groups = [], set()
            batch.append(finding)
            groups.add(key)
        if batch:
            batches.append(batch)
    return batches


def save_scan_status(path: Path, status: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps({"status": status, "observed_at": datetime.now(UTC).isoformat()}) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def send_notification(
    url: str, secret: str, source: str, message: str, context: dict[str, Any], *, kind: str = "cve",
) -> None:
    body = json.dumps(
        {
            "kind": kind,
            "source": source,
            "message": message,
            "context": context,
            "observed_at": datetime.now(UTC).isoformat(),
        },
        separators=(",", ":"),
    ).encode()
    outgoing = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "User-Agent": "homelab-cve-monitor/1",
        },
    )
    try:
        with request.urlopen(outgoing, timeout=20) as response:
            if response.status != 202:
                raise RuntimeError(f"notification endpoint returned HTTP {response.status}")
    except error.URLError as exc:
        raise RuntimeError(f"notification delivery failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", default="trivy")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--report-file", type=Path)
    parser.add_argument("--go-binary", type=Path, action="append", default=[])
    parser.add_argument('--deployment-config', type=Path)
    parser.add_argument("--snapshot-only", action="store_true", help="Write scan evidence without notifications; use a separate state path")
    args = parser.parse_args()

    source = os.environ.get("UPDATE_MONITOR_SYSTEM_NAME", "unknown host").strip()
    webhook_url = os.environ.get("UPDATE_MONITOR_WEBHOOK_URL", "").strip()
    if not webhook_url and not args.snapshot_only:
        raise RuntimeError("UPDATE_MONITOR_WEBHOOK_URL is not set")

    status_path = args.state.with_suffix(".status.json")
    try:
        prior_status = json.loads(status_path.read_text()).get("status")
    except (OSError, ValueError):
        prior_status = None
    save_scan_status(status_path, "running")
    config = json.loads(args.deployment_config.read_text()) if args.deployment_config else None
    try:
        if args.report_file:
            reports = [json.loads(args.report_file.read_text(encoding="utf-8"))]
        else:
            reports = scan_reports(args.trivy, args.cache, args.state.parent, args.go_binary,
                                   (config or {}).get('libraries', []))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        save_scan_status(status_path, "failed")
        if not args.snapshot_only and prior_status != "failure_notified":
            send_notification(webhook_url, read_credential("webhook-secret"), source,
                "CVE scanning failed. Current coverage is unknown; previous findings are retained. Check homelab-cve-monitor.service.",
                {}, kind="system")
            save_scan_status(status_path, "failure_notified")
        elif prior_status == "failure_notified":
            save_scan_status(status_path, "failure_notified")
        raise
    native_coverage = [r["_homelab_host_binary"] for r in reports if r.get("_homelab_host_binary")]
    coverage = scan_coverage(reports)
    if config:
        from homelab_deployment_inventory import discover
        coverage['discovery'] = discover(config)
        coverage['requirements'] = config['deployments']
    current = extract_findings(reports)
    # Runtime drift invalidates previous assessment even if package versions are unchanged.
    if config:
        for finding in current.values():
            finding['runtime_sha256'] = coverage['discovery']['runtime_sha256']
    previous = load_state(args.state)
    incomplete = {s['deployment']: set(s.get('identified_types', []))
                  for s in coverage.get('libraries', []) if s['status'] != 'covered'}
    for key, finding in ((previous or {}).get('findings') or {}).items():
        deployment = finding.get('deployment')
        if deployment in incomplete and finding.get('result_type') not in incomplete[deployment] and key not in current:
            current[key] = {**finding, 'coverage_status': 'unknown_retained_from_prior_scan'}

    if args.snapshot_only:
        save_state(args.state, current, native_coverage, coverage)
        save_scan_status(status_path, "complete")
        print(f"snapshot findings={len(current)} native_binaries={len(native_coverage)} images={len(coverage['docker_images'])}")
        return 0

    previous_values = ((previous or {}).get("findings") or {}).values()
    previous_findings = {
        finding_key(canonicalize_finding(value)): canonicalize_finding(value)
        for value in previous_values
    }
    new = [value for key, value in current.items()
           if key not in previous_findings or runtime_identity(value) != runtime_identity(previous_findings[key])]
    resolved = len(set(previous_findings) - set(current))
    for batch in finding_batches(new):
        send_notification(
            webhook_url,
            read_credential("webhook-secret"),
            source,
            format_findings(batch, len(current)),
            build_finding_context(batch, coverage),
        )
    if prior_status in {"failed", "failure_notified"}:
        send_notification(webhook_url, read_credential("webhook-secret"), source,
            "CVE scanning recovered. The declared artifacts were scanned successfully; findings are tracked separately.",
            {}, kind="system")
    gaps = sorted([item['deployment'] + ': ' + item['reason'] for item in coverage.get('libraries', [])
                   if item['status'] != 'covered'] + coverage.get('discovery', {}).get('gaps', []))
    old_coverage = (previous or {}).get('coverage', {})
    old_gaps = old_coverage.get('gap_summary', [])
    if gaps != old_gaps:
        message = (f'Deployment coverage has {len(gaps)} gaps. ' + '; '.join(gaps[:4]) +
                   '. Full evidence is in cve-state.json; incomplete coverage blocks automatic patch eligibility.') if gaps else 'Previously reported deployment discovery and library scan gaps cleared.'
        send_notification(webhook_url, read_credential('webhook-secret'), source, message, {}, kind='system')
    coverage['gap_summary'] = gaps
    save_state(args.state, current, native_coverage, coverage)
    save_scan_status(status_path, "complete")
    print(f"tracked={len(current)} new={len(new)} resolved={resolved}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"homelab-cve-monitor: {exc}", file=sys.stderr)
        raise SystemExit(1)
