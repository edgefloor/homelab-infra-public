#!/usr/bin/env python3
"""Correlate an advisory across explicit scan inventories; missing hosts stay unknown."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def monitored_hosts(inventory: dict) -> list[str]:
    groups = inventory["all"]["children"]

    def hosts(name: str) -> set[str]:
        group = groups[name] or {}
        result = set(group.get("hosts", {}))
        for child in group.get("children", {}):
            result.update(hosts(child))
        return result

    return sorted(hosts("beszel_agents"))


def expected_systems(inventory: dict, workloads: dict) -> list[str]:
    """The coverage denominator comes from deployments, never scanner enrollment."""
    systems = {w["name"] for w in workloads["inventory"]["workloads"]}
    def collect(group: dict) -> None:
        systems.update(group.get("hosts", {}))
        for child in group.get("children", {}).values():
            collect(child or {})

    collect(inventory["all"])
    kinds = inventory["all"]["vars"]["infrastructure_contract"]["host_kinds"]
    systems.update(name for name, kind in kinds.items() if kind in {"proxmox_host", "external_vps"})
    return sorted(systems)


def load(path: Path) -> dict:
    try:
        if path.stat().st_size > 32 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def fresh(value: str, now: datetime) -> bool:
    try:
        age = now - datetime.fromisoformat(value)
        return timedelta(0) <= age <= timedelta(hours=36)
    except (ValueError, TypeError):
        return False


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render(directory: Path, hosts: list[str], advisory: str, now: datetime) -> str:
    lines = [f"# {advisory}: detection coverage", "", f"Checked: {now.isoformat()}", "",
             "These are dependency matches in scanned artifacts. Runtime reachability and exploitation are separate questions.", "",
             "| Host | Scan status | Native Go binaries | Library roots | Docker images | Matching occurrences |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    matches = []
    for host in hosts:
        state, status = load(directory / f"{host}.json"), load(directory / f"{host}.status.json")
        coverage = state.get("coverage", {})
        complete = (status.get("status") == "complete" and fresh(state.get("updated_at"), now)
                    and fresh(status.get("observed_at"), now) and coverage.get("os_packages") is True)
        if not complete:
            lines.append(f"| {cell(host)} | Unknown: missing, failed, stale, or incomplete scan | — | — | — | — |")
            continue
        findings = [f for f in state.get("findings", {}).values() if f.get("id") == advisory]
        lines.append(f"| {cell(host)} | Completed for declared artifacts | {len(coverage.get('native_go', []))} | {len(coverage.get('libraries', []))} | {len(coverage.get('docker_images', []))} | {len(findings)} |")
        for finding in findings:
            names = [c.get("name", "unnamed") for c in finding.get("containers") or []]
            location = ", ".join(names) if names else finding.get("target", "unknown artifact")
            matches.append((host, location, finding.get("package"), finding.get("installed"), finding.get("fixed") or "No published fix"))
    lines += ["", "## Matches", "", "| Host | Installation / file | Package | Installed | Scanner-listed fix |",
              "| --- | --- | --- | --- | --- |"]
    lines.extend("| " + " | ".join(cell(v) for v in row) + " |" for row in sorted(matches))
    if not matches:
        lines += ["", "No matches in the completed scans. Unknown rows are not negative results."]
    lines += ["", "## Boundaries", "",
              "- Native coverage includes OS packages, declared Go executables, and the identified installed-library analyzers. An attempted library root is not proof of coverage; inspect its analyzer status in the readiness report.",
              "- Docker scans cover running images. Writable-layer and bind-mounted replacements need runtime checks.",
              "- Every declared LXC, the Proxmox host, and the VPS must appear. Missing scanner enrollment is an unknown result, not an exclusion.",
              "- Completing the declared artifact scan does not establish full application, runtime, configuration, or recovery coverage.",
              "- A completed scan is limited by analyzer and vulnerability-database coverage. Zero matches does not mean unaffected.",
              "- The NeroCD Caddy route assessment cannot establish the main HTTPS proxy's reachability.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--advisory", required=True)
    parser.add_argument("--inventory", type=Path, default=ROOT / "ansible/inventory/hosts.yml")
    parser.add_argument("--workloads", type=Path, default=ROOT / "inventory/workloads.yml")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    hosts = expected_systems(yaml.safe_load(args.inventory.read_text()), yaml.safe_load(args.workloads.read_text()))
    args.output.write_text(render(args.directory, hosts, args.advisory, datetime.now(UTC)))
    args.output.chmod(0o600)


if __name__ == "__main__":
    main()
