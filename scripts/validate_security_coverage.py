#!/usr/bin/env python3
"""Require declared coverage for every application and deployment system."""
from __future__ import annotations

from pathlib import Path

import yaml

from cve_coverage_report import expected_systems

ROOT = Path(__file__).resolve().parents[1]


def validate(contract: dict, applications: set[str], systems: set[str]) -> None:
    if contract.get("schema_version") != 1:
        raise ValueError("unsupported security coverage contract")
    profiles = contract.get("applications", {})
    if set(profiles) != applications:
        raise ValueError(f"application coverage drift: missing={sorted(applications - set(profiles))}, stale={sorted(set(profiles) - applications)}")
    covered_systems = set()
    for kind in ("applications", "additional_deployments"):
        for name, profile in contract.get(kind, {}).items():
            targets, adapters = profile.get("targets", []), profile.get("adapters", [])
            if not targets or not adapters:
                raise ValueError(f"{name}: missing targets or required adapters")
            if set(targets) - systems:
                raise ValueError(f"{name}: unknown target {sorted(set(targets) - systems)}")
            covered_systems.update(targets)
    if missing := systems - covered_systems:
        raise ValueError(f"systems missing from security coverage: {sorted(missing)}")
    required_layers = {"platform", "application", "dependencies", "runtime", "exposure", "provenance", "recovery"}
    if set(contract.get("layers", {})) != required_layers:
        raise ValueError("coverage must include all seven evidence layers")
    if contract.get("autonomy", {}).get("patching_enabled") is not False or contract.get("autonomy", {}).get("emergency_measures_enabled") is not False:
        raise ValueError("this inventory has no authorized executor policy; fleet-wide enablement must remain disabled")


def main() -> None:
    def read(path: str) -> dict:
        return yaml.safe_load((ROOT / path).read_text())

    applications = {yaml.safe_load(p.read_text())["id"] for p in (ROOT / "apps").glob("*.yml")}
    systems = set(expected_systems(read("ansible/inventory/hosts.yml"), read("inventory/workloads.yml")))
    validate(read("inventory/security-coverage.yml"), applications, systems)
    print(f"validated coverage requirements for {len(applications)} application manifests and {len(systems)} systems; this does not attest scan completeness")


if __name__ == "__main__":
    main()
