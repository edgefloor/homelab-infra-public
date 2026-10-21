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


def validate_relationships(contract: dict, relationships: dict) -> None:
    if relationships.get("schema_version") != 1:
        raise ValueError("unsupported security relationship inventory")
    expected = (set(contract.get("applications", {})) |
                set(contract.get("additional_deployments", {})) |
                {"defensive-monitor"})
    mapped = set(relationships.get("applications", {}))
    if mapped != expected:
        raise ValueError(
            f"input relationship drift: missing={sorted(expected - mapped)}, "
            f"stale={sorted(mapped - expected)}")
    sources = relationships.get("input_sources", {})
    if not sources or any(type(item.get("targetable")) is not bool or
                          not item.get("evidence") for item in sources.values()):
        raise ValueError("input sources require targetability and evidence")
    allowed_relations = {
        "consumes_files_from", "consumes_index_data_from", "consumes_logs_from",
        "parses_content_from", "receives_authorization_from",
        "receives_backups_from", "receives_control_from",
        "receives_database_queries_from", "receives_events_from",
        "receives_graph_updates_from", "receives_jobs_from",
        "receives_messages_from", "receives_peer_data_from",
        "receives_requests_from", "receives_telemetry_from",
        "receives_timer_events_from", "serves_queries_from", "stores_for",
        "transports_requests_from",
    }
    for name, mapping in relationships["applications"].items():
        if type(mapping.get("complete")) is not bool:
            raise ValueError(f"{name}: input mapping completeness is required")
        if not mapping.get("evidence") or not mapping.get("inputs"):
            raise ValueError(f"{name}: input mapping requires evidence and inputs")
        for item in mapping["inputs"]:
            if set(item) not in ({"source", "relation"},
                                 {"application", "relation"}):
                raise ValueError(f"{name}: invalid input relationship")
            if item["relation"] not in allowed_relations:
                raise ValueError(f"{name}: invalid input relationship type")
            if "source" in item and item["source"] not in sources:
                raise ValueError(f"{name}: unknown input source {item['source']}")
            if "application" in item and item["application"] not in expected:
                raise ValueError(
                    f"{name}: unknown input application {item['application']}")
            if item.get("application") == name:
                raise ValueError(f"{name}: self-referential input relationship")


def main() -> None:
    def read(path: str) -> dict:
        return yaml.safe_load((ROOT / path).read_text())

    applications = {yaml.safe_load(p.read_text())["id"] for p in (ROOT / "apps").glob("*.yml")}
    systems = set(expected_systems(read("ansible/inventory/hosts.yml"), read("inventory/workloads.yml")))
    contract = read("inventory/security-coverage.yml")
    validate(contract, applications, systems)
    validate_relationships(contract, read("inventory/security-relationships.yml"))
    print(f"validated coverage requirements for {len(applications)} application manifests and {len(systems)} systems; this does not attest scan completeness")


if __name__ == "__main__":
    main()
