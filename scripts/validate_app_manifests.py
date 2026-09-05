#!/usr/bin/env python3
"""Validate the small, versioned application manifest contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
APPS = ROOT / "apps"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUNTIMES = {"native_systemd", "docker_compose", "hybrid"}
DISTRIBUTIONS = {
    "official_package",
    "official_binary",
    "official_container_and_packages",
    "source_build",
}
CADDY_POLICIES = {"none", "lan", "direct_edge"}
PANGOLIN_POLICIES = {"none", "remote"}


def require(condition: bool, path: Path, message: str) -> None:
    if not condition:
        try:
            display_path = path.relative_to(ROOT)
        except ValueError:
            display_path = path
        raise ValueError(f"{display_path}: {message}")


def validate(path: Path) -> None:
    data = yaml.safe_load(path.read_text())
    require(isinstance(data, dict), path, "document must be a mapping")
    require(data.get("schema_version") == 1, path, "schema_version must be 1")
    require(isinstance(data.get("id"), str) and data["id"], path, "id is required")
    require(isinstance(data.get("name"), str) and data["name"], path, "name is required")

    upstream = data.get("upstream")
    require(isinstance(upstream, dict), path, "upstream is required")
    repository = upstream.get("repository", "")
    require(repository.startswith("https://github.com/"), path, "upstream must be an HTTPS GitHub repository")
    require(isinstance(upstream.get("release"), str), path, "upstream release is required")
    require(COMMIT.fullmatch(upstream.get("commit", "")) is not None, path, "upstream commit must be a 40-character SHA")
    require(upstream.get("distribution") in DISTRIBUTIONS, path, "unsupported upstream distribution")
    require(data.get("runtime") in RUNTIMES, path, "unsupported runtime")

    environments = data.get("environments")
    require(isinstance(environments, dict), path, "environments are required")
    for name in ("staging", "production"):
        environment = environments.get(name)
        require(isinstance(environment, dict), path, f"{name} environment is required")
        require(isinstance(environment.get("target"), str), path, f"{name} target is required")
        require(isinstance(environment.get("status"), str), path, f"{name} status is required")

    routing = data.get("routing")
    require(isinstance(routing, dict), path, "routing is required")
    require(routing.get("caddy") in CADDY_POLICIES, path, "unsupported Caddy policy")
    require(routing.get("pangolin") in PANGOLIN_POLICIES, path, "unsupported Pangolin policy")

    health = data.get("health")
    require(isinstance(health, dict), path, "health is required")
    require(str(health.get("local_url", "")).startswith("http"), path, "local health URL is required")
    require(isinstance(health.get("expected_units"), list) and health["expected_units"], path, "expected units are required")

    state = data.get("state")
    require(isinstance(state, dict), path, "state is required")
    require(isinstance(state.get("paths"), list), path, "state paths must be a list")
    require(isinstance(state.get("backup_required_before_cutover"), bool), path, "backup policy must be boolean")


def main() -> int:
    paths = sorted(APPS.glob("*.yml"))
    if not paths:
        print("no application manifests found", file=sys.stderr)
        return 1
    try:
        for path in paths:
            validate(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"validated {len(paths)} application manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
