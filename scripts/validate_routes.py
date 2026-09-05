#!/usr/bin/env python3
"""Validate the canonical homelab routing inventory."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROUTES = ROOT / "inventory" / "routes.yml"
PUBLIC_TARGETS = {"home_dynamic", "pangolin_vps", "internal_caddy", "internal_only"}


def require(condition: bool, path: Path, message: str) -> None:
    if not condition:
        try:
            display_path = path.relative_to(ROOT)
        except ValueError:
            display_path = path
        raise ValueError(f"{display_path}: {message}")


def validate(data: object, path: Path = ROUTES) -> None:
    require(isinstance(data, dict), path, "document must be a mapping")
    routing = data.get("homelab_routing")
    require(isinstance(routing, dict), path, "homelab_routing is required")
    require(routing.get("schema_version") == 1, path, "schema_version must be 1")

    base_domain = routing.get("base_domain")
    require(isinstance(base_domain, str) and base_domain, path, "base_domain is required")
    for field in ("caddy_address", "pangolin_vps_address"):
        try:
            ipaddress.ip_address(routing.get(field, ""))
        except ValueError as exc:
            raise ValueError(f"{path}: {field} must be an IP address") from exc

    cloudflare = routing.get("cloudflare_record")
    require(isinstance(cloudflare, dict), path, "cloudflare_record is required")
    require(cloudflare.get("type") == "A", path, "only Cloudflare A routes are supported")
    require(isinstance(cloudflare.get("ttl"), int), path, "Cloudflare TTL must be an integer")
    require(isinstance(cloudflare.get("proxied"), bool), path, "Cloudflare proxied must be boolean")

    routes = routing.get("routes")
    require(isinstance(routes, list) and routes, path, "routes must be a non-empty list")
    route_ids: set[str] = set()
    hostnames: set[str] = set()
    resource_ids: set[str] = set()
    policy_ids: set[str] = set()

    for route in routes:
        require(isinstance(route, dict), path, "each route must be a mapping")
        route_id = route.get("id")
        hostname = route.get("hostname")
        require(isinstance(route_id, str) and route_id, path, "every route needs an id")
        require(route_id not in route_ids, path, f"duplicate route id {route_id}")
        route_ids.add(route_id)
        require(
            isinstance(hostname, str)
            and (hostname == base_domain or hostname.endswith("." + base_domain)),
            path,
            f"{route_id} has a hostname outside {base_domain}",
        )
        require(hostname not in hostnames, path, f"duplicate hostname {hostname}")
        hostnames.add(hostname)

        public_target = route.get("public_target")
        require(public_target in PUBLIC_TARGETS, path, f"{route_id} has unsupported public_target")
        caddy = route.get("caddy")
        pangolin = route.get("pangolin")

        if route.get("internal_dns", False):
            require(isinstance(caddy, dict), path, f"{route_id} internal DNS must terminate at Caddy")
        if isinstance(caddy, dict):
            require(isinstance(caddy.get("upstream"), str), path, f"{route_id} needs a Caddy upstream")
            require(isinstance(caddy.get("health_path"), str), path, f"{route_id} needs a health path")
            openid_redirect = caddy.get("openid_redirect")
            if openid_redirect is not None:
                require(isinstance(openid_redirect, dict), path, f"{route_id} openid_redirect must be a mapping")
                redirect_path = openid_redirect.get("path")
                require(
                    isinstance(redirect_path, str) and redirect_path.startswith("/") and redirect_path != "/",
                    path,
                    f"{route_id} openid_redirect.path must be a non-root absolute path",
                )
                require(
                    isinstance(openid_redirect.get("realm"), str) and openid_redirect["realm"],
                    path,
                    f"{route_id} openid_redirect.realm is required",
                )

        if public_target in {"pangolin_vps", "internal_caddy", "internal_only"} and isinstance(caddy, dict):
            require(
                caddy.get("internal_source_only") is True,
                path,
                f"{route_id} must reject direct home-WAN access",
            )
        if public_target == "home_dynamic":
            require(not isinstance(pangolin, dict), path, f"{route_id} cannot be direct-home and Pangolin-managed")

        if isinstance(pangolin, dict):
            require(public_target == "pangolin_vps", path, f"{route_id} Pangolin route must resolve to the VPS")
            for field in ("resource_id", "name", "policy_id"):
                require(isinstance(pangolin.get(field), str) and pangolin[field], path, f"{route_id} needs pangolin.{field}")
            require(pangolin["resource_id"] not in resource_ids, path, f"duplicate Pangolin resource {pangolin['resource_id']}")
            require(pangolin["policy_id"] not in policy_ids, path, f"duplicate Pangolin policy {pangolin['policy_id']}")
            resource_ids.add(pangolin["resource_id"])
            policy_ids.add(pangolin["policy_id"])
            roles = pangolin.get("roles")
            require(isinstance(roles, list) and roles, path, f"{route_id} needs Pangolin roles")
            require("Admin" not in roles, path, f"{route_id} must not declare Pangolin's implicit Admin role")
            require(isinstance(pangolin.get("sso", True), bool), path, f"{route_id} pangolin.sso must be boolean")
            post_auth_path = pangolin.get("post_auth_path")
            if post_auth_path is not None:
                require(
                    isinstance(post_auth_path, str) and post_auth_path.startswith("/") and post_auth_path != "/",
                    path,
                    f"{route_id} pangolin.post_auth_path must be a non-root absolute path",
                )
            target = pangolin.get("target")
            require(isinstance(target, dict), path, f"{route_id} needs a Pangolin target")
            require(target.get("method") in {"http", "https", "h2c"}, path, f"{route_id} has invalid target method")
            require(isinstance(target.get("hostname"), str), path, f"{route_id} target hostname is required")
            require(isinstance(target.get("port"), int), path, f"{route_id} target port is required")
            require(isinstance(target.get("site"), str), path, f"{route_id} target site is required")
            if target["site"] == routing.get("pangolin_home_site"):
                require(isinstance(caddy, dict), path, f"{route_id} home Pangolin target must use Caddy")
                require(target["hostname"] == routing["caddy_address"], path, f"{route_id} target must use Caddy")
                require(target["port"] == 443 and target["method"] == "https", path, f"{route_id} target must use Caddy HTTPS")


def main() -> int:
    try:
        validate(yaml.safe_load(ROUTES.read_text(encoding="utf-8")))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print("validated canonical routing inventory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
