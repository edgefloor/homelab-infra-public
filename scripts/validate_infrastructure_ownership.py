#!/usr/bin/env python3
"""Validate ownership boundaries across OpenTofu, Ansible, and routing."""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOFU_LOCALS = ROOT / "tofu" / "proxmox" / "locals.tf"
ANSIBLE_INVENTORY = ROOT / "ansible" / "inventory" / "hosts.yml"
ROUTES = ROOT / "inventory" / "routes.yml"
HOST_KINDS = {"opentofu_guest", "proxmox_host", "external_vps"}


@dataclass(frozen=True)
class Guest:
    key: str
    vm_id: int
    hostname: str
    address: str


def require(condition: bool, path: Path, message: str) -> None:
    if not condition:
        try:
            display_path = path.relative_to(ROOT)
        except ValueError:
            display_path = path
        raise ValueError(f"{display_path}: {message}")


def _skip_space_and_comments(text: str, offset: int) -> int:
    while offset < len(text):
        if text[offset].isspace() or text[offset] == ",":
            offset += 1
        elif text.startswith("#", offset) or text.startswith("//", offset):
            newline = text.find("\n", offset)
            offset = len(text) if newline == -1 else newline + 1
        elif text.startswith("/*", offset):
            end = text.find("*/", offset + 2)
            if end == -1:
                raise ValueError("unterminated HCL block comment")
            offset = end + 2
        else:
            break
    return offset


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    quoted = False
    escaped = False
    offset = opening
    while offset < len(text):
        char = text[offset]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif text.startswith("#", offset) or text.startswith("//", offset):
            newline = text.find("\n", offset)
            offset = len(text) if newline == -1 else newline
        elif text.startswith("/*", offset):
            end = text.find("*/", offset + 2)
            if end == -1:
                raise ValueError("unterminated HCL block comment")
            offset = end + 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return offset
        offset += 1
    raise ValueError("unterminated HCL mapping")


def parse_managed_containers(text: str, path: Path = TOFU_LOCALS) -> list[Guest]:
    assignment = re.search(r"\bmanaged_containers\s*=\s*\{", text)
    require(assignment is not None, path, "local.managed_containers is required")
    opening = text.find("{", assignment.start())
    closing = _matching_brace(text, opening)
    body = text[opening + 1 : closing]
    guests: list[Guest] = []
    offset = 0

    while True:
        offset = _skip_space_and_comments(body, offset)
        if offset >= len(body):
            break
        key_match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", body[offset:])
        require(key_match is not None, path, "managed container keys must be identifiers")
        key = key_match.group(0)
        offset += len(key)
        offset = _skip_space_and_comments(body, offset)
        require(offset < len(body) and body[offset] == "=", path, f"{key} must use key = {{ ... }} syntax")
        offset = _skip_space_and_comments(body, offset + 1)
        require(offset < len(body) and body[offset] == "{", path, f"{key} must be a mapping")
        block_end = _matching_brace(body, offset)
        block = body[offset + 1 : block_end]

        def field(pattern: str, label: str) -> str:
            match = re.search(pattern, block, flags=re.MULTILINE)
            require(match is not None, path, f"{key}.{label} is required")
            return match.group(1)

        vm_id = int(field(r"^\s*vm_id\s*=\s*(\d+)\s*$", "vm_id"))
        hostname = field(r'^\s*hostname\s*=\s*"([^"]+)"\s*$', "hostname")
        address_value = field(r'^\s*address\s*=\s*"([^"]+)"\s*$', "address")
        try:
            address = str(ipaddress.ip_interface(address_value).ip)
        except ValueError as exc:
            raise ValueError(f"{path}: {key}.address must be an IP interface") from exc
        guests.append(Guest(key=key, vm_id=vm_id, hostname=hostname, address=address))
        offset = block_end + 1

    require(bool(guests), path, "local.managed_containers must not be empty")
    return guests


def collect_ansible_hosts(data: object, path: Path = ANSIBLE_INVENTORY) -> tuple[dict[str, dict], dict]:
    require(isinstance(data, dict), path, "document must be a mapping")
    root = data.get("all")
    require(isinstance(root, dict), path, "all group is required")
    contract = (root.get("vars") or {}).get("infrastructure_contract")
    require(isinstance(contract, dict), path, "all.vars.infrastructure_contract is required")
    require(contract.get("schema_version") == 1, path, "infrastructure contract schema_version must be 1")
    require(contract.get("default_host_kind") == "opentofu_guest", path, "default host kind must be opentofu_guest")
    overrides = contract.get("host_kinds")
    require(isinstance(overrides, dict), path, "infrastructure contract host_kinds must be a mapping")

    hosts: dict[str, dict] = {}

    def visit(group: object) -> None:
        if not isinstance(group, dict):
            return
        group_hosts = group.get("hosts") or {}
        require(isinstance(group_hosts, dict), path, "group hosts must be a mapping")
        for name, variables in group_hosts.items():
            require(isinstance(name, str) and name, path, "inventory host names must be non-empty strings")
            variables = variables or {}
            require(isinstance(variables, dict), path, f"host {name} variables must be a mapping")
            if name in hosts:
                require(hosts[name] == variables, path, f"host {name} has conflicting definitions")
            else:
                hosts[name] = variables
        children = group.get("children") or {}
        require(isinstance(children, dict), path, "group children must be a mapping")
        for child in children.values():
            visit(child)

    visit(root)
    require(bool(hosts), path, "inventory must define hosts")
    for name, kind in overrides.items():
        require(name in hosts, path, f"host kind override references unknown host {name}")
        require(kind in HOST_KINDS - {"opentofu_guest"}, path, f"host {name} has unsupported exception kind {kind}")
    return hosts, contract


def _target_hostname(value: str) -> str:
    candidate = value if "://" in value else "//" + value
    hostname = urlsplit(candidate).hostname
    if hostname is None:
        raise ValueError(f"invalid route target {value!r}")
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return hostname.lower()


def validate(
    tofu_text: str,
    ansible_data: object,
    routes_data: object,
    tofu_path: Path = TOFU_LOCALS,
    ansible_path: Path = ANSIBLE_INVENTORY,
    routes_path: Path = ROUTES,
) -> None:
    guests = parse_managed_containers(tofu_text, tofu_path)
    hosts, contract = collect_ansible_hosts(ansible_data, ansible_path)

    guest_hostnames: dict[str, Guest] = {}
    guest_addresses: dict[str, Guest] = {}
    guest_vm_ids: dict[int, Guest] = {}
    for guest in guests:
        require(guest.hostname not in guest_hostnames, tofu_path, f"duplicate guest hostname {guest.hostname}")
        require(guest.address not in guest_addresses, tofu_path, f"duplicate guest address {guest.address}")
        require(guest.vm_id not in guest_vm_ids, tofu_path, f"duplicate guest VMID {guest.vm_id}")
        guest_hostnames[guest.hostname] = guest
        guest_addresses[guest.address] = guest
        guest_vm_ids[guest.vm_id] = guest

    host_kinds = contract["host_kinds"]
    inventory_addresses: dict[str, str] = {}
    managed_inventory_hosts: set[str] = set()
    for name, variables in hosts.items():
        address_value = variables.get("ansible_host")
        require(isinstance(address_value, str), ansible_path, f"host {name} needs ansible_host")
        try:
            address = str(ipaddress.ip_address(address_value))
        except ValueError as exc:
            raise ValueError(f"{ansible_path}: host {name} ansible_host must be an IP address") from exc
        require(address not in inventory_addresses, ansible_path, f"hosts {inventory_addresses.get(address)} and {name} share {address}")
        inventory_addresses[address] = name
        kind = host_kinds.get(name, contract["default_host_kind"])
        require(kind in HOST_KINDS, ansible_path, f"host {name} has unsupported infrastructure kind {kind}")
        if kind != "opentofu_guest":
            continue
        managed_inventory_hosts.add(name)
        require(name in guest_hostnames, ansible_path, f"Ansible guest {name} has no OpenTofu container")
        require(
            guest_hostnames[name].address == address,
            ansible_path,
            f"Ansible guest {name} address {address} differs from OpenTofu {guest_hostnames[name].address}",
        )

    for guest in guests:
        require(guest.hostname in managed_inventory_hosts, tofu_path, f"OpenTofu guest {guest.hostname} has no Ansible host")

    require(isinstance(routes_data, dict), routes_path, "document must be a mapping")
    routing = routes_data.get("homelab_routing")
    require(isinstance(routing, dict), routes_path, "homelab_routing is required")
    exceptions = routing.get("unmanaged_route_targets")
    require(isinstance(exceptions, dict), routes_path, "unmanaged_route_targets must be a mapping")
    normalized_exceptions: dict[str, str] = {}
    for target, reason in exceptions.items():
        require(isinstance(target, str), routes_path, "unmanaged route target keys must be strings")
        require(isinstance(reason, str) and reason.strip(), routes_path, f"unmanaged target {target} needs a reason")
        normalized_exceptions[_target_hostname(target)] = reason

    known_targets = set(hosts) | set(inventory_addresses)
    used_exceptions: set[str] = set()
    route_targets: list[tuple[str, str]] = []
    routes = routing.get("routes")
    require(isinstance(routes, list), routes_path, "routes must be a list")
    for route in routes:
        require(isinstance(route, dict), routes_path, "each route must be a mapping")
        route_id = route.get("id", "<unknown>")
        caddy = route.get("caddy")
        if isinstance(caddy, dict):
            for field in ("upstream", "crowdsec_webhook_upstream"):
                value = caddy.get(field)
                if value is not None:
                    require(isinstance(value, str), routes_path, f"{route_id}.{field} must be a string")
                    route_targets.append((f"{route_id}.caddy.{field}", value))
        pangolin = route.get("pangolin")
        if isinstance(pangolin, dict) and isinstance(pangolin.get("target"), dict):
            value = pangolin["target"].get("hostname")
            require(isinstance(value, str), routes_path, f"{route_id}.pangolin.target.hostname must be a string")
            route_targets.append((f"{route_id}.pangolin.target.hostname", value))

    for label, value in route_targets:
        try:
            target = _target_hostname(value)
        except ValueError as exc:
            raise ValueError(f"{routes_path}: {label} is invalid: {exc}") from exc
        if target in known_targets:
            continue
        require(target in normalized_exceptions, routes_path, f"{label} target {target} is not in Ansible inventory")
        used_exceptions.add(target)

    unused_exceptions = set(normalized_exceptions) - used_exceptions
    require(not unused_exceptions, routes_path, f"unused unmanaged route targets: {', '.join(sorted(unused_exceptions))}")


def main() -> int:
    try:
        validate(
            TOFU_LOCALS.read_text(encoding="utf-8"),
            yaml.safe_load(ANSIBLE_INVENTORY.read_text(encoding="utf-8")),
            yaml.safe_load(ROUTES.read_text(encoding="utf-8")),
        )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print("validated OpenTofu, Ansible, and route ownership")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
