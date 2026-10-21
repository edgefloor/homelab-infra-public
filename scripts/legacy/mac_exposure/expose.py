#!/usr/bin/env python3
"""Expose a Mac-local HTTP service through Pangolin and the persistent home Newt."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import quote, urlsplit


NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DEFAULT_CONFIG = Path("~/Library/Application Support/homelab-exposure/config.json").expanduser()
GENERATED_ADJECTIVES = (
    "bright", "calm", "clear", "cool", "fresh", "gentle", "golden", "green",
    "happy", "kind", "lively", "lucky", "neat", "quiet", "rapid", "silver",
    "smooth", "steady", "sunny", "swift", "tidy", "warm", "wild", "young",
)
GENERATED_NOUNS = (
    "badger", "comet", "falcon", "fern", "fox", "harbor", "heron", "island",
    "maple", "meadow", "otter", "panda", "pebble", "pine", "river", "robin",
    "sparrow", "star", "stone", "tiger", "valley", "wave", "willow", "wolf",
)


class ExposureError(RuntimeError):
    pass


class HostnameCollision(ExposureError):
    pass


def generate_name(unavailable: set[str]) -> str:
    for _ in range(128):
        candidate = (
            f"{secrets.choice(GENERATED_ADJECTIVES)}-"
            f"{secrets.choice(GENERATED_NOUNS)}-{secrets.token_hex(2)}"
        )
        if candidate not in unavailable:
            return candidate
    raise ExposureError("could not generate an unused exposure name")


def target_argument(value: str) -> str:
    if "://" in value:
        return value
    if value.isdecimal():
        return f"http://127.0.0.1:{value}"
    raise ExposureError("target must be a port or an HTTP or HTTPS URL")


class Config:
    def __init__(
        self,
        *,
        org_id: str,
        domain_id: str,
        site_id: int,
        role_ids: list[int],
        idp_id: int,
        base_domain: str,
        proxy_address: str,
        proxy_port: int,
        newt_address: str,
        ssh_host: str,
        caddy_binary: str,
        caddyfile: Path,
        state_file: Path,
        api_key_file: Path | None = None,
    ) -> None:
        self.org_id = org_id
        self.domain_id = domain_id
        self.site_id = site_id
        self.role_ids = role_ids
        self.idp_id = idp_id
        self.base_domain = base_domain
        self.proxy_address = proxy_address
        self.proxy_port = proxy_port
        self.newt_address = newt_address
        self.ssh_host = ssh_host
        self.caddy_binary = caddy_binary
        self.caddyfile = caddyfile
        self.state_file = state_file
        self.api_key_file = api_key_file

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExposureError(f"cannot read configuration at {path}") from exc
        required = {
            "org_id",
            "domain_id",
            "site_id",
            "role_ids",
            "idp_id",
            "base_domain",
            "proxy_address",
            "proxy_port",
            "newt_address",
            "ssh_host",
            "caddy_binary",
            "caddyfile",
            "state_file",
            "api_key_file",
        }
        if set(raw) != required:
            raise ExposureError("configuration fields do not match the supported schema")
        try:
            ipaddress.ip_address(raw["proxy_address"])
            ipaddress.ip_address(raw["newt_address"])
            if not raw["role_ids"] or not all(isinstance(value, int) and value > 0 for value in raw["role_ids"]):
                raise ValueError
            if not isinstance(raw["site_id"], int) or raw["site_id"] < 1:
                raise ValueError
            if not isinstance(raw["idp_id"], int) or raw["idp_id"] < 1:
                raise ValueError
            if not isinstance(raw["proxy_port"], int) or not 1 <= raw["proxy_port"] <= 65535:
                raise ValueError
        except ValueError as exc:
            raise ExposureError("configuration contains an invalid address, port, site, role, or provider") from exc
        return cls(
            org_id=raw["org_id"],
            domain_id=raw["domain_id"],
            site_id=raw["site_id"],
            role_ids=raw["role_ids"],
            idp_id=raw["idp_id"],
            base_domain=raw["base_domain"],
            proxy_address=raw["proxy_address"],
            proxy_port=raw["proxy_port"],
            newt_address=raw["newt_address"],
            ssh_host=raw["ssh_host"],
            caddy_binary=raw["caddy_binary"],
            caddyfile=Path(raw["caddyfile"]).expanduser(),
            state_file=Path(raw["state_file"]).expanduser(),
            api_key_file=Path(raw["api_key_file"]).expanduser(),
        )


class Transport(Protocol):
    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any: ...


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_secret(path: Path) -> str:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ExposureError(f"API key file must be a mode 0600 regular file: {path}")
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ExposureError(f"cannot read Pangolin API key at {path}") from exc
    if not value or "\n" in value or "." not in value:
        raise ExposureError("Pangolin API key file is invalid")
    return value


class SshPangolinTransport:
    def __init__(self, ssh_host: str, api_key_file: Path) -> None:
        self.ssh_host = ssh_host
        self.api_key_file = api_key_file

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/") or any(character in path for character in " \n\r"):
            raise ExposureError("invalid Pangolin API path")
        remote = [
            "docker",
            "exec",
            "-i",
            "pangolin",
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--request",
            method,
            "--header",
            "@-",
        ]
        if payload is not None:
            remote.extend(["--header", "Content-Type: application/json", "--data", json.dumps(payload, separators=(",", ":"))])
        remote.append("http://127.0.0.1:3003/v1" + path)
        completed = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.ssh_host, shlex.join(remote)],
            input=f"Authorization: Bearer {read_secret(self.api_key_file)}\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            detail = completed.stderr.strip() or "Pangolin returned a non-JSON response"
            raise ExposureError(detail) from exc
        if completed.returncode != 0 or response.get("success") is not True:
            detail = response.get("message") or response.get("error") or completed.stderr.strip()
            raise ExposureError(f"Pangolin API request failed: {detail}")
        return response.get("data")


class ExposureManager:
    def __init__(self, config: Config, transport: Transport, reload_caddy: Callable[[], None] | None = None) -> None:
        self.config = config
        self.transport = transport
        self.reload_caddy = reload_caddy or self._reload_caddy

    def load_state(self) -> dict[str, Any]:
        if not self.config.state_file.exists():
            return {"schema_version": 1, "exposures": {}}
        try:
            state = json.loads(self.config.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExposureError("cannot read local exposure state") from exc
        if state.get("schema_version") != 1 or not isinstance(state.get("exposures"), dict):
            raise ExposureError("local exposure state has an unsupported format")
        return state

    def save_state(self, state: dict[str, Any]) -> None:
        atomic_write(self.config.state_file, json.dumps(state, indent=2, sort_keys=True) + "\n")

    def validate(self, name: str, target: str) -> str:
        if not NAME_PATTERN.fullmatch(name):
            raise ExposureError("name must be one lowercase DNS label")
        try:
            parsed = urlsplit(target)
            port = parsed.port
        except ValueError as exc:
            raise ExposureError("target must include a valid port") from exc
        if parsed.scheme not in {"http", "https"} or port is None:
            raise ExposureError("target must be an HTTP or HTTPS URL with an explicit port")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ExposureError("target must not contain a path, query, fragment, or credentials")
        host = (parsed.hostname or "").lower()
        if host == "localhost":
            host = "127.0.0.1"
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ExposureError("target host must be localhost or a Mac address") from exc
        if not address.is_loopback and str(address) != self.config.proxy_address:
            raise ExposureError("target must resolve on this Mac")
        return f"{parsed.scheme}://{address}:{port}"

    def write_proxy_config(self, exposures: dict[str, Any]) -> None:
        lines = [
            "{\n",
            "\tauto_https off\n",
            "\tadmin 127.0.0.1:2019\n",
            "}\n\n",
            f"http://:{self.config.proxy_port} {{\n",
            f"\tbind {self.config.proxy_address}\n",
        ]
        for name, exposure in sorted(exposures.items()):
            target = exposure["target"].removeprefix("http://").removeprefix("https://")
            upstream = f"https://{target}" if exposure["target"].startswith("https://") else target
            lines.extend(
                [
                    f"\t@{name} {{\n",
                    f"\t\thost {name}.{self.config.base_domain}\n",
                    f"\t\tremote_ip {self.config.newt_address}\n",
                    "\t}\n",
                    f"\thandle @{name} {{\n",
                    f"\t\treverse_proxy {upstream}\n",
                    "\t}\n",
                ]
            )
        lines.extend(['\trespond "No active exposure" 404\n', "}\n"])
        atomic_write(self.config.caddyfile, "".join(lines))

    def _reload_caddy(self) -> None:
        for command in (
            [self.config.caddy_binary, "validate", "--config", str(self.config.caddyfile), "--adapter", "caddyfile"],
            [self.config.caddy_binary, "reload", "--config", str(self.config.caddyfile), "--adapter", "caddyfile"],
        ):
            completed = subprocess.run(command, text=True, capture_output=True, timeout=15)
            if completed.returncode != 0:
                raise ExposureError(completed.stderr.strip() or "Caddy rejected its configuration")

    def _resources(self) -> list[dict[str, Any]]:
        data = self.transport.request(
            "GET", f"/org/{quote(self.config.org_id)}/public-resources?pageSize=100&page=1"
        )
        if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
            raise ExposureError("Pangolin returned an invalid resource list")
        return data["resources"]

    def expose(
        self,
        name: str,
        target: str,
        *,
        update_existing: bool = True,
    ) -> dict[str, Any]:
        target = self.validate(name, target)
        state = self.load_state()
        existing = state["exposures"].get(name)
        if existing:
            if not update_existing:
                raise HostnameCollision(f"local exposure {name} already exists")
            previous = dict(existing)
            existing["target"] = target
            try:
                self.write_proxy_config(state["exposures"])
                self.reload_caddy()
                self.save_state(state)
            except Exception:
                state["exposures"][name] = previous
                self.write_proxy_config(state["exposures"])
                raise
            return self.describe(name, existing)

        hostname = f"{name}.{self.config.base_domain}"
        if any(resource.get("fullDomain") == hostname for resource in self._resources()):
            raise HostnameCollision(f"Pangolin already has a resource for {hostname}")

        state["exposures"][name] = {"target": target, "resource_id": 0}
        self.write_proxy_config(state["exposures"])
        self.reload_caddy()
        resource_id = None
        try:
            resource = self.transport.request(
                "PUT",
                f"/org/{quote(self.config.org_id)}/public-resource",
                {"name": f"On-demand {name}", "subdomain": name, "domainId": self.config.domain_id, "mode": "http"},
            )
            resource_id = int(resource["resourceId"])
            self.transport.request(
                "POST",
                f"/public-resource/{resource_id}",
                {
                    "niceId": f"on-demand-{name}",
                    "sso": True,
                    "skipToIdpId": self.config.idp_id,
                    "setHostHeader": hostname,
                },
            )
            self.transport.request(
                "POST", f"/public-resource/{resource_id}/roles", {"roleIds": self.config.role_ids}
            )
            self.transport.request(
                "PUT",
                f"/public-resource/{resource_id}/target",
                {
                    "siteId": self.config.site_id,
                    "ip": self.config.proxy_address,
                    "mode": "http",
                    "method": "http",
                    "port": self.config.proxy_port,
                    "enabled": True,
                },
            )
        except Exception:
            if resource_id is not None:
                try:
                    self.transport.request("DELETE", f"/public-resource/{resource_id}")
                except Exception:
                    pass
            state["exposures"].pop(name, None)
            self.write_proxy_config(state["exposures"])
            self.reload_caddy()
            raise
        state["exposures"][name]["resource_id"] = resource_id
        self.save_state(state)
        return self.describe(name, state["exposures"][name])

    def expose_generated(self, target: str) -> dict[str, Any]:
        state = self.load_state()
        unavailable = set(state["exposures"])
        suffix = f".{self.config.base_domain}"
        for resource in self._resources():
            hostname = resource.get("fullDomain")
            if not isinstance(hostname, str) or not hostname.endswith(suffix):
                continue
            name = hostname.removesuffix(suffix)
            if "." not in name:
                unavailable.add(name)

        for _ in range(128):
            name = generate_name(unavailable)
            if name in self.load_state()["exposures"]:
                unavailable.add(name)
                continue
            try:
                return self.expose(name, target, update_existing=False)
            except HostnameCollision:
                unavailable.add(name)
        raise ExposureError("could not reserve an unused exposure name")

    def remove(self, name: str) -> dict[str, Any]:
        if not NAME_PATTERN.fullmatch(name):
            raise ExposureError("name must be one lowercase DNS label")
        state = self.load_state()
        exposure = state["exposures"].get(name)
        if not exposure:
            raise ExposureError(f"exposure {name} does not exist")
        self.transport.request("DELETE", f"/public-resource/{int(exposure['resource_id'])}")
        removed = self.describe(name, exposure)
        del state["exposures"][name]
        self.write_proxy_config(state["exposures"])
        self.reload_caddy()
        self.save_state(state)
        return removed

    def list(self) -> list[dict[str, Any]]:
        state = self.load_state()
        return [self.describe(name, exposure) for name, exposure in sorted(state["exposures"].items())]

    def describe(self, name: str, exposure: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": name,
            "url": f"https://{name}.{self.config.base_domain}",
            "target": exposure["target"],
            "resource_id": exposure["resource_id"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  expose 3000
  expose https://127.0.0.1:3443
  expose demo 3000
  expose demo https://127.0.0.1:3443
  expose list
  expose remove demo""",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("command", help="exposure name, target, list, or remove")
    parser.add_argument("value", nargs="?", help="port, target URL, or exposure name")
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        if config.api_key_file is None:
            raise ExposureError("api_key_file is missing")
        manager = ExposureManager(config, SshPangolinTransport(config.ssh_host, config.api_key_file))
        if args.command == "list":
            if args.value is not None:
                raise ExposureError("list does not accept an argument")
            for exposure in manager.list():
                print(f"{exposure['name']}\t{exposure['url']}\t{exposure['target']}")
        elif args.command == "remove":
            if args.value is None:
                raise ExposureError("remove requires an exposure name")
            print(f"removed {manager.remove(args.value)['url']}")
        else:
            if args.value is None:
                print(manager.expose_generated(target_argument(args.command))["url"])
            else:
                print(manager.expose(args.command, target_argument(args.value))["url"])
        return 0
    except ExposureError as exc:
        print(f"expose: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
