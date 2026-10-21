#!/usr/bin/env python3
"""Fail-closed Cloudflare updater for home.homelab.example.

The token is read only from the configured credential file.  This module uses
only the Python standard library so it can be tested with an injected transport.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import stat
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


EXPECTED_ZONE_NAME = "homelab.example"
EXPECTED_RECORD_NAME = "home.homelab.example"
API_BASE = "https://api.cloudflare.com/client/v4"


class DDNSError(RuntimeError):
    """An identity, configuration, or Cloudflare API check failed."""


class Transport(Protocol):
    def request(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Config:
    zone_id: str
    record_id: str
    record_name: str
    credential_file: Path

    @classmethod
    def load(cls, path: Path) -> "Config":
        require_secure_root_file(path, "config")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise DDNSError("cannot read config file") from exc
        required = ("zone_id", "record_id", "record_name", "credential_file")
        if any(not isinstance(raw.get(key), str) or not raw[key].strip() for key in required):
            raise DDNSError("config requires non-empty zone_id, record_id, record_name, and credential_file")
        if raw["record_name"] != EXPECTED_RECORD_NAME:
            raise DDNSError(f"record_name must be exactly {EXPECTED_RECORD_NAME}")
        credential_file = Path(raw["credential_file"])
        if not credential_file.is_absolute():
            raise DDNSError("credential_file must be an absolute path")
        return cls(raw["zone_id"], raw["record_id"], raw["record_name"], credential_file)


class UrlLibTransport:
    def request(self, method: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            API_BASE + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise DDNSError("Cloudflare request failed") from exc
        if not payload.get("success"):
            raise DDNSError("Cloudflare API rejected request")
        return payload


def require_secure_root_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
        mode = metadata.st_mode & 0o777
        if not stat.S_ISREG(metadata.st_mode):
            raise DDNSError(f"{label} file must be a regular non-symlink file")
        if metadata.st_uid != 0:
            raise DDNSError(f"{label} file must be owned by root")
        if mode & 0o077:
            raise DDNSError(f"{label} file must not be accessible by group or other")
    except OSError as exc:
        raise DDNSError(f"cannot inspect {label} file") from exc


def read_token(path: Path) -> str:
    require_secure_root_file(path, "credential")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise DDNSError("cannot read credential file") from exc
    if not token or "\n" in token:
        raise DDNSError("credential file must contain exactly one non-empty token")
    return token


def _single_result(payload: dict[str, Any], kind: str) -> dict[str, Any]:
    result = payload.get("result")
    if not isinstance(result, dict):
        raise DDNSError(f"Cloudflare returned invalid {kind} data")
    return result


def update(config: Config, address: str, transport: Transport, token: str) -> bool:
    """Update the record, returning False when its content is already current."""
    address = str(ipaddress.ip_address(address))

    # These reads occur directly before the write.  No cached identity is trusted.
    zone = _single_result(transport.request("GET", f"/zones/{config.zone_id}", token), "zone")
    if zone.get("id") != config.zone_id or zone.get("name") != EXPECTED_ZONE_NAME:
        raise DDNSError("live zone identity mismatch; refusing write")

    record_path = f"/zones/{config.zone_id}/dns_records/{config.record_id}"
    record = _single_result(transport.request("GET", record_path, token), "record")
    if record.get("id") != config.record_id or record.get("zone_id") != config.zone_id:
        raise DDNSError("live record zone or ID mismatch; refusing write")
    if record.get("name") != config.record_name or record.get("name") != EXPECTED_RECORD_NAME:
        raise DDNSError("live record name mismatch; refusing write")
    if record.get("type") not in ("A", "AAAA"):
        raise DDNSError("live record type is not A or AAAA; refusing write")
    if not isinstance(record.get("ttl"), int) or not isinstance(record.get("proxied"), bool):
        raise DDNSError("live record TTL or proxied value is invalid; refusing write")
    if ipaddress.ip_address(address).version != (4 if record["type"] == "A" else 6):
        raise DDNSError("address family does not match live record type; refusing write")
    if record.get("content") == address:
        return False

    body = {
        "type": record["type"],
        "name": record["name"],
        "content": address,
        "ttl": record.get("ttl"),
        "proxied": record.get("proxied"),
    }
    transport.request("PUT", record_path, token, body)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--address", required=True)
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        changed = update(config, args.address, UrlLibTransport(), read_token(config.credential_file))
        print("DDNS record updated" if changed else "DDNS record already current")
        return 0
    except (DDNSError, ValueError, json.JSONDecodeError) as exc:
        print(f"DDNS update failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
