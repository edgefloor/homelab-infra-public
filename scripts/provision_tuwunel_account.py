#!/usr/bin/env python3
"""Provision one Tuwunel account without exposing credentials on stdout."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def request_json(
    method: str,
    url: str,
    *,
    payload: dict[str, object] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, object]]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            detail = json.load(error)
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = {"errcode": "HTTP_ERROR", "error": error.reason}
        raise RuntimeError(
            f"Matrix request failed with HTTP {error.code}: "
            f"{detail.get('errcode', 'unknown')}"
        ) from error


def registration_mac(
    secret: bytes, nonce: str, username: str, password: str
) -> str:
    fields = (nonce, username, password, "notadmin")
    return hmac.new(
        secret,
        b"\x00".join(field.encode("utf-8") for field in fields),
        hashlib.sha1,
    ).hexdigest()


def write_secret(path: Path, payload: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--homeserver", required=True)
    parser.add_argument("--public-homeserver")
    parser.add_argument("--shared-secret-file", type=Path, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--device-display-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    homeserver = args.homeserver.rstrip("/")
    secret = args.shared_secret_file.read_bytes().strip()
    if len(secret) < 32:
        raise RuntimeError("registration shared secret is unexpectedly short")

    status, nonce_response = request_json(
        "GET", f"{homeserver}/_synapse/admin/v1/register"
    )
    nonce = str(nonce_response.get("nonce", ""))
    if status != 200 or not nonce:
        raise RuntimeError("Tuwunel did not issue a registration nonce")

    password = secrets.token_urlsafe(48)
    _, registered = request_json(
        "POST",
        f"{homeserver}/_synapse/admin/v1/register",
        payload={
            "nonce": nonce,
            "username": args.username,
            "displayname": args.display_name,
            "password": password,
            "admin": False,
            "mac": registration_mac(secret, nonce, args.username, password),
        },
    )

    access_token = str(registered.get("access_token", ""))
    user_id = str(registered.get("user_id", ""))
    device_id = str(registered.get("device_id", ""))
    if not access_token or not user_id or not device_id:
        raise RuntimeError("registration did not return a device-bound access token")

    device_path = urllib.parse.quote(device_id, safe="")
    request_json(
        "PUT",
        f"{homeserver}/_matrix/client/v3/devices/{device_path}",
        payload={"display_name": args.device_display_name},
        token=access_token,
    )
    whoami_status, whoami = request_json(
        "GET",
        f"{homeserver}/_matrix/client/v3/account/whoami",
        token=access_token,
    )
    if (
        whoami_status != 200
        or whoami.get("user_id") != user_id
        or whoami.get("device_id") != device_id
    ):
        raise RuntimeError("device-bound token failed the authoritative whoami check")

    write_secret(
        args.output,
        {
            "homeserver": args.public_homeserver or args.homeserver,
            "user_id": user_id,
            "device_id": device_id,
            "access_token": access_token,
            "password": password,
        },
    )
    print(
        json.dumps(
            {
                "status": whoami_status,
                "user_id": user_id,
                "device_id": device_id,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"provisioning failed: {error}", file=sys.stderr)
        raise SystemExit(1)
