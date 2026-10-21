#!/usr/bin/env python3
"""Atomically refresh sapics user-country IPv4 and IPv6 CSV files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import os
import re
import tempfile
from pathlib import Path
from urllib import request


DEFAULT_DATA_DIR = Path("/var/lib/ip-location-db/user-country")
RELEASE_BASE = "https://github.com/sapics/ip-location-db/releases/download"
FILES = ("user-country-ipv4.csv", "user-country-ipv6.csv")
CHECKSUM = re.compile(r"^[0-9a-f]{64}$")
COUNTRY = re.compile(r"^[A-Z]{2}$")
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024


def fetch(url: str, maximum: int) -> bytes:
    remote_request = request.Request(
        url,
        headers={"User-Agent": "homelab-ip-country-updater/1"},
    )
    with request.urlopen(remote_request, timeout=90) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError(f"download exceeded {maximum} bytes")
    return data


def expected_checksum(filename: str) -> str:
    raw = fetch(f"{RELEASE_BASE}/checksum/{filename}.sha256", 1024)
    checksum = raw.decode("ascii").split()[0].lower()
    if not CHECKSUM.fullmatch(checksum):
        raise RuntimeError(f"invalid checksum document for {filename}")
    return checksum


def file_checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(path: Path, version: int) -> None:
    rows = 0
    previous_start = -1
    with path.open(encoding="ascii", newline="") as handle:
        for fields in csv.reader(handle):
            if len(fields) != 3 or not COUNTRY.fullmatch(fields[2]):
                raise RuntimeError(f"invalid record in {path.name}")
            start = ipaddress.ip_address(fields[0])
            end = ipaddress.ip_address(fields[1])
            if (
                start.version != version
                or end.version != version
                or int(start) > int(end)
                or int(start) < previous_start
            ):
                raise RuntimeError(f"invalid or unsorted range in {path.name}")
            previous_start = int(start)
            rows += 1
    if rows < 1000:
        raise RuntimeError(f"implausibly small country database: {path.name}")


def stage(data_dir: Path, filename: str, checksum: str) -> Path | None:
    destination = data_dir / filename
    if destination.is_file() and file_checksum(destination) == checksum:
        return None

    data = fetch(f"{RELEASE_BASE}/latest/{filename}", MAX_DOWNLOAD_BYTES)
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=f".{filename}.",
        dir=data_dir,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if file_checksum(temporary) != checksum:
            raise RuntimeError(f"checksum mismatch for {filename}")
        validate(temporary, 4 if "ipv4" in filename else 6)
        temporary.chmod(0o644)
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    staged: dict[str, Path] = {}
    try:
        for filename in FILES:
            checksum = expected_checksum(filename)
            temporary = stage(args.data_dir, filename, checksum)
            if temporary is not None:
                staged[filename] = temporary
        for filename, temporary in staged.items():
            os.replace(temporary, args.data_dir / filename)
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    print(f"updated={len(staged)}")


if __name__ == "__main__":
    main()
