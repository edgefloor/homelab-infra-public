#!/usr/bin/env python3
"""Local IP-to-country lookup for sapics user-country range files."""

from __future__ import annotations

import argparse
import bisect
import ipaddress
import json
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Iterator


DEFAULT_DATA_DIR = Path("/var/lib/ip-location-db/user-country")
INDEX_STRIDE = 256
COUNTRY_NAMES_PATH = Path("/usr/share/zoneinfo/iso3166.tab")


@lru_cache(maxsize=1)
def _country_names() -> dict[str, str]:
    """Read the usual English country names supplied by tzdata."""
    names = {"XK": "Kosovo"}
    try:
        for line in COUNTRY_NAMES_PATH.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                code, separator, name = line.partition("\t")
                if separator and name.strip():
                    names[code] = name.strip()
    except OSError:
        pass
    return names


def country_name(country: str) -> str:
    """Return a country name, falling back to its code when unavailable."""
    code = country.strip().upper()
    return _country_names().get(code, code)


def country_flag(country: str | None) -> str | None:
    """Turn an ISO 3166-1 alpha-2 code into its regional-indicator flag."""
    if country is None:
        return None
    normalized = country.strip().upper()
    if len(normalized) != 2 or not normalized.isascii() or not normalized.isalpha():
        return None
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in normalized)


def _parse_record(raw_line: bytes, version: int) -> tuple[int, int, str]:
    fields = raw_line.rstrip(b"\r\n").split(b",")
    if len(fields) != 3:
        raise ValueError("country database contains an invalid record")
    start = ipaddress.ip_address(fields[0].decode("ascii"))
    end = ipaddress.ip_address(fields[1].decode("ascii"))
    country = fields[2].decode("ascii").strip().upper()
    if start.version != version or end.version != version or int(start) > int(end):
        raise ValueError("country database contains an invalid range")
    if country_flag(country) is None:
        raise ValueError("country database contains an invalid country code")
    return int(start), int(end), country


class RangeFile:
    """A CSV range file with a small byte-offset index rebuilt on file changes."""

    def __init__(self, path: Path, version: int, stride: int = INDEX_STRIDE) -> None:
        self.path = path
        self.version = version
        self.stride = stride
        self._signature: tuple[int, int] | None = None
        self._starts: list[int] = []
        self._offsets: list[int] = []
        self._lock = threading.Lock()

    def _current_signature(self) -> tuple[int, int] | None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        return stat.st_mtime_ns, stat.st_size

    def _refresh(self) -> bool:
        signature = self._current_signature()
        if signature == self._signature:
            return bool(self._starts)
        if signature is None:
            self._signature = None
            self._starts = []
            self._offsets = []
            return False

        starts: list[int] = []
        offsets: list[int] = []
        previous_start = -1
        with self.path.open("rb") as handle:
            line_number = 0
            while True:
                offset = handle.tell()
                raw_line = handle.readline()
                if not raw_line:
                    break
                if line_number % self.stride == 0:
                    start, _end, _country = _parse_record(raw_line, self.version)
                    if start < previous_start:
                        raise ValueError("country database ranges are not sorted")
                    starts.append(start)
                    offsets.append(offset)
                    previous_start = start
                line_number += 1

        if not starts:
            raise ValueError("country database is empty")
        self._signature = signature
        self._starts = starts
        self._offsets = offsets
        return True

    def lookup(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        target = int(address)
        for _attempt in range(2):
            with self._lock:
                if not self._refresh():
                    return None
                block = max(0, bisect.bisect_right(self._starts, target) - 1)
                offset = self._offsets[block]
                next_start = (
                    self._starts[block + 1] if block + 1 < len(self._starts) else None
                )

                with self.path.open("rb") as handle:
                    stat = os.fstat(handle.fileno())
                    if (stat.st_mtime_ns, stat.st_size) != self._signature:
                        self._signature = None
                        continue
                    handle.seek(offset)
                    while raw_line := handle.readline():
                        start, end, country = _parse_record(raw_line, self.version)
                        if next_start is not None and start >= next_start and target < start:
                            return None
                        if target < start:
                            return None
                        if target <= end:
                            return country
                    return None
        return None


class CountryDatabase:
    def __init__(self, data_dir: Path | str = DEFAULT_DATA_DIR) -> None:
        directory = Path(data_dir)
        self._files = {
            4: RangeFile(directory / "user-country-ipv4.csv", 4),
            6: RangeFile(directory / "user-country-ipv6.csv", 6),
        }

    def lookup(self, value: str) -> str | None:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return self._files[address.version].lookup(address)

    def lookup_many(self, values: Iterator[str]) -> dict[str, str | None]:
        return {value: self.lookup(value) for value in values}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("IP_COUNTRY_DB_DIR", DEFAULT_DATA_DIR)),
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("addresses", nargs="+")
    args = parser.parse_args()

    database = CountryDatabase(args.data_dir)
    results = database.lookup_many(iter(args.addresses))
    if args.json:
        print(json.dumps(results, separators=(",", ":"), sort_keys=True))
        return
    for address, country in results.items():
        flag = country_flag(country)
        rendered = f"{flag} {country}" if flag else "unknown"
        print(f"{address}\t{rendered}")


if __name__ == "__main__":
    main()
