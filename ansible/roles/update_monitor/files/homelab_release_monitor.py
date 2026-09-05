#!/usr/bin/env python3
"""Watch upstream Atom/RSS feeds and report new stable releases to Matrix."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request


UNSTABLE = re.compile(r"(?:^|[.\-_\s])(alpha|beta|rc|pre|preview|nightly|dev)(?:[.\-_\d\s]|$)", re.I)
MAX_SEEN_PER_FEED = 100
MAX_RELEASES_PER_MESSAGE = 30


def read_credential(name: str) -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise RuntimeError("CREDENTIALS_DIRECTORY is not set")
    value = (Path(directory) / name).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"credential {name!r} is empty")
    return value


def child_text(element: ET.Element, local_name: str) -> str:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == local_name:
            return (child.text or "").strip()
    return ""


def parse_feed(raw: bytes) -> list[dict[str, str]]:
    root = ET.fromstring(raw)
    entries: list[dict[str, str]] = []
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local not in {"entry", "item"}:
            continue
        title = child_text(element, "title")
        identifier = child_text(element, "id") or child_text(element, "guid")
        published = (
            child_text(element, "published")
            or child_text(element, "updated")
            or child_text(element, "pubDate")
        )
        link = child_text(element, "link")
        if not link:
            for child in element:
                if child.tag.rsplit("}", 1)[-1] == "link" and child.attrib.get("href"):
                    link = child.attrib["href"].strip()
                    if child.attrib.get("rel", "alternate") == "alternate":
                        break
        identifier = identifier or link or f"{title}|{published}"
        if title and identifier:
            entries.append(
                {"id": identifier, "title": title, "url": link, "published": published}
            )
    return entries


def fetch(url: str) -> bytes:
    incoming = request.Request(url, headers={"User-Agent": "homelab-release-monitor/1"})
    try:
        with request.urlopen(incoming, timeout=20) as response:
            return response.read(2 * 1024 * 1024)
    except error.URLError as exc:
        raise RuntimeError(f"feed request failed: {exc.reason}") from exc


def is_stable(title: str) -> bool:
    return UNSTABLE.search(title) is None


def newly_seen_stable_entries(
    entries: list[dict[str, str]], previous_ids: list[str] | None
) -> list[dict[str, str]]:
    """Return new stable entries, or silently baseline a feed without state."""
    if previous_ids is None:
        return []
    seen = set(previous_ids)
    return [
        entry
        for entry in reversed(entries)
        if entry["id"] not in seen and is_stable(entry["title"])
    ]


def load_state(path: Path) -> dict[str, Any] | None:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(state, dict) or state.get("schema") != 1:
        raise RuntimeError("unsupported release monitor state")
    return state


def save_state(path: Path, feeds: dict[str, list[str]]) -> None:
    state = {
        "schema": 1,
        "updated_at": datetime.now(UTC).isoformat(),
        "feeds": feeds,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def format_releases(releases: list[dict[str, str]]) -> str:
    lines = [f"{len(releases)} new stable upstream release{'s' if len(releases) != 1 else ''}"]
    for release in releases[:MAX_RELEASES_PER_MESSAGE]:
        line = f"- {release['source']}: {release['title']}"
        if release.get("url"):
            line += f"\n  {release['url']}"
        lines.append(line)
    if len(releases) > MAX_RELEASES_PER_MESSAGE:
        lines.append(f"- and {len(releases) - MAX_RELEASES_PER_MESSAGE} more")
    return "\n".join(lines)


def send_notification(url: str, secret: str, message: str, kind: str = "release") -> None:
    body = json.dumps(
        {
            "kind": kind,
            "source": "upstream releases",
            "message": message,
            "observed_at": datetime.now(UTC).isoformat(),
        },
        separators=(",", ":"),
    ).encode()
    outgoing = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "User-Agent": "homelab-release-monitor/1",
        },
    )
    try:
        with request.urlopen(outgoing, timeout=20) as response:
            if response.status != 202:
                raise RuntimeError(f"notification endpoint returned HTTP {response.status}")
    except error.URLError as exc:
        raise RuntimeError(f"notification delivery failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feeds", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--test-notification", action="store_true")
    args = parser.parse_args()

    webhook_url = os.environ.get("UPDATE_MONITOR_WEBHOOK_URL", "").strip()
    if not webhook_url:
        raise RuntimeError("UPDATE_MONITOR_WEBHOOK_URL is not set")
    secret = read_credential("webhook-secret")
    if args.test_notification:
        send_notification(
            webhook_url,
            secret,
            "Release and CVE monitoring is enabled.",
            kind="system",
        )
        return 0

    configured = json.loads(args.feeds.read_text(encoding="utf-8"))
    if not isinstance(configured, list) or not configured:
        raise RuntimeError("feed configuration must be a non-empty list")
    previous = load_state(args.state)
    previous_feeds = (previous or {}).get("feeds") or {}
    next_feeds: dict[str, list[str]] = dict(previous_feeds)
    releases: list[dict[str, str]] = []
    failures: list[str] = []

    for feed in configured:
        name, url = str(feed["name"]), str(feed["url"])
        try:
            entries = parse_feed(fetch(url))
        except (ET.ParseError, RuntimeError) as exc:
            failures.append(f"{name}: {exc}")
            continue
        identifiers = [entry["id"] for entry in entries]
        prior_ids = previous_feeds[name] if name in previous_feeds else None
        for entry in newly_seen_stable_entries(entries, prior_ids):
            releases.append({**entry, "source": name})
        next_feeds[name] = identifiers[:MAX_SEEN_PER_FEED]

    if len(failures) == len(configured):
        raise RuntimeError("all release feeds failed")
    if releases:
        send_notification(webhook_url, secret, format_releases(releases))
    save_state(args.state, next_feeds)
    print(
        f"feeds={len(configured)} releases={len(releases)} failures={len(failures)}"
    )
    for failure in failures:
        print(f"warning: {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"homelab-release-monitor: {exc}", file=sys.stderr)
        raise SystemExit(1)
