#!/usr/bin/env python3
"""Observe package updates in the channel used by each tracked installation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from urllib import request


PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:@/~-]{0,255}$")
APT_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,255}$")
RELEASE_VERSION = re.compile(r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+)+)")
UNSTABLE = re.compile(
    r"(?:^|[.\-_\s])(alpha|beta|rc|pre|preview|nightly|dev)(?:[.\-_\d\s]|$)",
    re.IGNORECASE,
)


def _run(arguments):
    try:
        return subprocess.run(arguments, text=True, capture_output=True,
                              timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(arguments, 127, "", str(exc))


def _fetch(url):
    incoming = request.Request(
        url, headers={"User-Agent": "homelab-update-opportunities/1"})
    with request.urlopen(incoming, timeout=20) as response:
        return response.read(2 * 1024 * 1024)


def _platform(run):
    release = run(["cat", "/etc/os-release"])
    machine = run(["uname", "-m"])
    values = {}
    if release.returncode == 0:
        for line in release.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    system = values.get("ID", "unknown")
    version = values.get("VERSION_CODENAME") or values.get("VERSION_ID", "unknown")
    architecture = machine.stdout.strip() if machine.returncode == 0 else "unknown"
    return system + ":" + version + ":" + architecture


def _candidate(policy):
    for line in policy.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator and key.lower() == "candidate":
            value = value.strip()
            return "" if value == "(none)" else value
    return ""


def _compare(left, operation, right, run):
    result = run(["dpkg", "--compare-versions", left, operation, right])
    if result.returncode not in {0, 1}:
        raise RuntimeError("package version comparison failed")
    return result.returncode == 0


def _version(value):
    match = RELEASE_VERSION.search(value)
    if not match:
        raise ValueError("release version missing")
    normalized = match.group(1)
    return normalized, tuple(int(part) for part in normalized.split("."))


def _child_text(element, name):
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return (child.text or "").strip()
    return ""


def _stable_candidate(raw):
    root = ET.fromstring(raw)
    candidates = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] not in {"entry", "item"}:
            continue
        title = _child_text(element, "title")
        if not title or UNSTABLE.search(title):
            continue
        try:
            normalized, key = _version(title)
        except ValueError:
            continue
        identifier = (_child_text(element, "id") or
                      _child_text(element, "guid") or title)
        candidates.append((key, normalized, identifier, title))
    if not candidates:
        raise ValueError("stable release missing")
    _, version, identifier, title = max(candidates)
    return version, identifier, title


def _release_state(channel, run, fetch):
    required = {"installation", "kind", "source", "url", "channel",
                "platform", "installed_command", "installed_pattern"}
    if (not isinstance(channel, dict) or set(channel) - required or
            not required.issubset(channel) or
            channel.get("kind") != "release-feed"):
        return {"reason": "invalid_release_channel"}
    command = channel["installed_command"]
    pattern = channel["installed_pattern"]
    if (not isinstance(command, list) or not command or
            any(not isinstance(part, str) or not part for part in command) or
            not isinstance(pattern, str) or not 1 <= len(pattern) <= 512):
        return {"reason": "invalid_release_channel"}
    try:
        installed_result = run(command)
    except (OSError, subprocess.SubprocessError):
        return {"reason": "installed_version_query_failed"}
    if installed_result.returncode != 0:
        return {"reason": "installed_version_query_failed"}
    try:
        installed_match = re.search(pattern, installed_result.stdout)
    except re.error:
        return {"reason": "invalid_release_channel"}
    if not installed_match or installed_match.lastindex != 1:
        return {"reason": "installed_version_missing"}
    try:
        installed, installed_key = _version(installed_match.group(1))
    except ValueError:
        return {"reason": "installed_version_missing"}
    try:
        candidate, entry_id, title = _stable_candidate(fetch(channel["url"]))
        _, candidate_key = _version(candidate)
    except (ET.ParseError, OSError, ValueError):
        return {"reason": "channel_query_failed", "installed": installed}
    available = candidate_key > installed_key
    return {
        "candidate": candidate, "installed": installed,
        "available": available,
        "reason": "" if available else "candidate_not_newer",
        "entry_id": entry_id, "title": title,
    }


def _owned_installation(record, owned_installations):
    installation = record.get("installation")
    matches = set()
    if installation in owned_installations:
        matches.add(installation)
    owners = record.get("owner_deployments", [])
    if not isinstance(owners, list):
        return None
    if len(owners) == 1:
        owner = owners[0]
        if isinstance(owner, str) and "deployment:" + owner in owned_installations:
            matches.add("deployment:" + owner)
    return next(iter(matches)) if len(matches) == 1 else None


def collect(snapshot, owned_installations, *, channels=None, expected=None,
            run=_run, fetch=_fetch, clock=time.time):
    if (not isinstance(snapshot, dict) or not isinstance(owned_installations, list)
            or (channels is not None and not isinstance(channels, list))
            or (expected is not None and not isinstance(expected, list))):
        raise ValueError("invalid availability input")
    channels = channels or []
    findings = snapshot.get("findings")
    if not isinstance(findings, list):
        findings = []
    expected_keys = None
    expected_owners = {}
    records = findings
    if expected is not None:
        expected_keys = set()
        for item in expected:
            if not isinstance(item, dict):
                raise ValueError("invalid expected observation")
            try:
                values = (item["installation"], item["ecosystem"], item["package"])
            except KeyError as exc:
                raise ValueError("invalid expected observation") from exc
            if (not all(isinstance(value, str) and value for value in values) or
                    not PACKAGE.fullmatch(values[2])):
                raise ValueError("invalid expected observation")
            key = (values[0], values[1].lower(), values[2])
            expected_keys.add(key)
            owner = item.get("owner_installation", values[0])
            if not isinstance(owner, str) or not owner:
                raise ValueError("invalid expected observation")
            expected_owners[key] = owner
        packages = snapshot.get("packages")
        records = findings + (packages if isinstance(packages, list) else [])
    grouped = {}
    for finding in records:
        if not isinstance(finding, dict):
            continue
        installation = finding.get("installation")
        ecosystem = str(finding.get("ecosystem") or "").lower()
        package = finding.get("package")
        key = (installation, ecosystem, package)
        owner = _owned_installation(finding, owned_installations)
        if (owner is None or
                not isinstance(package, str) or not PACKAGE.fullmatch(package) or
                (expected_keys is not None and key not in expected_keys)):
            continue
        value = grouped.setdefault(
            key, {"findings": [], "owner_installation": owner})
        if value["owner_installation"] != owner:
            raise ValueError("conflicting installation ownership")
        value["findings"].append(finding)
    for key in expected_keys or ():
        owner = expected_owners[key]
        if owner in owned_installations:
            grouped.setdefault(
                key, {"findings": [], "owner_installation": owner})

    observed_at = clock()
    observations = []
    missing = []
    release_cache = {}
    for (installation, ecosystem, package), value in sorted(grouped.items()):
        owner_installation = value["owner_installation"]
        fixed = sorted({version.strip() for item in value["findings"]
                        for version in str(item.get("fixed") or "").split(",")
                        if version.strip()})
        installed = sorted({str(item.get("installed") or "")
                            for item in value["findings"] if item.get("installed")})
        reason = ""
        release_channels = [item for item in channels
                            if isinstance(item, dict) and
                            item.get("installation") in
                            {installation, owner_installation}]
        is_host_apt = (installation == "os" and
                       ecosystem in {"debian", "ubuntu"})
        if not is_host_apt and len(release_channels) != 1:
            reason = ("release_channel_not_unique" if release_channels
                      else "owning_release_channel_missing")
        elif is_host_apt and not APT_PACKAGE.fullmatch(package):
            reason = "invalid_package_name"
        platform = (_platform(run)
                    if is_host_apt and not reason else "unknown")
        policy_text = ""
        candidate = ""
        observed_installed = installed[0] if len(installed) == 1 else "unknown"
        available = False
        source = "configured-apt-channel"
        channel_name = "apt:" + platform
        provenance_input = {}
        collected = False
        if not reason and is_host_apt:
            policy = run(["apt-cache", "policy", package])
            policy_text = policy.stdout
            if policy.returncode != 0:
                reason = "channel_query_failed"
            else:
                candidate = _candidate(policy.stdout)
                if not candidate:
                    reason = "candidate_missing"
                elif not installed:
                    reason = "installed_version_missing"
                else:
                    try:
                        newer = any(_compare(candidate, "gt", version, run)
                                    for version in installed)
                    except RuntimeError:
                        reason = "version_comparison_failed"
                    else:
                        available = newer
                        reason = "" if available else "candidate_not_newer"
                        collected = True
            provenance_input = {"policy": policy_text}
        elif not reason:
            release_channel = release_channels[0]
            cache_key = json.dumps(release_channel, sort_keys=True,
                                   separators=(",", ":"))
            if cache_key not in release_cache:
                release_cache[cache_key] = _release_state(
                    release_channel, run, fetch)
            release = release_cache[cache_key]
            reason = release["reason"]
            candidate = release.get("candidate", "")
            observed_installed = release.get("installed", "unknown")
            available = release.get("available", False)
            collected = reason in {"", "candidate_not_newer"}
            source = "configured-release-channel"
            channel_name = str(release_channel.get("channel") or "unknown")
            platform = str(release_channel.get("platform") or "unknown")
            provenance_input = {
                "release_source": release_channel.get("source"),
                "url": release_channel.get("url"),
                "entry_id": release.get("entry_id"),
                "title": release.get("title"),
                "installed": release.get("installed"),
            }
        provenance = "sha256:" + hashlib.sha256(json.dumps({
            "installation": installation, "ecosystem": ecosystem,
            "owner_installation": owner_installation, "package": package,
            "platform": platform, "policy": policy_text,
            **provenance_input,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        observation = {
            "installation": installation, "ecosystem": ecosystem,
            "owner_installation": owner_installation,
            "package": package, "candidate": candidate or "unknown",
            "installed": observed_installed,
            "available": available, "source": source,
            "channel": channel_name, "platform": platform,
            "provenance": provenance, "observed_at": observed_at,
            "reason": reason, "advisory_fixed_versions": fixed,
        }
        observations.append(observation)
        if not collected:
            missing.append({"installation": installation,
                            "owner_installation": owner_installation,
                            "ecosystem": ecosystem, "package": package,
                            "reason": reason})

    status = "complete" if grouped and not missing else "incomplete"
    receipt = {
        "collector": "homelab-update-opportunities/v1", "status": status,
        "observed_at": observed_at,
        "source_snapshot": {
            "source": snapshot.get("source"), "generation": snapshot.get("generation"),
            "sequence": snapshot.get("sequence"),
        },
        "owned_installations": sorted(set(owned_installations)),
        "resolved_installations": sorted({
            value["owner_installation"] + "->" + key[0]
            for key, value in grouped.items()}),
        "missing": missing,
    }
    return {"observations": observations, "receipt": receipt}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--installations", required=True)
    parser.add_argument("--channels", default="[]")
    parser.add_argument("--expected")
    args = parser.parse_args()
    owned = json.loads(args.installations)
    channels = json.loads(args.channels)
    expected = json.loads(args.expected) if args.expected is not None else None
    if args.snapshot.exists():
        envelope = json.loads(args.snapshot.read_text(encoding="utf-8"))
        snapshot = envelope.get("snapshot") or {}
    else:
        snapshot = {}
    print(json.dumps(collect(
        snapshot, owned, channels=channels, expected=expected), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
