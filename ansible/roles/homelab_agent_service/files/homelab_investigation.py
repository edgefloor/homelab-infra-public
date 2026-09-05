"""Investigation contracts, attributable observations, and private durable records."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

PROTOCOL = 2
RUNTIME_OPERATIONS = {
    "list_processes",
    "list_listeners",
    "container_metadata",
    "read_proc_maps",
    "read_config",
    "inspect_executable",
    "package_info",
    "run_analyzer",
}
ADVISORY_OPERATIONS = {"official_advisory", "advisory_reference"}


def obj(properties: dict) -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
    }


def string(limit: int = 1200) -> dict:
    return {"type": "string", "minLength": 1, "maxLength": limit}


def array(items: dict, limit: int = 64) -> dict:
    return {"type": "array", "items": items, "maxItems": limit}


def enum(*values: str) -> dict:
    return {"type": "string", "enum": list(values)}


REFS = array(string(64), 32)
CONDITION = obj(
    {
        "condition": string(),
        "state": enum("supported", "contradicted", "unresolved"),
        "claim": string(800),
        "refs": REFS,
    }
)
LIMITATION = obj({"text": string(800), "refs": REFS})
PATH_RESULT = obj(
    {
        "path_id": string(160),
        "preconditions": array(CONDITION, 32),
        "reachability": enum("confirmed", "plausible", "not_found", "unknown"),
        "decision": enum(
            "urgent", "normal_update", "targeted_check", "insufficient_evidence"
        ),
        "rationale": string(1600),
        "limitations": array(LIMITATION, 32),
        "patched_artifact": enum("available", "unavailable", "unverified"),
        "patch_refs": REFS,
        "next_check": {"type": ["string", "null"], "maxLength": 800},
    }
)
INVESTIGATION_SCHEMA = obj(
    {
        "groups": array(
            obj(
                {
                    "group_id": string(64),
                    "mechanism": string(2400),
                    "mechanism_refs": REFS,
                    "paths": array(PATH_RESULT, 80),
                }
            ),
            20,
        )
    }
)


def check_schema(value: Any, schema: dict, location: str = "record") -> None:
    """Small validator for the exact JSON Schema vocabulary used by these contracts."""
    kind = schema["type"]
    kinds = kind if isinstance(kind, list) else [kind]
    valid = any(
        (k == "null" and value is None)
        or (k == "string" and isinstance(value, str))
        or (k == "object" and isinstance(value, dict))
        or (k == "array" and isinstance(value, list))
        or (k == "integer" and type(value) is int)
        for k in kinds
    )
    if not valid or ("enum" in schema and value not in schema["enum"]):
        raise ValueError(f"{location}: invalid value")
    if isinstance(value, str):
        if (
            not schema.get("minLength", 0)
            <= len(value)
            <= schema.get("maxLength", 100000)
        ):
            raise ValueError(f"{location}: invalid text length")
        if schema.get("minLength") and not value.strip():
            raise ValueError(f"{location}: empty text")
    elif isinstance(value, dict):
        if set(value) != set(schema["properties"]):
            raise ValueError(f"{location}: unexpected or missing fields")
        for key, child in schema["properties"].items():
            check_schema(value[key], child, f"{location}.{key}")
    elif isinstance(value, list):
        if len(value) > schema.get("maxItems", 10000):
            raise ValueError(f"{location}: too many items")
        for index, item in enumerate(value):
            check_schema(item, schema["items"], f"{location}[{index}]")


def normalize_scope(context: str, target: str) -> dict:
    payload = json.loads(context)
    scope = copy.deepcopy(payload.get("evidence"))
    if not isinstance(scope, dict) or scope.get("schema") != 2:
        raise ValueError("CVE alert does not contain schema-2 normalized findings")
    groups = scope.get("groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 20:
        raise ValueError("Expected 1-20 finding groups")
    paths: dict[str, dict] = {}
    count = 0
    for group in groups:
        group["group_id"] = (
            "g"
            + hashlib.sha256(
                json.dumps(
                    [group["id"], group["package"], group.get("fixed")],
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()[:20]
        )
        group_paths = set()
        occurrences = group.get("occurrences", [])
        for occurrence in occurrences:
            count += 1
            artifact = str(occurrence.get("artifact") or "host rootfs")
            label = artifact.split("@sha256:", 1)[0].removeprefix("docker.io/")
            containers = occurrence.get("containers") or [None]
            occurrence_paths = []
            for container in containers:
                if container:
                    if not container.get("id"):
                        raise ValueError(
                            "Container occurrence lacks immutable runtime identity"
                        )
                    identity = container["id"]
                    display = str(container.get("name") or label)
                    if (
                        not display
                        or len(display) > 140
                        or any(ord(c) < 32 for c in display)
                    ):
                        raise ValueError("Invalid component display label")
                else:
                    identity = "host:" + str(
                        occurrence.get("reported_file") or group["package"]
                    )
                    display = (
                        Path(str(occurrence["reported_file"])).name
                        if occurrence.get("reported_file") else "host " + str(group["package"])
                    )
                path_id = (
                    "p"
                    + hashlib.sha256(f"{target}:{identity}".encode()).hexdigest()[:32]
                )
                path = paths.setdefault(
                    path_id,
                    {
                        "path_id": path_id,
                        "display_label": display,
                        "container": container,
                        "artifact_id": occurrence.get("artifact_id") or "",
                        "exact_artifact": artifact,
                        "occurrence_count": 0,
                        "reported_files": [],
                        "packages": [],
                    },
                )
                path["occurrence_count"] += 1
                if group["package"] not in path["packages"]:
                    path["packages"].append(group["package"])
                reported = occurrence.get("reported_file")
                if reported and reported not in path["reported_files"]:
                    path["reported_files"].append(reported)
                occurrence_paths.append(path_id)
                group_paths.add(path_id)
            occurrence["deployed_path_ids"] = occurrence_paths
        group["path_ids"] = sorted(group_paths)
        group["occurrence_count"] = len(occurrences)
    if count > 40 or len(paths) > 80:
        raise ValueError("Finding scope exceeds the supported investigation size")
    if len({g["group_id"] for g in groups}) != len(groups):
        raise ValueError("Duplicate finding group")
    scope["deployed_paths"] = list(paths.values())
    scope["occurrence_count"] = count
    scope["complete"] = not bool(scope.get("truncated")) and all(
        g["path_ids"] for g in groups
    )
    return scope


def image_repository(artifact: str) -> str:
    repository = artifact.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    if "/" not in repository:
        return "docker.io/library/" + repository
    if (
        "." not in repository.split("/", 1)[0]
        and ":" not in repository.split("/", 1)[0]
    ):
        return "docker.io/" + repository
    return repository


def receipt_matches(receipt: dict, path: dict, advisory: str) -> bool:
    args = receipt.get("arguments", {})
    if args.get("advisory") and args["advisory"].upper() != advisory.upper():
        return False
    if receipt.get("operation") in ADVISORY_OPERATIONS | {"repository_search"}:
        return (
            receipt.get("operation") == "repository_search"
            or args.get("advisory") == advisory
        )
    if receipt.get("operation") == "upstream_releases":
        return bool(args.get("artifact")) and image_repository(
            args["artifact"]
        ) == image_repository(path["exact_artifact"])
    container = path["container"]
    if container:
        identity = receipt.get("identity", {})
        return (
            identity.get("container_id") == container["id"]
            and identity.get("artifact_id") == path["artifact_id"]
        )
    if args.get("container") or receipt.get("identity", {}).get("container_id"):
        return False
    if args.get("package") and args["package"] not in path["packages"]:
        return False
    if args.get("path") and receipt.get("operation") in {
        "inspect_executable",
        "run_analyzer",
        "extract_file",
    }:
        return args["path"] in path["reported_files"]
    return True


def validate_investigation(value: dict, scope: dict, receipts: list[dict]) -> dict:
    check_schema(value, INVESTIGATION_SCHEMA)
    observed = {r["observation_id"]: r for r in receipts}
    if len(observed) != len(receipts):
        raise ValueError("Duplicate observation ID")
    expected = {g["group_id"]: g for g in scope["groups"]}
    if {g["group_id"] for g in value["groups"]} != set(expected) or len(
        value["groups"]
    ) != len(expected):
        raise ValueError("Investigation omitted or duplicated finding groups")
    paths = {p["path_id"]: p for p in scope["deployed_paths"]}

    def references(
        ids: list, path: dict, advisory: str, successful: bool = True
    ) -> list:
        selected = []
        for ref in ids:
            receipt = observed.get(ref)
            if not receipt or not receipt_matches(receipt, path, advisory):
                raise ValueError(
                    f"Unknown or cross-path evidence reference {ref!r} "
                    f"({receipt.get('operation') if receipt else 'missing receipt'}) "
                    f"for path {path['path_id']}. Container facts require matching "
                    "container and artifact identities; host observations do not "
                    "establish container state. Use a matching observation or leave "
                    "the claim unresolved without that reference."
                )
            if successful and (
                receipt["status"] != "success" or receipt.get("truncated")
            ):
                raise ValueError(
                    "Failed or incomplete observation cannot establish a fact"
                )
            selected.append(receipt)
        return selected

    for group in value["groups"]:
        source = expected[group["group_id"]]
        if len(group["paths"]) != len(source["path_ids"]) or {
            p["path_id"] for p in group["paths"]
        } != set(source["path_ids"]):
            raise ValueError("Investigation omitted or duplicated runtime paths")
        mechanism_ok = bool(group["mechanism_refs"])
        official_mechanism = False
        for ref in group["mechanism_refs"]:
            r = observed.get(ref, {})
            official = (
                r.get("operation") in ADVISORY_OPERATIONS
                and r.get("arguments", {}).get("advisory") == source["id"]
            )
            bound_source = r.get("operation") == "dependency_source" and any(
                receipt_matches(r, paths[path_id], source["id"])
                for path_id in source["path_ids"]
            )
            if (
                not (official or bound_source)
                or r.get("status") != "success"
                or r.get("truncated")
            ):
                raise ValueError(
                    f"Invalid mechanism reference {ref!r} ({r.get('operation', 'missing receipt')}). "
                    "Use successful scoped advisory references or source from a runtime path in this group."
                )
            official_mechanism |= official
        if mechanism_ok and not official_mechanism:
            raise ValueError(
                "Mechanism requires an official advisory reference; source evidence supplements it"
            )
        for assessment in group["paths"]:
            path = paths[assessment["path_id"]]
            attempts = [
                r
                for r in receipts
                if r.get("operation") in RUNTIME_OPERATIONS
                and receipt_matches(r, path, source["id"])
            ]
            if not attempts:
                raise ValueError("Every runtime path requires an attempted observation")
            public = [c["claim"] for c in assessment["preconditions"]]
            if (
                len(assessment["rationale"].split()) > 45
                or "\n" in assessment["rationale"]
            ):
                raise ValueError(
                    "The operator rationale must be a decision explanation within 45 words; retain diagnostics in limitations"
                )
            public.extend(l["text"] for l in assessment["limitations"])
            public.append(assessment["next_check"] or "")
            if any(
                len(text.split()) > 90 or "sha256:" in text or "\n" in text
                for text in public
            ):
                raise ValueError(
                    "Public facts must be complete concise sentences without internal IDs"
                )
            conditions = assessment["preconditions"]
            for condition in conditions:
                refs = references(
                    condition["refs"],
                    path,
                    source["id"],
                    condition["state"] != "unresolved",
                )
                if condition["state"] != "unresolved" and not refs:
                    raise ValueError(
                        "Supported and contradicted preconditions require observations"
                    )
                if condition["state"] != "unresolved" and not any(
                    r["operation"] in RUNTIME_OPERATIONS for r in refs
                ):
                    raise ValueError("Path preconditions require deployed observations")
            for limitation in assessment["limitations"]:
                references(limitation["refs"], path, source["id"], False)
            reach = assessment["reachability"]
            states = [c["state"] for c in conditions]
            if reach != "unknown" and (not mechanism_ok or not conditions):
                raise ValueError(
                    "Reachability requires a known mechanism and assessed preconditions"
                )
            if reach == "confirmed" and any(s != "supported" for s in states):
                raise ValueError("Confirmed reachability requires every precondition")
            if reach == "plausible" and not (
                "supported" in states
                and "unresolved" in states
                and "contradicted" not in states
            ):
                raise ValueError(
                    "Plausible reachability requires a concrete incomplete path"
                )
            if reach == "not_found" and "contradicted" not in states:
                raise ValueError("Absence requires an observed blocked precondition")
            if (reach == "unknown" or "unresolved" in states) and not assessment[
                "limitations"
            ]:
                raise ValueError("Unresolved assessments require a precise limitation")
            if assessment["decision"] == "normal_update" and not any(
                s != "unresolved" for s in states
            ):
                raise ValueError(
                    "Routine maintenance requires a successful deployed observation"
                )
            if assessment["decision"] == "urgent" and reach != "confirmed":
                raise ValueError("Urgent decision requires confirmed reachability")
            if (assessment["decision"] == "targeted_check") != bool(
                assessment["next_check"]
            ):
                raise ValueError("Only a targeted check decision requires a next check")
            patch = references(assessment["patch_refs"], path, source["id"])
            if assessment["patched_artifact"] == "available" and not any(
                r["operation"] == "verify_candidate"
                and r["result"].get("verified") is True
                and r["arguments"].get("advisory") == source["id"]
                and r["arguments"].get("package") == source["package"]
                for r in patch
            ):
                raise ValueError("A deployable patch requires candidate verification")
            if assessment["patched_artifact"] == "unavailable" and not any(
                r["operation"] in ADVISORY_OPERATIONS for r in patch
            ):
                raise ValueError("Unavailable patch requires authoritative evidence")
    return value


class RecordStore:
    def __init__(
        self, root: Path, retention_days: int = 30, max_bytes: int = 256 * 1024 * 1024
    ):
        self.root, self.retention_days, self.max_bytes = root, retention_days, max_bytes
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)

    def directory(self, record_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{16}", record_id):
            raise ValueError("Invalid evidence record ID")
        return self.root / record_id

    def create(self, target: str, event_id: str) -> dict:
        self.prune(reserve_bytes=32 * 1024 * 1024)
        record_id = secrets.token_hex(8)
        directory = self.directory(record_id)
        directory.mkdir(mode=0o700)
        (directory / "receipts").mkdir(mode=0o700)
        record = {
            "schema": 1,
            "record_id": record_id,
            "target": target,
            "event_id": event_id,
            "started_at": time.time(),
            "status": "active",
            "scope": None,
            "investigation": None,
            "metrics": {},
        }
        self.save(record)
        return record

    def save(self, record: dict) -> None:
        directory = self.directory(record["record_id"])
        encoded = json.dumps(record, ensure_ascii=False, indent=2).encode()
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("Investigation record exceeds storage limit")
        temporary = directory / (secrets.token_hex(8) + ".tmp")
        try:
            with temporary.open("xb") as handle:
                os.chmod(temporary, 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(directory / "record.json")
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, record_id: str) -> dict:
        return json.loads((self.directory(record_id) / "record.json").read_text())

    def receipts(self, record_id: str) -> list[dict]:
        return [
            json.loads(p.read_text())
            for p in sorted((self.directory(record_id) / "receipts").glob("*.json"))
        ]

    def prune(self, reserve_bytes: int = 0) -> None:
        import shutil

        entries = []
        total = 0
        for directory in self.root.iterdir():
            if not directory.is_dir() or not re.fullmatch(
                r"[a-f0-9]{16}", directory.name
            ):
                continue
            size = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
            total += size
            try:
                record = self.load(directory.name)
            except (OSError, ValueError):
                continue
            if record["status"] != "active":
                entries.append((record["started_at"], directory, size))
        for timestamp, directory, size in sorted(entries):
            if (
                timestamp < time.time() - self.retention_days * 86400
                or total + reserve_bytes >= self.max_bytes
            ):
                shutil.rmtree(directory)
                total -= size
        if total + reserve_bytes >= self.max_bytes:
            raise OSError(
                "Evidence storage is full; active investigations were preserved"
            )
