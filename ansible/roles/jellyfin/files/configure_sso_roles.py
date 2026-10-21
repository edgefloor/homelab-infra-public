#!/usr/bin/env python3
"""Add a required access role to one Jellyfin SSO OIDC provider."""

import argparse
import json
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")


def provider_configuration(tree: ET.ElementTree, provider: str) -> ET.Element:
    root = tree.getroot()
    providers = [
        item
        for item in root.findall("./OidConfigs/item")
        if item.findtext("./key/string") == provider
    ]
    if len(providers) != 1:
        raise ValueError(
            f"expected exactly one OIDC provider named {provider!r}, found {len(providers)}"
        )

    configuration = providers[0].find("./value/PluginConfiguration")
    if configuration is None:
        raise ValueError(f"OIDC provider {provider!r} has no configuration")
    return configuration


def write_tree(path: Path, tree: ET.ElementTree) -> None:
    metadata = path.stat()
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
    ) as output:
        temporary = Path(output.name)
        tree.write(output, encoding="utf-8", xml_declaration=True)
        output.flush()
        os.fsync(output.fileno())
    try:
        os.chmod(temporary, metadata.st_mode)
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_allowed_role(path: Path, provider: str, role: str) -> bool:
    tree = ET.parse(path)
    configuration = provider_configuration(tree, provider)
    roles = configuration.find("Roles")
    if roles is None:
        roles = ET.SubElement(configuration, "Roles")
    if role in {(entry.text or "").strip() for entry in roles.findall("string")}:
        return False

    ET.SubElement(roles, "string").text = role
    write_tree(path, tree)
    return True


def migrate_legacy_links(
    path: Path, provider: str, identities: dict[str, str]
) -> bool:
    tree = ET.parse(path)
    configuration = provider_configuration(tree, provider)
    links = configuration.find("CanonicalLinks")
    if links is None:
        return False

    subjects_by_username = {
        username.casefold(): subject for username, subject in identities.items()
    }
    existing = {
        item.findtext("./key/string"): item
        for item in links.findall("item")
        if item.findtext("./key/string")
    }
    changed = False
    for canonical_name, item in list(existing.items()):
        subject = subjects_by_username.get(canonical_name.casefold())
        if not subject or subject == canonical_name:
            continue
        duplicate = existing.get(subject)
        if duplicate is not None:
            if duplicate.findtext("./value/guid") != item.findtext("./value/guid"):
                raise ValueError(
                    f"subject {subject!r} is already linked to another Jellyfin account"
                )
            links.remove(item)
        else:
            item.find("./key/string").text = subject
            existing[subject] = item
        changed = True

    if changed:
        write_tree(path, tree)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--allow-role", required=True)
    parser.add_argument("--identity-map-json")
    args = parser.parse_args()
    changed = ensure_allowed_role(args.config, args.provider, args.allow_role)
    if args.identity_map_json:
        identities = json.loads(args.identity_map_json)
        if not isinstance(identities, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in identities.items()
        ):
            raise ValueError("identity map must be a JSON object of string pairs")
        changed = migrate_legacy_links(args.config, args.provider, identities) or changed
    print("updated" if changed else "unchanged")


if __name__ == "__main__":
    main()
