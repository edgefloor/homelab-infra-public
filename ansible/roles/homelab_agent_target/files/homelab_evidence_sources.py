"""Bounded public-source retrieval and immutable candidate image inspection."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import tempfile
import time
from pathlib import Path
from urllib import parse

MAX_DOCUMENT = 128 * 1024
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)


def public_get(
    url: str, headers: dict | None = None, maximum: int = MAX_DOCUMENT
) -> tuple[bytes, dict]:
    """Pin each TLS connection to a validated public IP; revalidate every redirect."""
    for redirect in range(4):
        parsed = parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
        ):
            raise ValueError("Only public HTTPS sources on port 443 are readable")
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(
            not ipaddress.ip_address(a[4][0]).is_global for a in addresses
        ):
            raise ValueError("Source resolves to a non-public address")
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=20)
        raw_socket = socket.create_connection((addresses[0][4][0], 443), timeout=20)
        try:
            connection.sock = ssl.create_default_context().wrap_socket(
                raw_socket, server_hostname=parsed.hostname
            )
            connection.request(
                "GET",
                parse.urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                headers={"User-Agent": "homelab-evidence/2", **(headers or {})},
            )
            response = connection.getresponse()
            response_headers = dict(response.getheaders())
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location or redirect == 3:
                    raise ValueError("Source redirect limit exceeded")
                url = parse.urljoin(url, location)
                headers = {}  # never forward registry authorization across redirects
                continue
            if response.status != 200:
                raise ValueError(f"Public source returned HTTP {response.status}")
            content = response.read(maximum + 1)
            if len(content) > maximum:
                raise ValueError("Public source exceeded its output limit")
            return content, response_headers
        finally:
            connection.close()
            raw_socket.close()
    raise ValueError("Source redirect limit exceeded")


def advisory_reference(scope: dict, args: dict, advisory_lookup) -> dict:
    document = advisory_lookup(scope, {"advisory": args.get("advisory")})
    if document.get("status") == "unavailable":
        return document
    index = args.get("reference_index")
    references = document.get("references", [])
    if type(index) is not int or not 0 <= index < len(references):
        raise ValueError("Reference must be an index from the scoped official advisory")
    url = references[index].get("url")
    if not isinstance(url, str):
        raise ValueError("Advisory reference has no URL")
    body, headers = public_get(url)
    content_type = next(
        (v for k, v in headers.items() if k.lower() == "content-type"), ""
    )
    if not any(t in content_type for t in ("text/", "json", "xml")):
        raise ValueError("Advisory reference is not a readable text document")
    text = body.decode("utf-8", errors="replace")
    if "html" in content_type:
        from html.parser import HTMLParser

        class TextParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.parts, self.hidden = [], 0

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style"):
                    self.hidden += 1

            def handle_endtag(self, tag):
                if tag in ("script", "style"):
                    self.hidden = max(0, self.hidden - 1)

            def handle_data(self, data):
                if not self.hidden and data.strip():
                    self.parts.append(data.strip())

        parser = TextParser()
        parser.feed(text)
        text = "\n".join(parser.parts)
    return {
        "url": url,
        "sha256": hashlib.sha256(body).hexdigest(),
        "content": text,
        "truncated": False,
    }


def registry_location(artifact: str) -> tuple[str, str]:
    repository = artifact.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    repository = repository.removeprefix("docker.io/")
    if repository.startswith("ghcr.io/"):
        host, repository = "ghcr.io", repository[len("ghcr.io/") :]
    else:
        if "." in repository.split("/")[0] or ":" in repository.split("/")[0]:
            raise ValueError("No adapter for this public registry")
        host = "registry-1.docker.io"
        if "/" not in repository:
            repository = "library/" + repository
    if not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repository):
        raise ValueError("Invalid registry repository")
    return host, repository


def registry_json(host: str, repository: str, suffix: str) -> tuple[dict, str]:
    service = "registry.docker.io" if host == "registry-1.docker.io" else "ghcr.io"
    token_url = (
        "https://auth.docker.io/token"
        if host == "registry-1.docker.io"
        else "https://ghcr.io/token"
    )
    token_raw, _ = public_get(
        token_url
        + "?"
        + parse.urlencode(
            {"service": service, "scope": f"repository:{repository}:pull"}
        )
    )
    token_doc = json.loads(token_raw)
    token = token_doc.get("token") or token_doc.get("access_token")
    if not isinstance(token, str) or "\n" in token or "\r" in token:
        raise ValueError("Registry did not grant public pull access")
    raw, _ = public_get(
        f"https://{host}/v2/{repository}/{suffix}",
        {"Authorization": "Bearer " + token, "Accept": MANIFEST_TYPES},
    )
    return json.loads(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def release_tags(artifact: str) -> dict:
    host, repository = registry_location(artifact)
    doc, _ = registry_json(host, repository, "tags/list?n=20")
    return {
        "repository": repository,
        "tags": doc.get("tags") or [],
        "truncated": len(doc.get("tags") or []) >= 20,
        "limitations": [
            "Tags are registry-ordered candidates, not proof of a patched dependency."
        ],
    }


def candidate_manifest(artifact: str, tag: str, platform: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise ValueError("Invalid candidate tag")
    host, repository = registry_location(artifact)
    manifest, digest = registry_json(host, repository, "manifests/" + tag)
    platform_parts = platform.split("/")
    if len(platform_parts) not in (2, 3) or platform_parts[0] != "linux":
        raise ValueError("Unsupported platform")
    if "manifests" in manifest:
        matches = [
            m
            for m in manifest["manifests"]
            if m.get("platform", {}).get("os") == platform_parts[0]
            and m.get("platform", {}).get("architecture") == platform_parts[1]
            and (
                len(platform_parts) == 2
                or m.get("platform", {}).get("variant") == platform_parts[2]
            )
        ]
        if len(matches) != 1:
            raise ValueError("No unambiguous candidate for the deployed platform")
        expected = matches[0]["digest"]
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", expected):
            raise ValueError("Unsupported manifest digest")
        manifest, digest = registry_json(host, repository, "manifests/" + expected)
        if digest != expected:
            raise ValueError("Registry manifest digest mismatch")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) > 200:
        raise ValueError("Candidate is not a supported image manifest")
    sizes = [layer.get("size") for layer in layers]
    if (
        any(type(size) is not int or size < 0 for size in sizes)
        or sum(sizes) > MAX_IMAGE_BYTES
    ):
        raise ValueError("Candidate exceeds download limit")
    config_digest = manifest.get("config", {}).get("digest", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", config_digest):
        raise ValueError("Candidate lacks immutable image configuration")
    config, actual = registry_json(host, repository, "blobs/" + config_digest)
    if (
        actual != config_digest
        or config.get("os") != platform_parts[0]
        or config.get("architecture") != platform_parts[1]
    ):
        raise ValueError("Candidate platform or configuration digest mismatch")
    prefix = "ghcr.io/" if host == "ghcr.io" else "docker.io/"
    return {
        "image": prefix + repository + "@" + digest,
        "digest": digest,
        "platform": platform,
        "tag": tag,
        "download_bytes": sum(sizes),
    }


def verify_candidate(
    scope: dict, args: dict, artifact: str, container: dict, run, scan
) -> dict:
    if (
        args.get("advisory") not in scope["advisories"]
        or args.get("package") not in scope["packages"]
    ):
        raise ValueError("Candidate verification is outside the finding scope")
    if not container:
        raise ValueError("Candidate image verification requires a deployed container")
    result = run(
        [
            "/usr/bin/docker",
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            container["image_id"],
        ],
        20,
    )
    if result["returncode"] or result.get("truncated"):
        raise ValueError("Deployed image platform could not be established")
    candidate = candidate_manifest(
        artifact, str(args.get("tag") or ""), result["stdout"].strip()
    )
    cache_key = candidate["image"] + ":" + args["advisory"] + ":" + args["package"]
    cached = scope.get("candidate_cache", {}).get(cache_key)
    if cached:
        return {**cached, "candidate": candidate, "reused_analysis": True}
    if not Path("/usr/local/bin/trivy").is_file():
        return {
            "status": "unavailable",
            "reason": "Trivy is not installed",
            "candidate": candidate,
        }
    with tempfile.TemporaryDirectory(prefix="homelab-candidate-") as directory:
        scan_result = scan(
            [
                "/usr/local/bin/trivy",
                "image",
                "--image-src",
                "remote",
                "--platform",
                candidate["platform"],
                "--cache-dir",
                directory,
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--list-all-pkgs",
                "--ignorefile",
                "/dev/null",
                "--timeout",
                "240s",
                candidate["image"],
            ],
            260,
            8 * 1024 * 1024,
            disk_root=Path(directory),
            disk_limit=MAX_IMAGE_BYTES,
        )
    if scan_result["returncode"] or scan_result["overflow"] or scan_result["timed_out"]:
        return {
            "status": "unavailable",
            "reason": "Candidate scan failed or exceeded its resource limits",
            "candidate": candidate,
        }
    report = json.loads(scan_result["stdout"])
    results = report.get("Results")
    if not isinstance(results, list) or report.get("Metadata", {}).get("OS", {}).get(
        "EOSL"
    ):
        return {
            "status": "unavailable",
            "reason": "Candidate scan lacks supported package coverage",
            "candidate": candidate,
        }
    packages = []
    affected = []
    for result in results:
        packages.extend(
            {
                "name": p.get("Name"),
                "version": p.get("Version"),
                "target": result.get("Target"),
            }
            for p in result.get("Packages") or []
            if p.get("Name") == args["package"]
        )
        affected.extend(
            v
            for v in result.get("Vulnerabilities") or []
            if v.get("VulnerabilityID") == args["advisory"]
        )
    result = {
        "analysis_timestamp": time.time(),
        "candidate": candidate,
        "verified": bool(packages) and not affected,
        "packages": packages[:100],
        "advisory_reported": bool(affected),
        "limitations": [
            "Verification describes this immutable platform image and the current scanner database."
        ],
        "truncated": len(packages) > 100,
    }
    scope.setdefault("candidate_cache", {})[cache_key] = result
    return result
