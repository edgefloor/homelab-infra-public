#!/usr/bin/env python3
"""Collect the Phase 0 Proxmox guest inventory without exposing credentials.

The live transport is deliberately small and HTTPS-only. Tests inject a mock
transport; importing this module never reads the environment or uses the network.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit


API_PREFIX = "/api2/json"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
APPROVED_PORT = 443
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
VMID_RE = re.compile(r"[1-9][0-9]{0,8}\Z")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z", re.IGNORECASE)
ENDPOINT_RE = re.compile(
    r"/api2/json/nodes(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,62}/(?:lxc|qemu)"
    r"(?:/[1-9][0-9]{0,8}/(?:config|status/current))?)?\Z"
)


class InventoryError(Exception):
    """A safe-to-classify inventory failure.

    Exception messages are intentionally constant and must not contain request
    URLs, response bodies, headers, environment values, or filesystem paths.
    """


@dataclass(frozen=True)
class Response:
    status: int
    content_type: str
    body: bytes


@dataclass(frozen=True)
class ApprovedOrigin:
    hostname: str
    port: int
    addresses: frozenset[str]

    @property
    def opaque_target(self) -> str:
        return hashlib.sha256(self.hostname.encode("ascii")).hexdigest()[:16]


class Transport(Protocol):
    def request(self, method: str, endpoint: str, headers: Mapping[str, str]) -> Response: ...


def normalize_fingerprint(value: str) -> str:
    candidate = value.strip()
    if candidate.lower().startswith("sha256:"):
        candidate = candidate[7:]
    if ":" in candidate and re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31}", candidate) is None:
        raise InventoryError("invalid TLS fingerprint")
    compact = candidate.replace(":", "")
    if FINGERPRINT_RE.fullmatch(compact) is None:
        raise InventoryError("invalid TLS fingerprint")
    return compact.lower()


def hostname_is_numeric(value: str) -> bool:
    """Classify modern and legacy numeric hosts without performing DNS."""
    try:
        answers = socket.getaddrinfo(
            value,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            flags=socket.AI_NUMERICHOST,
        )
    except socket.gaierror as exc:
        if exc.errno == socket.EAI_NONAME:
            return False
        raise InventoryError("numeric hostname classification failed") from exc
    return bool(answers)


def parse_host(value: str) -> tuple[str, int]:
    """Parse a strict HTTPS hostname origin without resolving it."""
    candidate = value
    if not candidate or candidate != candidate.strip() or any(ord(char) < 33 for char in candidate):
        raise InventoryError("invalid Proxmox host")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        raise InventoryError("invalid Proxmox host")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise InventoryError("invalid Proxmox host") from exc
    port = APPROVED_PORT if parsed_port is None else parsed_port
    hostname = parsed.hostname.lower()
    labels = hostname.split(".")
    if (
        port != APPROVED_PORT
        or len(hostname) > 253
        or any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in labels
        )
    ):
        raise InventoryError("Proxmox host outside approved origin")
    if hostname_is_numeric(hostname):
        raise InventoryError("Proxmox host must be a hostname")
    return hostname, APPROVED_PORT


def normalize_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InventoryError("invalid resolved address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def address_is_private_admin(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(
            address in network
            for network in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    return address in ipaddress.ip_network("fc00::/7")


def resolve_approved_origin(
    value: str,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> ApprovedOrigin:
    hostname, port = parse_host(value)
    try:
        answers = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise InventoryError("Proxmox hostname resolution failed") from exc
    try:
        addresses = frozenset(normalize_address(answer[4][0]) for answer in answers)
    except (IndexError, TypeError) as exc:
        raise InventoryError("Proxmox hostname resolution rejected") from exc
    if not addresses or any(not address_is_private_admin(address) for address in addresses):
        raise InventoryError("Proxmox hostname resolved outside private administration addresses")
    return ApprovedOrigin(hostname, port, addresses)


def require_bound_peer(sock: ssl.SSLSocket, origin: ApprovedOrigin) -> None:
    try:
        peer = normalize_address(sock.getpeername()[0])
    except (OSError, IndexError, TypeError) as exc:
        raise InventoryError("TLS peer address unavailable") from exc
    if peer not in origin.addresses:
        raise InventoryError("TLS peer address changed after resolution")


def endpoint_is_allowlisted(value: str) -> bool:
    return (
        isinstance(value, str)
        and "?" not in value
        and "#" not in value
        and ENDPOINT_RE.fullmatch(value) is not None
    )


class HTTPSPinnedTransport:
    """HTTPS transport that checks the exact pin before sending credentials.

    System trust is attempted first. For a locally self-signed node1 certificate,
    the fallback TLS context uses the exact operator-approved pin as the trust
    decision; the Authorization header is not sent until that comparison passes.
    """

    def __init__(self, origin: ApprovedOrigin, tls_sha256: str, timeout: float = 20.0):
        self.origin = origin
        self.fingerprint = normalize_fingerprint(tls_sha256)
        self.timeout = timeout

    def _connect(self, context: ssl.SSLContext) -> tuple[http.client.HTTPSConnection, str]:
        connection = http.client.HTTPSConnection(
            self.origin.hostname,
            self.origin.port,
            timeout=self.timeout,
            context=context,
        )
        try:
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise InventoryError("TLS connection failed")
            require_bound_peer(sock, self.origin)
            certificate = sock.getpeercert(binary_form=True)
            if not certificate:
                raise InventoryError("TLS peer certificate unavailable")
            return connection, hashlib.sha256(certificate).hexdigest()
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _exact_pin_context() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        # Exact leaf-certificate pin comparison below replaces CA-path validation
        # for a self-signed local node. No HTTP request is sent before comparison.
        context.verify_mode = ssl.CERT_NONE
        return context

    def request(self, method: str, endpoint: str, headers: Mapping[str, str]) -> Response:
        if method != "GET" or not endpoint_is_allowlisted(endpoint):
            raise InventoryError("transport rejected request")
        connection: http.client.HTTPSConnection | None = None
        try:
            try:
                connection, observed = self._connect(ssl.create_default_context())
            except ssl.SSLCertVerificationError:
                connection, observed = self._connect(self._exact_pin_context())
            if not secrets.compare_digest(observed, self.fingerprint):
                raise InventoryError("TLS fingerprint mismatch")
            connection.request("GET", endpoint, headers=dict(headers))
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "")
            body = response.read(MAX_RESPONSE_BYTES + 1)
        except InventoryError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise InventoryError("HTTPS request failed") from exc
        finally:
            if connection is not None:
                connection.close()
        if len(body) > MAX_RESPONSE_BYTES:
            raise InventoryError("response too large")
        return Response(response.status, content_type, body)


def capture_local_tofu_fingerprint(origin: ApprovedOrigin, timeout: float = 20.0) -> str:
    """Capture node1's leaf certificate without sending an HTTP request.

    This is explicitly trust on first use, not independent certificate
    verification. The private origin resolved at process start is bound for the run.
    """
    context = HTTPSPinnedTransport._exact_pin_context()
    connection = http.client.HTTPSConnection(
        origin.hostname,
        origin.port,
        timeout=timeout,
        context=context,
    )
    try:
        connection.connect()
        sock = connection.sock
        if sock is None:
            raise InventoryError("TLS connection failed")
        require_bound_peer(sock, origin)
        certificate = sock.getpeercert(binary_form=True)
        if not certificate:
            raise InventoryError("TLS peer certificate unavailable")
        return hashlib.sha256(certificate).hexdigest()
    except InventoryError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise InventoryError("TOFU certificate capture failed") from exc
    finally:
        connection.close()


def tofu_observation(
    origin: ApprovedOrigin,
    fingerprint: str,
    observed_at: datetime | None = None,
) -> str:
    timestamp = (observed_at or datetime.now(timezone.utc)).isoformat()
    return (
        "check_id=phase0-proxmox-local-tls-tofu status=observed "
        f"target_sha256={origin.opaque_target} port={origin.port} fingerprint_sha256={fingerprint} "
        f"observed_at={timestamp} residual_risk=not-independently-verified"
    )


def endpoint(kind: str, node: str | None = None, vmid: int | str | None = None) -> str:
    """Build one endpoint from the closed W1.3-A read-only allowlist."""
    if kind == "nodes" and node is None and vmid is None:
        return f"{API_PREFIX}/nodes"
    if node is None or NODE_RE.fullmatch(node) is None:
        raise InventoryError("invalid node identifier")
    if kind in ("lxc-list", "qemu-list") and vmid is None:
        guest_kind = kind.removesuffix("-list")
        return f"{API_PREFIX}/nodes/{node}/{guest_kind}"
    if kind in ("lxc-config", "lxc-status", "qemu-config", "qemu-status"):
        vmid_text = str(vmid)
        if VMID_RE.fullmatch(vmid_text) is None:
            raise InventoryError("invalid guest identifier")
        guest_kind, resource = kind.split("-", 1)
        suffix = "config" if resource == "config" else "status/current"
        return f"{API_PREFIX}/nodes/{node}/{guest_kind}/{vmid_text}/{suffix}"
    raise InventoryError("endpoint not allowlisted")


class RawDirectory:
    """A verified raw directory held open against path substitution."""

    def __init__(self, fd: int):
        self.fd = fd

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "RawDirectory":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def unlink(self, filename: str) -> None:
        os.unlink(filename, dir_fd=self.fd)


def open_raw_dir(
    raw_dir: Path,
    repository_root: Path = REPOSITORY_ROOT,
    temporary_root: Path = Path("/tmp"),
) -> RawDirectory:
    """Open and verify PHASE0_RAW_DIR, returning only a held directory fd."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(raw_dir, flags)
    except OSError as exc:
        raise InventoryError("raw directory unavailable") from exc
    try:
        held = os.fstat(fd)
        resolved = raw_dir.resolve(strict=True)
        resolved_stat = os.stat(resolved, follow_symlinks=False)
        repository_resolved = repository_root.resolve(strict=True)
        temporary_resolved = temporary_root.resolve(strict=True)
        if not stat.S_ISDIR(held.st_mode):
            raise InventoryError("raw directory is not a directory")
        if held.st_dev != resolved_stat.st_dev or held.st_ino != resolved_stat.st_ino:
            raise InventoryError("raw directory identity changed")
        if stat.S_IMODE(held.st_mode) != 0o700 or held.st_uid != os.getuid():
            raise InventoryError("raw directory permissions rejected")
        if resolved == repository_resolved or repository_resolved in resolved.parents:
            raise InventoryError("raw directory inside worktree")
        if resolved == temporary_resolved or temporary_resolved in resolved.parents:
            raise InventoryError("temporary raw directory rejected")
        return RawDirectory(fd)
    except (InventoryError, OSError) as exc:
        os.close(fd)
        if isinstance(exc, InventoryError):
            raise
        raise InventoryError("raw directory verification failed") from exc


def decode_response(response: Response, expected: type[list] | type[dict]):
    if response.status != 200:
        raise InventoryError("API request rejected")
    media_type = response.content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise InventoryError("response content type rejected")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise InventoryError("response too large")
    try:
        envelope = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("response JSON rejected") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"data"}:
        raise InventoryError("response schema rejected")
    data = envelope["data"]
    if not isinstance(data, expected):
        raise InventoryError("response schema rejected")
    return envelope, data


def write_new_json(raw_dir: RawDirectory, filename: str, payload: dict) -> None:
    """Atomically create a mode-0600 artifact without replacing an old one."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.json", filename):
        raise InventoryError("artifact filename rejected")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    temporary = f".phase0-{secrets.token_hex(12)}.tmp"
    fd: int | None = None
    final_linked = False
    completed = False
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=raw_dir.fd,
        )
        os.fchmod(fd, 0o600)
        created = os.fstat(fd)
        if (
            not stat.S_ISREG(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o600
            or created.st_uid != os.getuid()
        ):
            raise InventoryError("artifact permissions rejected")
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary,
            filename,
            src_dir_fd=raw_dir.fd,
            dst_dir_fd=raw_dir.fd,
            follow_symlinks=False,
        )
        final_linked = True
        os.unlink(temporary, dir_fd=raw_dir.fd)
        os.fsync(raw_dir.fd)
        completed = True
    except FileExistsError as exc:
        raise InventoryError("artifact already exists") from exc
    except OSError as exc:
        raise InventoryError("artifact write failed") from exc
    finally:
        if fd is not None:
            os.close(fd)
        cleanup_failed = False
        if final_linked and not completed:
            try:
                os.unlink(filename, dir_fd=raw_dir.fd)
            except OSError:
                cleanup_failed = True
        try:
            os.unlink(temporary, dir_fd=raw_dir.fd)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
        if final_linked and not completed:
            try:
                os.fsync(raw_dir.fd)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise InventoryError("artifact cleanup failed")


def fetch(transport: Transport, token_id: str, token_secret: str, path: str, expected: type):
    if (
        not token_id
        or not token_secret
        or any(ord(char) < 33 or ord(char) > 126 for char in token_id)
        or any(ord(char) < 33 or ord(char) > 126 for char in token_secret)
    ):
        raise InventoryError("credential environment rejected")
    headers = {
        "Accept": "application/json",
        "Authorization": f"PVEAPIToken={token_id}={token_secret}",
    }
    response = transport.request("GET", path, headers)
    return decode_response(response, expected)


def collect(
    transport: Transport,
    token_id: str,
    token_secret: str,
    raw_dir: RawDirectory,
    emit: Callable[[str], None] = print,
) -> None:
    artifacts = 0
    created: list[str] = []
    try:
        nodes_envelope, nodes = fetch(transport, token_id, token_secret, endpoint("nodes"), list)
        for item in nodes:
            if not isinstance(item, dict) or not isinstance(item.get("node"), str):
                raise InventoryError("node list schema rejected")
            if NODE_RE.fullmatch(item["node"]) is None:
                raise InventoryError("node list schema rejected")
        filename = "w1.3-nodes.json"
        write_new_json(raw_dir, filename, nodes_envelope)
        created.append(filename)
        artifacts += 1

        guest_count = 0
        for node_item in nodes:
            node = node_item["node"]
            for guest_kind in ("lxc", "qemu"):
                listing_envelope, guests = fetch(
                    transport, token_id, token_secret, endpoint(f"{guest_kind}-list", node), list
                )
                for guest in guests:
                    if not isinstance(guest, dict):
                        raise InventoryError("guest list schema rejected")
                    vmid = guest.get("vmid")
                    if isinstance(vmid, bool) or VMID_RE.fullmatch(str(vmid)) is None:
                        raise InventoryError("guest list schema rejected")
                filename = f"w1.3-{node}-{guest_kind}-list.json"
                write_new_json(raw_dir, filename, listing_envelope)
                created.append(filename)
                artifacts += 1
                guest_count += len(guests)
                for guest in guests:
                    vmid = guest["vmid"]
                    for resource in ("config", "status"):
                        payload, _ = fetch(
                            transport,
                            token_id,
                            token_secret,
                            endpoint(f"{guest_kind}-{resource}", node, vmid),
                            dict,
                        )
                        filename = f"w1.3-{node}-{guest_kind}-{vmid}-{resource}.json"
                        write_new_json(raw_dir, filename, payload)
                        created.append(filename)
                        artifacts += 1
    except Exception as original_error:
        cleanup_failed = False
        for artifact in reversed(created):
            try:
                raw_dir.unlink(artifact)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        try:
            os.fsync(raw_dir.fd)
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise InventoryError("collection cleanup failed") from original_error
        raise

    emit(f"check_id=phase0-proxmox-nodes count={len(nodes)}")
    emit(f"check_id=phase0-proxmox-guests count={guest_count}")
    emit(f"check_id=phase0-proxmox-raw-artifacts count={artifacts}")


def environment_host() -> str:
    try:
        return os.environ["PROXMOX_HOST"]
    except KeyError as exc:
        raise InventoryError("required environment unavailable") from exc


def environment_token() -> tuple[str, str]:
    try:
        return os.environ["PROXMOX_TOKEN_ID"], os.environ["PROXMOX_TOKEN_SECRET"]
    except KeyError as exc:
        raise InventoryError("required environment unavailable") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Phase 0 Proxmox inventory collector")
    parser.add_argument("--raw-dir", type=Path, required=True, help="existing operator-approved PHASE0_RAW_DIR")
    tls_group = parser.add_mutually_exclusive_group(required=True)
    tls_group.add_argument("--tls-sha256", help="independently verified peer certificate SHA-256 fingerprint")
    tls_group.add_argument(
        "--operator-approved-local-tofu",
        action="store_true",
        help="capture node1 leaf pin without credentials; records residual TOFU risk",
    )
    args = parser.parse_args(argv)
    try:
        origin = resolve_approved_origin(environment_host())
        if args.operator_approved_local_tofu:
            tls_sha256 = capture_local_tofu_fingerprint(origin)
            print(tofu_observation(origin, tls_sha256))
        else:
            tls_sha256 = args.tls_sha256
        token_id, token_secret = environment_token()
        transport = HTTPSPinnedTransport(origin, tls_sha256)
        with open_raw_dir(args.raw_dir) as raw_dir:
            collect(transport, token_id, token_secret, raw_dir)
    except InventoryError as exc:
        print(f"check_id=phase0-proxmox-inventory status=failed category={exc}", file=sys.stderr)
        return 1
    except Exception:
        print(
            "check_id=phase0-proxmox-inventory status=failed category=unexpected-client-error",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
