#!/usr/bin/env python3
"""Authenticated alert webhook that routes concise notices to Matrix rooms."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from ip_country_lookup import CountryDatabase, country_flag, country_name


LOGGER = logging.getLogger("crowdsec-matrix-bridge")
MAX_BODY_BYTES = 1024 * 1024
MAX_GENERIC_MESSAGE_CHARS = 12000
MAX_MACHINE_CONTEXT_BYTES = 128 * 1024
MACHINE_CONTEXT_KEY = "org.example.alert"
COUNTRY_DATABASE = CountryDatabase(
    Path(os.environ.get("IP_COUNTRY_DB_DIR", "/var/lib/ip-location-db/user-country"))
)
GENERIC_NOTIFICATION_KINDS = {"release", "cve", "system", "beszel"}
NOTIFICATION_ROOMS = {
    "beszel": "health",
    "system": "health",
    "crowdsec": "security",
    "release": "releases",
    "cve": "vulnerabilities",
}
ROOM_CREDENTIALS = {
    "health": "matrix-room-health",
    "security": "matrix-room-security",
    "releases": "matrix-room-releases",
    "vulnerabilities": "matrix-room-vulnerabilities",
}
HTTP_URL = re.compile(r"^https?://", re.IGNORECASE)
BESZEL_STATUS_TITLE = re.compile(
    r"^Connection to (?P<system>.+) is (?P<status>up|down)(?:\s+[✅🔴])?$",
    re.IGNORECASE,
)
BESZEL_METRIC_TITLE = re.compile(
    r"^(?P<system>.+) (?P<metric>CPU|GPU|memory|disk usage|temperature|"
    r"bandwidth|\d+m load|battery) (?P<direction>above|below) threshold$",
    re.IGNORECASE,
)
BESZEL_AVERAGE_BODY = re.compile(
    r"^(?P<metric>.+?) averaged (?P<value>[0-9.]+)(?P<unit>.*?) "
    r"for the previous (?P<minutes>[0-9]+) minutes?\.$",
    re.IGNORECASE,
)
ALERT_RECORD_ID = re.compile(r"^crowdsec_[0-9a-f]{40}$")


class AlertStore:
    """Keep the complete accepted webhook beside its Matrix delivery receipts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, record_id: str) -> Path:
        if not ALERT_RECORD_ID.fullmatch(record_id):
            raise ValueError("invalid alert record ID")
        return self.root / f"{record_id}.json"

    def _read(self, record_id: str) -> dict[str, Any]:
        record = json.loads(self._path(record_id).read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("record_id") != record_id:
            raise RuntimeError("invalid stored alert record")
        return record

    def _write(self, record: dict[str, Any]) -> None:
        path = self._path(str(record["record_id"]))
        temporary = path.with_suffix(".new")
        temporary.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    def begin(
        self,
        record_id: str,
        kind: str,
        payload: dict[str, Any],
        room: str,
        transaction_ids: list[str],
        received_at: str,
    ) -> None:
        with self.lock:
            path = self._path(record_id)
            if path.exists():
                record = self._read(record_id)
                if record.get("payload") != payload:
                    raise RuntimeError("alert record ID collision")
                record["last_received_at"] = received_at
                record["attempts"] = int(record.get("attempts", 1)) + 1
                record["status"] = "delivering"
            else:
                record = {
                    "schema": 1,
                    "record_id": record_id,
                    "received_at": received_at,
                    "last_received_at": received_at,
                    "attempts": 1,
                    "kind": kind,
                    "status": "delivering",
                    "payload": payload,
                    "deliveries": [
                        {
                            "room": room,
                            "transaction_id": transaction_id,
                            "matrix_event_id": None,
                        }
                        for transaction_id in transaction_ids
                    ],
                }
            self._write(record)

    def mark_delivery(
        self, record_id: str, transaction_id: str, matrix_event_id: str
    ) -> None:
        with self.lock:
            record = self._read(record_id)
            for delivery in record["deliveries"]:
                if delivery["transaction_id"] == transaction_id:
                    delivery["matrix_event_id"] = matrix_event_id
                    break
            else:
                raise RuntimeError("unknown alert delivery transaction")
            record["status"] = (
                "delivered"
                if all(item.get("matrix_event_id") for item in record["deliveries"])
                else "delivering"
            )
            self._write(record)

    def mark_failed(self, record_id: str) -> None:
        with self.lock:
            record = self._read(record_id)
            record["status"] = "delivery_failed"
            self._write(record)

    def get(self, record_id: str) -> dict[str, Any]:
        with self.lock:
            return self._read(record_id)


def read_credential(name: str) -> str:
    credential_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not credential_directory:
        raise RuntimeError("CREDENTIALS_DIRECTORY is not set")
    with open(os.path.join(credential_directory, name), encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise RuntimeError(f"systemd credential {name!r} is empty")
    return value


def transaction_id(raw_body: bytes) -> str:
    return "crowdsec_" + hashlib.sha256(raw_body).hexdigest()[:40]


def _text(value: Any, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    rendered = str(value).strip()
    return rendered or fallback


def neutralize_matrix_mentions(message: str) -> str:
    """Keep machine-authored alert text from addressing Matrix users."""
    return message.replace("@", "@\u200b")


def format_source_ip(value: str) -> str:
    """Show the country flag and name above an IP when a lookup succeeds."""
    try:
        country = COUNTRY_DATABASE.lookup(value)
    except (OSError, ValueError) as exc:
        LOGGER.warning("country lookup unavailable: %s", exc)
        return value
    flag = country_flag(country)
    return f"{flag} {country_name(country)}\n{value}" if flag else value


def format_message(payload: dict[str, Any]) -> str:
    edge = _text(payload.get("edge"))
    edge = {"home-caddy": "Home Caddy", "pangolin-vps": "Pangolin VPS"}.get(edge, edge)
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        raise ValueError("payload must contain a non-empty alerts list")

    noun = "alert" if len(alerts) == 1 else "alerts"
    replay = payload.get("replay") is True
    status = "replayed" if replay else "new"
    lines = [f"CrowdSec · {edge}", f"{len(alerts)} {status} {noun}"]
    for alert in alerts[:10]:
        if not isinstance(alert, dict):
            continue
        scenario = _text(alert.get("scenario")).removeprefix("crowdsecurity/")
        source = alert.get("source") if isinstance(alert.get("source"), dict) else {}
        source_value = format_source_ip(
            _text(source.get("value") or source.get("ip"))
        )
        decisions = alert.get("decisions")
        decision_summary = "No remediation"
        if isinstance(decisions, list) and decisions and isinstance(decisions[0], dict):
            decision = decisions[0]
            decision_summary = _text(decision.get("type"), "decision").capitalize()
            duration = _text(decision.get("duration"), "")
            if duration:
                hours = re.fullmatch(r"([1-9]\d*)h(?:0m)?(?:0s)?", duration)
                if hours:
                    duration = f"{hours.group(1)}h"
                decision_summary += f" · {duration}"
        event_count = alert.get("events_count")
        lines.extend(["", source_value, f"Rule: {scenario}", f"Action: {decision_summary}"])
        if event_count is not None:
            lines.append(f"Events: {_text(event_count)}")

    if len(alerts) > 10:
        lines.extend(["", f"… and {len(alerts) - 10} more"])
    if replay:
        lines.extend(["", "Historical replay · no new ban"])
    return "\n".join(lines)


def format_generic_notification(payload: dict[str, Any]) -> str:
    kind = _text(payload.get("kind"), "").lower()
    if kind not in GENERIC_NOTIFICATION_KINDS:
        raise ValueError("unsupported notification kind")

    if kind == "beszel":
        return format_beszel_notification(payload)

    source = _text(payload.get("source"), "")
    if not source or len(source) > 100:
        raise ValueError("source must contain between 1 and 100 characters")

    message = _text(payload.get("message"), "")
    if not message or len(message) > MAX_GENERIC_MESSAGE_CHARS:
        raise ValueError(
            f"message must contain between 1 and {MAX_GENERIC_MESSAGE_CHARS} characters"
        )

    return f"{kind.upper()} | {source}\n{message}"


def matrix_safe_json(value: Any) -> Any:
    """Convert webhook JSON into values accepted by Matrix canonical JSON."""
    if isinstance(value, float):
        return format(value, ".15g")
    if isinstance(value, list):
        return [matrix_safe_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): matrix_safe_json(item) for key, item in value.items()}
    return value


def machine_context(
    payload: dict[str, Any], record_id: str | None = None
) -> dict[str, Any] | None:
    if _text(payload.get("kind"), "").lower() != "cve":
        return None
    context = payload.get("context")
    if context is None:
        return None
    if not isinstance(context, dict) or context.get("schema") not in (1, 2):
        raise ValueError("CVE context must be a supported schema object")
    envelope = {
        "schema": 1,
        "kind": "cve",
        "notification_mode": "notify_only",
        "source": _text(payload.get("source"), ""),
        "record_id": record_id,
        "observed_at": _text(payload.get("observed_at"), ""),
        "context": matrix_safe_json(context),
    }
    encoded = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MACHINE_CONTEXT_BYTES:
        raise ValueError("CVE machine context is too large")
    return envelope


def _bounded_values(values: list[str], limit: int = 6) -> str:
    unique = list(dict.fromkeys(value for value in values if value))
    rendered = ", ".join(unique[:limit])
    if len(unique) > limit:
        rendered += f", and {len(unique) - limit} more"
    return rendered or "unknown"


def format_cve_root(payload: dict[str, Any], record_id: str) -> str:
    """Render the alert root with enough routing data for exact investigation."""
    generic = format_generic_notification(payload)
    _, _, finding_summary = generic.partition("\n")
    context = payload.get("context")
    groups = context.get("groups", []) if isinstance(context, dict) else []
    advisory_ids: list[str] = []
    services: list[str] = []
    artifacts: list[str] = []
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        advisory_ids.append(_text(group.get("id"), ""))
        occurrences = group.get("occurrences", [])
        for occurrence in occurrences if isinstance(occurrences, list) else []:
            if not isinstance(occurrence, dict):
                continue
            containers = occurrence.get("containers", [])
            for container in containers if isinstance(containers, list) else []:
                if isinstance(container, dict):
                    services.append(_text(container.get("name"), ""))
            artifacts.append(_text(occurrence.get("artifact"), ""))

    service_values = services or artifacts
    observed_at = _text(
        payload.get("observed_at")
        or (context.get("generated_at") if isinstance(context, dict) else None)
    )
    return "\n".join(
        [
            "CVE alert",
            f"Target: {_text(payload.get('source'))}",
            f"Service: {_bounded_values(service_values)}",
            f"Observed: {observed_at}",
            f"Advisory: {_bounded_values(advisory_ids)}",
            f"Alert record: {record_id}",
            "",
            finding_summary,
        ]
    )


def format_beszel_notification(payload: dict[str, Any]) -> str:
    title = _text(payload.get("title"), "")
    message = _text(payload.get("message"), "")
    if not title or len(title) > 300:
        raise ValueError("Beszel title must contain between 1 and 300 characters")
    if not message or len(message) > MAX_GENERIC_MESSAGE_CHARS:
        raise ValueError(
            f"Beszel message must contain between 1 and "
            f"{MAX_GENERIC_MESSAGE_CHARS} characters"
        )

    status = BESZEL_STATUS_TITLE.fullmatch(title)
    if status:
        system = status.group("system").strip()
        if status.group("status").lower() == "down":
            return f"🔴 {system} down"
        return f"🟢 {system} recovered"

    metric = BESZEL_METRIC_TITLE.fullmatch(title)
    if metric:
        system = metric.group("system").strip()
        metric_name = metric.group("metric")
        direction = metric.group("direction").lower()
        is_battery = metric_name.lower() == "battery"
        triggered = direction == ("below" if is_battery else "above")
        if triggered:
            state = "low" if is_battery else "high"
            headline = f"⚠️ {system}: {metric_name} {state}"
        else:
            headline = f"🟢 {system}: {metric_name} normal"

        body = _concise_beszel_body(message, title)
        return f"{headline}\n{body}" if body else headline

    body = _concise_beszel_body(message, title)
    headline = f"Beszel: {title}"
    return f"{headline}\n{body}" if body else headline


def notification_room(kind: str) -> str:
    try:
        return NOTIFICATION_ROOMS[kind]
    except KeyError as exc:
        raise ValueError("unsupported notification kind") from exc


def _concise_beszel_body(message: str, title: str) -> str:
    lines = [
        line.strip()
        for line in message.splitlines()
        if line.strip() and not HTTP_URL.match(line.strip())
    ]
    lines = [line for line in lines if line.rstrip(" ✅🔴") != title.rstrip(" ✅🔴")]
    if not lines:
        return ""

    average = BESZEL_AVERAGE_BODY.fullmatch(lines[0])
    if average:
        metric = average.group("metric")
        value = average.group("value").rstrip("0").rstrip(".")
        unit = average.group("unit")
        minutes = average.group("minutes")
        return f"{metric}: {value}{unit} avg / {minutes}m"
    return "\n".join(lines[:2])


class MatrixClient:
    def __init__(self, base_url: str, room_id: str, access_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.room_id = room_id
        self.access_token = access_token

    def send(
        self,
        message: str,
        txn_id: str,
        context: dict[str, Any] | None = None,
        *,
        mentions: list[str] | None = None,
        thread_root: str | None = None,
        reply_to: str | None = None,
        formatted_body: str | None = None,
    ) -> str:
        room = parse.quote(self.room_id, safe="")
        transaction = parse.quote(txn_id, safe="")
        url = (
            f"{self.base_url}/_matrix/client/v3/rooms/{room}"
            f"/send/m.room.message/{transaction}"
        )
        content: dict[str, Any] = {"msgtype": "m.text", "body": message}
        if formatted_body is not None:
            content.update(format="org.matrix.custom.html", formatted_body=formatted_body)
        if mentions:
            content["m.mentions"] = {"user_ids": mentions}
        if thread_root:
            content["m.relates_to"] = {
                "rel_type": "m.thread",
                "event_id": thread_root,
                "is_falling_back": True,
                "m.in_reply_to": {"event_id": reply_to or thread_root},
            }
        if context is not None:
            content[MACHINE_CONTEXT_KEY] = context
        body = json.dumps(content, separators=(",", ":")).encode("utf-8")
        matrix_request = request.Request(
            url,
            data=body,
            method="PUT",
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "User-Agent": "crowdsec-matrix-bridge/1",
            },
        )
        try:
            with request.urlopen(matrix_request, timeout=10) as response:
                response_body = json.load(response)
        except error.HTTPError as exc:
            detail = exc.read(512).decode("utf-8", errors="replace")
            raise RuntimeError(f"Matrix returned HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Matrix request failed: {exc.reason}") from exc

        event_id = response_body.get("event_id")
        if not event_id:
            raise RuntimeError("Matrix response did not include an event_id")
        return str(event_id)


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        webhook_secret: str,
        matrix_clients: dict[str, MatrixClient],
        alert_store: AlertStore | None = None,
    ) -> None:
        super().__init__(server_address, BridgeHandler)
        self.webhook_secret = webhook_secret
        self.matrix_clients = matrix_clients
        self.alert_store = alert_store


class BridgeHandler(BaseHTTPRequestHandler):
    server: BridgeServer

    def _json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/healthz":
            self._json_response(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self._json_response(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/crowdsec":
            self._json_response(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        # The incident service validates its own source-scoped credentials. This
        # fixed local proxy does not accept a caller-selected upstream or URL.
        if self.headers.get('X-Homelab-Incident-API') == '1':
            self._incident_proxy()
            return

        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.webhook_secret}"
        if not hmac.compare_digest(supplied, expected):
            self._json_response(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self._json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "invalid content length"},
            )
            return

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body)
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            context = None
            txn_id = transaction_id(raw_body)
            if "alerts" in payload:
                alerts = payload["alerts"]
                if not isinstance(alerts, list) or not alerts:
                    raise ValueError("payload must contain a non-empty alerts list")
                if any(not isinstance(alert, dict) for alert in alerts):
                    raise ValueError("each alert must be a JSON object")
                # Prepare every message before sending; retries reuse each alert's
                # transaction ID even if an earlier attempt only partly succeeded.
                messages = [
                    (
                        format_message({**payload, "alerts": [alert]}),
                        txn_id if len(alerts) == 1 else f"{txn_id}_{index}",
                    )
                    for index, alert in enumerate(alerts)
                ]
                notification_kind = "crowdsec"
            else:
                message = format_generic_notification(payload)
                messages = [(message, txn_id)]
                notification_kind = _text(payload.get("kind"))
                context = machine_context(payload, txn_id)
                if notification_kind == "cve":
                    message = neutralize_matrix_mentions(
                        format_cve_root(payload, txn_id)
                    )
                    messages = [(message, txn_id)]
            room = notification_room(notification_kind)
            transaction_ids = [message_txn_id for _, message_txn_id in messages]
            received_at = datetime.now(UTC).isoformat()
            if self.server.alert_store is not None:
                self.server.alert_store.begin(
                    txn_id,
                    notification_kind,
                    payload,
                    room,
                    transaction_ids,
                    received_at,
                )
            try:
                for message, message_txn_id in messages:
                    event_id = self.server.matrix_clients[room].send(
                        message,
                        message_txn_id,
                        context,
                    )
                    if self.server.alert_store is not None:
                        self.server.alert_store.mark_delivery(
                            txn_id, message_txn_id, event_id
                        )
            except RuntimeError:
                if self.server.alert_store is not None:
                    self.server.alert_store.mark_failed(txn_id)
                raise
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except RuntimeError as exc:
            LOGGER.error("notification delivery failed: %s", exc)
            self._json_response(HTTPStatus.BAD_GATEWAY, {"error": "delivery failed"})
            return

        LOGGER.info("delivered %s notification as %s", notification_kind, txn_id)
        self._json_response(HTTPStatus.ACCEPTED, {"status": "delivered"})

    def _incident_proxy(self) -> None:
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 768 * 1024:
                self._json_response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {'error': 'request size limit'})
                return
            outgoing = request.Request('http://127.0.0.1:8790/v1', data=self.rfile.read(length), headers={
                'Authorization': self.headers.get('Authorization', ''), 'Content-Type': 'application/json'})
            try:
                with request.urlopen(outgoing, timeout=30) as response:
                    self._json_response(response.status, json.loads(response.read(16 * 1024 * 1024)))
            except error.HTTPError as exc:
                self._json_response(exc.code, {'error': 'incident request rejected'})
        except (ValueError, OSError, error.URLError):
            self._json_response(HTTPStatus.SERVICE_UNAVAILABLE, {'error': 'incident service unavailable'})

    def log_message(self, message_format: str, *args: Any) -> None:
        LOGGER.debug(message_format, *args)


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("listen address must be HOST:PORT")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("listen port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("listen port is outside 1-65535")
    return host, port


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=parse_listen, default=("0.0.0.0", 8789))
    parser.add_argument(
        "--matrix-url",
        default="http://127.0.0.1:6167",
        help="Matrix client API base URL",
    )
    parser.add_argument("--alert-store", type=Path)
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(levelname)s %(message)s",
    )
    access_token = read_credential("matrix-access-token")
    matrix_clients = {
        room: MatrixClient(
            args.matrix_url,
            read_credential(credential),
            access_token,
        )
        for room, credential in ROOM_CREDENTIALS.items()
    }
    server = BridgeServer(
        args.listen,
        read_credential("webhook-secret"),
        matrix_clients,
        AlertStore(args.alert_store) if args.alert_store else None,
    )
    LOGGER.info("listening on %s:%d", *args.listen)
    server.serve_forever()


if __name__ == "__main__":
    main()
