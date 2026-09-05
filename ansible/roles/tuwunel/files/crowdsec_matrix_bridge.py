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


def machine_context(payload: dict[str, Any]) -> dict[str, Any] | None:
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
        "source": _text(payload.get("source"), ""),
        "context": matrix_safe_json(context),
    }
    encoded = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MACHINE_CONTEXT_BYTES:
        raise ValueError("CVE machine context is too large")
    return envelope


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
    ) -> str:
        room = parse.quote(self.room_id, safe="")
        transaction = parse.quote(txn_id, safe="")
        url = (
            f"{self.base_url}/_matrix/client/v3/rooms/{room}"
            f"/send/m.room.message/{transaction}"
        )
        content: dict[str, Any] = {"msgtype": "m.text", "body": message}
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
    ) -> None:
        super().__init__(server_address, BridgeHandler)
        self.webhook_secret = webhook_secret
        self.matrix_clients = matrix_clients


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
                context = machine_context(payload)
            room = notification_room(notification_kind)
            for message, message_txn_id in messages:
                self.server.matrix_clients[room].send(message, message_txn_id, context)
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except RuntimeError as exc:
            LOGGER.error("notification delivery failed: %s", exc)
            self._json_response(HTTPStatus.BAD_GATEWAY, {"error": "delivery failed"})
            return

        LOGGER.info("delivered %s notification as %s", notification_kind, txn_id)
        self._json_response(HTTPStatus.ACCEPTED, {"status": "delivered"})

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
    )
    LOGGER.info("listening on %s:%d", *args.listen)
    server.serve_forever()


if __name__ == "__main__":
    main()
