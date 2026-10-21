"""Exercise the rendered Jellyfin route with a local Caddy and a stub upstream."""

import http.client
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]
CADDY = shutil.which("caddy")


class Upstream(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(CADDY, "install Caddy to exercise its real HTTP path matcher")
class JellyfinLoginBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="caddy-jellyfin-test-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        cls.backend = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.addClassCleanup(cls.backend.server_close)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.backend.shutdown)

        routing = yaml.safe_load((ROOT / "inventory/routes.yml").read_text())["homelab_routing"]
        jellyfin = next(route for route in routing["routes"] if route["id"] == "jellyfin")
        cls.hostname = jellyfin["hostname"]
        defaults = yaml.safe_load((ROOT / "ansible/roles/caddy/defaults/main.yml").read_text())
        defaults["caddy_access_log_path"] = str(directory / "access.log")
        defaults["caddy_routes"] = [{
            **jellyfin["caddy"],
            "hostname": cls.hostname,
            "upstream": f"127.0.0.1:{cls.backend.server_port}",
        }]
        template = (ROOT / "ansible/roles/caddy/templates/Caddyfile.j2").read_text()
        # The standard Caddy binary has no Cloudflare module. Omit only the
        # certificate issuer; all production host/path/handler rules stay intact.
        template = template.replace(
            "    tls {\n        dns cloudflare {env.CF_API_TOKEN}\n"
            "        resolvers 1.1.1.1\n    }\n", ""
        )
        environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
        environment.filters["to_json"] = json.dumps
        rendered = environment.from_string(template).render(**defaults)
        caddyfile = directory / "Caddyfile"
        caddyfile.write_text(rendered)
        adapted = subprocess.run(
            [CADDY, "adapt", "--config", str(caddyfile), "--adapter", "caddyfile"],
            check=True, capture_output=True, text=True,
        )
        config = json.loads(adapted.stdout)
        server = next(
            server for server in config["apps"]["http"]["servers"].values()
            if ":443" in server["listen"]
        )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            cls.port = reservation.getsockname()[1]
        server["listen"] = [f"127.0.0.1:{cls.port}"]
        server.pop("tls_connection_policies", None)
        server["automatic_https"] = {"disable": True}
        config["apps"] = {"http": {"servers": {"test": server}}}
        config["admin"] = {"disabled": True, "config": {"persist": False}}
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(config))
        cls.log = (directory / "caddy.log").open("w+")
        cls.addClassCleanup(cls.log.close)
        cls.process = subprocess.Popen(
            [CADDY, "run", "--config", str(config_path)],
            stdout=cls.log, stderr=subprocess.STDOUT,
        )
        cls.addClassCleanup(cls.stop_caddy)
        for _ in range(100):
            if cls.process.poll() is not None:
                cls.log.seek(0)
                raise AssertionError(f"Caddy exited during startup: {cls.log.read()}")
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("Caddy did not start its loopback listener")

    @classmethod
    def stop_caddy(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait(timeout=5)

    def status(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request("POST", path, body=b"{}", headers={
                "Host": self.hostname,
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_password_login_aliases_never_reach_the_upstream(self):
        for path in (
            "/Users/authenticatebyname",
            "/Users/authenticatebyname/",
            "/users/AUTHENTICATEBYNAME/",
            "/%55sers/authenticatebyname/",
            "/Users/%61uthenticatebyname/",
            "/Users/authenticatebyname%2f",
            "/Users%2Fauthenticatebyname%2F",
            "//Users//authenticatebyname//",
            "/Users/./authenticatebyname/",
            "/web/../Users/authenticatebyname/",
            "/Users/authenticatebyname/?returnUrl=%2Fweb",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.status(path), 403)

    def test_other_jellyfin_paths_still_reach_the_upstream(self):
        for path in (
            "/health",
            "/sso/OID/start/PocketID",
            "/Videos/example/stream",
            "/Users/example/Items",
            "/Users/authenticatebyname-other",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.status(path), 204)


if __name__ == "__main__":
    unittest.main()
