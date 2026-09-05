from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class EvidenceGatewayTests(unittest.TestCase):
    def test_native_evidence_rejects_a_different_binary_than_the_scan(self):
        scope = {"bindings": [{"container_id": None, "reported_file": "/usr/bin/caddy",
                                "artifact_id": "sha256:" + "a" * 64}]}
        self.gateway.validate_host_binary(scope, "/usr/bin/caddy", "a" * 64)
        with self.assertRaisesRegex(ValueError, "changed since the scan"):
            self.gateway.validate_host_binary(scope, "/usr/bin/caddy", "b" * 64)

    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway = load_module(
            "homelab_evidence_gateway_under_test",
            ROOT
            / "ansible"
            / "roles"
            / "homelab_agent_target"
            / "files"
            / "homelab_evidence_gateway.py",
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_root = self.root / "config"
        self.config_root.mkdir()
        self.policy = self.root / "evidence-policy.json"
        self.units = self.root / "units.json"
        self.capabilities = self.root / "capabilities"
        self.policy.write_text(
            json.dumps({"config_roots": [str(self.config_root)]}), encoding="utf-8"
        )
        self.units.write_text(json.dumps({"app": "app.service"}), encoding="utf-8")
        self.patchers = [
            mock.patch.object(self.gateway, "POLICY_FILE", self.policy),
            mock.patch.object(self.gateway, "UNIT_FILE", self.units),
            mock.patch.object(self.gateway, "CAPABILITY_DIR", self.capabilities),
            mock.patch.object(self.gateway, "audit"),
            mock.patch.object(
                self.gateway,
                "docker_inventory",
                return_value={
                    "app": {
                        "id": "a" * 64,
                        "short_id": "a" * 12,
                        "name": "app",
                        "image_id": "sha256:" + "b" * 64,
                        "image_ref": "example/app:1.0",
                    }
                },
            ),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    @staticmethod
    def scope(image_id: str | None = None) -> dict:
        return {
            "schema": 2,
            "groups": [
                {
                    "id": "CVE-2026-12345",
                    "package": "example.org/module",
                    "installed": "1.0.0",
                    "fixed": "1.1.0",
                    "severity": "HIGH",
                    "occurrences": [
                        {
                            "artifact": "example/app:1.0",
                            "artifact_id": image_id or "sha256:" + "b" * 64,
                            "containers": [{"id": "a" * 64, "name": "app"}],
                            "reported_file": "/usr/local/bin/app",
                        }
                    ],
                }
            ],
        }

    def test_open_binds_running_artifact_and_creates_private_state(self) -> None:
        opened = self.gateway.open_capability(self.scope())

        capability_path = self.gateway.capability_path(opened["token"])
        state = json.loads(capability_path.read_text(encoding="utf-8"))
        self.assertEqual(os.stat(capability_path).st_mode & 0o777, 0o600)
        self.assertEqual(state["scope"]["containers"][0]["name"], "app")
        self.assertEqual(state["scope"]["advisories"], ["CVE-2026-12345"])
        self.assertEqual(state["scope"]["reported_files"], ["/usr/local/bin/app"])
        self.assertEqual(opened["protocol"], 2)
        self.assertEqual(opened["limits"]["calls"], 20)
        self.assertLessEqual(opened["limits"]["calls"], self.gateway.MAX_CALLS)

    def test_open_rejects_stale_container_image(self) -> None:
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            self.gateway.open_capability(self.scope("sha256:" + "c" * 64))

    def test_mounted_configuration_is_read_inside_the_scoped_container(self):
        config = self.config_root / "Caddyfile"
        config.write_text("host copy is not the observed content")
        scope = self.gateway.normalized_scope(self.scope())
        mount = {
            "Type": "bind",
            "Source": str(config),
            "Destination": "/etc/caddy/Caddyfile",
        }

        def run(argv, *_args, **_kwargs):
            stdout = (
                json.dumps([mount]) if "inspect" in argv else "/etc/caddy/Caddyfile\n"
            )
            return {"stdout": stdout, "returncode": 0, "truncated": False}

        def copy(container, path, destination, limit):
            self.assertEqual(container["id"], "a" * 64)
            self.assertEqual(path, mount["Destination"])
            self.assertEqual(limit, self.gateway.MAX_CONFIG_BYTES)
            destination.write_text("reverse_proxy server:8080\npassword: hidden\n")

        with (
            mock.patch.object(self.gateway, "bounded_run", side_effect=run),
            mock.patch.object(self.gateway, "copy_container_file", side_effect=copy),
        ):
            result = self.gateway.read_config(
                scope, {"container": "app", "path": mount["Destination"]}
            )
        self.assertIn("reverse_proxy server:8080", result["content"])
        self.assertNotIn("host copy", result["content"])
        self.assertNotIn("hidden", result["content"])
        self.assertIn("[REDACTED]", result["content"])

    def test_mount_mapping_never_grants_unapproved_host_paths_or_symlink_escape(self):
        scope = self.gateway.normalized_scope(self.scope())
        outside = self.root / "outside"
        outside.write_text("not approved")
        link = self.config_root / "escaped"
        link.symlink_to(outside)
        for source in (outside, link):
            mount = {
                "Type": "bind",
                "Source": str(source),
                "Destination": "/etc/caddy/Caddyfile",
            }
            with (
                mock.patch.object(
                    self.gateway,
                    "bounded_run",
                    return_value={"stdout": json.dumps([mount]), "returncode": 0},
                ),
                mock.patch.object(self.gateway, "copy_container_file") as copy,
            ):
                with self.assertRaisesRegex(ValueError, "approved roots"):
                    self.gateway.read_config(
                        scope, {"container": "app", "path": mount["Destination"]}
                    )
                copy.assert_not_called()

    def test_container_configuration_symlink_cannot_escape_authorized_mount(self):
        config = self.config_root / "Caddyfile"
        config.write_text("approved")
        scope = self.gateway.normalized_scope(self.scope())
        mount = {
            "Type": "bind",
            "Source": str(config),
            "Destination": "/etc/caddy/Caddyfile",
        }
        with (
            mock.patch.object(
                self.gateway,
                "bounded_run",
                side_effect=[
                    {"stdout": json.dumps([mount]), "returncode": 0},
                    {"stdout": "/etc/shadow\n", "returncode": 0},
                ],
            ),
            mock.patch.object(self.gateway, "copy_container_file") as copy,
        ):
            with self.assertRaisesRegex(ValueError, "symlink escapes"):
                self.gateway.read_config(
                    scope, {"container": "app", "path": mount["Destination"]}
                )
            copy.assert_not_called()

    def test_go_build_metadata_preserves_versions_and_safe_build_settings(self):
        def inline(value):
            size = len(value)
            encoded = bytearray()
            while size >= 128:
                encoded.append((size & 127) | 128)
                size >>= 7
            return bytes(encoded) + bytes([size]) + value

        module = (
            b"x" * 16
            + (
                b"path\texample/app\nmod\tgithub.com/example/app\tv1.2.3\n"
                b"dep\tgolang.org/x/net\tv0.55.0\n"
                b"build\tCGO_ENABLED=0\nbuild\t-ldflags=secret-value\n"
            )
            + b"y" * 16
        )
        blob = (
            b"\xff Go buildinf:"
            + bytes([8, 2])
            + bytes(16)
            + inline(b"go1.26.3")
            + inline(module)
        )
        build = self.gateway.parse_go_build_info(blob)
        self.assertEqual(build["go_version"], "go1.26.3")
        self.assertEqual(build["modules"][0]["version"], "v0.55.0")
        self.assertEqual(build["settings"], {"CGO_ENABLED": "0"})
        self.assertNotIn("secret-value", json.dumps(build))
        with self.assertRaises(ValueError):
            self.gateway.parse_go_build_info(blob[:-20])

    def test_source_revision_is_bound_to_observed_binary_not_model_input(self):
        scope = self.gateway.normalized_scope(self.scope())
        scope["binary_metadata"] = {
            "a" * 64 + ":/usr/local/bin/app": {
                "go_version": "go1.26.3",
                "sha256": "c" * 64,
                "main": {},
                "modules": [{"path": "golang.org/x/net", "version": "v0.55.0"}],
                "settings": {},
            }
        }
        args = {
            "container": "app",
            "executable": "/usr/local/bin/app",
            "module": "stdlib",
            "path": "net/lookup.go",
            "query": "Lookup",
        }
        with mock.patch.object(
            self.gateway,
            "public_get",
            return_value=(b"package net\nfunc Lookup() {}\n", {}),
        ) as get:
            result = self.gateway.dependency_source(scope, args)
            self.assertEqual(
                get.call_args.args[0],
                "https://raw.githubusercontent.com/golang/go/go1.26.3/src/net/lookup.go",
            )
            self.assertEqual(result["binary_sha256"], "c" * 64)
            self.assertEqual(result["lines"][1]["line"], 2)
            for module, path in (
                ("github.com/other/repo", "README.md"),
                ("stdlib", "../credentials"),
            ):
                with self.assertRaises(ValueError):
                    self.gateway.dependency_source(
                        scope, {**args, "module": module, "path": path}
                    )
            self.assertEqual(get.call_count, 1)

    def test_analyzer_keeps_affected_version_and_receiver(self):
        stream = "".join(
            json.dumps(value)
            for value in [
                {"osv": {"id": "GO-2026-1234", "aliases": ["CVE-2026-12345"]}},
                {
                    "finding": {
                        "osv": "GO-2026-1234",
                        "fixed_version": "v1.26.6",
                        "trace": [
                            {
                                "module": "stdlib",
                                "version": "v1.26.3",
                                "package": "net",
                                "receiver": "Resolver",
                                "function": "LookupCNAME",
                            }
                        ],
                    }
                },
            ]
        )
        summary = self.gateway.summarize_govulncheck(stream, "CVE-2026-12345")
        self.assertEqual(
            summary["affected_versions"],
            [{"module": "stdlib", "installed": "v1.26.3", "fixed": "v1.26.6"}],
        )
        self.assertEqual(summary["symbols"], ["net.Resolver.LookupCNAME"])

    def test_source_uses_submodule_tags_and_observed_pseudoversion_commits(self):
        scope = self.gateway.normalized_scope(self.scope())
        module = {"path": "github.com/example/app/sub/v2", "version": "v2.1.0"}
        scope["binary_metadata"] = {
            "a" * 64 + ":/usr/local/bin/app": {
                "go_version": "go1.26.3",
                "sha256": "c" * 64,
                "main": {},
                "modules": [module],
                "settings": {},
            }
        }
        args = {
            "container": "app",
            "executable": "/usr/local/bin/app",
            "module": module["path"],
            "path": "handler.go",
        }
        with mock.patch.object(
            self.gateway, "public_get", return_value=(b"package sub\n", {})
        ) as get:
            self.gateway.dependency_source(scope, args)
            self.assertEqual(
                get.call_args.args[0],
                "https://raw.githubusercontent.com/example/app/sub/v2.1.0/sub/handler.go",
            )
            module["version"] = "v2.1.1-0.20260801000000-012345abcdef"
            self.gateway.dependency_source(scope, args)
            self.assertEqual(
                get.call_args.args[0],
                "https://raw.githubusercontent.com/example/app/012345abcdef/sub/handler.go",
            )

    def test_startup_metadata_does_not_disclose_other_arguments(self):
        response = {
            "returncode": 0,
            "stdout": json.dumps("caddy")
            + "\t"
            + json.dumps(
                [
                    "run",
                    "--config",
                    "/etc/caddy/Caddyfile",
                    "--password",
                    "do-not-return",
                ]
            ),
        }
        with mock.patch.object(self.gateway, "bounded_run", return_value=response):
            value = self.gateway.startup_configuration({"id": "a" * 64})
        self.assertEqual(value["configuration_paths"], ["/etc/caddy/Caddyfile"])
        self.assertNotIn("do-not-return", json.dumps(value))

    def test_invoke_enforces_scope_and_accounts_output(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        with mock.patch.object(
            self.gateway,
            "invoke_operation",
            return_value={"listeners": ["127.0.0.1:8080"]},
        ) as invoked:
            result = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {"container": "app"}
            )

        self.assertEqual(result["operation"], "list_listeners")
        invoked.assert_called_once()
        state = json.loads(
            self.gateway.capability_path(opened["token"]).read_text(encoding="utf-8")
        )
        self.assertEqual(state["calls"], 1)
        self.assertGreater(state["bytes"], 0)

    def test_failed_invoke_is_audited_with_operation(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        self.gateway.audit.reset_mock()
        with mock.patch.object(
            self.gateway, "invoke_operation", side_effect=ValueError("outside scope")
        ):
            receipt = self.gateway.invoke_capability(
                opened["token"], "package_info", {}
            )["result"]
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("outside scope", receipt["limitations"][0])

        event = self.gateway.audit.call_args.args[0]
        self.assertEqual(event["action"], "invoke")
        self.assertEqual(event["operation"], "package_info")
        self.assertEqual(event["status"], "failed")

    def test_credential_like_configuration_path_is_never_readable(self) -> None:
        scope = self.gateway.normalized_scope(self.scope())
        with self.assertRaisesRegex(ValueError, "never readable"):
            self.gateway.read_config(
                scope, {"path": str(self.config_root / "service-token.yml")}
            )

    def test_nested_secret_values_are_removed_from_allowed_configuration(self) -> None:
        config = self.config_root / "service.yml"
        config.write_text(
            "public: retained\ntokens:\n  - must-not-leak\nnext: retained\n",
            encoding="utf-8",
        )
        scope = self.gateway.normalized_scope(self.scope())

        result = self.gateway.read_config(scope, {"path": str(config)})

        self.assertIn("public: retained", result["content"])
        self.assertIn("tokens:[REDACTED]", result["content"])
        self.assertIn("next: retained", result["content"])
        self.assertNotIn("must-not-leak", result["content"])

    def test_expired_capability_cannot_be_invoked(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        capability_path = self.gateway.capability_path(opened["token"])
        state = json.loads(capability_path.read_text(encoding="utf-8"))
        state["expires"] = 0
        capability_path.write_text(json.dumps(state), encoding="utf-8")

        result = self.gateway.invoke_capability(opened["token"], "list_processes", {})[
            "result"
        ]
        self.assertEqual(result["status"], "failed")
        self.assertIn("expired", result["limitations"][0].lower())

    def test_close_revokes_capability(self) -> None:
        opened = self.gateway.open_capability(self.scope())
        capability_path = self.gateway.capability_path(opened["token"])

        self.gateway.close_capability(opened["token"])

        self.assertFalse(capability_path.exists())

    def test_govulncheck_reduces_output_to_scoped_advisory(self) -> None:
        stream = "".join(
            json.dumps(message)
            for message in [
                {
                    "osv": {
                        "id": "GO-2026-9999",
                        "aliases": ["CVE-2026-12345"],
                        "summary": "Affected server callback.",
                    }
                },
                {
                    "finding": {
                        "osv": "GO-2026-9999",
                        "trace": [
                            {
                                "module": "example.org/module",
                                "package": "example.org/module/server",
                                "function": "Serve",
                            }
                        ],
                    }
                },
                {"osv": {"id": "GO-2026-OTHER", "summary": "unrelated"}},
            ]
        )

        result = self.gateway.summarize_govulncheck(stream, "CVE-2026-12345")

        self.assertEqual(result["status"], "symbol_present")
        self.assertEqual(
            result["interpretation"],
            "The affected symbol was found in the executable.",
        )
        self.assertEqual(result["advisories"][0]["id"], "GO-2026-9999")
        self.assertEqual(result["symbols"], ["example.org/module/server.Serve"])
        self.assertNotIn("GO-2026-OTHER", json.dumps(result))

    def test_artifact_aliases_do_not_expand_beyond_scoped_repository(self) -> None:
        aliases = self.gateway.artifact_aliases(
            "docker.io/example/app:1.0@sha256:" + "b" * 64
        )

        self.assertIn("example/app", aliases)
        self.assertIn("example/app:1.0", aliases)
        self.assertNotIn("example/other", aliases)

    def test_container_listeners_are_read_from_its_network_namespace(self) -> None:
        scope = self.gateway.normalized_scope(self.scope())
        with (
            mock.patch.object(self.gateway, "process_ids", return_value=[1234]),
            mock.patch.object(
                self.gateway,
                "bounded_run",
                return_value={
                    "returncode": 0,
                    "stdout": "tcp LISTEN 0 10 *:8080\n",
                    "stderr": "",
                },
            ) as run,
        ):
            result = self.gateway.invoke_operation(
                scope, "list_listeners", {"container": "app"}
            )

        self.assertEqual(result["listeners"], ["tcp LISTEN 0 10 *:8080"])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/nsenter", "--target", "1234", "--net"])

    def test_failed_attempts_are_charged_and_budget_denial_is_a_receipt(self):
        opened = self.gateway.open_capability(self.scope())
        path = self.gateway.capability_path(opened["token"])
        state = json.loads(path.read_text())
        state["limits"]["calls"] = 1
        path.write_text(json.dumps(state))
        with mock.patch.object(
            self.gateway, "invoke_operation", side_effect=RuntimeError("check failed")
        ):
            first = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {}
            )["result"]
            second = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {}
            )["result"]
        self.assertEqual(first["status"], "failed")
        self.assertIn("budget", second["limitations"][0])
        self.assertEqual(json.loads(path.read_text())["calls"], 1)

    def test_lock_allows_two_reads_and_revocation_discards_inflight_result(self):
        import threading

        opened = self.gateway.open_capability(self.scope())
        entered = threading.Barrier(3)
        release = threading.Event()
        results = []

        def invoke(*args):
            entered.wait(timeout=3)
            release.wait(timeout=3)
            return {"listeners": []}

        def worker():
            results.append(
                self.gateway.invoke_capability(opened["token"], "list_listeners", {})[
                    "result"
                ]
            )

        with mock.patch.object(self.gateway, "invoke_operation", side_effect=invoke):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            try:
                entered.wait(timeout=3)
                self.gateway.close_capability(opened["token"])
            finally:
                release.set()
                for thread in threads:
                    thread.join(timeout=3)
        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(r["status"] == "failed" and not r["result"] for r in results)
        )

    def test_stale_runtime_never_produces_successful_empty_result(self):
        opened = self.gateway.open_capability(self.scope())
        with mock.patch.object(self.gateway, "docker_inventory", return_value={}):
            result = self.gateway.invoke_capability(
                opened["token"], "list_listeners", {"container": "app"}
            )["result"]
        self.assertEqual(result["status"], "failed")
        self.assertIn("changed", result["limitations"][0])

    def test_failed_listener_command_is_not_negative_evidence(self):
        with mock.patch.object(
            self.gateway,
            "bounded_run",
            return_value={
                "returncode": 1,
                "stdout": "",
                "stderr": "denied",
                "truncated": False,
            },
        ):
            with self.assertRaises(RuntimeError):
                self.gateway.invoke_operation({"containers": []}, "list_listeners", {})

    def test_discovered_executable_is_bound_to_its_container(self):
        scope = self.gateway.normalized_scope(self.scope())
        scope["discovered_files"] = {"a" * 64: ["/usr/bin/discovered"]}
        container = scope["containers"][0]
        self.assertEqual(
            self.gateway.allowed_reported_file(scope, "/usr/bin/discovered", container),
            "/usr/bin/discovered",
        )
        with self.assertRaises(ValueError):
            self.gateway.allowed_reported_file(scope, "/usr/bin/discovered", None)

    def test_nested_failure_and_truncation_are_visible(self):
        self.assertTrue(self.gateway.result_incomplete({"state": {"returncode": 1}}))
        self.assertTrue(self.gateway.result_incomplete({"maps": {"truncated": True}}))
        self.assertFalse(self.gateway.result_incomplete({"listeners": []}))

    def test_analyzer_reports_unavailable_for_inconclusive_binary(self):
        scope = self.gateway.normalized_scope(self.scope())

        def copy_file(container, path, destination):
            destination.write_bytes(b"ELF fixture")

        with (
            mock.patch.object(
                self.gateway, "copy_container_file", side_effect=copy_file
            ),
            mock.patch.object(self.gateway.Path, "exists", return_value=True),
            mock.patch.object(
                self.gateway,
                "limited_output_run",
                return_value={
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "build info unavailable",
                    "overflow": False,
                    "timed_out": False,
                },
            ),
        ):
            result = self.gateway.run_analyzer(
                scope,
                {
                    "analyzer": "govulncheck",
                    "container": "app",
                    "path": "/usr/local/bin/app",
                    "advisory": "CVE-2026-12345",
                },
            )
        self.assertEqual(result["status"], "unavailable")

    def test_binary_analysis_is_reused_only_after_hashing_current_file(self):
        scope = self.gateway.normalized_scope(self.scope())
        content = [b"same executable"]

        def copy_file(container, path, destination):
            destination.write_bytes(content[0])

        stream = json.dumps({"config": {"scanMode": "binary"}})
        with (
            mock.patch.object(
                self.gateway, "copy_container_file", side_effect=copy_file
            ),
            mock.patch.object(self.gateway.Path, "exists", return_value=True),
            mock.patch.object(
                self.gateway,
                "limited_output_run",
                return_value={
                    "returncode": 0,
                    "stdout": stream,
                    "stderr": "",
                    "overflow": False,
                    "timed_out": False,
                },
            ) as analyzer,
        ):
            args = {
                "analyzer": "govulncheck",
                "container": "app",
                "path": "/usr/local/bin/app",
                "advisory": "CVE-2026-12345",
            }
            self.gateway.run_analyzer(scope, args)
            reused = self.gateway.run_analyzer(scope, args)
            self.assertTrue(reused["reused_analysis"])
            self.assertEqual(
                sum(
                    call.args[0][0] == "/usr/local/bin/govulncheck"
                    for call in analyzer.call_args_list
                ),
                1,
            )
            content[0] = b"changed executable"
            self.gateway.run_analyzer(scope, args)
            self.assertEqual(
                sum(
                    call.args[0][0] == "/usr/local/bin/govulncheck"
                    for call in analyzer.call_args_list
                ),
                2,
            )

    def test_empty_analyzer_output_cannot_establish_absence(self):
        with self.assertRaises(ValueError):
            self.gateway.summarize_govulncheck("", "CVE-2026-12345")

    def test_small_read_budget_cannot_overbook_concurrent_reservations(self):
        import threading

        opened = self.gateway.open_capability(self.scope())
        path = self.gateway.capability_path(opened["token"])
        state = json.loads(path.read_text())
        state["limits"]["total_bytes"] = self.gateway.MAX_RESULT_BYTES
        path.write_text(json.dumps(state))
        entered, release = threading.Event(), threading.Event()

        def invoke(*args):
            entered.set()
            release.wait(timeout=3)
            return {"listeners": []}

        with mock.patch.object(self.gateway, "invoke_operation", side_effect=invoke):
            thread = threading.Thread(
                target=lambda: self.gateway.invoke_capability(
                    opened["token"], "list_listeners", {}
                )
            )
            thread.start()
            try:
                self.assertTrue(entered.wait(timeout=3))
                second = self.gateway.invoke_capability(
                    opened["token"], "list_listeners", {}
                )["result"]
                self.assertEqual(second["status"], "failed")
                self.assertIn("budget", second["limitations"][0])
            finally:
                release.set()
                thread.join(timeout=3)
        self.assertEqual(json.loads(path.read_text())["pending"], {})


if __name__ == "__main__":
    unittest.main()
