"""Replay operator outcomes and evidence contracts without network access or model calls."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible/roles/homelab_agent_service/files"))
from homelab_investigation import (
    normalize_scope,
    validate_investigation,
    receipt_matches,
    RecordStore,
)
from homelab_cve_alert import (
    render_alert,
    evidence_pages,
)
from test_homelab_agent import load_module


def fixture(name="complete"):
    return json.loads((ROOT / "scripts/fixtures/cve" / (name + ".json")).read_text())


class InvestigationTests(unittest.TestCase):
    def test_native_alert_names_the_executable_and_preserves_coverage_limits(self):
        evidence = {"schema": 2, "groups": [{"id": "CVE-2026-46600", "package": "stdlib", "fixed": "",
                    "occurrences": [{"artifact": "host executable /usr/bin/caddy", "reported_file": "/usr/bin/caddy",
                                     "containers": [], "artifact_id": "sha256:" + "a" * 64}]}],
                    "coverage": {"scope": "this host only", "native_go_paths": ["/usr/bin/caddy"]}}
        scope = normalize_scope(json.dumps({"evidence": evidence}), "caddy")
        self.assertEqual(scope["deployed_paths"][0]["display_label"], "caddy")
        self.assertEqual(scope["coverage"]["scope"], "this host only")
        self.assertEqual(scope["groups"][0]["fixed"], "")

    def test_mechanism_accepts_bound_source_with_official_advisory(self):
        data = fixture()
        record = data["record"]
        source = json.loads(json.dumps(data["receipts"][1]))
        source.update(observation_id="versioned-source", operation="dependency_source")
        source["arguments"] = {"module": "stdlib", "path": "net/lookup.go"}
        data["receipts"].append(source)
        group = record["investigation"]["groups"][0]
        group["mechanism_refs"].append("versioned-source")
        validate_investigation(
            record["investigation"], record["scope"], data["receipts"]
        )
        group["mechanism_refs"] = ["versioned-source"]
        with self.assertRaisesRegex(ValueError, "official advisory"):
            validate_investigation(
                record["investigation"], record["scope"], data["receipts"]
            )
        group["mechanism_refs"].insert(0, data["receipts"][0]["observation_id"])
        source["identity"]["container_id"] = "other-container"
        with self.assertRaisesRegex(ValueError, "Invalid mechanism reference"):
            validate_investigation(
                record["investigation"], record["scope"], data["receipts"]
            )

    def test_release_evidence_matches_repository_without_runtime_identity(self):
        path = fixture()["record"]["scope"]["deployed_paths"][0]
        path["exact_artifact"] = "docker.io/library/caddy@sha256:" + "a" * 64
        receipt = {
            "operation": "upstream_releases",
            "identity": {},
            "arguments": {"artifact": "caddy"},
        }
        self.assertTrue(receipt_matches(receipt, path, "CVE-2099-1000"))
        receipt["arguments"]["artifact"] = "docker.io/library/caddy:2"
        self.assertTrue(receipt_matches(receipt, path, "CVE-2099-1000"))
        for artifact in ("ghcr.io/library/caddy", "docker.io/library/postgres"):
            receipt["arguments"]["artifact"] = artifact
            self.assertFalse(receipt_matches(receipt, path, "CVE-2099-1000"))

    def test_replay_expected_operator_alerts(self):
        for name in ("complete", "mixed", "incomplete", "partial_input"):
            with self.subTest(name=name):
                data = fixture(name)
                record = data["record"]
                validate_investigation(
                    record["investigation"], record["scope"], data["receipts"]
                )
                pages = render_alert(record)
                self.assertEqual(
                    "\n\n---\n\n".join(pages) + "\n",
                    (ROOT / "scripts/fixtures/cve" / (name + ".txt")).read_text(),
                )
                self.assertTrue(all(len(p.split()) <= 160 for p in pages))
                self.assertTrue(all("…" not in p for p in pages))

    def test_shared_images_keep_separate_runtime_paths_and_mixed_decisions(self):
        data = fixture("mixed")
        record = data["record"]
        paths = record["scope"]["deployed_paths"]
        self.assertEqual(len({p["artifact_id"] for p in paths}), 1)
        self.assertEqual(len({p["path_id"] for p in paths}), 8)
        text = "\n".join(render_alert(record))
        self.assertIn("CVE-2099-1001 | example / service-8 — urgent remediation", text)
        self.assertIn("CVE-2099-1000 | example / 8 components — routine update", text)
        self.assertEqual(len(render_alert(record)), 1)
        self.assertTrue(
            text.startswith("CVE-2099-1001 | example / service-8 — urgent remediation")
        )

    def test_unknown_stale_cross_path_and_failed_evidence_rejected(self):
        for mutation in ("unknown", "cross_path", "failed", "incomplete", "stale"):
            data = fixture("mixed")
            record = data["record"]
            path = record["investigation"]["groups"][0]["paths"][0]
            if mutation == "unknown":
                path["preconditions"][0]["refs"] = ["fabricated"]
            elif mutation == "cross_path":
                path["preconditions"][0]["refs"] = ["runtime-0-1"]
            elif mutation == "failed":
                data["receipts"][1]["status"] = "failed"
            elif mutation == "incomplete":
                data["receipts"][1]["truncated"] = True
            else:
                data["receipts"][1]["identity"]["artifact_id"] = "sha256:" + "b" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_investigation(
                    record["investigation"], record["scope"], data["receipts"]
                )

    def test_missing_paths_groups_and_attempts_are_rejected(self):
        for missing in ("group", "path", "attempt"):
            data = fixture("mixed")
            record = data["record"]
            if missing == "group":
                record["investigation"]["groups"].pop()
            elif missing == "path":
                record["investigation"]["groups"][0]["paths"].pop()
            else:
                data["receipts"] = [
                    r for r in data["receipts"] if r["operation"] == "official_advisory"
                ]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                validate_investigation(
                    record["investigation"], record["scope"], data["receipts"]
                )

    def test_tag_lookup_cannot_verify_a_patch(self):
        data = fixture()
        record = data["record"]
        path = record["investigation"]["groups"][0]["paths"][0]
        path["patched_artifact"] = "available"
        path["patch_refs"] = ["runtime-0-0"]
        with self.assertRaisesRegex(ValueError, "candidate verification"):
            validate_investigation(
                record["investigation"], record["scope"], data["receipts"]
            )

    def test_alert_keeps_decision_qualification_while_details_retain_diagnostics(self):
        data = fixture()
        record = data["record"]
        path = record["investigation"]["groups"][0]["paths"][0]
        path["rationale"] = (
            "The affected handler is disabled now; whether a restart preserves that setting remains unverified."
        )
        diagnostic = "Configuration discovery attempted an inaccessible path. " * 12
        path["limitations"] = [{"text": diagnostic, "refs": []}]
        pages = render_alert(record)
        self.assertEqual(len(pages), 1)
        self.assertLess(len(pages[0].split()), 90)
        self.assertIn("restart", pages[0])
        self.assertNotIn(diagnostic, pages[0])
        self.assertIn(
            diagnostic.strip(), "\n".join(evidence_pages(record, data["receipts"]))
        )

    def test_operator_rationale_cannot_be_a_long_diagnostic_dump(self):
        data = fixture()
        data["record"]["investigation"]["groups"][0]["paths"][0]["rationale"] = (
            "diagnostic " * 46
        )
        with self.assertRaisesRegex(ValueError, "45 words"):
            validate_investigation(
                data["record"]["investigation"],
                data["record"]["scope"],
                data["receipts"],
            )

    def test_detail_view_has_facts_without_raw_tool_output(self):
        data = fixture()
        data["receipts"][1]["result"]["secret"] = "must-not-appear"
        text = "\n".join(evidence_pages(data["record"], data["receipts"]))
        self.assertIn("running service configuration", text)
        self.assertNotIn("must-not-appear", text)

    def test_detail_pagination_also_respects_transport_characters(self):
        from homelab_cve_alert import paginate

        items = [str(i) + "x" * 1000 + "." for i in range(20)]
        pages = paginate("Evidence", items, words=1200)
        self.assertGreater(len(pages), 1)
        self.assertTrue(all(len(page) < 12000 for page in pages))
        for item in items:
            self.assertIn(item, "\n".join(pages))

    def test_one_occurrence_two_containers_preserves_occurrence_count(self):
        raw = fixture()["record"]["scope"]
        g = raw["groups"][0]
        g["occurrences"][0]["containers"].append({"id": "f" * 64, "name": "another"})
        scope = normalize_scope(json.dumps({"evidence": raw}), "example")
        self.assertEqual(scope["occurrence_count"], 1)
        self.assertEqual(len(scope["deployed_paths"]), 2)

    def test_private_atomic_storage_and_retention_preserve_active(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RecordStore(Path(directory), retention_days=1)
            active = store.create("example", "$event")
            self.assertEqual(store.load(active["record_id"]), active)
            self.assertEqual(
                os.stat(store.directory(active["record_id"]) / "record.json").st_mode
                & 0o777,
                0o600,
            )
            old = store.create("example", "$old")
            old.update(status="failed", started_at=time.time() - 172800)
            store.save(old)
            store.prune()
            self.assertFalse(store.directory(old["record_id"]).exists())
            self.assertTrue(store.directory(active["record_id"]).exists())
            with self.assertRaises(ValueError):
                store.load("../../etc/passwd")


class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stub = types.ModuleType("openai_codex")
        stub.ApprovalMode = types.SimpleNamespace(deny_all="deny-all")
        stub.Sandbox = types.SimpleNamespace(read_only="read-only")
        stub.Codex = object
        with mock.patch.dict(sys.modules, {"openai_codex": stub}):
            cls.agent = load_module(
                "cve_controller_test",
                ROOT / "ansible/roles/homelab_agent_service/files/homelab_agent.py",
            )

    def subject(self):
        subject = self.agent.HomelabAgent.__new__(self.agent.HomelabAgent)
        subject.model = "test-model"
        return subject

    def test_operator_alert_renders_without_another_model_call(self):
        record = fixture()["record"]
        with mock.patch.object(
            self.agent,
            "bounded_codex",
            side_effect=AssertionError("No drafting model needed"),
        ):
            pages = self.subject().draft_cve(record)
        self.assertEqual(record["metrics"]["renderer_version"], 2)
        self.assertIn("routine update", pages[0])

    def test_pipeline_persists_before_drafting_and_closes_capability(self):
        data = fixture()
        subject = self.subject()
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            store = RecordStore(Path(directory))
            subject.record_store = lambda: store
            subject.finding_scope = lambda job: data["record"]["scope"]
            subject.open_evidence_capability = lambda job: {
                "token": "sensitive",
                "protocol": 2,
            }
            subject.investigate_cve = lambda *args: data["record"]["investigation"]
            subject.close_evidence_capability = lambda target, token: calls.append(
                "closed"
            )

            def draft(record):
                self.assertEqual(
                    store.load(record["record_id"])["investigation"],
                    record["investigation"],
                )
                self.assertEqual(calls, ["closed"])
                return render_alert(record)

            subject.draft_cve = draft
            subject.send = lambda message, seed: calls.append(message)
            job = self.agent.Job(
                "cve-triage", "example", None, "$test", "@bot", "scanner"
            )
            subject.process_job(job)
            record = store.load(next(store.root.iterdir()).name)
            self.assertNotIn("sensitive", json.dumps(record))
            self.assertEqual(record["status"], "complete")
            self.assertIn("routine update", calls[-1])

    def test_failed_investigation_retains_partial_record(self):
        subject = self.subject()
        with tempfile.TemporaryDirectory() as directory:
            store = RecordStore(Path(directory))
            subject.record_store = lambda: store
            subject.finding_scope = lambda job: fixture()["record"]["scope"]
            subject.open_evidence_capability = lambda job: {"token": "sensitive"}
            subject.investigate_cve = mock.Mock(side_effect=RuntimeError("unavailable"))
            subject.close_evidence_capability = mock.Mock()
            subject.send = mock.Mock()
            subject.process_cve(
                self.agent.Job(
                    "cve-triage", "example", None, "$test", "@bot", "scanner"
                )
            )
            record = store.load(next(store.root.iterdir()).name)
            self.assertEqual(record["status"], "failed")
            subject.close_evidence_capability.assert_called_once()
            self.assertIn("assessment incomplete", subject.send.call_args.args[0])

    def test_investigation_consumes_receipts_and_repairs_invalid_references(self):
        data = fixture()
        subject = self.subject()
        with tempfile.TemporaryDirectory() as directory:
            store = RecordStore(Path(directory))
            record = store.create("example", "$event")
            record["scope"] = data["record"]["scope"]
            store.save(record)
            for index, receipt in enumerate(data["receipts"]):
                (
                    store.directory(record["record_id"]) / "receipts" / f"{index}.json"
                ).write_text(json.dumps(receipt))
            invalid = json.loads(json.dumps(data["record"]["investigation"]))
            invalid["groups"][0]["paths"][0]["preconditions"][0]["refs"] = ["invented"]
            fake_thread = mock.Mock()
            fake_thread.run.side_effect = [
                types.SimpleNamespace(error=None, final_response=json.dumps(value))
                for value in (invalid, data["record"]["investigation"])
            ]
            codex = mock.Mock()
            codex.thread_start.return_value = fake_thread
            capability = {
                "token": "sensitive",
                "expires_at": time.time() + 900,
                "protocol": 2,
            }
            job = self.agent.Job(
                "cve-triage", "example", None, "$event", "@bot", "scanner"
            )
            with (
                mock.patch.object(self.agent, "bounded_codex") as context,
                mock.patch.object(
                    self.agent,
                    "AGENT_CONTEXT_PATH",
                    ROOT / "ansible/roles/homelab_agent_service/files/CONTEXT.md",
                ),
            ):
                context.return_value.__enter__.return_value = codex
                result = subject.investigate_cve(job, capability, record, store)
            self.assertEqual(result, data["record"]["investigation"])
            rejected = store.load(record["record_id"])["validation_attempts"][0]
            self.assertEqual(rejected["candidate"], invalid)
            self.assertIn("invented", rejected["error"])
            self.assertEqual(fake_thread.run.call_count, 2)
            self.assertEqual(fake_thread.run.call_args.kwargs["effort"], "high")
            self.assertNotIn("sensitive", fake_thread.run.call_args_list[0].args[0])
            config = codex.thread_start.call_args.kwargs["config"]
            self.assertFalse(config["features"]["shell_tool"])
            self.assertEqual(config["web_search"], "disabled")
            self.assertEqual(
                config["mcp_servers"]["evidence"]["env"]["HOMELAB_EVIDENCE_TOKEN"],
                "sensitive",
            )

    def test_existing_mcp_servers_are_disabled_for_investigation(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "config.toml").write_text(
                '[mcp_servers.inherited]\ncommand="some-command"\n'
            )
            with mock.patch.dict(os.environ, {"CODEX_HOME": directory}):
                config = self.agent.evidence_config()
            self.assertEqual(config["mcp_servers"]["inherited"], {"enabled": False})

    def test_matrix_transport_rejects_oversize_without_truncation(self):
        client = self.agent.MatrixClient("https://example", "secret")
        client.api = mock.Mock()
        with self.assertRaises(ValueError):
            client.send("room", "x" * 12001, "seed")
        client.api.assert_not_called()

    def test_evidence_command_is_owner_only(self):
        subject = self.subject()
        subject.owner = "@owner"
        subject.send = mock.Mock()
        subject.record_store = mock.Mock()
        event = {
            "sender": "@other",
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "!evidence 0123456789abcdef"},
        }
        subject.handle_agent_event(event)
        subject.record_store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
