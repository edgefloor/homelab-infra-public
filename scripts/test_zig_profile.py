import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "ansible/roles/vulnerability_incidents/files"))
zig = importlib.import_module("zig_incidents")


class ZigProfileTests(unittest.TestCase):
    def current(self, **changes):
        return dict(platform="matrix", user_id=zig.OWNER, chat_id=zig.ROOM,
                    chat_type="group", thread_id="$root",
                    message_id="$request") | changes

    def test_read_question_uses_native_thread_context(self):
        with mock.patch.object(zig, "session", return_value=self.current()), \
                mock.patch.object(zig, "client") as get:
            get.return_value.call.side_effect = [
                {"kind": "incident"}, {"incidents": [{"id": "vuln_one"}]}]
            result = json.loads(zig.query({}))["data"]
            self.assertEqual("vuln_one", result["incidents"][0]["id"])
            self.assertEqual(get.return_value.call.call_args_list, [
                mock.call("conversation_context", root="$root"),
                mock.call("query", identifiers=[], search="", root="$root")])

    def test_scope_and_relationship_reads_preserve_continuation(self):
        with mock.patch.object(zig, "client") as get:
            get.return_value.call.return_value = {
                "occurrences": [], "continuation": "next", "complete": False}
            scope = json.loads(zig.work_scope({
                "work": "work-1", "kind": "remediation", "limit": 10,
                "continuation": "prior"}))["data"]
            self.assertEqual("next", scope["continuation"])
            get.return_value.call.assert_called_with(
                "remediation_scope", work="work-1", limit=10,
                continuation="prior")
            zig.relationships({
                "resource_key": "deployment:one", "relationship": "RUNS_ON",
                "continuation": "edge-page"})
            get.return_value.call.assert_called_with(
                "relationships", resource_key="deployment:one", limit=100,
                relationship="RUNS_ON", continuation="edge-page")

    def test_manual_turn_can_record_outcomes_and_proposals(self):
        with mock.patch.object(zig, "session", return_value=self.current()), \
                mock.patch.object(zig, "client") as get:
            get.return_value.call.return_value = {"status": "saved"}
            result = json.loads(zig.record_outcome({
                "work": "work-1", "occurrence": "occ-1", "outcome": "blocked",
                "detail": "compatible update unavailable"}))["data"]
            self.assertEqual("saved", result["status"])
            get.return_value.call.assert_called_with(
                "record_outcome", work="work-1", occurrence="occ-1",
                outcome="blocked", detail="compatible update unavailable")
            zig.propose_change({
                "work": "work-1", "repository": "homelab", "branch": "fix/cve",
                "changes": [{"path": "apps/a.yml"}],
                "validation": [{"status": "passed"}], "blockers": [],
                "occurrences": ["occ-1"]})
            get.return_value.call.assert_called_with(
                "propose_change", work="work-1", repository="homelab",
                branch="fix/cve", changes=[{"path": "apps/a.yml"}],
                validation=[{"status": "passed"}], blockers=[],
                occurrences=["occ-1"])

    def test_pr_tool_creates_the_pr_before_recording_derived_metadata(self):
        broker_result = {
            "status": "proposed", "workspace": "repo_" + "1" * 32,
            "repository": "homelab", "branch": "fix/cve", "pr": "https://example.invalid/pr/7",
            "changes": [" M apps/a.yml"],
            "validation": [{"command": ["python3", "test.py"], "status": "passed"}],
        }
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(broker_result), stderr="")
        with mock.patch.object(zig, "session", return_value=self.current()), \
                mock.patch.object(zig.subprocess, "run", return_value=completed), \
                mock.patch.object(zig, "client") as get:
            get.return_value.call.return_value = {"status": "saved", "proposal": "proposal-7"}
            result = json.loads(zig.create_pr({
                "work": "work-1", "workspace": broker_result["workspace"],
                "title": "Fix CVE", "body": "Covers every occurrence",
                "blockers": [], "occurrences": ["occ-1"]}))["data"]
        self.assertEqual("https://example.invalid/pr/7", result["pr"])
        get.return_value.call.assert_called_once_with(
            "propose_change", work="work-1", repository="homelab",
            branch="fix/cve", changes=[{"status": " M", "path": "apps/a.yml"}],
            validation=broker_result["validation"], blockers=[],
            occurrences=["occ-1"], pr="https://example.invalid/pr/7")

    def test_non_operator_context_cannot_mutate(self):
        for changes in ({"user_id": "@monitor:matrix.homelab.example"},
                        {"message_id": ""}, {"platform": "webhook"},
                        {"chat_id": "!other-room"}):
            with self.subTest(changes=changes), \
                    mock.patch.object(zig, "session",
                                      return_value=self.current(**changes)), \
                    mock.patch.object(zig, "client") as get:
                result = json.loads(zig.record_outcome({
                    "work": "work-1", "occurrence": "occ-1",
                    "outcome": "blocked", "detail": "gap"}))["data"]
                self.assertEqual("operator_turn_required", result["error"])
                get.assert_not_called()

    def test_plugin_registers_callable_tools_without_prompt_injection(self):
        class Context:
            def __init__(self):
                self.tools = {}

            def register_tool(self, **values):
                self.tools[values["name"]] = values

            def register_system_prompt_section(self, *_args, **_kwargs):
                raise AssertionError("lifecycle plugin must not inject a role prompt")

        context = Context()
        zig.register(context)
        self.assertEqual({
            "cve_lookup", "cve_work_scope", "cve_relationships", "cve_evidence",
            "cve_record_outcome", "cve_propose_change", "cve_repository_checkout",
            "cve_create_pr"}, set(context.tools))
        self.assertTrue(all(callable(value["handler"])
                            for value in context.tools.values()))
        encoded = json.dumps(context.tools, default=str).lower()
        self.assertNotIn("persona", encoded)
        self.assertNotIn("mention zig", encoded)

    def test_native_chat_budget_is_durable_and_hourly_bounded(self):
        budget = importlib.import_module("zig_chat_budget")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.db"
            for _ in range(120):
                budget.reserve(path, 10000)
            with self.assertRaises(ValueError):
                budget.reserve(path, 10001)
            budget.reserve(path, 13601)


if __name__ == "__main__":
    unittest.main()
