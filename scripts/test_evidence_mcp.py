"""The adapter must persist receipts even when remote transport fails."""

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

from test_homelab_agent import load_module
from test_cve_investigation import fixture

ROOT = Path(__file__).resolve().parents[1]


class EvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "receipts").mkdir()
        (self.root / "record.json").write_text(json.dumps(fixture()["record"]))

        class Server:
            def __init__(self, *args):
                pass

            def tool(self, **kwargs):
                return lambda function: function

        modules = {
            "mcp": types.ModuleType("mcp"),
            "mcp.server": types.ModuleType("mcp.server"),
            "mcp.server.fastmcp": types.ModuleType("mcp.server.fastmcp"),
            "mcp.types": types.ModuleType("mcp.types"),
        }
        modules["mcp.server.fastmcp"].FastMCP = Server
        modules["mcp.types"].ToolAnnotations = lambda **kwargs: kwargs
        with (
            mock.patch.dict(sys.modules, modules),
            mock.patch.dict(
                os.environ,
                {
                    "HOMELAB_EVIDENCE_TARGET": "example",
                    "HOMELAB_EVIDENCE_TOKEN": "sensitive",
                    "HOMELAB_EVIDENCE_RECORD_DIR": str(self.root),
                    "HOMELAB_EVIDENCE_DEADLINE": str(time.time() + 900),
                },
            ),
        ):
            self.adapter = load_module(
                "test_adapter",
                ROOT
                / "ansible/roles/homelab_agent_service/files/homelab_evidence_mcp.py",
            )

    def tearDown(self):
        self.temporary.cleanup()

    def test_transport_failure_is_attributable_without_exposing_token(self):
        with mock.patch.object(
            self.adapter.subprocess, "run", side_effect=OSError("transport unavailable")
        ):
            receipt = self.adapter.read_configuration(
                "/etc/service/config.yml", container="service-1"
            )
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["identity"]["container_id"], "0" * 63 + "1")
        persisted = next((self.root / "receipts").glob("*.json"))
        self.assertEqual(json.loads(persisted.read_text()), receipt)
        self.assertNotIn("sensitive", persisted.read_text())
        self.assertEqual(persisted.stat().st_mode & 0o777, 0o600)

    def test_repository_context_preserves_file_local_line_numbers(self):
        context = self.root / "repository-context"
        context.write_text(
            "# inventory/routes.yml\nfirst: value\nservice: backend\nnext: value\n"
        )
        with mock.patch.object(self.adapter, "CONTEXT", context):
            receipt = self.adapter.search_deployment_repository("backend")
        match = receipt["result"]["matches"][0]
        self.assertEqual(match["source"], "inventory/routes.yml")
        self.assertEqual(match["line"], 2)
        self.assertEqual(len(match["context"]), 3)
        self.assertEqual(receipt["operation"], "repository_search")

    def test_gateway_envelope_is_saved_and_returned_unchanged(self):
        receipt = fixture()["receipts"][1]
        receipt["observation_id"] = "a" * 32
        response = types.SimpleNamespace(
            returncode=0, stdout=json.dumps({"ok": True, "result": {"result": receipt}})
        )
        with mock.patch.object(self.adapter.subprocess, "run", return_value=response):
            result = self.adapter.read_configuration(
                "/etc/service/config.yml", "service-1"
            )
        self.assertEqual(result, receipt)
        self.assertEqual(len(list((self.root / "receipts").glob("*.json"))), 1)

    def test_invalid_receipt_id_cannot_escape_storage(self):
        receipt = fixture()["receipts"][1]
        receipt["observation_id"] = "../../escape"
        with self.assertRaises(ValueError):
            self.adapter.save_receipt(receipt)

    def test_oversized_receipt_is_rejected_without_truncating_provenance(self):
        receipt = fixture()["receipts"][1]
        receipt["observation_id"] = "a" * 32
        receipt["result"]["content"] = "x" * (128 * 1024)
        with self.assertRaises(ValueError):
            self.adapter.save_receipt(receipt)
        self.assertFalse(list((self.root / "receipts").glob("*.json")))


if __name__ == "__main__":
    unittest.main()
