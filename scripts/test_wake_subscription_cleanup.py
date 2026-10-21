import contextlib
import importlib.util
import io
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "ansible/roles/homelab_agent_service/files/"
          "remove_kanban_wake_subscriptions.py")


class WakeSubscriptionCleanupTests(unittest.TestCase):
    def test_cleanup_removes_wake_modes_and_keeps_notify_only(self):
        subscriptions = [{
            "task_id": "wake", "platform": "matrix", "chat_id": "!room",
            "thread_id": "$thread", "delivery_mode": "notify+wake"}, {
            "task_id": "notify", "platform": "matrix", "chat_id": "!room",
            "thread_id": "$thread", "delivery_mode": "notify"}]
        removed = []
        database = types.SimpleNamespace(
            connect=lambda: types.SimpleNamespace(close=lambda: None),
            list_notify_subs=lambda _connection: list(subscriptions),
            remove_notify_sub=lambda _connection, **values: removed.append(values))
        package = types.ModuleType("hermes_cli")
        package.kanban_db = database
        with mock.patch.dict(
                sys.modules, {"hermes_cli": package,
                              "hermes_cli.kanban_db": database}):
            spec = importlib.util.spec_from_file_location("wake_cleanup_test", SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                module.main()
        self.assertEqual(["wake"], [value["task_id"] for value in removed])
        self.assertIn("removed 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
