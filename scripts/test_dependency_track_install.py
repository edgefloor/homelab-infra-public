"""Check executable Python after YAML has interpreted its escaping."""
from pathlib import Path
import unittest

import yaml


class InstallationPythonTests(unittest.TestCase):
    def test_inline_python_survives_yaml_parsing(self):
        root = Path(__file__).resolve().parents[1]
        tasks = yaml.safe_load((root / "ansible/roles/dependency_track/tasks/main.yml").read_text())
        checked = 0
        for task in tasks:
            args = task.get("ansible.builtin.command", {}).get("argv", [])
            if args[:2] == ["python3", "-c"]:
                with self.subTest(task=task["name"]):
                    compile(args[2], task["name"], "exec")
                checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
