from __future__ import annotations

import json
import unittest
from pathlib import Path

import jinja2
import yaml

from test_provisioning_root import all_tasks


PLAYBOOK = Path(__file__).resolve().parents[1] / "ansible/playbooks/firecrawl-provision.yml"


class FirecrawlPlanGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tasks = list(all_tasks(yaml.safe_load(PLAYBOOK.read_text())[0]["tasks"]))
        cls.selection = next(task["ansible.builtin.set_fact"]["firecrawl_plan_changes"]
                             for task in tasks if task["name"] == "Select actual resource changes in the saved plan")
        cls.conditions = next(task["ansible.builtin.assert"]["that"]
                              for task in tasks if task["name"] == "Require an isolated Firecrawl create or a converged root")
        cls.environment = jinja2.Environment()
        cls.environment.filters["from_json"] = json.loads

    def accepts(self, changes, rc=2):
        plan = {"resource_changes": changes}
        expression = self.selection.strip().removeprefix("{{").removesuffix("}}").strip()
        selected = self.environment.compile_expression(expression)(
            firecrawl_tofu_plan_json={"stdout": json.dumps(plan)})
        values = {"firecrawl_tofu_plan": {"rc": rc}, "firecrawl_plan_changes": selected}
        return all(bool(self.environment.compile_expression(condition)(**values))
                   for condition in self.conditions)

    @staticmethod
    def change(name, vmid, actions=None):
        return {"address": f'proxmox_virtual_environment_container.managed["{name}"]',
                "change": {"actions": actions or ["create"], "after": {"vm_id": vmid}}}

    def test_accepts_only_the_declared_firecrawl_create(self):
        self.assertTrue(self.accepts([self.change("firecrawl", 215)]))
        self.assertTrue(self.accepts([], rc=0))

    def test_rejects_unrelated_guest_even_with_one_add(self):
        self.assertFalse(self.accepts([self.change("other", 216)]))
        self.assertFalse(self.accepts([self.change("firecrawl", 216)]))
        self.assertFalse(self.accepts([self.change("firecrawl", 215, ["update"])]))
        self.assertFalse(self.accepts([self.change("firecrawl", 215),
                                       self.change("other", 216)]))


if __name__ == "__main__":
    unittest.main()
