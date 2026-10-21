from __future__ import annotations

import json
import unittest
from pathlib import Path

import jinja2
import yaml

from test_provisioning_root import all_tasks


PLAYBOOK = Path(__file__).resolve().parents[1] / "ansible/playbooks/news-embeddings-provision.yml"


class NewsEmbeddingsPlanGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tasks = list(all_tasks(yaml.safe_load(PLAYBOOK.read_text())[0]["tasks"]))
        cls.selection = next(task["ansible.builtin.set_fact"]["news_embeddings_plan_changes"]
                             for task in tasks if task["name"] == "Select actual resource changes in the saved plan")
        cls.conditions = next(task["ansible.builtin.assert"]["that"]
                              for task in tasks if task["name"] == "Require an isolated news embeddings create or a converged root")
        cls.environment = jinja2.Environment()
        cls.environment.filters["from_json"] = json.loads

    def accepts(self, changes, rc=2):
        plan = {"resource_changes": changes}
        expression = self.selection.strip().removeprefix("{{").removesuffix("}}").strip()
        selected = self.environment.compile_expression(expression)(
            news_embeddings_tofu_plan_json={"stdout": json.dumps(plan)})
        values = {"news_embeddings_tofu_plan": {"rc": rc}, "news_embeddings_plan_changes": selected}
        return all(bool(self.environment.compile_expression(condition)(**values))
                   for condition in self.conditions)

    @staticmethod
    def change(name, vmid, actions=None):
        return {"address": f'proxmox_virtual_environment_container.managed["{name}"]',
                "change": {"actions": actions or ["create"], "after": {"vm_id": vmid}}}

    def test_accepts_only_the_declared_news_embeddings_create(self):
        self.assertTrue(self.accepts([self.change("news_embeddings", 217)]))
        self.assertTrue(self.accepts([], rc=0))
        self.assertTrue(self.accepts([self.change("n8n", 216, ["no-op"]),
                                      self.change("news_embeddings", 217)]))

    def test_rejects_unrelated_guest_even_with_one_add(self):
        self.assertFalse(self.accepts([self.change("other", 218)]))
        self.assertFalse(self.accepts([self.change("news_embeddings", 218)]))
        self.assertFalse(self.accepts([self.change("news_embeddings", 217, ["update"])]))
        self.assertFalse(self.accepts([self.change("news_embeddings", 217),
                                       self.change("other", 218)]))

    def test_rejects_replacement_deletion_or_existing_guest_mutation(self):
        self.assertFalse(self.accepts([self.change("news_embeddings", 217, ["delete", "create"])]))
        self.assertFalse(self.accepts([self.change("news_embeddings", 217, ["delete"])]))
        self.assertFalse(self.accepts([self.change("news_embeddings", 217),
                                       self.change("n8n", 216, ["update"])]))

    def test_rejects_inconsistent_plan_exit_codes(self):
        self.assertFalse(self.accepts([], rc=2))
        self.assertFalse(self.accepts([self.change("news_embeddings", 217)], rc=0))


if __name__ == "__main__":
    unittest.main()
