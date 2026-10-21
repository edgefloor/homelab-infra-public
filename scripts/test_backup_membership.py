from pathlib import Path
import json
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ("firecrawl", "incident", "helix-adopt", "n8n", "news-embeddings")


class BackupMembershipTests(unittest.TestCase):
    def test_service_deployments_preserve_all_canonical_backup_members(self):
        canonical = yaml.safe_load((ROOT / "inventory/backup-plan.yml").read_text())["backup_plan"]["scheduled_jobs"][0]["lxc_ids"]
        for name in PLAYBOOKS:
            with self.subTest(playbook=name):
                plays = yaml.safe_load((ROOT / f"ansible/playbooks/{name}.yml").read_text())
                play = plays[-1]
                if "managed_backup_membership" in play.get("roles", []):
                    continue
                configured = play.get("vars", {}).get("managed_backup_guests")
                if configured is not None:
                    self.assertTrue(set(canonical) <= set(map(int, configured.split(","))))

    def test_membership_has_one_owner_and_preserves_extra_existing_guests(self):
        for name in PLAYBOOKS:
            plays = yaml.safe_load((ROOT / f"ansible/playbooks/{name}.yml").read_text())
            self.assertIn("managed_backup_membership", plays[-1].get("roles", []))
        tasks = yaml.safe_load((ROOT / "ansible/roles/managed_backup_membership/tasks/main.yml").read_text())
        target = next(task["ansible.builtin.set_fact"]["managed_backup_target_ids"] for task in tasks
                      if "managed_backup_target_ids" in task.get("ansible.builtin.set_fact", {}))
        env = jinja2.Environment()
        env.filters["from_json"] = json.loads
        evaluate = env.compile_expression(target.strip().removeprefix("{{").removesuffix("}}").strip())
        # Newly declared IDs and unrelated existing members must both survive a service deploy.
        result = evaluate(managed_backup_job={"stdout": json.dumps({"vmid": "200,217,999"})},
                          managed_backup_definition={"lxc_ids": [200, 217, 218]})
        self.assertEqual(result, [200, 217, 218, 999])
