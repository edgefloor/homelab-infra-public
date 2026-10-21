from pathlib import Path
import glob
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]


def all_tasks(tasks):
    for task in tasks:
        yield task
        for section in ('block', 'rescue', 'always'):
            yield from all_tasks(task.get(section, []))


class ProvisioningRootTests(unittest.TestCase):
    def test_all_provisioners_stage_the_complete_current_root(self):
        required = {p.name for p in (ROOT / "tofu/proxmox").glob("*.tf")} | {".terraform.lock.hcl"}
        for name in ("firecrawl-provision", "n8n-provision", "news-embeddings-provision", "helix-adopt"):
            with self.subTest(playbook=name):
                tasks = all_tasks(yaml.safe_load((ROOT / f"ansible/playbooks/{name}.yml").read_text())[0]["tasks"])
                staged = next(task["loop"] for task in tasks if task["name"] == "Stage the reviewed Proxmox root")
                if isinstance(staged, str):
                    env = jinja2.Environment()
                    env.filters["basename"] = lambda path: Path(path).name
                    expression = staged.strip().removeprefix("{{").removesuffix("}}").strip()
                    staged = env.compile_expression(expression)(
                        query=lambda name, pattern: glob.glob(pattern), playbook_dir=str(ROOT / "ansible/playbooks"))
                self.assertEqual(set(staged), required)

    def test_failed_provisioning_always_removes_the_private_root_and_saved_plan(self):
        for name in ('firecrawl', 'n8n', 'news-embeddings'):
            with self.subTest(playbook=name):
                tasks = yaml.safe_load((ROOT / f'ansible/playbooks/{name}-provision.yml').read_text())[0]['tasks']
                self.assertTrue(any('always' in task for task in tasks))
                block = next(task for task in tasks if 'always' in task)
                cleanup = block['always'][0]['ansible.builtin.file']
                self.assertEqual(cleanup['state'], 'absent')
                root = cleanup['path']
                planned = next(task for task in all_tasks(block['block']) if task['name'].startswith('Plan the fresh'))
                arguments = planned['ansible.builtin.command']['argv']
                self.assertIn('-out=' + root + '/provision.tfplan', arguments)
