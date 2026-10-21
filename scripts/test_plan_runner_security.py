from __future__ import annotations

import configparser
import unittest
from pathlib import Path

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]


def runner_tasks():
    return [task for path in (ROOT / 'ansible/roles/plan_runner/tasks').glob('*.yml')
            for task in yaml.safe_load(path.read_text())]


class PlanRunnerSecurityTests(unittest.TestCase):
    def test_runner_owned_programs_are_never_executed_by_privileged_provisioning(self):
        play = yaml.safe_load((ROOT / 'ansible/playbooks/plan-runner.yml').read_text())[0]
        self.assertTrue(play['become'])
        for task in runner_tasks():
            for module in ('ansible.builtin.command', 'ansible.builtin.shell', 'ansible.builtin.script'):
                if module not in task:
                    continue
                command = str(task[module])
                if '/opt/actions-runner' in command:
                    with self.subTest(task=task['name']):
                        self.assertEqual(task.get('become_user'), '{{ github_runner_user }}',
                                         'Runner-writable code must not inherit root from the play')

    def test_managed_service_drops_privileges_before_starting_runner_code(self):
        role = ROOT / 'ansible/roles/plan_runner'
        tasks = runner_tasks()
        install = next(task['ansible.builtin.template'] for task in tasks
                       if task.get('ansible.builtin.template', {}).get('src') == 'actions-runner.service.j2')
        self.assertEqual((install['owner'], install['group'], install['mode']), ('root', 'root', '0644'))
        unit = configparser.ConfigParser(interpolation=None)
        unit.read_string(jinja2.Template((role / 'templates/actions-runner.service.j2').read_text()).render(
            github_runner_name='plan-runner', github_runner_user='github-runner'))
        self.assertEqual(unit['Service']['User'], 'github-runner')
        self.assertEqual(unit['Service']['Group'], 'github-runner')
        self.assertEqual(unit['Service']['ExecStart'], '/opt/actions-runner/runsvc.sh')
        self.assertFalse(any(key.lower().startswith('exec') and value.startswith(('+', '!'))
                             for key, value in unit['Service'].items()))

    def test_debian_runner_dependencies_are_installed_from_signed_packages(self):
        tasks = runner_tasks()
        packages = {package for task in tasks for package in task.get('ansible.builtin.apt', {}).get('name', [])}
        self.assertLessEqual({'libicu76', 'libkrb5-3', 'liblttng-ust1t64', 'libssl3t64', 'zlib1g'}, packages)
        self.assertFalse(any(task.get('ansible.builtin.apt', {}).get('allow_unauthenticated') for task in tasks))


if __name__ == '__main__':
    unittest.main()
