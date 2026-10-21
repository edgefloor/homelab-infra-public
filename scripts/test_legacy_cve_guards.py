from __future__ import annotations

import unittest
from pathlib import Path

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / 'ansible'
FLAG = 'homelab_legacy_cve_enabled'
LEGACY_PLAYBOOKS = [
    'cve-helix.yml', 'cve-coverage.yml', 'cve-lifecycle-migration.yml',
    'cve-message-rollout.yml', 'cve-source-observations.yml',
    'cve-source-observations-runtime.yml', 'cve-source-observations-canary.yml',
    'cve-source-observations-full.yml', 'cve-source-observations-artifact-broker.yml',
    'incident.yml', 'incident-backup.yml', 'incident-canary.yml',
    'incident-enable-manual.yml', 'incident-evidence-rollout.yml',
    'incident-migrate.yml', 'incident-pangolin-cleanup.yml', 'incident-rollback.yml',
    'incident-runtime-rollout.yml', 'investigation-runtime.yml',
    'vulnerability-incidents.yml', 'zig.yml', 'ops-message-rollout.yml',
    'hermes-scan-declaration.yml', 'helix-adopt.yml', 'helix-bootstrap.yml',
    'homelab-agent.yml', 'defense-agent-tools.yml', 'container-lookup-rollout.yml',
]


def read(path):
    return yaml.safe_load((ANSIBLE / path).read_text())


def is_guard(task):
    return task.get('ansible.builtin.import_role', {}).get('name') == 'legacy_cve_guard'


class LegacyCVEGuardTests(unittest.TestCase):
    def test_legacy_opt_in_defaults_to_false(self):
        self.assertIs(read('roles/legacy_cve_guard/defaults/main.yml')[FLAG], False)

    def test_dedicated_legacy_plays_require_opt_in_before_tasks_or_roles(self):
        for name in LEGACY_PLAYBOOKS:
            for play in read('playbooks/' + name):
                if 'hosts' not in play:
                    continue
                with self.subTest(playbook=name, play=play.get('name')):
                    self.assertTrue(play.get('pre_tasks') and is_guard(play['pre_tasks'][0]),
                                    'Legacy activation must fail before any host mutation')

    def test_direct_role_entrypoints_are_guarded(self):
        for entry in ('cve_helix/tasks/main.yml', 'vulnerability_incidents/tasks/main.yml',
                      'incident_backup/tasks/main.yml', 'homelab_agent_service/tasks/main.yml',
                      'homelab_agent_service/tasks/storage.yml',
                      'homelab_agent/tasks/main.yml', 'homelab_agent_target/tasks/main.yml',
                      'homelab_agent_target/tasks/evidence.yml',
                      'homelab_agent_target/tasks/artifact_tools.yml'):
            with self.subTest(entry=entry):
                self.assertTrue(is_guard(read('roles/' + entry)[0]))

    def test_normal_provisioning_runs_without_the_incident_backend(self):
        tasks = read('playbooks/tasks/provision-with-cve-cycle.yml')
        ordinary = [task for task in tasks if 'ansible.builtin.include_role' in task]
        self.assertEqual(len(ordinary), 1)
        self.assertEqual(ordinary[0]['ansible.builtin.include_role']['name'], '{{ cve_provisioning_role }}')
        environment = jinja2.Environment()
        environment.filters['bool'] = bool
        condition = environment.compile_expression(ordinary[0]['when'])
        self.assertTrue(condition())
        self.assertTrue(condition(**{FLAG: False}))
        self.assertFalse(condition(**{FLAG: True}))
        legacy = next(task for task in tasks if 'block' in task)
        self.assertTrue(is_guard(legacy['block'][0]))
        self.assertFalse(environment.compile_expression(legacy['when'])())

    def test_general_monitoring_remains_outside_the_legacy_guard(self):
        roles = ['hermes_agent', 'beszel_agent', 'trivy_server']
        # The personal profile is deliberately excluded from the public mirror.
        if (ROOT / 'public-mirror/config.yml').exists():
            roles.append('hermes_zag')
        for role in roles:
            self.assertFalse(is_guard(read(f'roles/{role}/tasks/main.yml')[0]))
        first_trivy_play = read('playbooks/trivy-central.yml')[0]
        self.assertIn('trivy_server', first_trivy_play['roles'])
        self.assertFalse(any(is_guard(task) for task in first_trivy_play.get('pre_tasks', [])))

    def test_default_update_monitor_can_only_enable_release_notifications(self):
        tasks = read('roles/update_monitor/tasks/main.yml')
        self.assertEqual(tasks[0]['ansible.builtin.include_tasks'], 'standard.yml')
        self.assertEqual(tasks[1]['ansible.builtin.include_tasks'], 'releases.yml')
        self.assertTrue(is_guard(tasks[2]['block'][0]))
        environment = jinja2.Environment()
        environment.filters['bool'] = bool
        self.assertTrue(environment.compile_expression(tasks[0]['when'])())
        self.assertFalse(environment.compile_expression(tasks[2]['when'])())
        enabled = []
        for entry in ('standard.yml', 'releases.yml', 'trivy_client.yml'):
            for task in read('roles/update_monitor/tasks/' + entry):
                unit = task.get('ansible.builtin.systemd_service', {})
                if unit.get('enabled') or unit.get('state') in ('started', 'restarted'):
                    enabled.append(unit['name'])
        self.assertEqual(enabled, ['homelab-release-monitor.timer'])

    def test_shared_matcher_does_not_run_legacy_scan_by_default(self):
        tasks = read('playbooks/trivy-central.yml')[1]['tasks']
        self.assertEqual(len(tasks), 1)
        environment = jinja2.Environment()
        environment.filters['bool'] = bool
        self.assertFalse(environment.compile_expression(tasks[0]['when'])())


if __name__ == '__main__':
    unittest.main()
