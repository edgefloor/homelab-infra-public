from __future__ import annotations

import re
import unittest
from pathlib import Path

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'ansible/playbooks/retire-custom-cve.yml'


class CVERetirementPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.play = yaml.safe_load(PLAYBOOK.read_text())[0]
        cls.environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
        cls.environment.filters.update({
            'regex_replace': lambda text, pattern, replacement: re.sub(pattern, replacement, text),
            'split': str.split,
            'intersect': lambda left, right: [item for item in left if item in right],
            'dict2items': lambda value: [{'key': key, 'value': item} for key, item in value.items()],
        })

    def expression(self, source, **values):
        expression = source.strip().removeprefix('{{').removesuffix('}}').strip()
        return self.environment.compile_expression(expression)(**values)

    def test_absent_and_not_found_services_are_skipped_and_order_is_preserved(self):
        select = next(task['ansible.builtin.set_fact'] for task in self.play['pre_tasks']
                      if 'ansible.builtin.set_fact' in task)
        services = {
            'helix-cve.service': {'status': 'enabled'},
            'homelab-incidents.service': {'status': 'enabled'},
            'zag-ops-worker.service': {'status': 'not-found'},
            'hermes-gateway.service': {'status': 'enabled'},
            # systemd can retain a static fact for a deleted referenced unit.
            'homelab-incidents-helix-sync.service': {'status': 'static', 'state': 'stopped'},
            # service_facts also reports SysV units without a systemd status.
            'cron': {'source': 'sysv', 'state': 'running'},
        }
        selected = self.expression(select['cve_installed_services'],
                                   **self.play['vars'], ansible_facts={'services': services},
                                   cve_service_unit_files={'stdout_lines': [
                                       'helix-cve.service enabled enabled',
                                       'homelab-incidents.service enabled enabled',
                                       'hermes-gateway.service enabled enabled']})
        self.assertEqual(selected, ['homelab-incidents.service', 'helix-cve.service'])
        self.assertEqual(self.expression(select['cve_installed_services'],
                         **self.play['vars'], ansible_facts={'services': {}},
                         cve_service_unit_files={'stdout_lines': []}), [])

    def test_only_installed_custom_timers_are_selected(self):
        select = next(task['ansible.builtin.set_fact'] for task in self.play['pre_tasks']
                      if 'ansible.builtin.set_fact' in task)
        selected = self.expression(select['cve_installed_timers'], **self.play['vars'],
                                  cve_timer_unit_files={'stdout_lines': [
                                      'homelab-cve-monitor.timer enabled enabled',
                                      'homelab-release-monitor.timer enabled enabled',
                                      'apt-daily.timer enabled enabled']})
        self.assertEqual(selected, ['homelab-cve-monitor.timer'])

    def test_retirement_preserves_personal_and_standard_services(self):
        retired = set(self.play['vars']['cve_retirement_services']) | set(self.play['vars']['cve_retirement_timers'])
        self.assertTrue(retired.isdisjoint({
            'hermes-gateway.service', 'beszel-agent.service', 'crowdsec.service',
            'crowdsec-firewall-bouncer.service', 'crowdsec-matrix-bridge.service',
            'homelab-release-monitor.service', 'homelab-release-monitor.timer',
            'homelab-trivy.service', 'docker.service', 'tuwunel-backup.timer'}))

    def test_preflight_is_read_only_and_timer_shutdown_precedes_services(self):
        preflight = self.play['pre_tasks']
        self.assertTrue(self.play['any_errors_fatal'])
        self.assertTrue(any('ansible.builtin.service_facts' in task for task in preflight))
        health = next(task['ansible.builtin.uri'] for task in preflight if 'ansible.builtin.uri' in task)
        self.assertEqual(health['method'], 'GET')
        self.assertEqual(health['status_code'], 200)
        self.assertEqual(health['follow_redirects'], 'none')
        self.assertTrue(health['validate_certs'])
        operations = [task for task in self.play['tasks'] if 'ansible.builtin.systemd_service' in task]
        self.assertEqual([task['loop'] for task in operations],
                         ['{{ cve_installed_timers }}', '{{ cve_installed_services }}'])
        for task in operations:
            self.assertEqual(task['ansible.builtin.systemd_service']['state'], 'stopped')
            self.assertFalse(task['ansible.builtin.systemd_service']['enabled'])
        all_tasks = self.play['tasks'] + preflight
        for task in all_tasks:
            self.assertNotIn('ansible.builtin.file', task)
            self.assertNotIn('ansible.builtin.shell', task)
            self.assertNotIn('ansible.builtin.copy', task)


if __name__ == '__main__':
    unittest.main()
