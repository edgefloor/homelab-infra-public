import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from jinja2 import Environment, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]


class N8nReleaseInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load((ROOT / 'ansible/roles/n8n/tasks/main.yml').read_text())
        cls.environment = Environment(undefined=StrictUndefined)
        cls.environment.filters['b64decode'] = lambda value: base64.b64decode(value).decode()
        cls.environment.filters['bool'] = bool

    def task(self, name):
        return next(task for task in self.tasks if task['name'] == name)

    def test_selected_release_artifacts_describe_the_same_integrity_lock(self):
        role = ROOT / 'ansible/roles/n8n'
        defaults = yaml.safe_load((role / 'defaults/main.yml').read_text())
        app = yaml.safe_load((ROOT / 'apps/n8n.yml').read_text())
        version = defaults['n8n_version']
        release = role / 'files' / version
        manifest = json.loads((release / 'package.json').read_text())
        lock_bytes = (release / 'package-lock.json').read_bytes()
        lock = json.loads(lock_bytes)
        digest = hashlib.sha256(lock_bytes).hexdigest()
        audit = json.loads((release / 'dependency-audit.json').read_text())
        provenance = json.loads((release / 'dependency-provenance.json').read_text())
        self.assertEqual(version, manifest['dependencies']['n8n'])
        self.assertEqual(version, lock['packages']['']['dependencies']['n8n'])
        self.assertEqual(version, lock['packages']['node_modules/n8n']['version'])
        self.assertEqual(version, app['upstream']['release'])
        self.assertEqual(defaults['n8n_commit'], app['upstream']['commit'])
        self.assertEqual(defaults['n8n_commit'], provenance['upstream_commit'])
        self.assertEqual(version, audit['release'])
        self.assertEqual(version, provenance['validation']['release'])
        for recorded in [audit['lock_sha256'], provenance['lock_sha256'],
                         provenance['lock_generation']['candidate_lock_sha256'],
                         provenance['validation']['lock_sha256']]:
            self.assertEqual(digest, recorded)

    def accepted(self, name, values):
        expressions = self.task(name)['ansible.builtin.assert']['that']
        return all(self.environment.compile_expression(expression)(**values)
                   for expression in expressions)

    def test_interrupted_install_can_resume_only_in_an_inactive_real_directory(self):
        name = 'Refuse to rebuild a selected or redirected release directory'
        values = {
            'n8n_release_path': '/opt/n8n/releases/2.43.7-fixture',
            'n8n_release_marker': {'stat': {'exists': False}},
            'n8n_release_directories': {'results': [
                {'stat': {'islnk': False}},
                {'stat': {'lnk_source': '/opt/n8n/releases/2.42.6'}},
            ]},
        }
        self.assertTrue(self.accepted(name, values))
        values['n8n_release_directories']['results'][1]['stat']['lnk_source'] = values['n8n_release_path']
        self.assertFalse(self.accepted(name, values))
        values['n8n_release_marker']['stat']['exists'] = True
        self.assertTrue(self.accepted(name, values))
        values['n8n_release_directories']['results'][0]['stat']['islnk'] = True
        self.assertFalse(self.accepted(name, values))
        preparation = self.task('Prepare an unprivileged build directory for a new release')
        self.assertTrue(preparation['ansible.builtin.file']['recurse'])
        self.assertFalse(preparation['ansible.builtin.file']['follow'])
        self.assertEqual('not n8n_release_marker.stat.exists', preparation['when'])

    def test_only_a_root_owned_protected_regular_receipt_is_trusted(self):
        name = 'Require a root-owned installation receipt'
        values = {
            'n8n_release_marker': {'stat': {'isreg': True, 'islnk': False, 'uid': 0, 'mode': '0644'}},
            'n8n_release_directories': {'results': [{'stat': {'isdir': True, 'uid': 0, 'mode': '0755'}}]},
        }
        self.assertTrue(self.accepted(name, values))
        for key, value in [('uid', 1001), ('mode', '0664'), ('islnk', True), ('isreg', False)]:
            with self.subTest(key=key):
                modified = copy.deepcopy(values)
                modified['n8n_release_marker']['stat'][key] = value
                self.assertFalse(self.accepted(name, modified))
        self.assertLess(self.tasks.index(self.task(name)),
                        self.tasks.index(self.task('Read the completed installation receipt')))

    def test_receipt_matches_exact_version_lock_and_newline(self):
        name = 'Require a matching installation receipt'
        for content, expected in [('2.43.7 abc\n', True), ('2.43.7 abc', False),
                                  ('2.42.6 abc\n', False), ('2.43.7 different\n', False)]:
            with self.subTest(content=content):
                values = {'n8n_release_receipt': {'content': base64.b64encode(content.encode()).decode()},
                          'n8n_version': '2.43.7', 'n8n_release_lock_sha256': 'abc'}
                self.assertIs(self.accepted(name, values), expected)

    def test_prepare_only_gates_link_configuration_service_and_restart_effects(self):
        activation = self.task('Activate the verified n8n release')
        enabled = self.environment.compile_expression(activation['when'])
        self.assertFalse(enabled(n8n_activate_release=False))
        self.assertTrue(enabled(n8n_activate_release=True))
        protected = {'/opt/n8n/current', '/etc/n8n/pangolin-auth.js', '/etc/n8n/pangolin-auth.json',
                     '/etc/n8n/n8n.env', '/etc/systemd/system/n8n.service'}

        def effects(task):
            found = set()
            for module in ['ansible.builtin.file', 'ansible.builtin.copy', 'ansible.builtin.template']:
                arguments = task.get(module, {})
                target = arguments.get('dest', arguments.get('path'))
                if target in protected:
                    found.add(target)
            if 'ansible.builtin.systemd_service' in task:
                found.add('service')
            if task.get('ansible.builtin.meta') == 'flush_handlers' or task.get('notify') == 'Restart n8n':
                found.add('restart')
            return found

        self.assertEqual(protected | {'service', 'restart'},
                         set().union(*(effects(task) for task in activation['block'])))
        for task in self.tasks:
            if task is not activation:
                self.assertEqual(set(), effects(task), task['name'])


if __name__ == '__main__':
    unittest.main()
