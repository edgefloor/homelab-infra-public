import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from build_security_config import compile_configs

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ansible/roles/update_monitor/files'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INVENTORY = load('homelab_deployment_inventory', SOURCE / 'homelab_deployment_inventory.py')
MONITOR = load('coverage_monitor_test', SOURCE / 'homelab_cve_monitor.py')


class DeploymentCoverageTests(unittest.TestCase):
    def test_chroot_fallback_requires_the_mapped_inode_and_device(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            library = root / 'library.so'
            library.write_bytes(b'library')
            info = library.stat()
            device = (os.major(info.st_dev), os.minor(info.st_dev))
            self.assertEqual(INVENTORY.mapped_backing_file(root / 'proc', str(library), info.st_ino, device), library)
            with self.assertRaises(ValueError):
                INVENTORY.mapped_backing_file(root / 'proc', str(library), info.st_ino + 1, device)

    def test_log_rotation_does_not_retrigger_every_container_advisory(self):
        container = {'id': 'one', 'image_id': 'image', 'changes': ['A /var/log/old.log'], 'main_pid': 10}
        rotated = {**container, 'changes': ['A /var/log/new.log'], 'main_pid': 20}
        self.assertEqual(INVENTORY.container_binding(container), INVENTORY.container_binding(rotated))
        modified = {**container, 'changes': ['C /usr/bin/caddy']}
        self.assertNotEqual(INVENTORY.container_binding(container), INVENTORY.container_binding(modified))

    def test_configs_include_every_deployment_and_missing_system(self):
        configs = compile_configs()
        self.assertEqual(len(configs), 15)
        self.assertEqual(configs['next-plaid']['libraries'][0]['path'], '/usr/local/bin/next-plaid-api')
        self.assertIn('diagnostic-agent', {d['id'] for d in configs['plan-runner']['deployments']})

    def test_metadata_identity_changes_when_installed_dependency_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'node_modules/pkg/package.json'
            path.parent.mkdir(parents=True)
            path.write_text('{"version":"1"}')
            before = INVENTORY.metadata_inventory(Path(temp))
            path.write_text('{"version":"2"}')
            after = INVENTORY.metadata_inventory(Path(temp))
            self.assertNotEqual(before['sha256'], after['sha256'])

    def test_lockfile_is_not_installed_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'Cargo.lock').write_text('source version')
            self.assertEqual(INVENTORY.metadata_inventory(Path(temp))['files'], [])

    def test_executable_replacement_changes_library_inventory_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / 'esbuild'
            binary.write_bytes(b'old')
            binary.chmod(0o755)
            before = INVENTORY.metadata_inventory(root)
            binary.write_bytes(b'new')
            self.assertNotEqual(before['sha256'], INVENTORY.metadata_inventory(root)['sha256'])

    def test_zero_analyzers_are_partial_not_clean(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(sys.modules, {'homelab_deployment_inventory': INVENTORY}), \
                mock.patch.object(MONITOR, 'run_json', return_value={'Results': []}):
            result = MONITOR.scan_library('trivy', Path(temp), Path(temp),
                                         {'deployment': 'test', 'path': temp, 'types': ['rustbinary']})
            self.assertEqual(result['_homelab_library']['status'], 'partial')
            self.assertIn('rustbinary', result['_homelab_library']['reason'])

    def test_scanner_target_cannot_grant_access_outside_library_root(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(sys.modules, {'homelab_deployment_inventory': INVENTORY}):
            root = Path(temp) / 'application'
            root.mkdir()
            outside = Path(temp) / 'outside'
            outside.write_text('not part of this application')
            report = {'Results': [{'Target': '../outside', 'Type': 'node-pkg', 'Packages': [{'Name': 'test', 'Version': '1'}]}]}
            with mock.patch.object(MONITOR, 'run_json', return_value=report):
                result = MONITOR.scan_library('trivy', root, root, {'deployment': 'test', 'path': str(root), 'types': ['node-pkg']})
            self.assertEqual(result['_homelab_library']['status'], 'failed')
            self.assertEqual(result['Results'], [])

    def test_installed_packages_are_retained_even_without_findings(self):
        report = {'Results': [{'Type': 'python-pkg', 'Packages': [{'Name': 'requests', 'Version': '2.0'}]}]}
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(sys.modules, {'homelab_deployment_inventory': INVENTORY}), \
                mock.patch.object(MONITOR, 'run_json', return_value=report):
            result = MONITOR.scan_library('trivy', Path(temp), Path(temp),
                                         {'deployment': 'test', 'path': temp, 'types': ['python-pkg', 'node-pkg']})
            self.assertEqual(result['_homelab_library']['status'], 'partial')
            self.assertEqual(result['_homelab_library']['packages'][0]['name'], 'requests')

    def test_scan_change_does_not_publish_unbound_findings(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(sys.modules, {'homelab_deployment_inventory': INVENTORY}), \
                mock.patch.object(INVENTORY, 'metadata_inventory', side_effect=[{'resolved_path': temp, 'sha256': 'old'}, {'sha256': 'new'}]), \
                mock.patch.object(MONITOR, 'run_json', return_value={'Results': [{'Vulnerabilities': [{}]}]}):
            result = MONITOR.scan_library('trivy', Path(temp), Path(temp),
                                         {'deployment': 'test', 'path': temp, 'types': ['node-pkg']})
            self.assertEqual(result['_homelab_library']['status'], 'failed')
            self.assertEqual(result['Results'], [])

    def test_unknown_service_and_failed_discovery_stay_gaps(self):
        config = {'host': 'test', 'deployments': []}
        def fake_run(argv):
            if 'list-units' in argv:
                return 'unexpected.service loaded active running Unexpected\n'
            if 'list-unit-files' in argv:
                return ''
            if argv[0] == 'ss':
                raise RuntimeError('unavailable')
            raise AssertionError(argv)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                mock.patch.object(INVENTORY, 'properties', return_value={'Id': 'unexpected.service'}), \
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None), \
                mock.patch.object(INVENTORY.Path, 'glob', return_value=[]):
            evidence = INVENTORY.discover(config, Path(temp))
        self.assertIn('unclassified-service:unexpected.service', evidence['gaps'])
        self.assertIn('listener-discovery-failed', evidence['gaps'])

    def test_runtime_change_invalidates_prior_finding(self):
        self.assertNotEqual(MONITOR.runtime_identity({'runtime_sha256': 'old'}),
                            MONITOR.runtime_identity({'runtime_sha256': 'new'}))
