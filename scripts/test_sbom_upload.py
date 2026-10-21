import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import tarfile
import time
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ansible/roles/sbom_upload/files/sbom_upload.py'
spec = importlib.util.spec_from_file_location('sbom_upload', SOURCE)
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)
BOM = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
       'components': [{'type': 'library', 'name': 'test-package', 'version': '1.0'}]}


class SbomUploadTests(unittest.TestCase):
    def source_fixture(self, root):
        config = self.fixture(root)
        binary = root / 'app'
        binary.write_bytes(b'installed Rust release')
        lock = root / 'Cargo.lock'
        lock.write_text('''version = 4
[[package]]
name = "example"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "forked-example"
version = "0.1.0"
source = "git+https://github.com/example/fork#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
[[package]]
name = "app"
version = "1.0.0"
''')
        config['libraries'] = [{'deployment': 'app', 'path': str(binary)}]
        config['source_locks'] = {'library/app': {
            'path': str(lock), 'sha256': sbom.file_digest(lock),
            'artifact_sha256': sbom.file_digest(binary),
            'repository': 'https://github.com/example/app', 'revision': 'c' * 40,
            'url': 'https://raw.githubusercontent.com/example/app/' + 'c' * 40 + '/Cargo.lock',
            'release': '1.0.0', 'association': 'operator-reviewed release source association',
        }}
        return config

    def test_source_inventory_never_uploads_after_binary_or_lock_drift(self):
        for target in ('app', 'Cargo.lock'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config = self.source_fixture(root)
                (root / target).write_bytes(b'changed')
                with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload') as upload:
                    self.assertEqual(sbom.collect(config), 1)
                self.assertEqual([call.args[1]['name'] for call in upload.call_args_list], ['os'])
                self.assertFalse(sbom.fresh(config))

    def test_source_candidates_are_labeled_and_git_forks_are_not_crates_io_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.source_fixture(root)
            captured = {}
            def upload(_config, scope, output):
                captured[scope['name']] = json.loads(output.read_text())
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload', side_effect=upload):
                self.assertEqual(sbom.collect(config), 0)
            bom = captured['library/app']
            self.assertEqual([item['name'] for item in bom['components']], ['example', 'forked-example', 'app'])
            self.assertEqual(bom['components'][0]['purl'], 'pkg:cargo/example@1.2.3')
            self.assertNotIn('purl', bom['components'][1])
            self.assertNotIn('purl', bom['components'][2])
            for component in bom['components']:
                properties = {p['name']: p['value'] for p in component['properties']}
                self.assertEqual(properties['homelab:inventory:compiled-membership'], 'unverified')
                self.assertEqual(properties['homelab:source:revision'], 'c' * 40)
                self.assertEqual(properties['homelab:source:lock-sha256'], config['source_locks']['library/app']['sha256'])
                self.assertIn('compiled membership is unverified', properties['homelab:inventory:limitations'])
            props = {p['name']: p['value'] for p in bom['metadata']['properties']}
            self.assertEqual(props['homelab:inventory:evidence'], 'source-lock-candidates')
            self.assertEqual(props['homelab:inventory:compiled-membership'], 'unverified')
            self.assertTrue(sbom.fresh(config))
            (root / 'app').write_bytes(b'upgraded without source review')
            self.assertFalse(sbom.fresh(config))

    def test_image_source_association_is_bound_to_running_content_and_preserves_inventory_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.source_fixture(root)
            config['libraries'] = []
            source = config['source_locks'].pop('library/app')
            source['image_id'] = 'sha256:' + 'd' * 64
            scope_name = 'container/compose/example/jwt'
            config['source_locks'][scope_name] = source
            def images():
                return [{'name': scope_name, 'kind': 'image', 'target': source['image_id'], 'packages': 'os,library'}]
            with patch.object(sbom, 'docker_targets', side_effect=lambda *_: images()), patch.object(sbom, 'upload'):
                self.assertEqual(sbom.collect(config), 0)
                self.assertTrue(sbom.fresh(config))
            changed = images()
            changed[0]['target'] = 'sha256:' + 'e' * 64
            with patch.object(sbom, 'docker_targets', return_value=changed), patch.object(sbom, 'upload') as uploaded:
                self.assertFalse(sbom.fresh(config))
                self.assertEqual(sbom.collect(config), 1)
                self.assertEqual([call.args[1]['name'] for call in uploaded.call_args_list], ['os'])
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload'):
                self.assertEqual(sbom.collect(config), 1)
                state = json.loads(Path(config['state']).read_text())
                self.assertIn('source-lock-scope-missing:' + scope_name, state['failed'])

    def test_source_candidate_upload_uses_a_distinct_project_name(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.source_fixture(root)
            scope = sbom.declared_scopes(config)[1]
            with patch.object(sbom, 'api', side_effect=[
                {'token': '22222222-2222-4222-8222-222222222222'},
                {'processing': False, 'status': 'COMPLETED'},
            ]) as api:
                sbom.upload(config, scope, root / 'bom.json')
            self.assertIn(('projectName', 'homelab/test-host/library/app/source-lock-candidates'), api.call_args_list[0].args[2])

    def fixture(self, root, output=BOM, exit_status=0):
        trivy = root / 'trivy'
        trivy.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\n'
                         + 'Path(sys.argv[sys.argv.index("--output")+1]).write_text(' + repr(json.dumps(output)) + ')\n'
                         + 'raise SystemExit(' + str(exit_status) + ')\n')
        trivy.chmod(0o755)
        return {'system': 'test-host', 'url': 'https://vulns.homelab.example',
                'parent_uuid': '11111111-1111-4111-8111-111111111111',
                'header_file': str(root / 'api-header'), 'trivy': str(trivy),
                'state': str(root / 'status.json'), 'cache_dir': str(root / 'cache'),
                'cache_max_bytes': 1024 * 1024, 'minimum_free_bytes': 0,
                'scan_timeout_seconds': 10, 'max_age_seconds': 129600,
                'go_binaries': [], 'libraries': [], 'skip_dirs': ['/proc', '/sys']}

    def test_failed_scan_never_uploads_even_if_it_left_a_valid_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root, exit_status=42)
            Path(config['state']).write_text(json.dumps({'last_success': 123}))
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload') as upload:
                self.assertEqual(sbom.collect(config), 1)
            upload.assert_not_called()
            state = json.loads(Path(config['state']).read_text())
            self.assertEqual(state['last_success'], 123)
            self.assertEqual(state['failed'], ['os'])
            self.assertFalse(list(Path(config['cache_dir']).iterdir()))

    def test_empty_bom_cannot_replace_previous_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp), output={'bomFormat': 'CycloneDX', 'components': []})
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload') as upload:
                self.assertEqual(sbom.collect(config), 1)
            upload.assert_not_called()

    def test_success_updates_freshness_only_after_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload') as upload:
                self.assertEqual(sbom.collect(config), 0)
            upload.assert_called_once()
            self.assertTrue(sbom.fresh(config))
            self.assertFalse(sbom.fresh(config, now=time.time() + 129601))
            self.assertFalse(list(Path(config['cache_dir']).iterdir()))
            config['libraries'] = [{'deployment': 'new', 'path': '/new'}]
            self.assertFalse(sbom.fresh(config))

    def test_missing_declared_binary_is_a_gap_without_erasing_other_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            config['go_binaries'] = ['/nonexistent-homelab-test-binary']
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload') as upload:
                self.assertEqual(sbom.collect(config), 1)
            upload.assert_called_once()
            self.assertFalse(sbom.fresh(config))

    def test_docker_projects_use_compose_service_and_actual_image_content(self):
        old = {'name': '/stack-api-abc', 'project': 'stack', 'service': 'api', 'image': 'sha256:' + 'a' * 64}
        new = {**old, 'name': '/stack-api-def'}
        self.assertEqual(sbom.image_scopes([old]), sbom.image_scopes([new]))
        self.assertEqual(sbom.image_scopes([old])[0]['target'], old['image'])
        with self.assertRaisesRegex(sbom.CollectionError, 'multiple'):
            sbom.image_scopes([old, {**new, 'image': 'sha256:' + 'b' * 64}])

    def test_api_header_is_a_file_argument_not_a_credential_argument(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            Path(config['header_file']).write_text('X-Api-Key: sentinel-secret\n')
            with patch.object(sbom, 'command', return_value='{}') as run:
                sbom.api(config, 'bom')
            arguments = run.call_args.args[0]
            self.assertIn('@' + config['header_file'], arguments)
            self.assertNotIn('sentinel-secret', ' '.join(arguments))
            self.assertNotIn('--insecure', arguments)

    def test_lan_upload_pins_caddy_without_disabling_certificate_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            config['resolve'] = ['vulns.homelab.example:443:10.42.0.202']
            with patch.object(sbom, 'command', return_value='{}') as run:
                sbom.api(config, 'bom')
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[arguments.index('--resolve') + 1], config['resolve'][0])
            self.assertNotIn('--insecure', arguments)

    def test_import_must_complete_successfully_before_reporting_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            token = '22222222-2222-4222-8222-222222222222'
            for status in ('FAILED', None):
                with self.subTest(status=status), patch.object(sbom, 'api', side_effect=[
                    {'token': token}, {'processing': False, 'status': status}
                ]), self.assertRaises(sbom.CollectionError):
                    sbom.upload(config, {'name': 'os'}, Path(temp) / 'bom.json')
            with patch.object(sbom, 'api', side_effect=[
                {'token': token}, {'processing': False, 'status': 'COMPLETED'}
            ]):
                sbom.upload(config, {'name': 'os'}, Path(temp) / 'bom.json')

    def test_native_parent_portfolio_is_attached_to_each_uploaded_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            config = self.fixture(Path(temp))
            with patch.object(sbom, 'api', side_effect=[
                {'token': '22222222-2222-4222-8222-222222222222'},
                {'processing': False, 'status': 'COMPLETED'}
            ]) as api:
                sbom.upload(config, {'name': 'os'}, Path(temp) / 'bom.json')
            self.assertIn(('parentUUID', config['parent_uuid']), api.call_args_list[0].args[2])

    def test_library_release_symlink_is_resolved_without_changing_project_name(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release = root / 'releases' / '1.0'
            release.mkdir(parents=True)
            current = root / 'current'
            current.symlink_to(release, target_is_directory=True)
            config = self.fixture(root)
            config['libraries'] = [{'deployment': 'example', 'path': str(current)}]
            with patch.object(sbom, 'docker_targets', return_value=[]), patch.object(sbom, 'upload'), \
                    patch.object(sbom, 'trivy_command', wraps=sbom.trivy_command) as command:
                self.assertEqual(sbom.collect(config), 0)
            scope = command.call_args_list[-1].args[1]
            self.assertEqual(scope['target'], str(release.resolve()))
            self.assertEqual(scope['name'], 'library/example')

    def vendor_fixture(self, root):
        config = self.fixture(root)
        release = root / 'release'
        release.mkdir()
        jar = release / 'application.jar'
        jar.write_bytes(b'installed release artifact')
        archive = root / 'release.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            bundle.add(jar, arcname='application.jar')
        bom = root / 'vendor-bom.json'
        bom.write_text(json.dumps({**BOM, 'metadata': {'component': {'version': '1.0'}}}))
        scope = {'name': 'library/example', 'kind': 'rootfs', 'target': str(release),
                 'packages': 'library', 'vendor_bom': {
                     'path': str(bom), 'sha256': hashlib.sha256(bom.read_bytes()).hexdigest(),
                     'version': '1.0', 'archive': str(archive),
                     'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}}
        return config, scope

    def test_vendor_sbom_requires_exact_installed_jars_and_pinned_release_archive(self):
        for change in ('jar', 'extra-jar', 'archive', 'bom'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config, scope = self.vendor_fixture(root)
                target = {'jar': root / 'release/application.jar', 'extra-jar': root / 'release/extra.jar',
                          'archive': root / 'release.tar.gz', 'bom': root / 'vendor-bom.json'}[change]
                target.write_bytes(b'changed')
                (root / 'tmp').mkdir()
                with self.assertRaises(sbom.CollectionError):
                    sbom.scan(config, scope, root / 'bom.json', root)

    def test_verified_vendor_sbom_does_not_require_a_java_index_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, scope = self.vendor_fixture(root)
            (root / 'tmp').mkdir()
            with patch.object(sbom, 'trivy_command', wraps=sbom.trivy_command) as command:
                sbom.scan(config, scope, root / 'bom.json', root)
            command.assert_not_called()
            self.assertEqual(sbom.validate_bom(root / 'bom.json'), 1)

    def test_os_and_library_scans_are_distinct_and_native_binaries_use_rootfs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.fixture(root)
            config['go_binaries'] = ['/usr/local/bin/filebrowser']
            config['libraries'] = [{'deployment': 'news-embeddings', 'path': '/opt/news-embeddings/venv'}]
            scopes = sbom.declared_scopes(config)
            self.assertEqual([scope['packages'] for scope in scopes], ['os', 'library', 'library'])
            self.assertEqual(scopes[1]['kind'], 'rootfs')
            argv = sbom.trivy_command(config, scopes[0], root / 'bom.json', root)
            self.assertIn('cyclonedx', argv)
            self.assertIn('--skip-dirs', argv)

    def test_fleet_contains_news_helper_and_explicitly_excludes_external_guests(self):
        play = yaml.safe_load((ROOT / 'ansible/playbooks/sbom-upload.yml').read_text())[0]
        self.assertIn('news_embeddings_servers', play['hosts'])
        tasks = yaml.safe_load((ROOT / 'ansible/roles/sbom_upload/tasks/main.yml').read_text())
        guard = tasks[0]['ansible.builtin.assert']['that']
        self.assertTrue(any('next-plaid' in item and 'eu-law-db' in item for item in guard))
        self.assertFalse(any('update_monitor' in task.get('ansible.builtin.include_role', {}).get('name', '') for task in tasks))
        initial = next(task for task in tasks if task['name'] == 'Run an explicitly requested initial upload')
        self.assertTrue(initial['ansible.builtin.systemd_service']['no_block'])
