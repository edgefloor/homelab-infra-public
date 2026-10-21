import importlib.util
import json
import os
import errno
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ansible/roles/update_monitor/files'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INVENTORY = load('homelab_deployment_inventory', SOURCE / 'homelab_deployment_inventory.py')
MONITOR = load('coverage_monitor_test', SOURCE / 'homelab_cve_monitor.py')
SNAPSHOT = load('coverage_snapshot_test', SOURCE / 'homelab_incident_snapshot.py')


class DeploymentCoverageTests(unittest.TestCase):
    def setUp(self):
        # Discovery fixtures have no scheduled jobs. Scheduler-specific tests
        # supply their own temporary paths instead of inspecting the runner.
        scheduled_directories = {
            '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
            '/etc/cron.weekly', '/etc/cron.monthly', '/var/spool/cron/crontabs',
        }
        original_glob = Path.glob
        original_is_file = Path.is_file

        def fixture_glob(path, pattern, **kwargs):
            if str(path) in scheduled_directories:
                return iter(())
            return original_glob(path, pattern, **kwargs)

        def fixture_is_file(path):
            if path == Path('/etc/crontab'):
                return False
            return original_is_file(path)

        self.enterContext(mock.patch.object(INVENTORY.Path, 'glob', fixture_glob))
        self.enterContext(mock.patch.object(INVENTORY.Path, 'is_file', fixture_is_file))

    def process_fixture(self, root, pid=42):
        directory = root / str(pid)
        (directory / 'ns').mkdir(parents=True)
        namespace = root / 'namespace'
        namespace.write_text('namespace')
        (directory / 'ns/pid').symlink_to(namespace)
        binary = root / 'app'
        binary.write_bytes(b'executable')
        (directory / 'exe').symlink_to(binary)
        (directory / 'stat').write_text(str(pid) + ' (app) S ' + '0 ' * 18 + '123')
        (directory / 'cgroup').write_text('0::/system.slice/app.service\n')
        (directory / 'maps').write_text('')
        (directory / 'status').write_text(
            'Name:\tsecret-process-name\nUid:\t999 999 999 999\n'
            'Gid:\t991 991 991 991\nCapInh:\t0000000000000400\n'
            'CapPrm:\t0000000000000400\nCapEff:\t0000000000000400\n'
            'CapBnd:\t0000000000000400\nCapAmb:\t0000000000000400\n'
            'NoNewPrivs:\t1\nSeccomp:\t2\n')
        (directory / 'environ').write_text('TOKEN=never-collect-this')
        return directory, namespace.stat().st_ino

    def test_process_privileges_retain_only_allowlisted_kernel_facts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, namespace = self.process_fixture(root)
            gaps = []
            processes = INVENTORY.process_inventory(root, namespace, INVENTORY.digest, gaps, 'host')
        self.assertEqual([], gaps)
        self.assertEqual(1, len(processes))
        facts = processes[0]['privileges']
        self.assertEqual('complete', facts['status'])
        self.assertEqual([999] * 4, facts['values']['Uid'])
        self.assertEqual('0000000000000400', facts['values']['CapEff'])
        self.assertEqual(1, facts['values']['NoNewPrivs'])
        self.assertEqual(2, facts['values']['Seccomp'])
        self.assertNotIn('secret-process-name', json.dumps(processes))
        self.assertNotIn('never-collect-this', json.dumps(processes))

    def test_scheduler_selection_ignores_placeholders_and_maps_standard_run_parts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            daily = root / 'etc/cron.daily'
            daily.mkdir(parents=True)
            placeholder = daily / '.placeholder'
            placeholder.write_text('package directory marker\n')
            cron_d_placeholder = root / 'etc/cron.d/.placeholder'
            cron_d_placeholder.parent.mkdir(parents=True, exist_ok=True)
            cron_d_placeholder.write_text('# package directory marker\n')
            job = daily / 'maint'
            job.write_text('#!/bin/sh\n')
            job.chmod(0o755)
            crontab = root / 'etc/crontab'
            crontab.write_text(
                'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n'
                '25 6 * * * root test -x /usr/sbin/anacron || '
                '{ cd / && run-parts --report /etc/cron.daily; }\n')

            ignored, ignored_gaps = INVENTORY.scheduled_file(
                placeholder, filesystem_root=root,
                run_parts_selector=lambda _: ['/etc/cron.daily/maint'])
            ignored_cron_d, ignored_cron_d_gaps = INVENTORY.scheduled_file(
                cron_d_placeholder, filesystem_root=root)
            selected, selected_gaps = INVENTORY.scheduled_file(
                crontab, filesystem_root=root,
                run_parts_selector=lambda _: ['/etc/cron.daily/maint'])

        self.assertEqual([], ignored['executables'])
        self.assertEqual('ineligible', ignored['scheduler_selection'])
        self.assertEqual([], ignored_gaps)
        self.assertEqual([], ignored_cron_d['executables'])
        self.assertEqual('ineligible', ignored_cron_d['scheduler_selection'])
        self.assertEqual([], ignored_cron_d_gaps)
        self.assertEqual(['/etc/cron.daily/maint', '/usr/bin/run-parts'],
                         selected['executables'])
        self.assertEqual([], selected_gaps)

    def test_unsupported_scheduler_command_is_scoped_to_owned_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            tool = root / 'usr/bin/readelf'
            info.mkdir(parents=True)
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b'readelf')
            tool.chmod(0o755)
            (root / 'var/lib/dpkg/status').write_text(
                'Package: binutils\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 2.44-3\n\n')
            (info / 'binutils:amd64.list').write_text('/usr/bin/readelf\n')
            cron = root / 'operator-crontab'
            cron.write_text(
                '* * * * * /usr/bin/readelf /tmp/upload | /usr/bin/cat\n')
            scheduled, unsupported = INVENTORY.scheduled_file(cron)
            cron.write_text(
                '* * * * * /bin/true | /usr/bin/readelf /tmp/upload\n')
            second_command, second_unsupported = INVENTORY.scheduled_file(cron)
            domain = {'id': 'inspection', 'packages': ['binutils'],
                'files': ['/usr/bin/readelf'], 'entries': [], 'inputs': [],
                'authority_paths': ['/usr/bin/readelf'],
                'disposition': 'administrative_input_boundary'}
            observation = {'id': 'inspection', 'entries': [], 'inputs': [],
                'files': ['/usr/bin/readelf'], 'authority_paths': [{
                    'path': '/usr/bin/readelf', 'status': 'complete'}],
                'evidence_refs': ['receipt:inspection']}
            evidence = INVENTORY.package_consumer_evidence(
                root, [{'name': 'binutils', 'version': '2.44-3',
                    'ecosystem': 'debian', 'source_name': 'binutils',
                    'source_version': '2.44-3', 'purl': ''}], [], [],
                [scheduled], namespace={'kind': 'host', 'host': 'host'},
                execution_domains=[domain],
                execution_observations=[observation])

        self.assertEqual(['1:unsupported-command'], unsupported)
        self.assertEqual([], scheduled['executables'])
        self.assertEqual(['/usr/bin/readelf'],
                         scheduled['unresolved_executables'])
        self.assertEqual(['1:unsupported-command'], second_unsupported)
        self.assertEqual([], second_command['executables'])
        self.assertEqual(['/bin/true'],
                         second_command['unresolved_executables'])
        self.assertTrue(evidence[0]['consumer_coverage_complete'])
        self.assertEqual([{
            'kind': 'scheduled_execution', 'path': str(cron),
            'sha256': scheduled['sha256'],
            'reasons': ['1:unsupported-command'],
            'executables': ['/usr/bin/readelf']}],
            evidence[0]['consumer_coverage_dependencies'])

    def test_e2scrub_cron_guard_uses_observed_systemd_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cron = root / 'etc/cron.d/e2scrub_all'
            cron.parent.mkdir(parents=True)
            cron.write_text(
                '57 3 * * 0 root test -e /run/systemd/system || '
                'SERVICE_MODE=1 /usr/libexec/e2fsprogs/e2scrub_all_cron\n'
                '52 3 * * * root test -e /run/systemd/system || '
                'SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n')
            systemd = root / 'run/systemd/system'
            systemd.mkdir(parents=True)

            inactive, inactive_gaps = INVENTORY.scheduled_file(
                cron, filesystem_root=root)
            systemd.rmdir()
            active, active_gaps = INVENTORY.scheduled_file(
                cron, filesystem_root=root)
            cron.write_text(
                '52 3 * * * root test -e /run/systemd/system || '
                'SERVICE_MODE=1 /sbin/e2scrub_all -A -r ; '
                '/usr/bin/readelf /tmp/upload\n')
            unsupported_tail, tail_gaps = INVENTORY.scheduled_file(
                cron, filesystem_root=root)

        self.assertEqual([], inactive_gaps)
        self.assertEqual([], inactive['executables'])
        self.assertTrue(all(record['guard_active'] for record in
                            inactive['selection_records']))
        self.assertEqual([], active_gaps)
        self.assertEqual([
            '/sbin/e2scrub_all',
            '/usr/libexec/e2fsprogs/e2scrub_all_cron'],
            active['executables'])
        self.assertEqual(['1:unsupported-command'], tail_gaps)
        self.assertEqual([], unsupported_tail['executables'])
        self.assertNotIn('selection_records', unsupported_tail)

    def test_e2scrub_midword_hash_does_not_hide_a_trailing_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cron = root / 'operator-crontab'
            (root / 'run/systemd/system').mkdir(parents=True)
            cron.write_text(
                '* * * * * test -e /run/systemd/system || '
                'SERVICE_MODE=1 /sbin/e2scrub_all -A -r#keep ; '
                '/usr/bin/readelf /tmp/upload\n')

            scheduled, unsupported = INVENTORY.scheduled_file(
                cron, filesystem_root=root)

        self.assertEqual(['1:unsupported-command'], unsupported)
        self.assertEqual([], scheduled['executables'])
        self.assertNotIn('selection_records', scheduled)

    def test_compound_and_shell_dispatched_cron_commands_stay_unresolved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cron = root / 'operator-crontab'
            commands = [
                '/bin/true ; /usr/bin/readelf /tmp/upload',
                "/bin/sh -c '/usr/bin/readelf /tmp/upload'",
                "cd / && run-parts --report '/etc/cron.daily; }'",
            ]
            results = []
            for command in commands:
                cron.write_text('* * * * * ' + command + '\n')
                results.append(INVENTORY.scheduled_file(cron))

        self.assertTrue(all(gaps == ['1:unsupported-command']
                            for _, gaps in results))
        self.assertTrue(all(job['executables'] == [] for job, _ in results))
        self.assertTrue(all('selection_records' not in job
                            for job, _ in results))

    def test_missing_credentials_do_not_erase_other_process_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, namespace = self.process_fixture(root)
            (directory / 'status').unlink()
            gaps = []
            processes = INVENTORY.process_inventory(root, namespace, INVENTORY.digest, gaps, 'host')
        self.assertEqual(1, len(processes))
        self.assertEqual({}, processes[0]['privileges']['values'])
        self.assertEqual('incomplete', processes[0]['privileges']['status'])
        self.assertIn('process-privileges-incomplete:host:42', gaps)

    def test_process_disappearance_or_pid_reuse_cannot_create_identity_edges(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, namespace = self.process_fixture(root)
            original_read = Path.read_text
            reads = []

            def changing_stat(path, *args, **kwargs):
                value = original_read(path, *args, **kwargs)
                if path == directory / 'stat':
                    reads.append(path)
                    if len(reads) > 1:
                        return value[:-3] + '456'
                return value

            gaps = []
            with mock.patch.object(Path, 'read_text', autospec=True, side_effect=changing_stat):
                self.assertEqual([], INVENTORY.process_inventory(root, namespace, INVENTORY.digest, gaps, 'host'))
            self.assertIn('process-changed-during-observation:host:42', gaps)
            (directory / 'exe').unlink()
            gaps = []
            self.assertEqual([], INVENTORY.process_inventory(root, namespace, INVENTORY.digest, gaps, 'host'))
            self.assertIn('process-disappeared:host:42', gaps)
            fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            fields[6] = str(0x00200000)
            (directory / 'stat').write_text('42 (kernel-thread) ' + ' '.join(fields))
            gaps = []
            self.assertEqual([], INVENTORY.process_inventory(root, namespace, INVENTORY.digest, gaps, 'host'))
            self.assertEqual([], gaps)

    def test_effective_unit_and_process_mismatch_preserves_both_sources(self):
        unit = INVENTORY.unit_evidence({
            'Id': 'app.service', 'MainPID': '42', 'ControlGroup': '/system.slice/app.service',
            'User': '999', 'Group': '991', 'NoNewPrivileges': 'yes',
            'Environment': 'TOKEN=never-collect-this',
            'ExecStart': '{ path=/usr/bin/app ; argv[]=/usr/bin/app --password=hidden ; }'})
        process = {'pid': 42, 'start_ticks': '123',
                   'cgroup': ['0::/system.slice/app.service'],
                   'privileges': {'kind': 'observation', 'source': 'proc.status',
                                  'values': {'Uid': [0] * 4, 'Gid': [991] * 4, 'NoNewPrivs': 0}}}
        comparison = INVENTORY.service_execution_identity(unit, [process])
        self.assertEqual('disagreement', comparison['status'])
        self.assertEqual({'User', 'NoNewPrivileges'}, {d['field'] for d in comparison['differences']})
        self.assertEqual('999', unit['execution_settings']['values']['User'])
        self.assertEqual(0, comparison['effective_uid'])
        self.assertNotIn('never-collect-this', json.dumps(unit))
        self.assertNotIn('hidden', json.dumps(unit))
        missing = INVENTORY.service_execution_identity(unit, [])
        self.assertEqual('main_process_not_observed', missing['reason'])
        self.assertNotIn('effective_uid', missing)
        process['cgroup'] = ['0::/another.service']
        self.assertNotIn('effective_uid', INVENTORY.service_execution_identity(unit, [process]))
        unit['MainPID'] = '0'
        self.assertEqual('no_current_main_process', INVENTORY.service_execution_identity(unit, [])['reason'])

    def test_permission_evidence_follows_symlink_target_and_preserves_acl_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            target = root / 'release' / 'app'
            target.parent.mkdir()
            target.write_text('app')
            target.chmod(0o664)
            link = root / 'app'
            link.symlink_to(target)
            with mock.patch.object(INVENTORY.os, 'getxattr', create=True, side_effect=OSError(errno.ENODATA, 'absent')):
                facts = INVENTORY.path_access_evidence(link)
            self.assertEqual('complete', facts['status'])
            entries = {entry['path']: entry for entry in facts['entries']}
            self.assertEqual('symlink', entries[str(link)]['type'])
            self.assertEqual('0o664', entries[str(target)]['mode'])
            self.assertIn(str(target.parent), entries)
            self.assertEqual({'status': 'absent'}, entries[str(target)]['posix_acl'])
            with mock.patch.object(INVENTORY.os, 'getxattr', create=True, side_effect=PermissionError(errno.EACCES, 'denied')):
                unknown = INVENTORY.path_access_evidence(link)
            self.assertEqual('incomplete', unknown['status'])
            self.assertEqual({'status': 'unknown'}, next(e for e in unknown['entries'] if e['path'] == str(target))['posix_acl'])

    def test_runtime_identity_tracks_privilege_changes_without_process_ids(self):
        observed = {'execution_observations': [{'unit': 'app.service',
            'process_privileges': {'values': {'Uid': [999] * 4, 'CapEff': '0000000000000400'}}}]}
        changed = json.loads(json.dumps(observed))
        changed['execution_observations'][0]['process_privileges']['values']['Uid'] = [0] * 4
        self.assertNotEqual(INVENTORY.stable_runtime_identity(observed), INVENTORY.stable_runtime_identity(changed))
        container = {'name': 'app', 'process_privileges': [{'pid': 42, 'start_ticks': '1',
            'executable': '/app', 'privileges': observed['execution_observations'][0]['process_privileges']}]}
        restarted = json.loads(json.dumps(container))
        restarted['process_privileges'][0].update(pid=99, start_ticks='3')
        self.assertEqual(INVENTORY.container_binding(container), INVENTORY.container_binding(restarted))
        self.assertEqual(INVENTORY.container_binding(container),
                         INVENTORY.container_binding(INVENTORY.container_binding(container)))

    def test_permission_walk_retains_multihop_links_and_resolves_dotdot_after_links(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(INVENTORY.os, 'getxattr', create=True,
                                  side_effect=OSError(errno.ENODATA, 'absent')):
            root = Path(temp).resolve()
            original = root / 'usr/bin/tool'
            alternative = root / 'etc/alternatives/tool'
            current = root / 'opt/current'
            binary = root / 'opt/releases/v1/tool'
            shared = root / 'opt/releases/shared/tool'
            for path in (original, alternative, current, binary, shared):
                path.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text('tool')
            shared.write_text('shared tool')
            original.symlink_to(alternative)
            alternative.symlink_to('../../opt/current/tool')
            current.symlink_to('releases/v1')
            facts = INVENTORY.path_access_evidence(original)
            self.assertEqual('complete', facts['status'])
            entries = {entry['path']: entry for entry in facts['entries']}
            for path in (original, alternative, current):
                self.assertEqual('symlink', entries[str(path)]['type'])
            for path in (alternative.parent, alternative.parent.parent, binary.parent):
                self.assertEqual('directory', entries[str(path)]['type'])
            self.assertEqual('file', entries[str(binary)]['type'])
            alternative.unlink()
            alternative.symlink_to('../../opt/current/../shared/tool')
            facts = INVENTORY.path_access_evidence(original)
            self.assertEqual('complete', facts['status'])
            self.assertIn(str(shared), {entry['path'] for entry in facts['entries']})
            alternative.unlink()
            alternative.symlink_to(original)
            facts = INVENTORY.path_access_evidence(original)
            self.assertEqual('incomplete', facts['status'])
            self.assertTrue(any(gap.endswith(':symlink-cycle') for gap in facts['gaps']))

    def test_transient_unit_privileges_are_retained_without_changing_runtime_identity(self):
        config = {'host': 'test', 'deployments': [
            {'id': 'app', 'units': ['app.service']}], 'configuration_roots': []}
        unit_names = ['app.service', 'session-old.service']

        def fake_run(argv):
            if 'list-units' in argv and '--type=service' in argv:
                return ''.join(name + ' loaded inactive dead Unit\n' for name in unit_names)
            if 'list-units' in argv or 'list-unit-files' in argv or argv[0] == 'ss':
                return ''
            raise AssertionError(argv)

        def unit(name):
            return {'Id': name, 'MainPID': '0', 'User': '999' if name == 'app.service' else '0',
                    'Group': '991', 'NoNewPrivileges': 'yes', 'ActiveState': 'inactive'}

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                mock.patch.object(INVENTORY, 'properties', side_effect=unit), \
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
            before = INVENTORY.discover(config, Path(temp), package_requests={'host': [], 'images': {}})
            unit_names[1] = 'session-new.service'
            after = INVENTORY.discover(config, Path(temp), package_requests={'host': [], 'images': {}})
        self.assertEqual(before['runtime_sha256'], after['runtime_sha256'])
        self.assertEqual({'app.service', 'session-new.service'}, {s['Id'] for s in after['services']})
        self.assertEqual('0', next(s for s in after['services'] if s['Id'] == 'session-new.service')
                         ['execution_settings']['values']['User'])

    def test_observed_principal_reaches_graph_and_missing_credentials_withdraw_it(self):
        config = {'host': 'test', 'deployments': [
            {'id': 'app', 'units': ['app.service']}], 'configuration_roots': []}

        def fake_run(argv):
            if 'list-units' in argv and '--type=service' in argv:
                return 'app.service loaded active running App\n'
            if 'list-units' in argv or 'list-unit-files' in argv or argv[0] == 'ss':
                return ''
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, _ = self.process_fixture(root)
            (root / 'self' / 'ns').mkdir(parents=True)
            (root / 'self' / 'ns' / 'pid').symlink_to(root / 'namespace')
            unit = {'Id': 'app.service', 'ActiveState': 'active', 'MainPID': '42',
                    'User': '0', 'Group': '991', 'NoNewPrivileges': 'yes',
                    'ControlGroup': '/system.slice/app.service',
                    'ExecStart': '{ path=' + str(root / 'app') + ' ; argv[]=secret ; }',
                    'Environment': 'TOKEN=never-collect-this'}
            with mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                    mock.patch.object(INVENTORY, 'properties', return_value=unit), \
                    mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
                evidence = INVENTORY.discover(config, root, package_requests={'host': [], 'images': {}})
                (directory / 'status').unlink()
                missing = INVENTORY.discover(config, root, package_requests={'host': [], 'images': {}})
                with mock.patch.object(INVENTORY, 'MAX_ACCESS_BYTES', 1):
                    bounded = INVENTORY.discover(config, root, package_requests={'host': [], 'images': {}})

        self.assertEqual('disagreement', evidence['services'][0]['execution_identity']['status'])
        self.assertNotIn('never-collect-this', json.dumps(evidence))
        self.assertNotEqual(evidence['runtime_sha256'], missing['runtime_sha256'])
        self.assertEqual([], bounded['path_access'])
        self.assertIn('path-access-coverage-incomplete:byte-limit', bounded['gaps'])
        graph = SNAPSHOT.lifecycle_graph('test', 'generation', 1, 100,
                                        {'discovery': evidence}, {})
        edge = next(item for item in graph['assertions'] if item['relation'] == 'EXECUTES_AS')
        self.assertEqual('principal:test:uid:999', edge['object_key'])
        self.assertEqual('derived', edge['kind'])
        self.assertEqual([graph['evidence'][0]['id']], edge['derivation']['input_evidence_ids'])
        self.assertIn('main-process:42:123', edge['derivation']['input_refs'])
        inputs = graph['evidence'][0]['content']['input_observations']
        self.assertEqual(evidence['path_access'], inputs['path_access'])
        witness = next(process for process in inputs['processes'] if process['pid'] == 42)
        self.assertEqual('123', witness['start_ticks'])
        self.assertEqual([999] * 4, witness['privileges']['values']['Uid'])
        self.assertEqual({'pid', 'start_ticks', 'executable', 'sha256', 'cgroup', 'privileges'},
                         set(witness))
        self.assertNotIn('secret', json.dumps(inputs))
        self.assertEqual('principal', next(item for item in graph['resources']
                         if item['resource_key'] == edge['object_key'])['kind'])
        refreshed = SNAPSHOT.lifecycle_graph('test', 'generation', 2, 200,
                                            {'discovery': missing}, {}, previous_graph=graph)
        withdrawn = next(item for item in refreshed['assertions'] if item['relation'] == 'EXECUTES_AS')
        self.assertEqual('withdrawn', withdrawn['status'])
        self.assertFalse(any(item['relation'] in {'CONSTRAINT_EXCLUDES', 'BUILD_DISPOSITION'}
                             for item in graph['assertions']))

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

    def test_container_fingerprint_ignores_log_rotation_but_tracks_changed_code(self):
        container = {'id': 'one', 'image_id': 'image', 'changes': ['A /var/log/old.log'], 'main_pid': 10}
        rotated = {**container, 'changes': ['A /var/log/new.log'], 'main_pid': 20}
        self.assertEqual(INVENTORY.container_binding(container), INVENTORY.container_binding(rotated))
        modified = {**container, 'changes': ['C /usr/bin/caddy']}
        self.assertNotEqual(INVENTORY.container_binding(container), INVENTORY.container_binding(modified))

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

    def test_library_scan_discards_findings_when_metadata_changes(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(sys.modules, {'homelab_deployment_inventory': INVENTORY}), \
                mock.patch.object(INVENTORY, 'metadata_inventory', side_effect=[{'resolved_path': temp, 'sha256': 'old'}, {'sha256': 'new'}]), \
                mock.patch.object(MONITOR, 'run_json', return_value={'Results': [{'Vulnerabilities': [{}]}]}):
            result = MONITOR.scan_library('trivy', Path(temp), Path(temp),
                                         {'deployment': 'test', 'path': temp, 'types': ['node-pkg']})
            self.assertEqual(result['_homelab_library']['status'], 'failed')
            self.assertEqual(result['Results'], [])

    def test_package_evidence_preserves_binary_source_architecture_and_loaded_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            info.mkdir(parents=True)
            (root / 'var/lib/dpkg/status').write_text(
                'Package: libssl3t64\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 3.5.1-1\n'
                'Source: openssl (3.5.1-1)\nMulti-Arch: same\n\n')
            (info / 'libssl3t64:amd64.list').write_text(
                '/usr/lib/x86_64-linux-gnu/libssl.so.3\n')
            requests = [{'name': 'libssl3t64', 'version': '3.5.1-1',
                         'ecosystem': 'debian', 'source_name': 'openssl',
                         'source_version': '3.5.1-1', 'purl': ''}]
            processes = [{'pid': 7, 'start_ticks': '11', 'executable': '/usr/bin/app',
                          'sha256': 'a' * 64, 'cgroup': ['0::/system.slice/app.service'],
                          'loaded_file_identities': [{
                              'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3',
                              'sha256': 'b' * 64, 'inode': 42}]}]
            services = [{'Id': 'app.service', 'MainPID': '7',
                         'ControlGroup': '/system.slice/app.service',
                         'deployments': ['app']}]
            evidence = INVENTORY.package_consumer_evidence(
                root, requests, processes, services, [],
                namespace={'kind': 'host', 'host': 'test'})

        self.assertEqual('libssl3t64', evidence[0]['installed']['binary_package'])
        self.assertEqual('openssl', evidence[0]['installed']['source_package'])
        self.assertEqual('amd64', evidence[0]['installed']['architecture'])
        self.assertEqual(['app'], evidence[0]['observations'][0]['consumer']['deployments'])
        self.assertFalse(evidence[0]['consumer_coverage_complete'])

    def test_finite_execution_domain_can_complete_exact_package_membership(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            tool = root / 'usr/bin/readelf'
            info.mkdir(parents=True)
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b'readelf')
            (root / 'var/lib/dpkg/status').write_text(
                'Package: binutils\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 2.44-3\n\n')
            (info / 'binutils:amd64.list').write_text('/usr/bin/readelf\n')
            request = [{'name': 'binutils', 'version': '2.44-3',
                        'ecosystem': 'debian', 'source_name': 'binutils',
                        'source_version': '2.44-3', 'purl': ''}]
            domain = {'id': 'native-elf-inspection', 'packages': ['binutils'],
                      'files': ['/usr/bin/readelf'],
                      'entries': ['forced-broker'],
                      'inputs': ['accepted-installed-artifact'],
                      'authority_paths': ['/usr/bin/readelf'],
                      'disposition': 'administrative_input_boundary'}
            observation = {'id': 'native-elf-inspection',
                           'entries': ['forced-broker'],
                           'inputs': ['accepted-installed-artifact'],
                           'files': ['/usr/bin/readelf'],
                           'authority_paths': [{'path': '/usr/bin/readelf',
                                               'status': 'complete'}],
                           'evidence_refs': ['receipt:broker-v2']}

            evidence = INVENTORY.package_consumer_evidence(
                root, request, [], [], [],
                namespace={'kind': 'host', 'host': 'network-ops'},
                execution_domains=[domain],
                execution_observations=[observation])

        self.assertTrue(evidence[0]['consumer_coverage_complete'])
        self.assertTrue(evidence[0]['execution_domains'][0]['complete'])
        self.assertEqual('administrative_input_boundary',
                         evidence[0]['execution_domains'][0]['disposition'])

    def test_new_execution_input_invalidates_domain_completeness(self):
        package = {'binary_package': 'binutils', 'files': ['/usr/bin/readelf'],
                   'file_inventory_sha256': 'a' * 64}
        domain = {'id': 'native-elf-inspection', 'packages': ['binutils'],
                  'files': ['/usr/bin/readelf'], 'entries': ['forced-broker'],
                  'inputs': ['accepted-installed-artifact'],
                  'authority_paths': ['/usr/bin/readelf'],
                  'disposition': 'administrative_input_boundary'}
        observation = {'id': 'native-elf-inspection',
                       'entries': ['forced-broker'],
                       'inputs': ['accepted-installed-artifact', 'https-download'],
                       'files': ['/usr/bin/readelf'],
                       'authority_paths': [{'path': '/usr/bin/readelf',
                                           'status': 'complete'}],
                       'evidence_refs': ['receipt:changed-input']}

        result = INVENTORY.reconcile_execution_domains(
            [package], [domain], [observation])

        self.assertFalse(result['packages']['binutils']['complete'])
        self.assertEqual(['https-download'], result['domains'][0]['unassigned_inputs'])
        self.assertFalse(result['domains'][0]['coverage']['input']['complete'])

    def test_conflicting_domain_observations_cannot_be_overwritten(self):
        package = {'binary_package': 'binutils', 'files': ['/usr/bin/readelf'],
                   'relevant_files': ['/usr/bin/readelf'],
                   'file_inventory_sha256': 'a' * 64}
        domain = {'id': 'native-elf-inspection', 'packages': ['binutils'],
                  'files': ['/usr/bin/readelf'], 'entries': ['forced-broker'],
                  'inputs': ['accepted-installed-artifact'],
                  'authority_paths': ['/usr/bin/readelf'],
                  'disposition': 'administrative_input_boundary'}
        base = {'id': domain['id'], 'entries': domain['entries'],
                'files': domain['files'],
                'authority_paths': [{'path': '/usr/bin/readelf',
                                     'status': 'complete'}],
                'evidence_refs': ['receipt:one']}
        conflicting = [
            {**base, 'inputs': ['accepted-installed-artifact', 'https-download']},
            {**base, 'inputs': ['accepted-installed-artifact']}]

        result = INVENTORY.reconcile_execution_domains(
            [package], [domain], conflicting)

        self.assertFalse(result['packages']['binutils']['complete'])
        self.assertTrue(result['domains'][0]['observation_conflict'])
        self.assertEqual(['https-download'], result['domains'][0][
            'unassigned_inputs'])
        self.assertEqual(2, len(result['domains'][0]['observation_records']))

    def test_package_membership_is_union_of_complete_action_domains(self):
        package = {'binary_package': 'binutils',
                   'files': ['/usr/bin/readelf', '/usr/bin/objdump'],
                   'relevant_files': ['/usr/bin/readelf', '/usr/bin/objdump'],
                   'file_inventory_sha256': 'a' * 64}
        declarations = [{
            'id': name, 'packages': ['binutils'], 'files': [path],
            'entries': [name], 'inputs': ['installed-artifact'],
            'authority_paths': [path],
            'disposition': 'administrative_input_boundary'}
            for name, path in (('readelf-inspection', '/usr/bin/readelf'),
                               ('objdump-inspection', '/usr/bin/objdump'))]
        observations = [{
            'id': item['id'], 'entries': item['entries'],
            'inputs': item['inputs'], 'files': item['files'],
            'authority_paths': [{'path': item['files'][0],
                                 'status': 'complete'}],
            'evidence_refs': ['receipt:' + item['id']]}
            for item in declarations]

        result = INVENTORY.reconcile_execution_domains(
            [package], declarations, observations)

        self.assertTrue(all(item['complete'] for item in result['domains']))
        self.assertTrue(result['packages']['binutils']['complete'])
        self.assertEqual([], result['packages']['binutils'][
            'unassigned_relevant_files'])

    def test_retained_admission_facts_derive_broker_members_without_labels(self):
        declaration = {
            'id': 'native-elf-inspection', 'packages': ['binutils'],
            'files': ['/usr/bin/readelf'],
            'entries': ['ssh-key:homelab-agent:forced-broker'],
            'inputs': ['accepted-installed-artifact'],
            'authority_paths': ['/usr/bin/readelf', '/gateway'],
            'entry_rules': [{'kind': 'forced_ssh_command',
                             'command': '/remote'}],
            'input_rules': [{'kind': 'verified_file_contracts',
                             'member': 'accepted-installed-artifact',
                             'paths': ['/remote', '/gateway']}],
        }
        facts = {
            'accounts': [{'name': 'homelab-agent', 'authorized_keys': {
                'records': [{'status': 'parsed',
                             'forced_command': '/remote'}]}}],
            'services': [], 'scheduled': [], 'listeners': [],
            'files': [
                {'path': '/remote', 'status': 'complete',
                 'contract_status': 'matched', 'sha256': 'a' * 64},
                {'path': '/gateway', 'status': 'complete',
                 'contract_status': 'matched', 'sha256': 'b' * 64},
                {'path': '/usr/bin/readelf', 'status': 'complete',
                 'contract_status': 'not-required', 'sha256': 'c' * 64}],
            'evidence_refs': ['admission:retained-shape']}

        observations = INVENTORY.derive_execution_domain_observations(
            [declaration], facts)

        self.assertEqual(['ssh-key:homelab-agent:forced-broker'],
                         observations[0]['entries'])
        self.assertEqual(['accepted-installed-artifact'],
                         observations[0]['inputs'])
        self.assertEqual(['/usr/bin/readelf'], observations[0]['files'])
        self.assertEqual('derived', observations[0]['claim_kind'])
        self.assertEqual('finite-execution-observation/v1',
                         observations[0]['derivation']['rule'])

    def test_snapshot_artifact_input_requires_exact_controlled_authority(self):
        declaration = {
            'id': 'native-elf-inspection', 'packages': ['binutils'],
            'files': ['/usr/bin/readelf'], 'entries': [],
            'inputs': ['accepted-installed-artifact'],
            'authority_paths': ['/usr/bin/readelf'],
            'input_rules': [{'kind': 'verified_file_contracts',
                'member': 'accepted-installed-artifact', 'paths': ['/gateway'],
                'require_snapshot_artifact_authority': True}],
        }
        facts = {
            'accounts': [], 'services': [], 'scheduled': [], 'listeners': [],
            'snapshot_artifact_inputs': [{
                'namespace': {'kind': 'host', 'host': 'network-ops'},
                'path': '/usr/local/bin/coredns', 'sha256': 'c' * 64,
                'artifact_id': 'sha256:' + 'c' * 64}],
            'files': [
                {'path': '/gateway', 'status': 'complete',
                 'contract_status': 'matched',
                 'authority_status': 'controlled', 'sha256': 'a' * 64},
                {'path': '/usr/bin/readelf', 'status': 'complete',
                 'contract_status': 'not-required',
                 'authority_status': 'controlled', 'sha256': 'b' * 64},
                {'path': '/usr/local/bin/coredns', 'status': 'complete',
                 'contract_status': 'not-required',
                 'authority_status': 'controlled', 'sha256': 'c' * 64}],
            'evidence_refs': ['snapshot:one']}

        controlled = INVENTORY.derive_execution_domain_observations(
            [declaration], facts)
        changed = json.loads(json.dumps(facts))
        changed['files'][2]['authority_status'] = 'unresolved'
        unsupported = INVENTORY.derive_execution_domain_observations(
            [declaration], changed)

        self.assertEqual(['accepted-installed-artifact'],
                         controlled[0]['inputs'])
        self.assertEqual([], unsupported[0]['inputs'])

    def test_scanner_snapshot_inputs_bind_exact_host_namespace_path_and_hash(self):
        reports = [{
            '_homelab_host_binary': {
                'path': '/usr/local/bin/coredns',
                'resolved_path': '/opt/coredns/releases/one/coredns',
                'sha256': 'd' * 64},
            'Results': [{
                'Target': '/usr/local/bin/coredns',
                'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1'}]}]}, {
            '_homelab_runtime': {'image_id': 'sha256:' + 'e' * 64},
            'Results': [{
                'Target': 'usr/bin/tool',
                'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-2'}]}]},
        ]

        inputs = INVENTORY.scanner_snapshot_artifact_inputs(
            reports, 'network-ops')

        self.assertEqual([{
            'namespace': {'kind': 'host', 'host': 'network-ops'},
            'path': '/usr/local/bin/coredns', 'sha256': 'd' * 64,
            'artifact_id': 'sha256:' + 'd' * 64}, {
            'namespace': {'kind': 'container', 'host': 'network-ops',
                          'image_id': 'sha256:' + 'e' * 64},
            'path': '/usr/bin/tool',
            'artifact_id': 'sha256:' + 'e' * 64,
            'support_status': 'unsupported',
            'reason': 'container-input-authority-unavailable'}], inputs)
        observation = INVENTORY.derive_execution_domain_observations([{
            'id': 'native-elf-inspection', 'files': [], 'entries': [],
            'inputs': ['accepted-installed-artifact'], 'authority_paths': [],
            'input_rules': [{'kind': 'verified_file_contracts',
                'member': 'accepted-installed-artifact', 'paths': ['/gateway'],
                'require_snapshot_artifact_authority': True}],
        }], {
            'snapshot_artifact_inputs': inputs,
            'accounts': [], 'services': [], 'scheduled': [], 'listeners': [],
            'files': [{
                'path': '/gateway', 'status': 'complete',
                'contract_status': 'matched', 'authority_status': 'controlled'}, {
                'path': '/usr/local/bin/coredns', 'status': 'complete',
                'sha256': 'd' * 64, 'contract_status': 'not-required',
                'authority_status': 'controlled'}],
            'evidence_refs': ['snapshot:container-unsupported'],
        })
        self.assertEqual([], observation[0]['inputs'])

    def test_unrestricted_ssh_availability_does_not_invent_tool_input(self):
        declaration = {
            'id': 'available-tools', 'packages': ['binutils'],
            'files': ['/usr/bin/objdump'],
            'entries': ['ssh-key:root:unrestricted'],
            'inputs': ['operator-selected-file'], 'authority_paths': [],
            'entry_rules': [{'kind': 'unrestricted_ssh_key'}],
            'input_rules': [{'kind': 'entry_present',
                             'member': 'operator-selected-file',
                             'prefix': 'ssh-key:'}]}
        facts = {
            'accounts': [{'name': 'root', 'authorized_keys': {'records': [{
                'status': 'parsed', 'unrestricted_key_options': True}]}}],
            'services': [], 'scheduled': [], 'listeners': [],
            'files': [{'path': '/usr/bin/objdump', 'status': 'complete'}],
            'evidence_refs': ['admission-only']}

        observations = INVENTORY.derive_execution_domain_observations(
            [declaration], facts)

        self.assertEqual(['ssh-key:root:unrestricted'],
                         observations[0]['entries'])
        self.assertEqual([], observations[0]['inputs'])

    def test_known_empty_relevant_file_set_does_not_fall_back_to_manifest(self):
        package = {'binary_package': 'sample',
                   'files': ['/usr/share/doc/sample/copyright'],
                   'relevant_files': []}
        declaration = {'id': 'sample-current-use', 'packages': ['sample'],
                       'files': [], 'entries': [], 'inputs': [],
                       'authority_paths': [],
                       'disposition': 'administrative_input_boundary'}
        observation = {'id': declaration['id'], 'entries': [], 'inputs': [],
                       'files': [], 'authority_paths': [],
                       'evidence_refs': ['manifest:known-empty']}

        result = INVENTORY.reconcile_execution_domains(
            [package], [declaration], [observation])

        self.assertTrue(result['packages']['sample']['complete'])
        self.assertEqual([], result['packages']['sample'][
            'unassigned_relevant_files'])

    def test_elf_dependency_selector_expands_current_package_membership(self):
        declaration = {
            'id': 'native-elf-declared-dependencies',
            'packages': ['libbinutils', 'libsframe1'],
            'files': [], 'elf_dependency_roots': ['/usr/bin/readelf'],
            'entries': ['readelf.service'], 'inputs': ['current-service-input'],
            'authority_paths': [],
            'entry_rules': [{'kind': 'service', 'id': 'readelf.service'}],
            'input_rules': [{'kind': 'current_service_contract',
                             'service': 'readelf.service',
                             'members': ['current-service-input'],
                             'paths': ['/lib/libsframe.so']}],
            'disposition': 'administrative_input_boundary'}
        facts = {
            'services': [{'Id': 'readelf.service', 'ActiveState': 'active'}],
            'scheduled': [], 'listeners': [], 'accounts': [],
            'elf_linkage_scans': [{'root': '/usr/bin/readelf',
                                   'status': 'complete'}],
            'elf_declared_dependencies': [{'root': '/usr/bin/readelf',
                                           'path': '/lib/libsframe.so',
                                           'package': 'libsframe1',
                                           'status': 'complete'}],
            'files': [{'path': '/lib/libsframe.so', 'status': 'complete',
                       'authority_status': 'controlled',
                       'contract_status': 'not-required',
                       'sha256': 'd' * 64}],
            'evidence_refs': ['elf-receipt:one']}
        package = {'binary_package': 'libsframe1',
                   'files': ['/lib/libsframe.so'],
                   'relevant_files': ['/lib/libsframe.so']}
        unrelated = {'binary_package': 'libbinutils',
                     'files': ['/lib/libbfd.so'], 'relevant_files': []}

        expanded = INVENTORY.expand_execution_domains([declaration], facts)
        observations = INVENTORY.derive_execution_domain_observations(
            expanded, facts)
        result = INVENTORY.reconcile_execution_domains(
            [package, unrelated], expanded, observations)

        self.assertEqual(['/lib/libsframe.so'], expanded[0]['files'])
        self.assertEqual(['/lib/libsframe.so'],
                         expanded[0]['authority_paths'])
        self.assertTrue(result['domains'][0]['complete'])
        self.assertTrue(result['packages']['libsframe1']['complete'])
        self.assertEqual([], result['packages']['libbinutils']['domains'])
        self.assertFalse(result['packages']['libbinutils']['complete'])

    def test_incomplete_elf_dependency_selector_keeps_domain_open(self):
        declaration = {
            'id': 'native-elf-declared-dependencies', 'packages': ['libsframe1'],
            'files': [], 'elf_dependency_roots': ['/usr/bin/readelf'],
            'entries': [], 'inputs': [], 'authority_paths': [],
            'disposition': 'administrative_input_boundary'}
        facts = {
            'services': [], 'scheduled': [], 'listeners': [], 'accounts': [],
            'elf_linkage_scans': [{'root': '/usr/bin/readelf',
                                   'status': 'incomplete'}],
            'elf_declared_dependencies': [], 'files': [],
            'evidence_refs': ['elf-receipt:incomplete']}
        package = {'binary_package': 'libsframe1', 'files': [],
                   'relevant_files': []}

        expanded = INVENTORY.expand_execution_domains([declaration], facts)
        observations = INVENTORY.derive_execution_domain_observations(
            expanded, facts)
        result = INVENTORY.reconcile_execution_domains(
            [package], expanded, observations)

        self.assertEqual('incomplete', expanded[0]['selector_evidence']['status'])
        self.assertTrue(observations[0]['status'] == 'incomplete')
        self.assertFalse(result['domains'][0]['complete'])
        self.assertFalse(result['packages']['libsframe1']['complete'])

    def test_new_service_executable_invalidates_operation_membership(self):
        declaration = {
            'id': 'ddns', 'packages': ['python3-minimal'],
            'files': ['/usr/bin/python3'],
            'operation_files': ['/usr/local/libexec/ddns'],
            'entries': ['ddns.service'], 'inputs': [],
            'authority_paths': [],
            'entry_rules': [{'kind': 'service', 'id': 'ddns.service'}],
            'disposition': 'requires_work'}
        facts = {
            'services': [{'Id': 'ddns.service', 'ActiveState': 'active',
                          'executables': ['/usr/local/libexec/ddns',
                                          '/usr/bin/curl']}],
            'scheduled': [], 'listeners': [], 'accounts': [],
            'files': [{'path': path, 'status': 'complete',
                       'authority_status': 'controlled',
                       'contract_status': 'not-required'} for path in
                      ('/usr/bin/python3', '/usr/local/libexec/ddns',
                       '/usr/bin/curl')],
            'evidence_refs': ['service-receipt:one']}
        package = {'binary_package': 'python3-minimal',
                   'files': ['/usr/bin/python3'],
                   'relevant_files': ['/usr/bin/python3']}

        observations = INVENTORY.derive_execution_domain_observations(
            [declaration], facts)
        result = INVENTORY.reconcile_execution_domains(
            [package], [declaration], observations)

        self.assertEqual(['/usr/bin/curl'], result['domains'][0][
            'unassigned_operation_files'])
        self.assertFalse(result['domains'][0]['complete'])
        self.assertFalse(result['packages']['python3-minimal']['complete'])

    def test_execution_fact_collector_verifies_exact_and_literal_contracts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gateway = root / 'gateway'
            script = root / 'script'
            tool = root / 'usr/bin/tool'
            tool.parent.mkdir(parents=True)
            gateway.write_text('exact gateway')
            script.write_text('urllib.request.urlopen\nhttps://api.example.test')
            tool.write_text('tool')
            config = {'execution_domains': [{
                'id': 'domain', 'files': ['/usr/bin/tool'],
                'authority_paths': ['/usr/bin/tool', '/gateway', '/script'],
                'file_contracts': [
                    {'path': '/gateway', 'expected_sha256':
                        INVENTORY.digest(gateway)},
                    {'path': '/script', 'required_literals': [
                        'urllib.request.urlopen', 'https://api.example.test']}]}]}

            facts = INVENTORY.collect_execution_domain_facts(
                config, [], [], [], root)

        files = {item['path']: item for item in facts['files']}
        self.assertEqual('matched', files['/gateway']['contract_status'])
        self.assertEqual('matched', files['/script']['contract_status'])
        self.assertEqual('not-required', files['/usr/bin/tool']['contract_status'])
        self.assertTrue(facts['evidence_refs'][0].startswith(
            'execution-domain-facts:sha256:'))
        self.assertNotIn('exact gateway', json.dumps(facts))

    def test_unassigned_current_consumer_keeps_finite_domain_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            tool = root / 'usr/bin/readelf'
            info.mkdir(parents=True)
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b'readelf')
            tool.chmod(0o755)
            (root / 'var/lib/dpkg/status').write_text(
                'Package: binutils\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 2.44-3\n\n')
            (info / 'binutils:amd64.list').write_text('/usr/bin/readelf\n')
            domain = {'id': 'native-elf-inspection', 'packages': ['binutils'],
                      'files': ['/usr/bin/readelf'], 'entries': ['forced-broker'],
                      'inputs': ['accepted-installed-artifact'],
                      'authority_paths': ['/usr/bin/readelf'],
                      'disposition': 'administrative_input_boundary'}
            observation = {'id': domain['id'], 'entries': ['forced-broker'],
                           'inputs': domain['inputs'], 'files': domain['files'],
                           'authority_paths': [{'path': '/usr/bin/readelf',
                                               'status': 'complete'}],
                           'evidence_refs': ['receipt:broker-v2']}
            requests = [{'name': 'binutils', 'version': '2.44-3',
                         'ecosystem': 'debian', 'source_name': 'binutils',
                         'source_version': '2.44-3', 'purl': ''}]
            services = [{'Id': 'surprise.service', 'ActiveState': 'active',
                         'UnitFileState': 'enabled',
                         'executables': ['/usr/bin/readelf'], 'deployments': []}]

            evidence = INVENTORY.package_consumer_evidence(
                root, requests, [], services, [],
                namespace={'kind': 'host', 'host': 'network-ops'},
                execution_domains=[domain],
                execution_observations=[observation])

        self.assertFalse(evidence[0]['consumer_coverage_complete'])
        self.assertEqual(['surprise.service'], evidence[0][
            'execution_domains'][0]['unassigned_entries'])

    def test_discover_reconciles_retained_finite_domain_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'self/ns').mkdir(parents=True)
            namespace = root / 'namespace'
            namespace.write_text('namespace')
            (root / 'self/ns/pid').symlink_to(namespace)
            info = root / 'var/lib/dpkg/info'
            tool = root / 'usr/bin/readelf'
            info.mkdir(parents=True)
            tool.parent.mkdir(parents=True)
            tool.write_bytes(b'readelf')
            (root / 'var/lib/dpkg/status').write_text(
                'Package: binutils\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 2.44-3\n\n')
            (info / 'binutils:amd64.list').write_text('/usr/bin/readelf\n')
            domain = {'id': 'native-elf-inspection', 'packages': ['binutils'],
                      'files': ['/usr/bin/readelf'],
                      'entries': ['ssh-key:homelab-agent:forced-broker'],
                      'inputs': ['accepted-installed-artifact'],
                      'authority_paths': ['/usr/bin/readelf'],
                      'disposition': 'administrative_input_boundary',
                      'entry_rules': [{'kind': 'forced_ssh_command',
                          'command': '/usr/local/libexec/homelab-agent-remote'}],
                      'input_rules': [{'kind': 'verified_file_contracts',
                          'member': 'accepted-installed-artifact',
                          'paths': ['/remote', '/gateway']}]}
            facts = {'accounts': [{'name': 'homelab-agent',
                       'authorized_keys': {'records': [{'status': 'parsed',
                       'forced_command': '/usr/local/libexec/homelab-agent-remote'}]}}],
                     'files': [
                         {'path': '/usr/bin/readelf', 'status': 'complete',
                          'contract_status': 'not-required'},
                         {'path': '/remote', 'status': 'complete',
                          'contract_status': 'matched'},
                         {'path': '/gateway', 'status': 'complete',
                          'contract_status': 'matched'}],
                     'services': [], 'scheduled': [], 'listeners': [],
                     'evidence_refs': ['facts:broker-v2']}
            config = {'host': 'network-ops', 'deployments': [],
                      'configuration_roots': [], 'package_capabilities': [],
                      'execution_domains': [domain]}
            requests = {'host': [{'name': 'binutils', 'version': '2.44-3',
                'ecosystem': 'debian', 'source_name': 'binutils',
                'source_version': '2.44-3', 'purl': '', 'vulnerable': True}],
                'images': {}}

            def fake_run(argv):
                if argv[0] in {'systemctl', 'ss'}:
                    return ''
                raise AssertionError(argv)

            with mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                    mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
                evidence = INVENTORY.discover(
                    config, root, package_requests=requests,
                    execution_facts=facts, filesystem_root=root)
                changed = json.loads(json.dumps(facts))
                changed['accounts'].append({'name': 'surprise-agent',
                    'authorized_keys': {'records': [{'status': 'parsed',
                    'forced_command': '/usr/local/libexec/homelab-agent-remote'}]}})
                invalidated = INVENTORY.discover(
                    config, root, package_requests=requests,
                    execution_facts=changed, filesystem_root=root)

        self.assertTrue(evidence['package_evidence'][0][
            'consumer_coverage_complete'])
        self.assertFalse(invalidated['package_evidence'][0][
            'consumer_coverage_complete'])
        self.assertNotEqual(evidence['runtime_sha256'],
                            invalidated['runtime_sha256'])

    def test_scanner_requests_use_full_native_package_versions(self):
        report = {'_homelab_scan_kind': 'os', 'Results': [{
            'Type': 'debian', 'Class': 'os-pkgs', 'Target': '/',
            'Packages': [{'Name': 'libacl1', 'Version': '2.3.2',
                          'Release': '2+b1', 'SrcName': 'acl',
                          'SrcVersion': '2.3.2', 'SrcRelease': '2',
                          'Identifier': {'PURL':
                              ('pkg:deb/debian/libacl1@2.3.2-2%2Bb1'
                               '?arch=amd64&distro=debian-13.6')}}],
            'Vulnerabilities': [{'PkgName': 'libacl1',
                                 'InstalledVersion': '2.3.2-2+b1'}]}]}

        requests = INVENTORY.scanner_package_requests([report])['host']

        self.assertEqual(1, len(requests))
        self.assertEqual('2.3.2-2+b1', requests[0]['version'])
        self.assertEqual('2.3.2-2', requests[0]['source_version'])
        self.assertTrue(requests[0]['vulnerable'])

    def test_native_scanner_request_preserves_purl_epoch_qualifier(self):
        identity = INVENTORY.native_scanner_identity({
            'Name': 'libepoch', 'Version': '1.2', 'Release': '3', 'Epoch': 1,
            'SrcName': 'epoch', 'SrcVersion': '1.2', 'SrcRelease': '3',
            'SrcEpoch': 1, 'Identifier': {'PURL':
                'pkg:deb/debian/libepoch@1.2-3?arch=amd64&epoch=1'}})

        self.assertEqual('1:1.2-3', identity['version'])
        self.assertEqual('1:1.2-3', identity['source_version'])

    def test_package_activation_binds_owned_executable_not_unit_definition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            info.mkdir(parents=True)
            (root / 'var/lib/dpkg/status').write_text(
                'Package: app\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 1\n\n')
            (info / 'app.list').write_text(
                '/usr/bin/app\n/usr/lib/systemd/system/app.service\n')
            executable = root / 'usr/bin/app'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'app')
            unit = root / 'usr/lib/systemd/system/app.service'
            unit.parent.mkdir(parents=True)
            unit.write_text('[Service]\nExecStart=/usr/bin/app\n')
            request = {'name': 'app', 'version': '1', 'ecosystem': 'debian',
                       'source_name': 'app', 'source_version': '1', 'purl': '',
                       'installation': 'os', 'consumer_class': 'host-os',
                       'artifact_id': '', 'architecture': 'amd64', 'vulnerable': True}
            services = [{'Id': 'app.service', 'FragmentPath':
                         '/usr/lib/systemd/system/app.service', 'ActiveState': 'active',
                         'UnitFileState': 'enabled', 'executables': ['/usr/bin/app'],
                         'deployments': ['app']}]
            evidence = INVENTORY.package_consumer_evidence(
                root, [request], [], services, [],
                namespace={'kind': 'host', 'host': 'test'})

        self.assertEqual(1, len(evidence[0]['observations']))
        observation = evidence[0]['observations'][0]
        self.assertEqual('service_execution', observation['relation'])
        self.assertEqual('/usr/bin/app', observation['file']['path'])
        self.assertNotEqual('/usr/lib/systemd/system/app.service',
                            observation['file']['path'])

    def test_live_timer_binds_an_idle_static_service_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            info = root / 'var/lib/dpkg/info'
            info.mkdir(parents=True)
            (root / 'var/lib/dpkg/status').write_text(
                'Package: app\nStatus: install ok installed\n'
                'Architecture: amd64\nVersion: 1\n\n')
            (info / 'app.list').write_text('/usr/bin/app\n')
            executable = root / 'usr/bin/app'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'app')
            request = {'name': 'app', 'version': '1', 'ecosystem': 'debian',
                       'source_name': 'app', 'source_version': '1', 'purl': '',
                       'installation': 'os', 'consumer_class': 'host-os',
                       'artifact_id': '', 'architecture': 'amd64',
                       'vulnerable': True}
            services = [{'Id': 'app.service', 'ActiveState': 'inactive',
                         'UnitFileState': 'static', 'executables': ['/usr/bin/app'],
                         'activation_sources': ['app.timer'],
                         'deployments': ['app']}]
            evidence = INVENTORY.package_consumer_evidence(
                root, [request], [], services, [],
                namespace={'kind': 'host', 'host': 'test'})

        self.assertEqual('triggered_service_execution',
                         evidence[0]['observations'][0]['relation'])
        self.assertEqual(['app.timer'], evidence[0]['observations'][0]
                         ['consumer']['activation_sources'])

    def test_discovery_discards_raw_systemd_command_arguments(self):
        secret = 'credential=do-not-retain'
        config = {'host': 'test', 'deployments': [{
            'id': 'app', 'units': ['app.service']}],
            'configuration_roots': []}

        def fake_run(argv):
            if 'list-units' in argv:
                return 'app.service loaded active running App\n'
            if 'list-unit-files' in argv:
                return ''
            if argv[0] == 'ss':
                return ''
            raise AssertionError(argv)

        unit = {'Id': 'app.service', 'ActiveState': 'active',
                'UnitFileState': 'static', 'MainPID': '0',
                'ExecStart': '{ path=/usr/bin/app ; argv[]=/usr/bin/app --' + secret + ' ; }',
                'ExecStartPre': '{ path=/usr/bin/check ; argv[]=/usr/bin/check ' + secret + ' ; }'}
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                mock.patch.object(INVENTORY, 'properties', return_value=unit.copy()), \
                mock.patch.object(INVENTORY, 'process_inventory', return_value=[]), \
                mock.patch.object(INVENTORY, 'scanner_package_requests',
                                  side_effect=AssertionError('scanner adapter used')), \
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
            evidence = INVENTORY.discover(
                config, Path(temp),
                package_requests={'host': [], 'images': {}})

        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(secret, serialized)
        self.assertEqual(['/usr/bin/app', '/usr/bin/check'],
                         evidence['services'][0]['executables'])
        self.assertFalse(any(key.startswith('Exec')
                             for key in evidence['services'][0]))

    def test_discovery_uses_only_effective_activation_sources(self):
        config = {'host': 'test', 'deployments': [{
            'id': 'app', 'units': ['app.service', 'active.timer']}],
            'configuration_roots': []}

        def fake_run(argv):
            if 'list-units' in argv:
                return 'app.service loaded inactive dead App\n'
            if 'list-unit-files' in argv and '--type=service' in argv:
                return ''
            if 'list-unit-files' in argv and '--type=timer' in argv:
                return 'active.timer disabled\ninactive.timer disabled\n'
            if 'list-unit-files' in argv:
                return ''
            if argv[0] == 'ss':
                return ''
            raise AssertionError(argv)

        units = {
            'app.service': {
                'Id': 'app.service', 'ActiveState': 'inactive',
                'UnitFileState': 'static', 'MainPID': '0',
                'TriggeredBy': 'active.timer inactive.timer',
                'ExecStart': '{ path=/usr/bin/app ; argv[]=/usr/bin/app ; }'},
            'active.timer': {
                'Id': 'active.timer', 'ActiveState': 'active',
                'UnitFileState': 'disabled', 'Triggers': 'app.service'},
            'inactive.timer': {
                'Id': 'inactive.timer', 'ActiveState': 'inactive',
                'UnitFileState': 'disabled', 'Triggers': 'app.service'},
        }
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                mock.patch.object(INVENTORY, 'properties',
                                  side_effect=lambda unit: units[unit].copy()), \
                mock.patch.object(INVENTORY, 'process_inventory', return_value=[]), \
                mock.patch.object(INVENTORY, 'scanner_package_requests',
                                  return_value={'host': [], 'images': {}}), \
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
            evidence = INVENTORY.discover(config, Path(temp))

        service = evidence['services'][0]
        self.assertEqual(['active.timer'], service['activation_sources'])
        self.assertEqual(['active.timer', 'inactive.timer'],
                         service['configured_activation_sources'])

    def test_template_and_failed_unit_do_not_hide_valid_activation_sources(self):
        config = {'host': 'test', 'deployments': [{
            'id': 'app', 'units': ['app.service', 'worker@*.service',
                                   'good.socket', 'good.timer']}],
            'configuration_roots': []}

        def fake_run(argv):
            unit_type = next((value.removeprefix('--type=') for value in argv
                              if value.startswith('--type=')), '')
            if 'list-units' in argv:
                return {
                    'service': ('app.service loaded inactive dead App\n'
                                'worker@one.service loaded active running Worker\n'),
                    'socket': ('systemd-journald@audit.socket loaded active listening Journal\n'
                               'good.socket loaded active listening Good\n'),
                    'timer': 'good.timer loaded active waiting Good\n',
                    'path': '',
                }[unit_type]
            if 'list-unit-files' in argv:
                return {
                    'service': 'worker@.service enabled\n',
                    'socket': ('systemd-journald@.socket disabled\n'
                               'broken.socket enabled\n'
                               'good.socket enabled\n'),
                    'timer': 'good.timer enabled\n',
                    'path': '',
                }[unit_type]
            if argv[0] == 'ss':
                return ''
            raise AssertionError(argv)

        units = {
            'app.service': {
                'Id': 'app.service', 'ActiveState': 'inactive',
                'UnitFileState': 'static', 'MainPID': '0',
                'TriggeredBy': 'good.socket good.timer',
                'ExecStart': '{ path=/usr/bin/app ; argv[]=/usr/bin/app ; }'},
            'worker@one.service': {
                'Id': 'worker@one.service', 'ActiveState': 'active',
                'UnitFileState': 'enabled', 'MainPID': '20',
                'ExecStart': '{ path=/usr/bin/worker ; argv[]=/usr/bin/worker ; }'},
            'good.socket': {
                'Id': 'good.socket', 'ActiveState': 'active',
                'UnitFileState': 'enabled', 'Triggers': 'app.service'},
            'good.timer': {
                'Id': 'good.timer', 'ActiveState': 'active',
                'UnitFileState': 'enabled', 'Triggers': 'app.service'},
            'systemd-journald@audit.socket': {
                'Id': 'systemd-journald@audit.socket', 'ActiveState': 'active',
                'UnitFileState': 'static',
                'Triggers': 'systemd-journald@audit.service'},
        }
        calls = []

        def fake_properties(unit):
            calls.append(unit)
            if unit in {'worker@.service', 'systemd-journald@.socket',
                        'broken.socket'}:
                raise RuntimeError('neither a valid invocation ID nor unit name')
            return units[unit].copy()

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(INVENTORY, 'run', side_effect=fake_run), \
                mock.patch.object(INVENTORY, 'properties',
                                  side_effect=fake_properties), \
                mock.patch.object(INVENTORY, 'process_inventory', return_value=[]), \
                mock.patch.object(INVENTORY, 'scanner_package_requests',
                                  return_value={'host': [], 'images': {}}), \
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
            evidence = INVENTORY.discover(config, Path(temp))

        activated = {item['Id'] for item in evidence['activated_units']}
        self.assertEqual({
            'good.socket', 'good.timer', 'systemd-journald@audit.socket'},
            activated)
        self.assertNotIn('systemd-journald@.socket', calls)
        self.assertNotIn('worker@.service', calls)
        self.assertIn('worker@one.service', {
            item['Id'] for item in evidence['services']})
        self.assertIn('activated-unit-properties-failed:socket:broken.socket',
                      evidence['gaps'])
        self.assertNotIn('activated-unit-discovery-failed:socket', evidence['gaps'])
        service = evidence['services'][0]
        self.assertEqual(['good.socket', 'good.timer'],
                         service['activation_sources'])
        self.assertEqual(['good.socket', 'good.timer'],
                         service['configured_activation_sources'])

    def test_stable_runtime_identity_ignores_transient_process_fields(self):
        evidence = {
            'containers': [], 'scheduled_files': [], 'activated_units': [],
            'configuration_files': [], 'kernel': {},
            'package_evidence': [{'namespace': {'kind': 'host', 'host': 'test'},
                'installed': {'binary_package': 'app', 'version': '1'},
                'observations': [{'relation': 'loaded_file',
                    'file': {'path': '/usr/lib/libapp.so', 'sha256': 'a' * 64,
                             'inode': 10, 'device': [8, 1]},
                    'consumer': {'kind': 'process', 'pid': 100, 'start_ticks': '20',
                                 'executable': '/usr/bin/app',
                                 'executable_sha256': 'b' * 64,
                                 'service': 'app.service',
                                 'deployments': ['app']}}]}]}
        restarted = json.loads(json.dumps(evidence))
        restarted['package_evidence'][0]['observations'][0]['file']['inode'] = 99
        restarted['package_evidence'][0]['observations'][0]['consumer']['pid'] = 200
        restarted['package_evidence'][0]['observations'][0]['consumer']['start_ticks'] = '30'
        restarted['package_evidence'][0]['observations'].append(
            json.loads(json.dumps(
                restarted['package_evidence'][0]['observations'][0])))

        self.assertEqual(INVENTORY.stable_runtime_identity(evidence),
                         INVENTORY.stable_runtime_identity(restarted))

    def test_stable_runtime_identity_ignores_transient_container_id(self):
        evidence = {
            'containers': [{'id': 'a' * 64, 'name': 'web',
                            'image_id': 'sha256:' + 'c' * 64,
                            'deployments': ['web']}],
            'scheduled_files': [], 'activated_units': [],
            'configuration_files': [], 'kernel': {},
            'relationships': [{
                'subject': 'deployment:test:web', 'relation': 'RUNS_AS',
                'object': 'container:test:' + 'a' * 64,
                'scope': 'runtime:test:web', 'kind': 'observation',
                'status': 'valid'}],
            'package_evidence': []}
        restarted = json.loads(json.dumps(evidence))
        restarted['containers'][0]['id'] = 'b' * 64
        restarted['relationships'][0]['object'] = 'container:test:' + 'b' * 64

        self.assertEqual(INVENTORY.stable_runtime_identity(evidence),
                         INVENTORY.stable_runtime_identity(restarted))

    def test_stable_runtime_identity_covers_declared_package_relationships(self):
        evidence = {
            'containers': [], 'scheduled_files': [], 'activated_units': [],
            'configuration_files': [], 'kernel': {},
            'package_evidence': [{
                'namespace': {'kind': 'host', 'host': 'test'},
                'installed': {'binary_package': 'binutils', 'version': '1'},
                'slots': [{'installation': 'os', 'ecosystem': 'debian'}],
                'file_inventory_sha256': 'a' * 64,
                'artifact_profile': {'kind': 'runtime-or-command',
                                     'classification_complete': True},
                'declared_capabilities': [{'id': 'readelf'}],
                'observations': []}]}
        changed = json.loads(json.dumps(evidence))
        changed['package_evidence'][0]['declared_capabilities'][0]['id'] = 'objdump'

        self.assertNotEqual(INVENTORY.stable_runtime_identity(evidence),
                            INVENTORY.stable_runtime_identity(changed))

    def test_complete_header_manifest_is_not_the_running_kernel(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            header = root / 'usr/include/linux/test.h'
            header.parent.mkdir(parents=True)
            header.write_text('#define TEST 1\n')
            documentation = root / 'usr/share/doc/linux-libc-dev/copyright'
            documentation.parent.mkdir(parents=True)
            documentation.write_text('copyright\n')
            profile = INVENTORY.package_artifact_profile(root, [
                '/usr/include/linux/test.h',
                '/usr/share/doc/linux-libc-dev/copyright'])
            executable = root / 'usr/bin/kernel-tool'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'tool')
            runtime_profile = INVENTORY.package_artifact_profile(
                root, ['/usr/include/linux/test.h', '/usr/bin/kernel-tool'])
            executable_header = root / 'usr/include/linux/executable.h'
            executable_header.write_text('#!/bin/sh\n')
            executable_header.chmod(0o755)
            executable_header_profile = INVENTORY.package_artifact_profile(
                root, ['/usr/include/linux/executable.h'])

        self.assertEqual('development-headers', profile['kind'])
        self.assertTrue(profile['classification_complete'])
        self.assertEqual('runtime-or-command', runtime_profile['kind'])
        self.assertEqual('runtime-or-command', executable_header_profile['kind'])
        self.assertEqual(1, executable_header_profile['executable_file_count'])

    def test_declared_package_capability_follows_installed_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            readelf = root / 'usr/bin/readelf'
            readelf.parent.mkdir(parents=True)
            readelf.write_bytes(b'elf parser')
            packages = [
                {'binary_package': 'binutils', 'dependencies': ['libbinutils']},
                {'binary_package': 'libbinutils', 'dependencies': ['libsframe1']},
                {'binary_package': 'libsframe1', 'dependencies': []},
                {'binary_package': 'unrelated', 'dependencies': []},
            ]
            bindings = INVENTORY.capability_bindings(packages, [{
                'id': 'diagnostic-artifact-inspection',
                'root_package': 'binutils',
                'binary_packages': ['binutils', 'libbinutils', 'libsframe1'],
                'required_executables': ['/usr/bin/readelf'],
                'applications': ['diagnostic-agent'],
                'evidence': ['gateway.py']}], root)

        self.assertEqual(['binutils', 'libbinutils', 'libsframe1'],
                         bindings['libsframe1'][0]['dependency_path'])
        self.assertNotIn('unrelated', bindings)
        self.assertNotIn('constraint_excludes', bindings['binutils'][0])

    def test_unknown_service_and_failed_discovery_stay_gaps(self):
        config = {'host': 'test', 'deployments': [], 'configuration_roots': []}
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
                mock.patch.object(INVENTORY.shutil, 'which', return_value=None):
            evidence = INVENTORY.discover(config, Path(temp))
        self.assertIn('unclassified-service:unexpected.service', evidence['gaps'])
        self.assertIn('listener-discovery-failed', evidence['gaps'])
