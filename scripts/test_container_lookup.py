"""Exercise Docker parsing and failures below the artifact-scope interface."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1]/'ansible/roles/homelab_agent_target/files/homelab_evidence_gateway.py'
spec = importlib.util.spec_from_file_location('lookup_gateway', PATH)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


def response(stdout='', returncode=0, truncated=False):
    return {'stdout': stdout, 'stderr': '', 'returncode': returncode, 'truncated': truncated}


class ContainerLookupTests(unittest.TestCase):
    def test_running_container_is_resolved_from_complete_json_records(self):
        item = {'id':'a'*64, 'name':'/app', 'image_id':'sha256:'+'b'*64,
                'image_ref':'example/app:1', 'running':True, 'state':'running', 'pid':123}
        with mock.patch.object(gateway.Path, 'exists', return_value=True), \
             mock.patch.object(gateway, 'bounded_run', side_effect=[response('a'*64+'\n'), response(json.dumps(item)+'\n')]):
            inventory = gateway.docker_inventory()
        self.assertEqual(inventory['app']['id'], 'a'*64)
        self.assertEqual(inventory['a'*12]['pid'], 123)
        self.assertTrue(inventory['app']['running'])

    def test_failed_or_truncated_list_is_never_an_empty_healthy_inventory(self):
        for result in (response(returncode=1), response('a'*64, truncated=True)):
            with self.subTest(result=result), mock.patch.object(gateway.Path, 'exists', return_value=True), \
                 mock.patch.object(gateway, 'bounded_run', return_value=result):
                with self.assertRaises(ValueError) as caught:
                    gateway.docker_inventory()
                self.assertEqual(caught.exception.details['code'], 'runtime_lookup_failed')
                self.assertEqual(caught.exception.details['lookup']['stage'], 'list')

    def test_failed_malformed_or_partial_inspect_is_never_silently_skipped(self):
        for result in (response(returncode=1), response('malformed'), response('')):
            with self.subTest(result=result), mock.patch.object(gateway.Path, 'exists', return_value=True), \
                 mock.patch.object(gateway, 'bounded_run', side_effect=[response('a'*64+'\n'), result]):
                with self.assertRaises(ValueError) as caught:
                    gateway.docker_inventory()
                self.assertEqual(caught.exception.details['code'], 'runtime_lookup_failed')
                self.assertEqual(caught.exception.details['lookup']['stage'], 'inspect')

    def test_missing_runtime_is_distinct_from_a_successful_empty_inventory(self):
        with mock.patch.object(gateway.Path, 'exists', return_value=False):
            self.assertEqual(gateway.docker_inventory(), {})
            with self.assertRaises(ValueError) as caught:
                gateway.docker_inventory(include_stopped=True)
        self.assertEqual(caught.exception.details['code'], 'runtime_lookup_failed')
