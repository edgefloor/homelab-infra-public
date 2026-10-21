import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'retire_evidence_access', ROOT / 'ansible/roles/retired_evidence_access/files/retire_evidence_access.py')
RETIRE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETIRE)


class EvidenceRetirementTests(unittest.TestCase):
    def test_revokes_only_capability_paths_and_keeps_personal_hermes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = RETIRE.ENDPOINT_PATHS + RETIRE.CONTROLLER_PATHS
            personal = ('/var/lib/hermes-agent/.hermes/config.yaml',
                        '/var/lib/hermes-agent/.hermes/auth.json',
                        '/var/lib/hermes-agent/.hermes/state.db',
                        '/etc/systemd/system/hermes-gateway.service',
                        '/etc/sudoers.d/homelab-admin')
            for name in active + personal:
                path = root / name.lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('retained-fixture')
            result = RETIRE.retire(root, controller=True)
            self.assertEqual(set(result['quarantined_paths']), set(active))
            self.assertNotIn('retained-fixture', str(result))
            archive = root / RETIRE.ARCHIVE.lstrip('/')
            self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
            for name in active:
                self.assertFalse((root / name.lstrip('/')).exists())
                saved = archive / name.lstrip('/')
                self.assertEqual(saved.read_text(), 'retained-fixture')
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            for name in personal:
                self.assertEqual((root / name.lstrip('/')).read_text(), 'retained-fixture')
            self.assertFalse(RETIRE.retire(root, controller=True)['changed'])

    def test_endpoint_only_retirement_does_not_move_personal_controller_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / RETIRE.CONTROLLER_PATHS[2].lstrip('/')
            key.mkdir(parents=True)
            (key / 'id_ed25519').write_text('fixture-key')
            self.assertFalse(RETIRE.retire(root)['changed'])
            self.assertEqual((key / 'id_ed25519').read_text(), 'fixture-key')


if __name__ == '__main__':
    unittest.main()
