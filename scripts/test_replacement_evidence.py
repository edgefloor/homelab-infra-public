import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from test_analyzer_contract import gateway

spec = importlib.util.spec_from_file_location('artifact_replacement', Path(__file__).resolve().parents[1]/'ansible/roles/homelab_agent_target/files/artifact_replacement.py')
replacement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replacement)


class ReplacementTests(unittest.TestCase):
    def test_same_binary_is_not_a_verified_fix(self):
        result = gateway.compare_replacement({'sha256': 'a'*64, 'status': 'symbol_reported'},
                                             {'sha256': 'a'*64, 'status': 'not_reported'})
        self.assertEqual(result['status'], 'same_executable')
        self.assertFalse(result['verified_fix'])

    def test_repository_cannot_be_changed_to_a_url_or_private_registry(self):
        self.assertEqual(replacement.repository('caddy:2'), 'docker.io/library/caddy')
        for image in ('http://localhost/a', 'localhost:123/a', 'example.org/a', 'ghcr.io/a/../b'):
            with self.subTest(image=image), self.assertRaises(ValueError):
                replacement.repository(image)

    def test_comparison_requires_matching_provenance_and_never_claims_safety(self):
        identity = {'advisory': 'GHSA-example', 'executable_sha256': 'a'*64, 'database': {'modified': 'one'}}
        baseline = {'sha256': 'a'*64, 'status': 'symbol_reported', 'cache': {'identity': identity}}
        candidate = {'sha256': 'b'*64, 'status': 'not_reported',
                     'cache': {'identity': {**identity, 'executable_sha256': 'b'*64}}}
        for state, expected in [('not_reported', 'match_removed'), ('module_reported', 'match_retained'),
                                ('package_reported', 'match_retained'), ('symbol_reported', 'match_retained'),
                                ('unavailable', 'visibility_gap')]:
            with self.subTest(state=state):
                report = gateway.compare_replacement(baseline, {**candidate, 'status': state})
                self.assertEqual(report['status'], expected)
                self.assertFalse(report['verified_fix'])
                self.assertEqual(report['deployment_exposure'], 'not_assessed')
        candidate['cache']['identity']['database'] = {'modified': 'two'}
        self.assertEqual(gateway.compare_replacement(baseline, candidate)['status'], 'visibility_gap')
        self.assertEqual(gateway.compare_replacement(baseline, {'sha256': 'b'*64, 'status': 'not_reported'})['status'], 'visibility_gap')

    def test_descriptor_rejects_external_urls_and_excessive_download(self):
        valid = {'digest': 'sha256:'+'a'*64, 'size': 1}
        for invalid in ({**valid, 'urls': ['http://localhost/internal']}, {**valid, 'size': replacement.MAX_DOWNLOAD+1},
                        {**valid, 'size': True}, {**valid, 'digest': '../escape'}, None):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                replacement.descriptor(invalid)

    def test_layer_replacement_whiteouts_links_and_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def layer(name, content=b'', link=False):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    if link:
                        info.type, info.linkname = tarfile.SYMTYPE, '/etc/shadow'
                    archive.addfile(info, io.BytesIO(content))
                data = buffer.getvalue()
                sha = hashlib.sha256(data).hexdigest()
                (root/sha).write_bytes(data)
                return {'digest': 'sha256:'+sha, 'size': len(data)}
            first = layer('usr/bin/app', b'first')
            second = layer('usr/bin/app', b'second')
            output = root/'output'
            replacement.extract_executable(root, {'layers': [first, second]}, '/usr/bin/app', output)
            self.assertEqual(output.read_bytes(), b'second')
            for last in (layer('usr/bin/.wh.app'), layer('usr/bin/.wh..wh..opq'), layer('usr/bin/app', link=True), layer('usr/bin', link=True)):
                with self.subTest(layer=last), self.assertRaises(ValueError):
                    replacement.extract_executable(root, {'layers': [first, last]}, '/usr/bin/app', output)
            (root/first['digest'].split(':')[1]).write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                replacement.checked_blob(root, first)


if __name__ == '__main__':
    unittest.main()
