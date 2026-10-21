import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_app_manifests.py")
SPEC = importlib.util.spec_from_file_location("validate_app_manifests", MODULE_PATH)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


VALID = {
    "schema_version": 1,
    "id": "example",
    "name": "Example",
    "upstream": {
        "repository": "https://github.com/example/example",
        "release": "v1.0.0",
        "commit": "a" * 40,
        "distribution": "official_binary",
    },
    "runtime": "native_systemd",
    "environments": {
        "staging": {"target": "example", "status": "planned"},
        "production": {"target": "example", "status": "blocked"},
    },
    "routing": {"caddy": "lan", "pangolin": "remote"},
    "health": {"local_url": "http://127.0.0.1:8000/health", "expected_units": ["example.service"]},
    "state": {"paths": ["/var/lib/example"], "backup_required_before_cutover": True},
}


class ManifestValidationTests(unittest.TestCase):
    def validate(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.yml"
            path.write_text(subject.yaml.safe_dump(data))
            subject.validate(path)

    def test_valid_manifest(self):
        self.validate(copy.deepcopy(VALID))

    def test_rejects_unpinned_commit(self):
        data = copy.deepcopy(VALID)
        data["upstream"]["commit"] = "main"
        with self.assertRaisesRegex(ValueError, "40-character SHA"):
            self.validate(data)

    def test_rejects_unknown_ingress(self):
        data = copy.deepcopy(VALID)
        data["routing"]["caddy"] = "cloudflare"
        with self.assertRaisesRegex(ValueError, "unsupported Caddy policy"):
            self.validate(data)

    def test_accepts_hybrid_container_and_package_distribution(self):
        data = copy.deepcopy(VALID)
        data["runtime"] = "hybrid"
        data["upstream"]["distribution"] = "official_container_and_packages"
        self.validate(data)
