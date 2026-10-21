import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('trivy_health', Path(__file__).resolve().parents[1] /
    'ansible/roles/trivy_server/files/trivy_health.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class TrivyHealthTests(unittest.TestCase):
    def test_fresh_database_is_accepted(self):
        health.validate_version({'Version': '0.74.0', 'VulnerabilityDB': {
            'Version': 2, 'UpdatedAt': '2026-09-08T00:00:00Z', 'NextUpdate': '2026-09-09T00:00:00Z'}},
            now=1788868800)

    def test_missing_stale_future_or_incompatible_database_is_rejected(self):
        for db in ({}, {'Version': 1, 'UpdatedAt': '2026-09-08T00:00:00Z', 'NextUpdate': '2026-09-09T00:00:00Z'},
                   {'Version': 2, 'UpdatedAt': '2026-09-01T00:00:00Z', 'NextUpdate': '2026-09-02T00:00:00Z'},
                   {'Version': 2, 'UpdatedAt': '2026-10-01T00:00:00Z', 'NextUpdate': '2026-10-02T00:00:00Z'}):
            with self.assertRaises((ValueError, KeyError)):
                health.validate_version({'Version': '0.74.0', 'VulnerabilityDB': db}, now=1788868800)
