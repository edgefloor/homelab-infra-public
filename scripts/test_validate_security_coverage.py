import copy
import unittest

import yaml

from cve_coverage_report import expected_systems
from validate_security_coverage import ROOT, validate


class SecurityCoverageTests(unittest.TestCase):
    def setUp(self):
        self.contract = yaml.safe_load((ROOT / "inventory/security-coverage.yml").read_text())
        self.apps = {yaml.safe_load(p.read_text())["id"] for p in (ROOT / "apps").glob("*.yml")}
        self.systems = set(expected_systems(
            yaml.safe_load((ROOT / "ansible/inventory/hosts.yml").read_text()),
            yaml.safe_load((ROOT / "inventory/workloads.yml").read_text())))

    def test_repository_inventory_has_requirements(self):
        validate(self.contract, self.apps, self.systems)

    def test_new_app_requires_profile(self):
        with self.assertRaisesRegex(ValueError, "application coverage drift"):
            validate(self.contract, self.apps | {"new-app"}, self.systems)

    def test_new_system_cannot_disappear(self):
        with self.assertRaisesRegex(ValueError, "systems missing"):
            validate(self.contract, self.apps, self.systems | {"new-host"})

    def test_target_typo_rejected(self):
        self.contract["applications"]["caddy"]["targets"] = ["cady"]
        with self.assertRaisesRegex(ValueError, "unknown target"):
            validate(self.contract, self.apps, self.systems)

    def test_requirement_missing_rejected(self):
        self.contract["applications"]["caddy"]["adapters"] = []
        with self.assertRaisesRegex(ValueError, "missing targets or required adapters"):
            validate(self.contract, self.apps, self.systems)

    def test_autonomy_cannot_be_enabled_without_executor_contract(self):
        for field in ("patching_enabled", "emergency_measures_enabled"):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                contract["autonomy"][field] = True
                with self.assertRaisesRegex(ValueError, "no authorized executor"):
                    validate(contract, self.apps, self.systems)

    def test_recovery_cannot_be_omitted(self):
        del self.contract["layers"]["recovery"]
        with self.assertRaisesRegex(ValueError, "seven evidence layers"):
            validate(self.contract, self.apps, self.systems)
