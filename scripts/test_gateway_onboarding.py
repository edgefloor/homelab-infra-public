import importlib.util
from pathlib import Path
import unittest

PATH=Path(__file__).resolve().parents[1]/'ansible/roles/hermes_agent/files/configure_gateway_onboarding.py'
spec=importlib.util.spec_from_file_location('onboarding_patch',PATH)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OnboardingPatchTests(unittest.TestCase):
    def test_installs_guard_once_and_survives_redeployment(self):
        source=(
            'async def test():\n'
            + module.ANCHOR
            + '        if history:\n'
            + '            return\n'
        )
        changed=module.patched(source)
        self.assertEqual(changed.count(".get('enabled', True)"),1)
        self.assertEqual(changed,module.patched(changed))

    def test_changed_upstream_source_requires_review(self):
        with self.assertRaises(ValueError): module.patched('async def test():\n    pass\n')
