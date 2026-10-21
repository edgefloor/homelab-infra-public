import copy
import unittest

from guard_dependency_track_plan import validate


class ResourceGuardTests(unittest.TestCase):
    def setUp(self):
        before = {"vm_id": 214, "cpu": [{"cores": 2, "architecture": "amd64"}],
                  "memory": [{"dedicated": 2048, "swap": 512}], "disk": [{"size": 8}]}
        after = copy.deepcopy(before)
        after["cpu"][0]["cores"] = 4
        after["memory"][0]["dedicated"] = 8192
        self.resource = {"address": 'proxmox_virtual_environment_container.managed["incident"]',
                         "change": {"actions": ["update"], "before": before, "after": after}}
        self.plan = {"resource_changes": [self.resource]}

    def test_reviewed_increase(self):
        self.assertEqual(validate(self.plan), "reviewed-update")

    def test_converged(self):
        self.resource["change"]["actions"] = ["no-op"]
        self.assertEqual(validate(self.plan), "converged")

    def test_rejects_other_guest(self):
        self.resource["address"] = 'proxmox_virtual_environment_container.managed["helix"]'
        with self.assertRaises(ValueError):
            validate(self.plan)

    def test_rejects_disk_change(self):
        self.resource["change"]["after"]["disk"][0]["size"] = 16
        with self.assertRaises(ValueError):
            validate(self.plan)

    def test_rejects_replacement(self):
        self.resource["change"]["actions"] = ["delete", "create"]
        with self.assertRaises(ValueError):
            validate(self.plan)

    def test_rejects_missing_iso_file(self):
        self.plan["resource_changes"].append({"address": "proxmox_virtual_environment_download_file.omarchy",
                                              "change": {"actions": ["delete"]}})
        with self.assertRaises(ValueError):
            validate(self.plan)


if __name__ == "__main__":
    unittest.main()
