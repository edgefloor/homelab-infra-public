import copy
import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_infrastructure_ownership.py")
SPEC = importlib.util.spec_from_file_location("validate_infrastructure_ownership", MODULE_PATH)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = subject
SPEC.loader.exec_module(subject)


TOFU = """
locals {
  managed_containers = {
    app = {
      vm_id = 201
      hostname = "app"
      address = "192.168.1.20/24"
      mount_points = [{ volume = "/data", path = "/storage" }]
    }
  }
}
"""

ANSIBLE = {
    "all": {
        "vars": {
            "infrastructure_contract": {
                "schema_version": 1,
                "default_host_kind": "opentofu_guest",
                "host_kinds": {
                    "hypervisor": "proxmox_host",
                    "edge": "external_vps",
                },
            }
        },
        "children": {
            "guests": {"hosts": {"app": {"ansible_host": "192.168.1.20"}}},
            "infrastructure": {
                "hosts": {
                    "hypervisor": {"ansible_host": "192.168.1.10"},
                    "edge": {"ansible_host": "203.0.113.10"},
                }
            },
        },
    }
}

ROUTES = {
    "homelab_routing": {
        "unmanaged_route_targets": {"192.168.1.1": "physical router"},
        "routes": [
            {"id": "app", "caddy": {"upstream": "192.168.1.20:8080"}},
            {"id": "hypervisor", "caddy": {"upstream": "https://192.168.1.10:8006"}},
            {"id": "router", "caddy": {"upstream": "https://192.168.1.1:8443"}},
            {
                "id": "remote",
                "pangolin": {
                    "target": {"hostname": "edge", "port": 443, "method": "https"}
                },
            },
        ],
    }
}


class InfrastructureOwnershipValidationTests(unittest.TestCase):
    def validate(self, tofu=TOFU, ansible=None, routes=None):
        subject.validate(
            tofu,
            copy.deepcopy(ANSIBLE if ansible is None else ansible),
            copy.deepcopy(ROUTES if routes is None else routes),
            Path("locals.tf"),
            Path("hosts.yml"),
            Path("routes.yml"),
        )

    def test_accepts_matching_desired_state_and_explicit_exceptions(self):
        self.validate()

    def test_rejects_ansible_guest_without_opentofu_container(self):
        ansible = copy.deepcopy(ANSIBLE)
        ansible["all"]["children"]["guests"]["hosts"]["orphan"] = {
            "ansible_host": "192.168.1.21"
        }
        with self.assertRaisesRegex(ValueError, "Ansible guest orphan has no OpenTofu container"):
            self.validate(ansible=ansible)

    def test_rejects_opentofu_guest_without_ansible_host(self):
        ansible = copy.deepcopy(ANSIBLE)
        del ansible["all"]["children"]["guests"]["hosts"]["app"]
        with self.assertRaisesRegex(ValueError, "OpenTofu guest app has no Ansible host"):
            self.validate(ansible=ansible)

    def test_rejects_address_mismatch(self):
        ansible = copy.deepcopy(ANSIBLE)
        ansible["all"]["children"]["guests"]["hosts"]["app"]["ansible_host"] = "192.168.1.99"
        with self.assertRaisesRegex(ValueError, "address 192.168.1.99 differs from OpenTofu 192.168.1.20"):
            self.validate(ansible=ansible)

    def test_rejects_duplicate_vmid(self):
        tofu = TOFU.replace(
            "    app = {",
            """    other = {
      vm_id = 201
      hostname = "other"
      address = "192.168.1.21/24"
    }
    app = {""",
        )
        with self.assertRaisesRegex(ValueError, "duplicate guest VMID 201"):
            self.validate(tofu=tofu)

    def test_rejects_unknown_route_target(self):
        routes = copy.deepcopy(ROUTES)
        routes["homelab_routing"]["routes"][0]["caddy"]["upstream"] = "192.168.1.99:8080"
        with self.assertRaisesRegex(ValueError, "target 192.168.1.99 is not in Ansible inventory"):
            self.validate(routes=routes)

    def test_accepts_named_route_target_from_inventory(self):
        routes = copy.deepcopy(ROUTES)
        routes["homelab_routing"]["routes"][0]["caddy"]["upstream"] = "app:8080"
        self.validate(routes=routes)

    def test_rejects_unexplained_route_exception(self):
        routes = copy.deepcopy(ROUTES)
        routes["homelab_routing"]["unmanaged_route_targets"]["192.168.1.1"] = ""
        with self.assertRaisesRegex(ValueError, "needs a reason"):
            self.validate(routes=routes)

    def test_rejects_unused_route_exception(self):
        routes = copy.deepcopy(ROUTES)
        routes["homelab_routing"]["unmanaged_route_targets"]["unused.internal"] = "legacy"
        with self.assertRaisesRegex(ValueError, "unused unmanaged route targets: unused.internal"):
            self.validate(routes=routes)

    def test_rejects_unknown_host_kind_override(self):
        ansible = copy.deepcopy(ANSIBLE)
        ansible["all"]["vars"]["infrastructure_contract"]["host_kinds"]["ghost"] = "external_vps"
        with self.assertRaisesRegex(ValueError, "references unknown host ghost"):
            self.validate(ansible=ansible)


if __name__ == "__main__":
    unittest.main()
