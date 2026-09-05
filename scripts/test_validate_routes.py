import copy
import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_routes.py")
SPEC = importlib.util.spec_from_file_location("validate_routes", MODULE_PATH)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


VALID = {
    "homelab_routing": {
        "schema_version": 1,
        "base_domain": "example.com",
        "caddy_address": "192.168.1.2",
        "pangolin_vps_address": "203.0.113.2",
        "pangolin_home_site": "home",
        "cloudflare_record": {"type": "A", "ttl": 1, "proxied": False},
        "routes": [
            {
                "id": "app",
                "hostname": "app.example.com",
                "internal_dns": True,
                "public_target": "pangolin_vps",
                "caddy": {
                    "upstream": "192.168.1.3:8080",
                    "internal_source_only": True,
                    "health_path": "/health",
                },
                "pangolin": {
                    "resource_id": "app-resource",
                    "name": "App",
                    "policy_id": "app-policy",
                    "roles": ["Member"],
                    "target": {"site": "home", "hostname": "192.168.1.2", "port": 443, "method": "https"},
                },
            }
        ],
    }
}


class RouteValidationTests(unittest.TestCase):
    def validate(self, data):
        subject.validate(data, Path("routes.yml"))

    def test_valid_inventory(self):
        self.validate(copy.deepcopy(VALID))

    def test_rejects_duplicate_hostname(self):
        data = copy.deepcopy(VALID)
        duplicate = copy.deepcopy(data["homelab_routing"]["routes"][0])
        duplicate["id"] = "other"
        duplicate["pangolin"]["resource_id"] = "other-resource"
        duplicate["pangolin"]["policy_id"] = "other-policy"
        data["homelab_routing"]["routes"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate hostname"):
            self.validate(data)

    def test_rejects_pangolin_route_without_home_wan_acl(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["caddy"]["internal_source_only"] = False
        with self.assertRaisesRegex(ValueError, "reject direct home-WAN"):
            self.validate(data)

    def test_accepts_internal_only_route_without_pangolin(self):
        data = copy.deepcopy(VALID)
        route = data["homelab_routing"]["routes"][0]
        route["public_target"] = "internal_only"
        route.pop("pangolin")
        self.validate(data)

    def test_rejects_internal_only_route_without_source_acl(self):
        data = copy.deepcopy(VALID)
        route = data["homelab_routing"]["routes"][0]
        route["public_target"] = "internal_only"
        route.pop("pangolin")
        route["caddy"]["internal_source_only"] = False
        with self.assertRaisesRegex(ValueError, "reject direct home-WAN"):
            self.validate(data)

    def test_rejects_home_target_that_bypasses_caddy(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["target"]["hostname"] = "192.168.1.3"
        with self.assertRaisesRegex(ValueError, "target must use Caddy"):
            self.validate(data)

    def test_rejects_admin_in_explicit_roles(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["roles"] = ["Admin"]
        with self.assertRaisesRegex(ValueError, "implicit Admin"):
            self.validate(data)

    def test_accepts_native_application_auth_without_pangolin_sso(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["sso"] = False
        self.validate(data)

    def test_rejects_non_boolean_pangolin_sso(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["sso"] = "false"
        with self.assertRaisesRegex(ValueError, "pangolin.sso must be boolean"):
            self.validate(data)

    def test_accepts_openid_redirect(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["caddy"]["openid_redirect"] = {
            "path": "/sso",
            "realm": "sso",
        }
        self.validate(data)

    def test_rejects_root_openid_redirect(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["caddy"]["openid_redirect"] = {
            "path": "/",
            "realm": "sso",
        }
        with self.assertRaisesRegex(ValueError, "non-root absolute path"):
            self.validate(data)

    def test_accepts_pangolin_post_auth_path(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["post_auth_path"] = "/sso"
        self.validate(data)

    def test_rejects_root_pangolin_post_auth_path(self):
        data = copy.deepcopy(VALID)
        data["homelab_routing"]["routes"][0]["pangolin"]["post_auth_path"] = "/"
        with self.assertRaisesRegex(ValueError, "pangolin.post_auth_path must be a non-root absolute path"):
            self.validate(data)
