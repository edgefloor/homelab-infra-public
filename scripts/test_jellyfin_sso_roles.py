import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "ansible/roles/jellyfin/files/configure_sso_roles.py"
)


class JellyfinSsoRoleTests(unittest.TestCase):
    def load_module(self):
        spec = importlib.util.spec_from_file_location("configure_sso_roles", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_adds_access_role_without_changing_secret_links_or_admin_roles(self):
        module = self.load_module()
        document = """<?xml version="1.0"?>
<PluginConfiguration>
  <OidConfigs><item><key><string>PocketID</string></key><value>
    <PluginConfiguration>
      <OidSecret>keep-this-secret</OidSecret>
      <AdminRoles><string>jellyfin_admins</string></AdminRoles>
      <Roles><string>jellyfin_users</string><string>jellyfin_admins</string></Roles>
      <CanonicalLinks><item><key><string>alice</string></key><value><guid>link-id</guid></value></item></CanonicalLinks>
    </PluginConfiguration>
  </value></item></OidConfigs>
</PluginConfiguration>
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SSO-Auth.xml"
            path.write_text(document)

            self.assertTrue(
                module.ensure_allowed_role(path, "PocketID", "jellyfin")
            )
            updated = path.read_text()
            self.assertIn("<OidSecret>keep-this-secret</OidSecret>", updated)
            self.assertIn("<guid>link-id</guid>", updated)
            self.assertIn(
                "<AdminRoles><string>jellyfin_admins</string></AdminRoles>",
                updated,
            )
            self.assertIn("<string>jellyfin</string>", updated)
            self.assertFalse(
                module.ensure_allowed_role(path, "PocketID", "jellyfin")
            )

    def test_rekeys_legacy_username_links_to_stable_subjects(self):
        module = self.load_module()
        document = """<?xml version="1.0"?>
<PluginConfiguration>
  <OidConfigs><item><key><string>PocketID</string></key><value>
    <PluginConfiguration><CanonicalLinks>
      <item><key><string>alice</string></key><value><guid>account-a</guid></value></item>
      <item><key><string>Bob</string></key><value><guid>account-b</guid></value></item>
      <item><key><string>already-a-subject</string></key><value><guid>account-c</guid></value></item>
    </CanonicalLinks></PluginConfiguration>
  </value></item></OidConfigs>
</PluginConfiguration>
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SSO-Auth.xml"
            path.write_text(document)

            self.assertTrue(
                module.migrate_legacy_links(
                    path,
                    "PocketID",
                    {"alice": "subject-a", "bob": "subject-b"},
                )
            )
            updated = path.read_text()
            self.assertIn("<string>subject-a</string>", updated)
            self.assertIn("<string>subject-b</string>", updated)
            self.assertNotIn("<string>alice</string>", updated)
            self.assertNotIn("<string>Bob</string>", updated)
            self.assertIn("<guid>account-a</guid>", updated)
            self.assertIn("<guid>account-b</guid>", updated)
            self.assertIn("<string>already-a-subject</string>", updated)
            self.assertFalse(
                module.migrate_legacy_links(
                    path,
                    "PocketID",
                    {"alice": "subject-a", "bob": "subject-b"},
                )
            )


if __name__ == "__main__":
    unittest.main()
