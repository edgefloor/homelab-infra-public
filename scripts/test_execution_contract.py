from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ExecutionContractTests(unittest.TestCase):
    def test_zig_receives_only_the_observation_key_via_systemd_credential(self):
        playbook = (ROOT / "ansible/playbooks/zig.yml").read_text()
        self.assertIn(
            "LoadCredential=homelab-observation-key:{{ homelab_investigation_execution.observation_key }}",
            playbook)
        self.assertIn("Environment=HOMELAB_AGENT_KEY=%d/homelab-observation-key", playbook)
        self.assertIn("Verify one observation as Zig's actual service identity", playbook)
        self.assertIn("observe hermes-agent list_processes {}", playbook)
        self.assertNotIn(
            "Environment=HOMELAB_AGENT_KEY=/var/lib/homelab-investigator/.ssh/id_ed25519",
            playbook)

    def test_shared_identity_paths_come_from_one_inventory_contract(self):
        inventory = (ROOT / "ansible/inventory/hosts.yml").read_text()
        self.assertIn("homelab_investigation_execution:", inventory)
        self.assertIn("known_hosts:", inventory)
        storage = (ROOT / "ansible/roles/homelab_agent_service/tasks/storage.yml").read_text()
        self.assertIn("homelab_agent_workspace_root", storage)
        self.assertIn("verify-access", storage)
        self.assertIn("Create a workspace as Zig", storage)
        self.assertIn("Finish the Zig-created workspace as the controller", storage)
        self.assertIn("Create a workspace as the controller", storage)
        self.assertIn("Finish the controller-created workspace as Zig", storage)
        zig = (ROOT / "ansible/playbooks/zig.yml").read_text()
        self.assertIn(
            "User={{ homelab_investigation_execution.investigator_user }}", zig)
        publisher = (ROOT / "ansible/roles/vulnerability_incidents/templates/cve-native-publisher.service.j2").read_text()
        self.assertIn(
            "User={{ homelab_investigation_execution.investigator_user }}", publisher)

    def test_existing_private_workspace_state_is_included_in_migration(self):
        storage = (ROOT / "ansible/roles/homelab_agent_service/tasks/storage.yml").read_text()
        self.assertIn("hidden: true", storage)
        self.assertIn("Find existing managed workspace directories", storage)
        self.assertIn("Migrate existing workspace manifests", storage)

    def test_owning_provisioning_playbooks_use_the_cycle_wrapper(self):
        for name in ("caddy", "media-automation", "downloads", "miniflux",
                     "pocket-id", "tuwunel", "newt", "network-ops", "nerocd",
                     "jellyfin", "beszel", "proxmox-host"):
            with self.subTest(playbook=name):
                value = (ROOT / "ansible/playbooks" / (name + ".yml")).read_text()
                self.assertIn("tasks/provision-with-cve-cycle.yml", value)
        wrapper = (ROOT / "ansible/playbooks/tasks/provision-with-cve-cycle.yml").read_text()
        self.assertIn("begin_provisioning_cycle", wrapper)
        self.assertIn("--channels", wrapper)
        self.assertIn("cve_provisioning_update_channels", wrapper)
        for name, installation, feed in (
                ("caddy", "binary:/usr/bin/caddy",
                 "https://github.com/caddyserver/caddy/releases.atom"),
                ("pocket-id", "binary:/opt/pocket-id/pocket-id",
                 "https://github.com/pocket-id/pocket-id/releases.atom")):
            with self.subTest(release_channel=name):
                value = (ROOT / "ansible/playbooks" / (name + ".yml")).read_text()
                self.assertIn(installation, value)
                self.assertIn(feed, value)
        self.assertIn("homelab-update-opportunities", wrapper)
        self.assertIn("--expected", wrapper)
        self.assertIn("post_availability", wrapper)
        self.assertNotIn("cve_provisioning_update_opportunities | default([])", wrapper)
        self.assertIn("homelab-cve-monitor.service", wrapper)
        self.assertIn("finish_provisioning_cycle", wrapper)


if __name__ == "__main__":
    unittest.main()
