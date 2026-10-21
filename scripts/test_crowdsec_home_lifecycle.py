from pathlib import Path
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "crowdsec_home"


class CrowdSecHomeLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())

    def task(self, name):
        return next(task for task in self.tasks if task.get("name") == name)

    def test_nftables_restart_and_reload_reconcile_the_firewall_bouncer(self):
        bouncer_override = self.task(
            "Bind the home CrowdSec firewall bouncer to nftables"
        )["ansible.builtin.copy"]["content"]
        nftables_override = self.task(
            "Restart the home CrowdSec firewall bouncer after nftables reloads"
        )["ansible.builtin.copy"]["content"]

        self.assertIn("After=nftables.service", bouncer_override)
        self.assertIn("PartOf=nftables.service", bouncer_override)
        self.assertIn("ExecReload=/usr/sbin/nft -f /etc/nftables.conf", nftables_override)
        self.assertIn(
            "systemctl --no-block try-restart crowdsec-firewall-bouncer.service",
            nftables_override,
        )

    def test_managed_config_changes_restart_and_deployment_verifies_the_bouncer(self):
        config = self.task("Configure the home nftables bouncer")
        bouncer = self.task("Enable and start the CrowdSec firewall bouncer")
        verification = self.task("Verify the home CrowdSec nftables hooks")

        state = bouncer["ansible.builtin.systemd_service"]["state"]
        dependencies = (
            config['register'],
            self.task('Bind the home CrowdSec firewall bouncer to nftables')['register'],
            self.task('Restart the home CrowdSec firewall bouncer after nftables reloads')['register'],
        )
        render = Environment(undefined=StrictUndefined).from_string
        for changed in (None, *dependencies):
            with self.subTest(changed=changed):
                values = {name: {'changed': name == changed} for name in dependencies}
                self.assertEqual(render(state).render(values), 'restarted' if changed else 'started')
        self.assertEqual(verification.get("changed_when"), False)
        commands = [
            tuple(render(arg).render(item=item) for arg in verification['ansible.builtin.command']['argv'])
            for item in verification['loop']
        ]
        self.assertCountEqual(commands, [
            ('nft', '-j', '-t', 'list', 'chain', family, table, f'{table}-chain-{hook}')
            for family, table in (('ip', 'crowdsec'), ('ip6', 'crowdsec6'))
            for hook in ('input', 'forward')
        ])


if __name__ == "__main__":
    unittest.main()
