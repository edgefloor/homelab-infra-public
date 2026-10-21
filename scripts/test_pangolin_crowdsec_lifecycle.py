from pathlib import Path
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "pangolin"


class PangolinCrowdSecLifecycleTests(unittest.TestCase):
    def test_nftables_reload_restarts_and_verifies_the_firewall_bouncer(self):
        tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        nftables = next(
            task for task in tasks if task.get("name") == "Install the VPS nftables policy"
        )
        bouncer = next(
            task
            for task in tasks
            if task.get("name") == "Enable and start the VPS CrowdSec nftables bouncer"
        )
        verification = next(
            task
            for task in tasks
            if task.get("name") == "Verify the VPS CrowdSec nftables hooks"
        )

        state = bouncer["ansible.builtin.systemd_service"]["state"]
        dependencies = [nftables['register']]
        for name in (
            'Configure the VPS CrowdSec nftables bouncer',
            'Bind the CrowdSec firewall bouncer to nftables',
            'Restart the VPS CrowdSec firewall bouncer after nftables reloads',
        ):
            dependencies.append(next(task for task in tasks if task.get('name') == name)['register'])
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

    def test_systemd_orders_and_restarts_the_bouncer_with_nftables(self):
        tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        override = next(
            task
            for task in tasks
            if task.get("name") == "Bind the CrowdSec firewall bouncer to nftables"
        )
        content = override["ansible.builtin.copy"]["content"]

        self.assertIn("After=nftables.service", content)
        self.assertIn("PartOf=nftables.service", content)

    def test_nftables_reload_restarts_the_bouncer(self):
        tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        override = next(
            task
            for task in tasks
            if task.get("name")
            == "Restart the VPS CrowdSec firewall bouncer after nftables reloads"
        )
        content = override["ansible.builtin.copy"]["content"]

        self.assertIn("ExecReload=/usr/sbin/nft -f /etc/nftables.conf", content)
        self.assertIn(
            "systemctl --no-block try-restart crowdsec-firewall-bouncer.service",
            content,
        )

    def test_nftables_restart_and_reload_restore_docker_firewall_rules(self):
        tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text())

        docker_override = next(
            task for task in tasks if task.get("name") == "Bind Docker to nftables"
        )
        docker_content = docker_override["ansible.builtin.copy"]["content"]
        self.assertIn("After=nftables.service", docker_content)
        self.assertIn("PartOf=nftables.service", docker_content)
        self.assertEqual(docker_override.get("notify"), "Restart nftables")

        reload_override = next(
            task
            for task in tasks
            if task.get("name")
            == "Restart the VPS CrowdSec firewall bouncer after nftables reloads"
        )
        reload_content = reload_override["ansible.builtin.copy"]["content"]
        self.assertIn(
            "systemctl --no-block try-restart docker.service", reload_content
        )

        docker_handler = next(
            handler for handler in handlers if handler.get("name") == "Restart Docker"
        )
        self.assertEqual(docker_handler.get("listen"), "Restart nftables")

        verification = next(
            task
            for task in tasks
            if task.get("name") == "Verify Docker restored its NAT chain"
        )
        self.assertEqual(verification.get("changed_when"), False)


if __name__ == "__main__":
    unittest.main()
