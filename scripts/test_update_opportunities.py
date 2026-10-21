from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible/roles/vulnerability_incidents/files"))
sys.path.insert(0, str(ROOT / "scripts"))
from build_security_config import compile_configs
from incident_store import IncidentStore

SOURCE = ROOT / "ansible/roles/update_monitor/files/homelab_update_opportunities.py"
SPEC = importlib.util.spec_from_file_location("homelab_update_opportunities", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SNAPSHOT_SOURCE = ROOT / "ansible/roles/update_monitor/files/homelab_incident_snapshot.py"
SNAPSHOT_SPEC = importlib.util.spec_from_file_location(
    "homelab_incident_snapshot_for_opportunities", SNAPSHOT_SOURCE)
SNAPSHOT = importlib.util.module_from_spec(SNAPSHOT_SPEC)
SNAPSHOT_SPEC.loader.exec_module(SNAPSHOT)


class UpdateOpportunityTests(unittest.TestCase):
    @staticmethod
    def container_report(name, service, running=True):
        return {'_homelab_runtime': {
            'image_id': 'sha256:' + name.ljust(64, '0'),
            'configured_refs': ['ghcr.io/edgefloor/nerocd:v0.3.23'],
            'containers': [{'id': name.ljust(64, '1'), 'name': name,
                            'running': running, 'compose_service': service}]},
            'Results': [{'Target': '/', 'Class': 'os-pkgs', 'Type': 'alpine',
                'Packages': [{'Name': 'zlib', 'Version': '1.3.1-r2'}],
                'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-9999',
                    'PkgName': 'zlib', 'InstalledVersion': '1.3.1-r2',
                    'FixedVersion': '1.3.1-r3'}]}]}

    @staticmethod
    def nerocd_provisioning():
        playbook = yaml.safe_load(
            (ROOT / 'ansible/playbooks/nerocd.yml').read_text())
        return playbook[0]['tasks'][0]['vars']

    def test_fresh_container_snapshot_resolves_the_actual_provisioning_owner(self):
        inventory = {'deployments': [
            {'id': 'nerocd', 'compose_services': ['server', 'shared']},
            {'id': 'other', 'compose_services': ['other', 'shared']}],
        }
        findings, _, packages = SNAPSHOT.snapshot_findings([
            self.container_report('nerocd-server-1', 'server'),
            self.container_report('other-server-1', 'other'),
            self.container_report('shared-server-1', 'shared')], inventory)
        provisioning = self.nerocd_provisioning()
        installed = provisioning['cve_provisioning_update_channels'][0][
            'installed_command']

        def run(arguments):
            self.assertEqual(installed, arguments)
            return subprocess.CompletedProcess(arguments, 0, 'NeroCD v0.3.23\n', '')

        feed = b'''<feed xmlns="http://www.w3.org/2005/Atom">
            <entry><id>v0.3.24</id><title>v0.3.24</title></entry>
        </feed>'''
        result = MODULE.collect({
            'schema': 1, 'source': 'nerocd', 'generation': 'test', 'sequence': 1,
            'findings': findings, 'packages': packages,
        }, provisioning['cve_provisioning_installations'],
            channels=provisioning['cve_provisioning_update_channels'], run=run,
            fetch=lambda _: feed, clock=lambda: 100)

        self.assertEqual(1, len(result['observations']))
        observation = result['observations'][0]
        self.assertEqual('container:nerocd-server-1', observation['installation'])
        self.assertEqual('deployment:nerocd', observation['owner_installation'])
        self.assertEqual('0.3.24', observation['candidate'])
        self.assertTrue(observation['available'])
        self.assertNotIn('container:other-server-1', {
            item['installation'] for item in result['observations']})
        self.assertNotIn('container:shared-server-1', {
            item['installation'] for item in result['observations']})

    def test_fresh_snapshot_ingestion_and_two_misses_create_owned_maintenance(self):
        inventory = {'deployments': [
            {'id': 'nerocd', 'compose_services': ['server', 'shared']},
            {'id': 'other', 'compose_services': ['other', 'shared']}],
        }
        findings, complete, packages = SNAPSHOT.snapshot_findings([
            self.container_report('nerocd-server-1', 'server'),
            self.container_report('other-server-1', 'other'),
            self.container_report('shared-server-1', 'shared')], inventory)
        provisioning = self.nerocd_provisioning()
        installed_command = provisioning['cve_provisioning_update_channels'][0][
            'installed_command']

        def run(arguments):
            self.assertEqual(installed_command, arguments)
            return subprocess.CompletedProcess(arguments, 0, 'NeroCD v0.3.23\n', '')

        feed = b'''<feed xmlns="http://www.w3.org/2005/Atom">
            <entry><id>v0.3.24</id><title>v0.3.24</title></entry>
        </feed>'''
        with tempfile.TemporaryDirectory() as temporary:
            store = IncidentStore(Path(temporary) / 'incidents.db', clock=lambda: 200)
            try:
                active_ids = None
                maintenance_work = None
                for sequence in (1, 2):
                    snapshot = {
                        'schema': 1, 'source': 'nerocd', 'generation': 'fresh',
                        'sequence': sequence, 'observed_at': 100 + sequence,
                        'findings': findings, 'packages': packages,
                        'complete_scopes': complete, 'coverage': {},
                    }
                    receipt = store.ingest(snapshot)
                    self.assertEqual('accepted', receipt['status'])
                    current_ids = {row[0] for row in store.db.execute(
                        "SELECT id FROM occurrences WHERE state!='retired'")}
                    if active_ids is None:
                        active_ids = current_ids
                    self.assertEqual(active_ids, current_ids)
                    opportunities = MODULE.collect(
                        snapshot, provisioning['cve_provisioning_installations'],
                        channels=provisioning['cve_provisioning_update_channels'],
                        run=run, fetch=lambda _: feed, clock=lambda: 200)
                    self.assertEqual(1, len(opportunities['observations']))
                    cycle_id = 'fresh-nerocd-' + str(sequence)
                    begun = store.lifecycle.begin_provisioning_cycle(
                        cycle_id, 'ansible:nerocd', ['nerocd'],
                        provisioning['cve_provisioning_installations'],
                        opportunities['observations'], opportunities['receipt'])
                    self.assertEqual(1, len(begun['candidates']))
                    finished = store.lifecycle.finish_provisioning_cycle(
                        cycle_id, 'fresh-attempt-' + str(sequence), 'success', {
                            'play': 'nerocd', 'scanner': 'accepted',
                            'post_availability': opportunities})
                    self.assertEqual(sequence, finished['results'][0]['missed'])
                    if finished['results'][0]['maintenance_work']:
                        maintenance_work = finished['results'][0][
                            'maintenance_work'][0]

                self.assertEqual(0, store.db.execute(
                    'SELECT count(*) FROM occurrence_identity_migrations').fetchone()[0])
                self.assertIsNotNone(maintenance_work)
                investigation = store.lifecycle.scope(
                    maintenance_work, 'investigation')['occurrences']
                selected = [item['id'] for item in investigation]
                self.assertEqual(1, len(selected))
                selected_finding = json.loads(store.db.execute(
                    'SELECT finding FROM occurrences WHERE id=?',
                    (selected[0],)).fetchone()[0])
                self.assertEqual('container:nerocd-server-1',
                                 selected_finding['installation'])
                self.assertEqual(['nerocd'],
                                 selected_finding['owner_deployments'])
            finally:
                store.close()

    def test_stopped_scanner_snapshot_keeps_owner_through_one_cycle(self):
        inventory = compile_configs()['nerocd']
        provisioning = self.nerocd_provisioning()
        installed_command = provisioning['cve_provisioning_update_channels'][0][
            'installed_command']

        def run(arguments):
            self.assertEqual(installed_command, arguments)
            return subprocess.CompletedProcess(
                arguments, 0, 'NeroCD v0.3.23\n', '')

        feed = b'''<feed xmlns="http://www.w3.org/2005/Atom">
            <entry><id>v0.3.24</id><title>v0.3.24</title></entry>
        </feed>'''
        stopped_report = self.container_report(
            'nerocd-migrate-1', 'migrate', running=False)
        findings, complete, packages = SNAPSHOT.snapshot_findings(
            [stopped_report], inventory)
        self.assertEqual('container:nerocd-migrate-1',
                         findings[0]['installation'])
        self.assertEqual(['nerocd'], findings[0]['owner_deployments'])
        self.assertEqual([], findings[0].get('consumer_deployments', []))
        self.assertEqual(['nerocd'], packages[0]['owner_deployments'])
        self.assertEqual([], packages[0]['consumer_deployments'])
        graph = SNAPSHOT.lifecycle_graph(
            'nerocd', 'fresh', 1, 100, {'discovery': {
                'runtime_sha256': 'a' * 64, 'gaps': [], 'relationships': [],
                'relationship_coverage': []}}, inventory, findings)
        self.assertFalse(any(item['relation'] in {
            'CONSUMED_BY', 'RUNS_IN', 'RUNS_UNDER', 'OWNED_BY'}
            for item in graph['assertions']))

        initial = {
            'schema': 1, 'source': 'nerocd', 'generation': 'stopped',
            'sequence': 1, 'observed_at': 101, 'findings': findings,
            'packages': packages, 'complete_scopes': complete, 'coverage': {},
        }
        opportunities = MODULE.collect(
            initial, provisioning['cve_provisioning_installations'],
            channels=provisioning['cve_provisioning_update_channels'], run=run,
            fetch=lambda _: feed, clock=lambda: 200)
        self.assertEqual(1, len(opportunities['observations']))
        self.assertEqual('deployment:nerocd',
                         opportunities['observations'][0]['owner_installation'])

        with tempfile.TemporaryDirectory() as temporary:
            store = IncidentStore(Path(temporary) / 'incidents.db', clock=lambda: 200)
            try:
                self.assertEqual('accepted', store.ingest(initial)['status'])
                active_ids = {row[0] for row in store.db.execute(
                    "SELECT id FROM occurrences WHERE state!='retired'")}
                begun = store.lifecycle.begin_provisioning_cycle(
                    'stopped-nerocd', 'ansible:nerocd', ['nerocd'],
                    provisioning['cve_provisioning_installations'],
                    opportunities['observations'], opportunities['receipt'])
                self.assertEqual(1, len(begun['candidates']))

                running_findings, running_complete, running_packages = \
                    SNAPSHOT.snapshot_findings([
                        self.container_report(
                            'nerocd-migrate-1', 'migrate', running=True)],
                        inventory)
                running = {**initial, 'sequence': 2, 'observed_at': 102,
                           'findings': running_findings,
                           'packages': running_packages,
                           'complete_scopes': running_complete}
                self.assertEqual('accepted', store.ingest(running)['status'])
                self.assertEqual(active_ids, {row[0] for row in store.db.execute(
                    "SELECT id FROM occurrences WHERE state!='retired'")})

                retained_report = self.container_report(
                    'nerocd-migrate-1', 'migrate', running=False)
                retained_report['Results'][0]['Vulnerabilities'] = []
                retained_findings, retained_complete, retained_packages = \
                    SNAPSHOT.snapshot_findings([retained_report], inventory)
                retained_snapshot = {
                    **initial, 'sequence': 3, 'observed_at': 103,
                    'findings': retained_findings,
                    'packages': retained_packages,
                    'complete_scopes': retained_complete,
                }
                self.assertEqual('accepted',
                                 store.ingest(retained_snapshot)['status'])
                self.assertEqual(active_ids, {row[0] for row in store.db.execute(
                    "SELECT id FROM occurrences WHERE state!='retired'")})
                retained = json.loads(store.db.execute(
                    "SELECT finding FROM occurrences WHERE state='unknown'").fetchone()[0])
                self.assertEqual(['nerocd'], retained['owner_deployments'])
                post = MODULE.collect(
                    retained_snapshot,
                    provisioning['cve_provisioning_installations'],
                    channels=provisioning['cve_provisioning_update_channels'],
                    expected=opportunities['observations'], run=run,
                    fetch=lambda _: feed, clock=lambda: 200)
                self.assertEqual(1, len(post['observations']))
                finished = store.lifecycle.finish_provisioning_cycle(
                    'stopped-nerocd', 'stopped-nerocd-attempt', 'success', {
                        'play': 'nerocd', 'scanner': 'accepted',
                        'post_availability': post})
                self.assertEqual('noop', store.db.execute(
                    "SELECT outcome FROM lifecycle_cycles").fetchone()[0])
                self.assertEqual(1, finished['results'][0]['missed'])
                self.assertEqual(0, store.db.execute(
                    'SELECT count(*) FROM occurrence_identity_migrations').fetchone()[0])
            finally:
                store.close()

    def test_host_apt_candidate_records_channel_platform_and_provenance(self):
        calls = []

        def run(arguments):
            calls.append(arguments)
            command = arguments
            if command == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess(
                    arguments, 0, 'ID=debian\nVERSION_CODENAME="bookworm"\n', "")
            if command == ["uname", "-m"]:
                return subprocess.CompletedProcess(arguments, 0, "x86_64\n", "")
            if command == ["apt-cache", "policy", "libssl3"]:
                return subprocess.CompletedProcess(
                    arguments, 0, "Installed: 1\nCandidate: 2\n", "")
            if command[:2] == ["dpkg", "--compare-versions"]:
                return subprocess.CompletedProcess(
                    arguments, 1 if command[3:] == ["ge", "3"] else 0,
                    "", "")
            raise AssertionError(arguments)

        result = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 4,
            "findings": [{
                "installation": "os", "ecosystem": "debian",
                "package": "libssl3", "installed": "1", "fixed": "3",
            }],
        }, ["os"], run=run, clock=lambda: 100)

        self.assertEqual("complete", result["receipt"]["status"])
        observation = result["observations"][0]
        self.assertTrue(observation["available"])
        self.assertEqual("2", observation["candidate"])
        self.assertEqual("debian:bookworm:x86_64", observation["platform"])
        self.assertEqual("apt:debian:bookworm:x86_64", observation["channel"])
        self.assertTrue(observation["provenance"].startswith("sha256:"))

    def test_container_package_does_not_stand_in_for_an_image_update(self):
        result = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 5,
            "findings": [{
                "installation": "deployment:web", "ecosystem": "debian",
                "package": "libssl3", "installed": "1", "fixed": "2",
                "containers": [{"name": "web"}],
            }],
        }, ["deployment:web"], run=lambda arguments: self.fail(arguments),
            clock=lambda: 101)

        self.assertEqual("incomplete", result["receipt"]["status"])
        self.assertEqual("owning_release_channel_missing",
                         result["receipt"]["missing"][0]["reason"])

    def test_native_release_channels_cover_binary_modules_including_slashes(self):
        feeds = {
            "https://github.com/caddyserver/caddy/releases.atom": b"""
                <feed xmlns="http://www.w3.org/2005/Atom">
                  <entry><id>caddy-beta</id><title>v2.12.0-beta.1</title></entry>
                  <entry><id>caddy-stable</id><title>v2.11.5</title></entry>
                </feed>
            """,
            "https://github.com/pocket-id/pocket-id/releases.atom": b"""
                <feed xmlns="http://www.w3.org/2005/Atom">
                  <entry><id>pocket-stable</id><title>v2.15.0</title></entry>
                </feed>
            """,
        }

        def run(arguments):
            outputs = {
                ("/usr/bin/caddy", "version"): "v2.11.4 h1:digest\n",
                ("readlink", "--canonicalize", "/opt/pocket-id/pocket-id"):
                    "/opt/pocket-id/releases/v2.14.0/pocket-id\n",
            }
            return subprocess.CompletedProcess(
                arguments, 0, outputs[tuple(arguments)], "")

        result = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 6,
            "findings": [
                {"installation": "binary:/usr/bin/caddy",
                 "ecosystem": "gobinary", "package": "stdlib",
                 "installed": "go1.26.6", "fixed": "go1.26.7"},
                {"installation": "binary:/opt/pocket-id/pocket-id",
                 "ecosystem": "gobinary", "package": "golang.org/x/net",
                 "installed": "v0.42.0", "fixed": "v0.43.0"},
            ],
        }, ["binary:/usr/bin/caddy", "binary:/opt/pocket-id/pocket-id"],
            channels=[
                {"installation": "binary:/usr/bin/caddy", "kind": "release-feed",
                 "source": "Caddy", "url": next(iter(feeds)),
                 "channel": "stable", "platform": "linux-amd64",
                 "installed_command": ["/usr/bin/caddy", "version"],
                 "installed_pattern": r"v?([0-9]+(?:\.[0-9]+)+)"},
                {"installation": "binary:/opt/pocket-id/pocket-id",
                 "kind": "release-feed", "source": "Pocket ID",
                 "url": "https://github.com/pocket-id/pocket-id/releases.atom",
                 "channel": "stable", "platform": "linux-amd64",
                 "installed_command": ["readlink", "--canonicalize",
                                       "/opt/pocket-id/pocket-id"],
                 "installed_pattern": r"/releases/(v?[0-9]+(?:\.[0-9]+)+)/"},
            ], run=run, fetch=lambda url: feeds[url], clock=lambda: 102)

        self.assertEqual("complete", result["receipt"]["status"])
        self.assertEqual([], result["receipt"]["missing"])
        self.assertEqual(2, len(result["observations"]))
        by_package = {item["package"]: item for item in result["observations"]}
        self.assertEqual("2.11.5", by_package["stdlib"]["candidate"])
        self.assertEqual("2.15.0", by_package["golang.org/x/net"]["candidate"])
        self.assertTrue(all(item["available"]
                            for item in result["observations"]))
        self.assertTrue(all(item["source"] == "configured-release-channel"
                            for item in result["observations"]))

    def test_unsupported_package_records_explicit_missing_observation(self):
        result = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 5,
            "findings": [{
                "installation": "binary:/usr/bin/tool", "ecosystem": "gobinary",
                "package": "stdlib", "installed": "1", "fixed": "2",
            }],
        }, ["binary:/usr/bin/tool"], run=lambda arguments: None,
            clock=lambda: 101)

        self.assertFalse(result["observations"][0]["available"])
        self.assertEqual("owning_release_channel_missing",
                         result["receipt"]["missing"][0]["reason"])
        self.assertEqual("incomplete", result["receipt"]["status"])

    def test_newer_apt_candidate_does_not_require_a_scanner_fix_version(self):
        def run(arguments):
            if arguments == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess(
                    arguments, 0, "ID=debian\nVERSION_CODENAME=bookworm\n", "")
            if arguments == ["uname", "-m"]:
                return subprocess.CompletedProcess(arguments, 0, "x86_64\n", "")
            if arguments == ["apt-cache", "policy", "openssl"]:
                return subprocess.CompletedProcess(
                    arguments, 0, "Installed: 1\nCandidate: 2\n", "")
            if arguments == ["dpkg", "--compare-versions", "2", "gt", "1"]:
                return subprocess.CompletedProcess(arguments, 0, "", "")
            raise AssertionError(arguments)

        result = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 7,
            "findings": [{"installation": "os", "ecosystem": "debian",
                          "package": "openssl", "installed": "1", "fixed": ""}],
        }, ["os"], run=run, clock=lambda: 103)

        self.assertEqual("complete", result["receipt"]["status"])
        self.assertTrue(result["observations"][0]["available"])
        self.assertEqual([], result["observations"][0]["advisory_fixed_versions"])

    def test_post_collection_retains_expected_native_artifact_after_cve_clears(self):
        installed = "2.11.4"

        def run(arguments):
            return subprocess.CompletedProcess(
                arguments, 0, "v" + installed + " h1:digest\n", "")

        channel = {
            "installation": "binary:/usr/bin/caddy", "kind": "release-feed",
            "source": "Caddy",
            "url": "https://github.com/caddyserver/caddy/releases.atom",
            "channel": "stable", "platform": "linux-amd64",
            "installed_command": ["/usr/bin/caddy", "version"],
            "installed_pattern": r"v?([0-9]+(?:\.[0-9]+)+)",
        }
        feed = b"""<feed xmlns="http://www.w3.org/2005/Atom">
            <entry><id>caddy-stable</id><title>v2.11.5</title></entry>
        </feed>"""
        pre = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 8,
            "findings": [{"installation": "binary:/usr/bin/caddy",
                          "ecosystem": "gobinary", "package": "stdlib",
                          "installed": "go1.26.6", "fixed": "go1.26.7"}],
        }, ["binary:/usr/bin/caddy"], channels=[channel], run=run,
            fetch=lambda url: feed, clock=lambda: 104)
        self.assertEqual("2.11.4", pre["observations"][0]["installed"])

        installed = "2.11.5"
        post = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 9,
            "findings": [], "packages": [],
        }, ["binary:/usr/bin/caddy"], channels=[channel],
            expected=pre["observations"], run=run,
            fetch=lambda url: feed, clock=lambda: 105)

        self.assertEqual(1, len(post["observations"]))
        self.assertEqual("2.11.5", post["observations"][0]["installed"])

        def fail_fetch(url):
            raise OSError("offline")

        failed_feed = MODULE.collect({
            "source": "host", "generation": "one", "sequence": 10,
            "findings": [], "packages": [],
        }, ["binary:/usr/bin/caddy"], channels=[channel],
            expected=pre["observations"], run=run,
            fetch=fail_fetch,
            clock=lambda: 106)
        self.assertEqual("incomplete", failed_feed["receipt"]["status"])
        self.assertEqual("2.11.5",
                         failed_feed["observations"][0]["installed"])
        self.assertEqual("channel_query_failed",
                         failed_feed["observations"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
