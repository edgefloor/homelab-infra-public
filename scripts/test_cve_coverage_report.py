import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cve_coverage_report import expected_systems, monitored_hosts, render


class CoverageReportTests(unittest.TestCase):
    def test_denominator_includes_unmonitored_and_new_managed_systems(self):
        inventory = {"all": {"vars": {"infrastructure_contract": {"host_kinds": {
            "proxmox": "proxmox_host", "pangolin": "external_vps"}}},
            "children": {"new_group": {"hosts": {"new-service": {}}}}}}
        workloads = {"inventory": {"workloads": [{"name": "firecrawl"}, {"name": "plan-runner"}]}}
        self.assertEqual(expected_systems(inventory, workloads),
                         ["firecrawl", "new-service", "pangolin", "plan-runner", "proxmox"])

    def test_inventory_collects_all_monitored_hosts_without_duplicates(self):
        inventory = {"all": {"children": {
            "beszel_agents": {"children": {"group_a": None, "group_b": None}},
            "group_a": {"hosts": {"caddy": {}, "nerocd": {}}},
            "group_b": {"hosts": {"caddy": {}}},
        }}}
        self.assertEqual(monitored_hosts(inventory), ["caddy", "nerocd"])

    def test_failed_stale_and_missing_hosts_never_become_negative_results(self):
        now = datetime(2026, 9, 5, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"updated_at": now.isoformat(), "coverage": {"os_packages": True, "native_go": [{}], "docker_images": []},
                     "findings": {"one": {"id": "CVE-2026-46600", "target": "/usr/bin/caddy", "package": "stdlib", "installed": "1.26.4", "fixed": ""}}}
            for host in ["caddy", "failed", "stale"]:
                (root / f"{host}.json").write_text(json.dumps(state))
                status = {"status": "failed" if host == "failed" else "complete", "observed_at": now.isoformat()}
                if host == "stale":
                    status["observed_at"] = (now - timedelta(days=2)).isoformat()
                (root / f"{host}.status.json").write_text(json.dumps(status))
            result = render(root, ["caddy", "failed", "stale", "missing"], "CVE-2026-46600", now)
            self.assertEqual(result.count("Unknown: missing, failed, stale, or incomplete scan"), 3)
            self.assertEqual(result.count("/usr/bin/caddy"), 1)
            self.assertIn("No published fix", result)
