from __future__ import annotations

import importlib.util
import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/vulnerability_incidents/files"
sys.path.insert(0, str(FILES))
from cve_lifecycle import EVALUATOR_VERSION
from incident_store import IncidentStore


class Clock:
    def __init__(self, value=2_000_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


class LifecycleCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "incidents.db"
        self.clock = Clock()
        self.store = IncidentStore(self.path, clock=self.clock)
        with self.store.db:
            self.incident = self.store._incident("CVE-2026-7001")
        self.lifecycle = self.store.lifecycle
        self.change = 0

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_decisions_have_occurrence_lookup_index(self):
        indexes = {row[1] for row in self.store.db.execute(
            "PRAGMA index_list(lifecycle_decisions)")}
        self.assertIn("lifecycle_decision_occurrence", indexes)

    def test_evaluator_version_is_loaded_source_digest(self):
        expected = 'cve_lifecycle.py:sha256:' + hashlib.sha256(
            (FILES / 'cve_lifecycle.py').read_bytes()).hexdigest()
        self.assertEqual(expected, EVALUATOR_VERSION)

    def test_administrative_input_boundary_is_quiet_not_an_exclusion(self):
        occurrence = 'occ-admin-boundary'
        resource = 'installation:admin-boundary'
        scope = 'current-domain:host:native-elf-inspection:membership'
        evidence_id = 'ev-admin-boundary'
        self.lifecycle.stage_graph_change(
            'admin-boundary', resources=[{
                'resource_key': resource, 'kind': 'installation',
                'name': 'admin-boundary', 'properties': {
                    'consumer_scope': scope}}], evidence=[{
                'id': evidence_id, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'status': 'complete', 'content': {'domain': 'finite'},
            }], assertions=[{
                'logical_key': 'admin-boundary-disposition', 'version': 'v1',
                'subject': resource, 'relation': 'WORK_DISPOSITION',
                'value': 'administrative_input_boundary', 'kind': 'derived',
                'scope': scope, 'source': 'fixture',
                'provenance': 'derived:finite-execution-domain/v1',
                'evidence_id': evidence_id,
                'derivation': {'rule': 'finite-execution-domain/v1',
                    'input_evidence_ids': [evidence_id],
                    'input_refs': ['receipt:broker-v2']},
            }], coverage=[{
                'logical_key': 'admin-boundary-coverage', 'version': 'v1',
                'scope': scope, 'relationship': 'current_domain_membership',
                'producer': 'fixture', 'complete': True, 'status': 'valid',
                'evidence_id': evidence_id,
            }])
        self.lifecycle.acknowledge_graph_change('admin-boundary')
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service='os', host='host',
            deployment='os')

        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1', dependency_scopes=[scope])

        self.assertEqual('quiet', decision['result'])
        self.assertEqual('administrative_input_boundary', decision['reason'])
        self.assertNotIn('CONSTRAINT_EXCLUDES', [item['relation'] for item in
            self.lifecycle.relationships(resource)['relationships']])

    def test_sqlite_relationships_round_trip_derived_provenance(self):
        resource = 'application:derived'
        derivation = {'rule': 'fixture-derivation/v1',
                      'input_evidence_ids': ['derived-evidence'],
                      'input_refs': ['fixture.json#value']}
        self.lifecycle.stage_graph_change(
            'derived-change', resources=[{
                'resource_key': resource, 'kind': 'application',
                'name': 'derived'}], evidence=[{
                'id': 'derived-evidence', 'kind': 'observation',
                'scope': 'derived-scope', 'source': 'fixture',
                'provenance': 'fixture:raw', 'status': 'complete',
                'content': {'value': True}}], assertions=[{
                'logical_key': 'derived-assertion', 'version': 'v1',
                'subject': resource, 'relation': 'TARGETABLE_PATH',
                'value': True, 'kind': 'derived', 'scope': 'derived-scope',
                'source': 'fixture',
                'provenance': 'derived:fixture-derivation/v1',
                'evidence_id': 'derived-evidence',
                'derivation': derivation}], coverage=[])
        self.lifecycle.acknowledge_graph_change('derived-change')

        relationship = self.lifecycle.relationships(resource)['relationships'][0]
        self.assertEqual('derived', relationship['kind'])
        self.assertEqual(derivation, relationship['derivation'])
        self.assertEqual('derived-evidence', relationship['evidence_id'])

    def test_graph_change_can_use_the_accepted_snapshot_size_budget(self):
        evidence = [{
            'id': 'large-evidence-' + str(number), 'kind': 'observation',
            'scope': 'large:' + str(number), 'source': 'fixture',
            'provenance': 'fixture', 'status': 'complete',
            'content': {'payload': character * (5 * 1024 * 1024)},
        } for number, character in enumerate(('a', 'b'), 1)]

        staged = self.lifecycle.stage_graph_change(
            'large-logical-change', evidence=evidence)

        self.assertEqual('pending', staged['status'])
        rows = self.store.db.execute("""SELECT id,revision,length(payload)
            FROM lifecycle_graph_changes ORDER BY revision""").fetchall()
        self.assertEqual(['large-logical-change'], [row['id'] for row in rows])
        self.assertGreater(rows[0]['length(payload)'], 8 * 1024 * 1024)
        self.assertLess(rows[0]['length(payload)'], 32 * 1024 * 1024)
        for row in rows:
            self.lifecycle.acknowledge_graph_change(row['id'])
        self.assertEqual(2, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_evidence WHERE id LIKE 'large-evidence-%'").fetchone()[0])

    def test_availability_is_retrievable_but_not_an_assessment_path(self):
        installation = 'installation:available-tool'
        capability = 'command-capability:host:inspection'
        application = 'application:diagnostic-agent'
        input_source = 'input-source:operators'
        occurrence = 'occ-available-tool'
        scope = 'consumer:host:available-tool'
        control_scope = 'input-paths:' + application
        evidence_id = 'ev-available-tool'
        resources = [
            {'resource_key': key, 'kind': key.partition(':')[0],
             'name': key.partition(':')[2]}
            for key in (installation, capability, application, input_source)
        ]
        relations = [
            (installation, 'AVAILABLE_TO', capability, scope),
            (capability, 'USED_BY', application, scope),
            (application, 'RECEIVES_MESSAGES_FROM', input_source, control_scope),
            (input_source, 'TARGETABLE_PATH', None, control_scope),
        ]
        assertions = [{
            'logical_key': 'available-tool:' + str(index), 'version': 'v1',
            'subject': subject, 'relation': relation, 'object_key': object_key,
            'value': True, 'kind': 'observation', 'scope': relation_scope,
            'source': 'fixture', 'provenance': 'fixture',
            'evidence_id': evidence_id, 'valid_from': self.clock(),
        } for index, (subject, relation, object_key, relation_scope)
        in enumerate(relations)]
        self.lifecycle.stage_graph_change(
            'available-tool-path', resources=resources, evidence=[{
                'id': evidence_id, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'status': 'complete', 'content': {'available': True},
            }], assertions=assertions, coverage=[{
                'logical_key': 'coverage:' + scope, 'version': 'v1',
                'scope': scope, 'relationship': 'package_consumer',
                'producer': 'fixture', 'complete': True, 'status': 'valid',
                'evidence_id': evidence_id,
            }])
        self.lifecycle.acknowledge_graph_change('available-tool-path')
        self.lifecycle.add_occurrence(
            self.incident, occurrence, installation, service='os', host='host',
            deployment='os')

        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1', dependency_scopes=[scope])

        self.assertEqual('pending', decision['result'])
        self.assertEqual('prerequisite_evidence_missing', decision['reason'])
        self.assertEqual(['AVAILABLE_TO'], [item['relation'] for item in
            self.lifecycle.relationships(installation)['relationships']])
        self.assertEqual(['USED_BY'], [item['relation'] for item in
            self.lifecycle.relationships(capability)['relationships']])
        self.assertIn(control_scope,
                      self.lifecycle.dependency_scopes(occurrence))

    def test_consumed_package_path_remains_targetable(self):
        keys = [
            'installation:consumed', 'package-file:consumed',
            'process:consumed', 'service:consumed', 'deployment:host:consumer',
            'application:consumer', 'input-source:internet',
        ]
        occurrence = 'occ-consumed'
        scope = 'consumer:host:consumed'
        evidence_id = 'ev-consumed'
        relations = [
            (keys[0], 'OWNS_FILE', keys[1]),
            (keys[1], 'LOADED_BY', keys[2]),
            (keys[2], 'RUNS_UNDER', keys[3]),
            (keys[3], 'OWNED_BY', keys[4]),
            (keys[4], 'DEPLOYS', keys[5]),
            (keys[5], 'RECEIVES_REQUESTS_FROM', keys[6]),
            (keys[6], 'TARGETABLE_PATH', None),
        ]
        self.lifecycle.stage_graph_change(
            'consumed-package-path', resources=[{
                'resource_key': key, 'kind': key.partition(':')[0],
                'name': key.partition(':')[2]} for key in keys], evidence=[{
                'id': evidence_id, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'status': 'complete', 'content': {'consumed': True},
            }], assertions=[{
                'logical_key': 'consumed:' + str(index), 'version': 'v1',
                'subject': subject, 'relation': relation,
                'object_key': object_key, 'value': True,
                'kind': 'observation', 'scope': scope, 'source': 'fixture',
                'provenance': 'fixture', 'evidence_id': evidence_id,
                'valid_from': self.clock(),
            } for index, (subject, relation, object_key)
            in enumerate(relations)], coverage=[{
                'logical_key': 'coverage:' + scope, 'version': 'v1',
                'scope': scope, 'relationship': 'package_consumer',
                'producer': 'fixture', 'complete': True, 'status': 'valid',
                'evidence_id': evidence_id,
            }])
        self.lifecycle.acknowledge_graph_change('consumed-package-path')
        self.lifecycle.add_occurrence(
            self.incident, occurrence, keys[0], service='os', host='host',
            deployment='os')

        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version='rules/v1',
            advisory_version='advisory/v1', dependency_scopes=[scope])

        self.assertEqual('work', decision['result'])
        self.assertEqual('targetable_path', decision['reason'])

    def test_repeated_immutable_declaration_keeps_its_original_valid_from(self):
        resource = "application:stable"
        payload = {
            "resources": [{"resource_key": resource, "kind": "application",
                           "name": "stable"}],
            "evidence": [{"id": "stable-evidence", "kind": "declaration",
                          "scope": "stable-scope", "source": "fixture",
                          "provenance": "sha256:stable", "status": "complete",
                          "content": {"stable": True}}],
            "assertions": [{"logical_key": "stable-assertion", "version": "v1",
                            "subject": resource, "relation": "TARGETABLE_PATH",
                            "value": False, "kind": "declaration",
                            "scope": "stable-scope", "source": "fixture",
                            "provenance": "sha256:stable",
                            "evidence_id": "stable-evidence"}],
            "coverage": [{"logical_key": "stable-coverage", "version": "v1",
                          "scope": "stable-scope", "relationship": "inputs",
                          "producer": "fixture", "complete": True,
                          "status": "valid", "evidence_id": "stable-evidence"}],
        }
        self.lifecycle.stage_graph_change("stable-one", **payload)
        self.lifecycle.acknowledge_graph_change("stable-one")
        self.clock.value += 60
        self.lifecycle.stage_graph_change("stable-two", **payload)
        self.lifecycle.acknowledge_graph_change("stable-two")
        self.assertEqual(2, self.lifecycle._revision())

    def availability_receipt(self):
        return {"collector": "fixture-availability", "status": "complete",
                "observed_at": self.clock(), "source_snapshot": {"sequence": 1},
                "missing": []}

    def graph(self, resource, relations, *, scope=None, complete=True,
              evidence_status="complete", expires=None, occurrences=None):
        self.change += 1
        scope = scope or "paths:" + resource
        evidence_id = f"ev-{self.change}"
        resources = [{"resource_key": resource, "kind": "deployment", "name": resource}]
        evidence = [{"id": evidence_id, "kind": "observation", "scope": scope,
                     "source": "fixture", "provenance": f"capture-{self.change}",
                     "status": evidence_status, "valid_from": self.clock(),
                     "valid_until": expires, "content": {"relations": relations}}]
        assertions = []
        for index, (relation, value, logical) in enumerate(relations):
            assertions.append({"logical_key": logical, "version": f"v{self.change}",
                               "subject": resource, "relation": relation, "value": value,
                               "kind": "observation", "scope": scope, "source": "fixture",
                               "provenance": f"capture-{self.change}",
                               "evidence_id": evidence_id, "valid_from": self.clock()})
            if occurrences:
                assertions[-1]["occurrences"] = occurrences
        coverage = [{"logical_key": "coverage:" + scope, "version": f"v{self.change}",
                     "scope": scope, "relationship": "*", "producer": "fixture",
                     "complete": complete, "status": "valid", "valid_from": self.clock(),
                     "evidence_id": evidence_id}]
        key = f"change-{self.change}"
        staged = self.lifecycle.stage_graph_change(
            key, resources=resources, evidence=evidence,
            assertions=assertions, coverage=coverage)
        self.assertEqual("pending", staged["status"])
        self.lifecycle.acknowledge_graph_change(key)
        return scope, evidence_id

    def occurrence(self, number, relations, **graph_args):
        resource = f"deployment:service-{number}"
        occurrence = f"occ-{number}"
        self.lifecycle.add_occurrence(self.incident, occurrence, resource,
                                      service=f"service-{number}", host=f"host-{number % 3}",
                                      deployment=f"container-{number}")
        scope, evidence = self.graph(
            resource, relations, occurrences=[occurrence], **graph_args)
        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/sha256:one", dependency_scopes=[scope])
        return occurrence, decision, evidence

    def package_alias_pair(self, suffix):
        current = f"occ-current-{suffix}"
        retired = f"occ-retired-{suffix}"
        finding = {"installation": "deployment:alias", "ecosystem": "Debian",
                   "package": "openssl", "location": "/usr/lib/libssl.so",
                   "installed": "3.0.17", "fixed": "3.0.18"}
        for sequence, occurrence in enumerate((current, retired), 1):
            resource = "deployment:" + occurrence
            self.lifecycle.add_occurrence(
                self.incident, occurrence, resource, service="alias.service",
                host="host-0", deployment="alias")
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "host-0", "packages", "[]",
                 "affected", json.dumps(finding), "material", self.clock(),
                 sequence))
        return current, retired, finding

    def retire_occurrence_alias(self, retired, current):
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO occurrence_identity_migrations VALUES (?,?,?,?,?,?)",
                (retired, current, "host-0", "stable-package-slot", "{}",
                 self.clock()))
            self.store.db.execute(
                "UPDATE occurrences SET state='retired' WHERE id=?", (retired,))
            self.store.db.execute(
                "UPDATE lifecycle_occurrences SET active=0 WHERE id=?", (retired,))

    def test_one_group_keeps_quiet_scope_and_pages_all_remediation(self):
        worthy = []
        quiet = []
        for number in range(2):
            occurrence, decision, _ = self.occurrence(
                number, [("TARGETABLE_PATH", True, f"path:{number}")])
            worthy.append(occurrence)
            self.assertEqual("work", decision["result"])
        for number in range(2, 12):
            occurrence, decision, _ = self.occurrence(
                number, [("BUILD_DISPOSITION", "fixed", f"build:{number}")])
            quiet.append(occurrence)
            self.assertEqual("quiet", decision["result"])

        work = self.lifecycle.work(self.incident)
        self.assertEqual(1, work["round"])
        first = self.lifecycle.scope(work["id"], "remediation", limit=5)
        second = self.lifecycle.scope(work["id"], "remediation", limit=5,
                                      continuation=first["continuation"])
        third = self.lifecycle.scope(work["id"], "remediation", limit=5,
                                     continuation=second["continuation"])
        self.assertEqual(12, first["total"])
        self.assertEqual(12, len(first["occurrences"] + second["occurrences"] + third["occurrences"]))
        investigation = self.lifecycle.scope(work["id"], "investigation")
        self.assertEqual(worthy, [value["id"] for value in investigation["occurrences"]])

        added, decision, _ = self.occurrence(
            12, [("BUILD_DISPOSITION", "unaffected", "build:12")])
        self.assertEqual("quiet", decision["result"])
        self.assertEqual(2, self.lifecycle.scope(work["id"], "investigation")["total"])
        self.assertEqual(13, self.lifecycle.scope(work["id"], "remediation")["total"])
        changes = self.store.db.execute(
            "SELECT kind FROM lifecycle_scope_changes WHERE occurrence=?", (added,)).fetchall()
        self.assertEqual(["added"], [row[0] for row in changes])

        for occurrence in worthy + quiet:
            self.lifecycle.record_outcome(work["id"], occurrence, "blocked", "deployment observation pending")
        incomplete = self.lifecycle.complete_round(work["id"])
        self.assertEqual([added], incomplete["missing"])
        self.lifecycle.record_outcome(work["id"], added, "blocked", "compatible build unavailable")
        complete = self.lifecycle.complete_round(work["id"])
        self.assertEqual("review", complete["status"])
        self.assertFalse(complete["deployment_resolved"])

    def test_live_round_outcomes_and_proposals_resolve_retired_aliases(self):
        current, retired, _ = self.package_alias_pair("round")
        work = self.lifecycle.ensure_work(
            self.incident, "fixture", "fixture:retired-alias-round")
        proposal_args = {
            "repository": "homelab", "branch": "fix/retired-alias",
            "changes": [{"path": "service.yml"}],
            "validation": [{"command": "test", "status": "passed"}],
            "blockers": [], "occurrences": [retired],
        }
        proposal = self.lifecycle.propose(work["id"], None, **proposal_args)
        historical_outcome = self.lifecycle.record_outcome(
            work["id"], retired, "blocked", "upstream has no release")
        self.retire_occurrence_alias(retired, current)

        completed = self.lifecycle.complete_round(work["id"])
        repeated = self.lifecycle.propose(
            work["id"], None,
            **{**proposal_args, "occurrences": [current]})

        self.assertEqual(retired, historical_outcome["occurrence"])
        self.assertEqual("review", completed["status"])
        self.assertEqual([], completed["missing"] if "missing" in completed else [])
        self.assertEqual("duplicate", repeated["status"])
        self.assertEqual(proposal["proposal"], repeated["proposal"])
        self.assertEqual([retired], [row[0] for row in self.store.db.execute(
            "SELECT occurrence FROM lifecycle_outcomes WHERE work=?",
            (work["id"],))])
        self.assertEqual({current, retired}, {row[0] for row in self.store.db.execute(
            "SELECT occurrence FROM lifecycle_round_occurrences WHERE work=?",
            (work["id"],))})
        self.assertEqual([retired], [row[0] for row in self.store.db.execute(
            "SELECT occurrence FROM lifecycle_proposal_occurrences "
            "WHERE proposal=?", (proposal["proposal"],))])
        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_proposals").fetchone()[0])

    def test_deployment_outcome_for_retired_alias_updates_the_survivor(self):
        current, retired, _ = self.package_alias_pair("deployment")
        scope, evidence = self.graph(
            "deployment:" + current,
            [("BUILD_DISPOSITION", "fixed", "build:retired-alias")],
            occurrences=[current])
        decision = self.lifecycle.evaluate(
            self.incident, current, rule_version="rules/v1",
            advisory_version="advisory/retired-alias",
            dependency_scopes=[scope])
        work = self.lifecycle.ensure_work(
            self.incident, "fixture", "fixture:retired-alias-deployment")
        self.retire_occurrence_alias(retired, current)

        staged = self.lifecycle.record_outcome(
            work["id"], retired, "validated", "ready for deployment")
        result = self.lifecycle.record_deployment_outcome(
            work["id"], retired, "fixed", "scanner observed fixed",
            evidence, decision["id"])

        self.assertEqual(current, staged["occurrence"])
        self.assertEqual(current, result["occurrence"])
        self.assertTrue(result["deployment_resolved"])
        self.assertEqual([current], [row[0] for row in self.store.db.execute(
            "SELECT occurrence FROM lifecycle_outcomes WHERE work=?",
            (work["id"],))])

    def test_live_maintenance_scope_resolves_retired_investigation_alias(self):
        current, retired, _ = self.package_alias_pair("maintenance")
        work = self.lifecycle.ensure_work(
            self.incident, "fixture", "fixture:retired-alias-maintenance")
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO lifecycle_round_investigation_occurrences "
                "VALUES (?,?,?,?)",
                (work["id"], work["round"], retired, "maintenance"))
        self.retire_occurrence_alias(retired, current)

        cycle = self.lifecycle.record_cycle(
            "retired-alias-cycle", owner="ansible:host-0",
            package_key="Debian:host-0:deployment:alias:openssl",
            affected_scope=[self.incident], affected_occurrences=[retired],
            update_available=True, expected="3.0.18", status="success",
            outcome="noop", relevant=True, attempt_id="retired-alias-attempt",
            receipt={"result": "unchanged"})
        investigation = self.lifecycle.scope(work["id"], "investigation")

        self.assertEqual("saved", cycle["status"])
        self.assertEqual([current], [item["id"]
                                     for item in investigation["occurrences"]])
        self.assertEqual([current], json.loads(self.store.db.execute(
            "SELECT affected_occurrences FROM lifecycle_cycles "
            "WHERE id='retired-alias-cycle'").fetchone()[0]))

    def test_frozen_provisioning_run_resolves_retired_candidates_on_finish(self):
        current, retired, finding = self.package_alias_pair("provisioning")
        opportunity = [{
            "installation": finding["installation"],
            "ecosystem": finding["ecosystem"], "package": finding["package"],
            "candidate": finding["fixed"], "available": True,
            "source": "stable-channel", "channel": "apt:bookworm",
            "platform": "debian:bookworm:x86_64", "provenance": "fixture",
            "observed_at": self.clock(), "reason": "",
        }]
        self.lifecycle.begin_provisioning_cycle(
            "retired-alias-provisioning", "ansible:host-0", ["host-0"],
            [finding["installation"]], opportunity, self.availability_receipt())
        saved_candidates = json.loads(self.store.db.execute(
            "SELECT candidates FROM lifecycle_provisioning_runs "
            "WHERE id='retired-alias-provisioning'").fetchone()[0])
        saved_candidates[0]["availability"].pop("owner_installation")
        self.store.db.execute(
            "UPDATE lifecycle_provisioning_runs SET candidates=? WHERE id=?",
            (json.dumps(saved_candidates, sort_keys=True, separators=(",", ":")),
             "retired-alias-provisioning"))
        self.retire_occurrence_alias(retired, current)

        finished = self.lifecycle.finish_provisioning_cycle(
            "retired-alias-provisioning", "retired-alias-provisioning-attempt",
            "success", {"play": "alias", "scanner": "accepted",
                        "post_availability": {"observations": [{
                            **opportunity[0], "installed": finding["installed"],
                            "provenance": "post-fixture",
                        }]}})

        cycle = self.store.db.execute(
            "SELECT affected_occurrences,receipt,outcome FROM lifecycle_cycles "
            "WHERE id LIKE 'retired-alias-provisioning:%'").fetchone()
        retained = json.loads(self.store.db.execute(
            "SELECT candidates FROM lifecycle_provisioning_runs "
            "WHERE id='retired-alias-provisioning'").fetchone()[0])
        self.assertEqual("saved", finished["status"])
        self.assertEqual("noop", cycle["outcome"])
        self.assertEqual([current], json.loads(cycle["affected_occurrences"]))
        self.assertEqual({current, retired}, set(retained[0]["occurrences"]))
        self.assertEqual([current], [item["occurrence"] for item in
                                     json.loads(cycle["receipt"])["after"]])
        self.assertNotIn("owner_installation", retained[0]["availability"])

    def test_legacy_frozen_run_retries_after_owner_field_upgrade(self):
        current, retired, finding = self.package_alias_pair("provisioning-retry")
        opportunity = [{
            "installation": finding["installation"],
            "ecosystem": finding["ecosystem"], "package": finding["package"],
            "candidate": finding["fixed"], "available": True,
            "source": "stable-channel", "channel": "apt:bookworm",
            "platform": "debian:bookworm:x86_64", "provenance": "fixture",
            "observed_at": self.clock(), "reason": "",
        }]
        receipt = self.availability_receipt()
        self.lifecycle.begin_provisioning_cycle(
            "legacy-owner-retry", "ansible:host-0", ["host-0"],
            [finding["installation"]], opportunity, receipt)
        row = self.store.db.execute(
            "SELECT opportunities,availability_receipt,candidates FROM "
            "lifecycle_provisioning_runs WHERE id='legacy-owner-retry'").fetchone()
        saved_candidates = json.loads(row["candidates"])
        saved_candidates[0]["availability"].pop("owner_installation")
        self.store.db.execute(
            "UPDATE lifecycle_provisioning_runs SET candidates=? WHERE id=?",
            (json.dumps(saved_candidates, sort_keys=True, separators=(",", ":")),
             "legacy-owner-retry"))
        historical = self.store.db.execute(
            "SELECT opportunities,availability_receipt,candidates FROM "
            "lifecycle_provisioning_runs WHERE id='legacy-owner-retry'").fetchone()
        self.retire_occurrence_alias(retired, current)

        upgraded_opportunity = [{
            **opportunity[0],
            "owner_installation": finding["installation"],
        }]
        upgraded_receipt = {
            **receipt,
            "resolved_installations": [
                finding["installation"] + "->" + finding["installation"]],
        }
        repeated = self.lifecycle.begin_provisioning_cycle(
            "legacy-owner-retry", "ansible:host-0", ["host-0"],
            [finding["installation"]], upgraded_opportunity,
            upgraded_receipt)

        self.assertEqual("duplicate", repeated["status"])
        self.assertEqual([current], repeated["candidates"][0]["occurrences"])
        self.assertEqual(finding["installation"], repeated["candidates"][0][
            "availability"]["owner_installation"])
        unchanged = self.store.db.execute(
            "SELECT opportunities,availability_receipt,candidates FROM "
            "lifecycle_provisioning_runs WHERE id='legacy-owner-retry'").fetchone()
        self.assertEqual(tuple(historical), tuple(unchanged))
        self.assertNotIn("owner_installation", json.loads(
            unchanged["candidates"])[0]["availability"])

    def test_deployment_owner_freezes_only_its_exact_container_installation(self):
        owned = "occ-owned-container"
        unrelated = "occ-unrelated-container"
        ambiguous = "occ-ambiguous-container"
        fixtures = (
            (owned, "container:nerocd-server-1", ["nerocd"], []),
            (unrelated, "container:other-server-1", ["other"], []),
            (ambiguous, "container:shared-server-1", [], ["nerocd", "other"]),
        )
        for occurrence, installation, owners, ambiguous_owners in fixtures:
            self.lifecycle.add_occurrence(
                self.incident, occurrence, "deployment:" + occurrence,
                service=occurrence, host="nerocd", deployment=occurrence)
            finding = {
                "installation": installation, "ecosystem": "alpine",
                "package": "zlib", "installed": "1.3.1-r2",
                "fixed": "1.3.1-r3", "owner_deployments": owners,
                "ambiguous_deployments": ambiguous_owners,
            }
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "nerocd", installation, "[]",
                 "affected", json.dumps(finding), "material", self.clock(), 1))
        owned_opportunity = {
            "installation": "container:nerocd-server-1",
            "owner_installation": "deployment:nerocd",
            "ecosystem": "alpine", "package": "zlib", "candidate": "0.3.24",
            "installed": "0.3.23", "available": True,
            "source": "configured-release-channel", "channel": "stable",
            "platform": "linux-amd64", "provenance": "fixture",
            "observed_at": self.clock(), "reason": "",
        }
        opportunity = [owned_opportunity, {
            **owned_opportunity, "installation": "container:other-server-1",
        }, {
            **owned_opportunity, "installation": "container:shared-server-1",
        }]

        work = None
        for number in (1, 2):
            cycle_id = "owned-container-cycle-" + str(number)
            begun = self.lifecycle.begin_provisioning_cycle(
                cycle_id, "ansible:nerocd", ["nerocd"],
                ["deployment:nerocd"], opportunity,
                self.availability_receipt())
            self.assertEqual(1, len(begun["candidates"]))
            self.assertEqual([owned], begun["candidates"][0]["occurrences"])
            finished = self.lifecycle.finish_provisioning_cycle(
                cycle_id, "owned-container-attempt-" + str(number), "success",
                {"play": "nerocd", "scanner": "accepted",
                 "post_availability": {"observations": opportunity}})
            self.assertEqual(number, finished["results"][0]["missed"])
            if finished["results"][0]["maintenance_work"]:
                work = finished["results"][0]["maintenance_work"][0]

        self.assertIsNotNone(work)
        self.assertEqual([owned], [item["id"] for item in
            self.lifecycle.scope(work, "investigation")["occurrences"]])
        package_keys = [row[0] for row in self.store.db.execute(
            "SELECT package_key FROM lifecycle_cycles ORDER BY id")]
        self.assertEqual([
            "alpine:nerocd:container:nerocd-server-1:zlib",
            "alpine:nerocd:container:nerocd-server-1:zlib"], package_keys)

    def test_only_observations_and_current_decisions_resolve_deployment(self):
        occurrences = []
        for number in (50, 51):
            occurrence, _, _ = self.occurrence(
                number, [("TARGETABLE_PATH", True, f"path:{number}")])
            occurrences.append(occurrence)
        work = self.lifecycle.work(self.incident)
        decisions = []
        evidence = []
        for number, occurrence, disposition in zip(
                (50, 51), occurrences, ("fixed", "removed")):
            resource = f"deployment:service-{number}"
            scope, evidence_id = self.graph(resource, [
                ("TARGETABLE_PATH", False, f"path:{number}"),
                ("BUILD_DISPOSITION", disposition, f"build:{number}"),
            ], occurrences=[occurrence])
            if disposition == "removed":
                self.lifecycle.add_occurrence(
                    self.incident, occurrence, resource,
                    service=f"service-{number}", host="host-0",
                    deployment=f"container-{number}", active=False)
            decisions.append(self.lifecycle.evaluate(
                self.incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/two", dependency_scopes=[scope]))
            evidence.append(evidence_id)
        first = self.lifecycle.record_deployment_outcome(
            work["id"], occurrences[0], "fixed", "scanner observed fixed build",
            evidence[0], decisions[0]["id"])
        self.assertFalse(first["deployment_resolved"])
        second = self.lifecycle.record_deployment_outcome(
            work["id"], occurrences[1], "removed", "scanner observed removal",
            evidence[1], decisions[1]["id"])
        self.assertTrue(second["deployment_resolved"])
        self.assertEqual("closed", self.lifecycle.work(work["id"])["state"])

        resource = "deployment:service-50"
        scope, _ = self.graph(resource, [
            ("TARGETABLE_PATH", True, "path:50"),
            ("BUILD_DISPOSITION", "affected", "build:50"),
        ])
        recurrence = self.lifecycle.evaluate(
            self.incident, occurrences[0], rule_version="rules/v1",
            advisory_version="advisory/three", dependency_scopes=[scope])
        self.assertEqual("work", recurrence["result"])
        self.assertEqual(2, self.lifecycle.work(work["id"])["round"])

    def test_uncorroborated_deployment_outcome_is_historical_only(self):
        occurrence, _, _ = self.occurrence(
            52, [("TARGETABLE_PATH", True, "path:52")])
        work = self.lifecycle.work(self.incident)
        resource = "deployment:service-52"
        scope, evidence = self.graph(resource, [
            ("TARGETABLE_PATH", False, "path:52"),
            ("BUILD_DISPOSITION", "fixed", "build:52"),
        ], occurrences=[occurrence])
        quiet = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/two", dependency_scopes=[scope])
        self.lifecycle.record_deployment_outcome(
            work["id"], occurrence, "fixed", "scanner observed fixed build",
            evidence, quiet["id"])
        self.assertTrue(self.lifecycle.complete_round(work["id"])[
            "deployment_resolved"])

        gap_scope, replacement_evidence = self.graph(resource, [
            ("BUILD_DISPOSITION", "affected", "build:52"),
        ], occurrences=[occurrence])
        gap = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/three",
            dependency_scopes=[gap_scope, "runtime:missing"])

        self.assertEqual("gap", gap["result"])
        corrected = self.lifecycle.correct_deployment_outcome(
            work["id"], work["round"], occurrence,
            expected_outcome="fixed", expected_evidence_id=evidence,
            expected_updated=self.clock(),
            replacement_evidence_id=replacement_evidence,
            replacement_decision_id=gap["id"],
            reason="native package release was omitted from retained inventory")
        self.assertEqual("corrected", corrected["status"])
        duplicate = self.lifecycle.correct_deployment_outcome(
            work["id"], work["round"], occurrence,
            expected_outcome="fixed", expected_evidence_id=evidence,
            expected_updated=self.clock(),
            replacement_evidence_id=replacement_evidence,
            replacement_decision_id=gap["id"],
            reason="native package release was omitted from retained inventory")
        self.assertEqual("duplicate", duplicate["status"])
        remediation = self.lifecycle.scope(work["id"], "remediation")
        retained = remediation["occurrences"][0]
        self.assertEqual("unresolved", retained["outcome"])
        self.assertEqual("fixed", retained["historical_outcome"])
        self.assertEqual(evidence, retained["historical_outcome_evidence_id"])
        completion = self.lifecycle.complete_round(work["id"])
        self.assertEqual("historical", completion["status"])
        self.assertFalse(completion["deployment_resolved"])
        stored = self.store.db.execute(
            "SELECT outcome,evidence_id FROM lifecycle_outcomes WHERE work=?",
            (work["id"],)).fetchone()
        self.assertEqual(("unresolved", replacement_evidence), tuple(stored))
        audit = self.store.db.execute(
            "SELECT original_outcome,original_evidence_id,original_updated,original_work_state,"
            "original_round_state FROM lifecycle_outcome_corrections WHERE work=?",
            (work["id"],)).fetchone()
        self.assertEqual(("fixed", evidence, self.clock(), "closed",
                          "deployed_resolved"),
                         tuple(audit))

        next_scope, _ = self.graph(resource, [
            ("TARGETABLE_PATH", True, "path:52"),
            ("BUILD_DISPOSITION", "affected", "build:52"),
        ], occurrences=[occurrence])
        work_again = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/four", dependency_scopes=[next_scope])
        self.assertEqual("work", work_again["result"])
        self.assertEqual(2, self.lifecycle.work(work["id"])["round"])

    def test_evidence_quality_route_changes_and_coverage_gaps(self):
        quiet, original, evidence = self.occurrence(
            20, [("CONSTRAINT_EXCLUDES", True, "constraint:20")])
        self.assertEqual("quiet", original["result"])

        resource = "deployment:service-20"
        scope, _ = self.graph(resource, [
            ("CONSTRAINT_EXCLUDES", False, "constraint:20"),
            ("AUTH_EXCEPTION", True, "auth-exception:20"),
        ], scope="paths:" + resource)
        old = self.lifecycle.decision(original["id"])
        self.assertEqual(0, old["current"])
        self.assertEqual(evidence, self.lifecycle.evidence(evidence)["id"])
        changed = self.lifecycle.evaluate(
            self.incident, quiet, rule_version="rules/v1",
            advisory_version="advisory/sha256:one", dependency_scopes=[scope])
        self.assertEqual("work", changed["result"])

        internal, decision, _ = self.occurrence(
            21, [("EXTERNAL_INPUT", True, "external-input:21")])
        self.assertEqual("work", decision["result"])
        self.assertTrue(internal)

        stale_resource = "deployment:stale"
        self.lifecycle.add_occurrence(self.incident, "occ-stale", stale_resource,
                                      service="stale", host="host", deployment="stale")
        stale_scope, _ = self.graph(
            stale_resource, [("CONSTRAINT_EXCLUDES", True, "constraint:stale")],
            expires=self.clock() - 1)
        stale = self.lifecycle.evaluate(
            self.incident, "occ-stale", rule_version="rules/v1",
            advisory_version="advisory/one", dependency_scopes=[stale_scope])
        self.assertNotEqual("quiet", stale["result"])

        incomplete, incomplete_decision, _ = self.occurrence(
            22, [("CONSTRAINT_EXCLUDES", True, "constraint:22")],
            evidence_status="incomplete")
        self.assertNotEqual("quiet", incomplete_decision["result"])
        self.assertTrue(incomplete)

        conflict, conflict_decision, _ = self.occurrence(23, [
            ("CONSTRAINT_EXCLUDES", True, "constraint:23:a"),
            ("CONSTRAINT_EXCLUDES", False, "constraint:23:b"),
        ])
        self.assertEqual("pending", conflict_decision["result"])
        self.assertEqual(["CONSTRAINT_EXCLUDES"], conflict_decision["conflicts"])
        self.assertTrue(conflict)

        unsupported, unsupported_decision, _ = self.occurrence(24, [
            ("TARGETABLE_PATH", True, "path:24"),
            ("EXPLOIT_PREREQUISITE", "unsupported", "prerequisite:24"),
        ])
        self.assertEqual("work", unsupported_decision["result"])
        self.assertEqual("unsupported_prerequisite", unsupported_decision["reason"])
        self.assertTrue(unsupported)

        internal_only, internal_decision, _ = self.occurrence(25, [
            ("BUILD_DISPOSITION", "affected", "build:25"),
            ("TARGETABLE_PATH", False, "path:25"),
        ])
        self.assertEqual("quiet", internal_decision["result"])
        self.assertEqual("no_targetable_path", internal_decision["reason"])
        self.assertTrue(internal_only)

        gap_resource = "deployment:unmapped"
        self.lifecycle.add_occurrence(self.incident, "occ-gap", gap_resource,
                                      service="new", host="host", deployment="new")
        gap = self.lifecycle.evaluate(
            self.incident, "occ-gap", rule_version="rules/v1",
            advisory_version="advisory/one", dependency_scopes=["paths:" + gap_resource])
        self.assertEqual("gap", gap["result"])
        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gaps WHERE scope=?",
            ("paths:" + gap_resource,)).fetchone()[0])

    def test_exact_unaffected_build_wins_without_relationship_coverage(self):
        resource = "deployment:fixed-without-topology"
        occurrence = "occ-fixed-without-topology"
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource,
            service="fixed", host="host", deployment="fixed")
        scope, _ = self.graph(
            resource,
            [("BUILD_DISPOSITION", "unaffected", "build:fixed-without-topology")],
            scope="scanner:fixed-without-topology")
        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1",
            dependency_scopes=[scope, "runtime:missing"])
        self.assertEqual("quiet", decision["result"])
        self.assertEqual("evidenced_exclusion", decision["reason"])

    def test_unpublished_work_is_superseded_when_mapping_removes_work_need(self):
        occurrence, first, _ = self.occurrence(
            26, [("TARGETABLE_PATH", True, "path:26")])
        self.assertEqual("work", first["result"])
        work = self.lifecycle.work(self.incident)
        self.assertEqual("pending", self.lifecycle.next_publication()["state"])
        self.graph("deployment:service-26", [],
                   scope="runtime:host-2:service-26")

        self.graph(
            "deployment:service-26",
            [("TARGETABLE_PATH", False, "path:26")],
            occurrences=[occurrence])
        result = next(item for item in self.lifecycle.evaluate_all()
                      if item["id"].startswith("decision_"))
        self.assertEqual("quiet", result["result"])
        self.assertEqual("superseded", self.lifecycle.work(work["id"])["state"])
        self.assertIsNone(self.lifecycle.next_publication())

        self.graph(
            "deployment:service-26",
            [("TARGETABLE_PATH", True, "path:26")],
            occurrences=[occurrence])
        self.lifecycle.evaluate_all()
        reopened = self.lifecycle.work(work["id"])
        self.assertEqual("ready", reopened["state"])
        self.assertEqual(2, reopened["round"])
        self.assertEqual("pending", self.lifecycle.next_publication()["state"])

    def test_evaluate_all_includes_clear_slots_and_excludes_retired_aliases(self):
        clear = 'occ-clear-current'
        retired = 'occ-retired-alias'
        for occurrence in (clear, retired):
            self.lifecycle.add_occurrence(
                self.incident, occurrence, 'deployment:' + occurrence,
                service=occurrence, host='host', deployment=occurrence)
        self.lifecycle.ensure_work(self.incident, 'fixture', 'fixture:active-round')
        with self.store.db:
            self.store.db.execute(
                'UPDATE lifecycle_occurrences SET active=0 WHERE id IN (?,?)',
                (clear, retired))
            self.store.db.execute(
                'DELETE FROM lifecycle_round_occurrences WHERE occurrence=?',
                (clear,))
            for occurrence, state in ((clear, 'clear'), (retired, 'retired')):
                self.store.db.execute('INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)', (
                    occurrence, self.incident, 'host', 'scope', '[]', state,
                    '{}', 'material', 1.0, 1))

        evaluated = {self.lifecycle.decision(item['id'])['occurrence']
                     for item in self.lifecycle.evaluate_all()}

        self.assertIn(clear, evaluated)
        self.assertNotIn(retired, evaluated)

    def test_expired_connecting_relationship_cannot_reach_a_live_exclusion(self):
        resource = "deployment:edge"
        consumer = "consumer:old"
        occurrence = "occ-expired-edge"
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource,
            service="edge", host="host", deployment="edge")
        evidence_id = "ev-expired-edge"
        scope = "paths:" + resource
        change = self.lifecycle.stage_graph_change(
            "expired-edge", resources=[
                {"resource_key": resource, "kind": "deployment", "name": "edge"},
                {"resource_key": consumer, "kind": "consumer", "name": "old"},
            ], evidence=[{
                "id": evidence_id, "kind": "observation", "scope": scope,
                "source": "fixture", "provenance": "expired-edge",
                "status": "complete", "valid_from": self.clock() - 100,
                "content": {"path": "old consumer"},
            }], assertions=[
                {"logical_key": "edge:old", "version": "v1", "subject": resource,
                 "relation": "RUNS_AS", "object_key": consumer, "value": True,
                 "kind": "observation", "scope": scope, "source": "fixture",
                 "provenance": "expired-edge", "evidence_id": evidence_id,
                 "valid_from": self.clock() - 100,
                 "valid_until": self.clock() - 1},
                {"logical_key": "constraint:old", "version": "v1", "subject": consumer,
                 "relation": "CONSTRAINT_EXCLUDES", "value": True,
                 "kind": "observation", "scope": scope, "source": "fixture",
                 "provenance": "expired-edge", "evidence_id": evidence_id,
                 "valid_from": self.clock() - 100},
            ], coverage=[{
                "logical_key": "coverage:" + scope, "version": "v1", "scope": scope,
                "relationship": "*", "producer": "fixture", "complete": True,
                "status": "valid", "valid_from": self.clock() - 100,
                "evidence_id": evidence_id,
            }])
        self.assertEqual("pending", change["status"])
        self.lifecycle.acknowledge_graph_change("expired-edge")

        decision = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1", dependency_scopes=[scope])

        self.assertNotEqual("quiet", decision["result"])
        retained = self.lifecycle.decision(decision["id"])
        self.assertNotIn("assertion_" + hashlib.sha256(
            json.dumps(["constraint:old", "v1"], sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest(),
            retained["assertion_versions"])

    def test_shared_gap_collects_once_before_one_gap_work_item(self):
        resource = "deployment:shared-gap"
        scope = "paths:" + resource
        for suffix in ("one", "two"):
            with self.store.db:
                incident = self.store._incident("CVE-2026-71" + ("01" if suffix == "one" else "02"))
            occurrence = "occ-gap-" + suffix
            self.lifecycle.add_occurrence(
                incident, occurrence, resource, service="shared", host="host",
                deployment="shared")
            result = self.lifecycle.evaluate(
                incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/v1", dependency_scopes=[scope])
            self.assertEqual("gap", result["result"])

        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gaps WHERE current=1").fetchone()[0])
        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gap_collections WHERE state='pending'").fetchone()[0])
        self.assertEqual(0, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_work").fetchone()[0])
        gap = self.store.db.execute(
            "SELECT id FROM lifecycle_gaps WHERE current=1").fetchone()[0]
        unresolved = self.lifecycle.record_gap_collection(
            gap, "unresolved", "collector has no supplier for this relationship scope")
        self.assertEqual("ready", unresolved["gap_work_state"])
        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gap_work").fetchone()[0])
        publication = self.lifecycle.next_publication()
        self.assertEqual("gap_card", publication["kind"])
        self.assertEqual(2, len(publication["payload"]["links"]))

    def test_shared_gap_membership_tracks_resolution_and_recurrence(self):
        resource = "deployment:shared-membership"
        scope = "paths:" + resource
        occurrences = []
        for suffix in ("one", "two"):
            with self.store.db:
                incident = self.store._incident(
                    "CVE-2026-72" + ("01" if suffix == "one" else "02"))
            occurrence = "occ-membership-" + suffix
            occurrences.append((incident, occurrence))
            self.lifecycle.add_occurrence(
                incident, occurrence, resource, service="shared", host="host",
                deployment="shared")
            decision = self.lifecycle.evaluate(
                incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/v1", dependency_scopes=[scope])
            self.assertEqual("gap", decision["result"])

        gap = self.lifecycle.pending_gap_collections()[0]["id"]
        unresolved = self.lifecycle.record_gap_collection(
            gap, "unresolved", "collector found no relationship supplier")
        self.assertEqual("ready", unresolved["gap_work_state"])

        first_incident, first_occurrence = occurrences[0]
        self.graph(
            resource, [("BUILD_DISPOSITION", "fixed", "build:membership-one")],
            scope="scanner:membership-one", occurrences=[first_occurrence])
        first_quiet = self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])

        self.assertEqual("quiet", first_quiet["result"])
        self.assertEqual(1, self.store.db.execute(
            "SELECT current FROM lifecycle_gaps WHERE id=?", (gap,)).fetchone()[0])
        self.assertEqual([occurrences[1]], [tuple(row) for row in
            self.store.db.execute("""SELECT incident,occurrence
                FROM lifecycle_gap_occurrences WHERE gap=?""", (gap,))])
        publication = self.lifecycle.next_publication()
        self.assertEqual("gap_card", publication["kind"])
        self.assertEqual(2, len(publication["payload"]["links"]))
        link_update = self.store.db.execute("""SELECT payload
            FROM lifecycle_publications WHERE work=? AND kind='gap_scope_update'
                AND state='pending'""", (unresolved["gap_work"],)).fetchone()
        self.assertEqual([{"incident": occurrences[1][0],
                           "occurrence": occurrences[1][1]}],
                         json.loads(link_update["payload"])["links"])

        second_incident, second_occurrence = occurrences[1]
        self.graph(
            resource, [("BUILD_DISPOSITION", "fixed", "build:membership-two")],
            scope="scanner:membership-two", occurrences=[second_occurrence])
        second_quiet = self.lifecycle.evaluate(
            second_incident, second_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])

        self.assertEqual("quiet", second_quiet["result"])
        self.assertEqual(0, self.store.db.execute(
            "SELECT current FROM lifecycle_gaps WHERE id=?", (gap,)).fetchone()[0])
        self.assertEqual(0, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gap_occurrences WHERE gap=?",
            (gap,)).fetchone()[0])
        self.assertEqual("resolved", self.store.db.execute(
            "SELECT state FROM lifecycle_gap_collections WHERE gap=?",
            (gap,)).fetchone()[0])
        self.assertEqual("closed", self.store.db.execute(
            "SELECT state FROM lifecycle_gap_work WHERE gap=?",
            (gap,)).fetchone()[0])
        self.assertEqual("superseded", self.store.db.execute(
            "SELECT state FROM lifecycle_publications WHERE work=?",
            (unresolved["gap_work"],)).fetchone()[0])

        self.graph(
            resource,
            [("BUILD_DISPOSITION", "affected", "build:membership-one")],
            scope="scanner:membership-one", occurrences=[first_occurrence])
        recurrence = self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v3", dependency_scopes=[scope])

        self.assertEqual("gap", recurrence["result"])
        self.assertEqual(gap, self.lifecycle.pending_gap_collections()[0]["id"])
        self.assertEqual([first_occurrence], [row[0] for row in
            self.store.db.execute("""SELECT occurrence
                FROM lifecycle_gap_occurrences WHERE gap=?""", (gap,))])
        reopened = self.lifecycle.record_gap_collection(
            gap, "unresolved", "relationship evidence is still missing")
        self.assertEqual("ready", reopened["gap_work_state"])
        self.assertEqual(2, self.store.db.execute(
            "SELECT round FROM lifecycle_gap_work WHERE gap=?", (gap,)).fetchone()[0])
        self.assertEqual([first_occurrence], [item["occurrence"] for item in
            self.lifecycle.next_publication()["payload"]["links"]])

    def test_occurrence_scoped_assertion_invalidates_outside_prior_scopes(self):
        resource = "deployment:scoped-invalidation"
        occurrence = "occ-scoped-invalidation"
        old_scope = "runtime:scoped-invalidation"
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="scoped", host="host",
            deployment="scoped")
        first = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1", dependency_scopes=[old_scope])
        self.assertEqual("gap", first["result"])

        self.graph(
            resource,
            [("BUILD_DISPOSITION", "fixed", "build:scoped-invalidation")],
            scope="scanner:new-scope", occurrences=[occurrence])

        self.assertEqual(0, self.lifecycle.decision(first["id"])["current"])
        quiet = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[old_scope])
        self.assertEqual("quiet", quiet["result"])

        self.change += 1
        evidence_id = "ev-" + str(self.change)
        self.lifecycle.stage_graph_change(
            "change-" + str(self.change), evidence=[{
                "id": evidence_id, "kind": "observation",
                "scope": "scanner:withdrawal", "source": "fixture",
                "provenance": "withdrawal", "status": "complete",
                "content": {"withdrawn": True},
            }], assertions=[{
                "logical_key": "build:scoped-invalidation", "version": "withdrawn",
                "subject": resource, "relation": "BUILD_DISPOSITION",
                "value": "unknown", "status": "withdrawn",
                "kind": "observation", "scope": "scanner:withdrawal",
                "source": "fixture", "provenance": "withdrawal",
                "evidence_id": evidence_id,
            }])
        self.lifecycle.acknowledge_graph_change("change-" + str(self.change))

        self.assertEqual(0, self.lifecycle.decision(quiet["id"])["current"])

    def test_completed_shared_collection_stays_resolved_during_reevaluation(self):
        resource = "deployment:completed-shared-gap"
        scope = "paths:" + resource
        occurrences = []
        for suffix in ("one", "two"):
            with self.store.db:
                incident = self.store._incident(
                    "CVE-2026-74" + ("01" if suffix == "one" else "02"))
            occurrence = "occ-completed-gap-" + suffix
            occurrences.append((incident, occurrence))
            self.lifecycle.add_occurrence(
                incident, occurrence, resource, service="shared", host="host",
                deployment="shared")
            self.lifecycle.evaluate(
                incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/v1", dependency_scopes=[scope])

        gap = self.lifecycle.pending_gap_collections()[0]["id"]
        self.graph(resource, [], scope=scope, complete=True)
        self.assertEqual((0, "resolved"), tuple(self.store.db.execute("""SELECT
            g.current,c.state FROM lifecycle_gaps g
            JOIN lifecycle_gap_collections c ON c.gap=g.id WHERE g.id=?""",
            (gap,)).fetchone()))

        first_incident, first_occurrence = occurrences[0]
        first = self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])

        self.assertEqual("pending", first["result"])
        self.assertEqual(0, self.store.db.execute(
            "SELECT current FROM lifecycle_gaps WHERE id=?", (gap,)).fetchone()[0])
        self.assertEqual("resolved", self.store.db.execute(
            "SELECT state FROM lifecycle_gap_collections WHERE gap=?",
            (gap,)).fetchone()[0])
        self.assertEqual([occurrences[1][1]], [row[0] for row in
            self.store.db.execute("""SELECT occurrence
                FROM lifecycle_gap_occurrences WHERE gap=?""", (gap,))])

    def test_gap_reevaluation_replaces_stale_scope_memberships(self):
        resource = "deployment:changed-gap-scopes"
        occurrence = "occ-changed-gap-scopes"
        old_scope = "runtime:old-gap-scope"
        retained_scope = "runtime:retained-gap-scope"
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="changed", host="host",
            deployment="changed")
        first = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1",
            dependency_scopes=[old_scope, retained_scope])
        self.assertEqual("gap", first["result"])
        gaps = {row["scope"]: row["id"] for row in self.store.db.execute(
            "SELECT id,scope FROM lifecycle_gaps WHERE current=1")}

        second = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[retained_scope])

        self.assertEqual("gap", second["result"])
        memberships = [row[0] for row in self.store.db.execute(
            "SELECT gap FROM lifecycle_gap_occurrences WHERE occurrence=?",
            (occurrence,))]
        self.assertEqual([gaps[retained_scope]], memberships)
        self.assertEqual(0, self.store.db.execute(
            "SELECT current FROM lifecycle_gaps WHERE id=?",
            (gaps[old_scope],)).fetchone()[0])
        self.assertEqual(1, self.store.db.execute(
            "SELECT current FROM lifecycle_gaps WHERE id=?",
            (gaps[retained_scope],)).fetchone()[0])

    def test_gap_link_updates_survive_unchanged_and_repeated_memberships(self):
        resource = "deployment:repeated-gap-links"
        scope = "paths:" + resource
        occurrences = []
        for suffix in ("a", "b"):
            with self.store.db:
                incident = self.store._incident("CVE-2026-75" + suffix.upper())
            occurrence = "occ-repeated-gap-" + suffix
            occurrences.append((incident, occurrence))
            self.lifecycle.add_occurrence(
                incident, occurrence, resource, service="shared", host="host",
                deployment="shared")
            self.lifecycle.evaluate(
                incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/v1", dependency_scopes=[scope])
        gap = self.lifecycle.pending_gap_collections()[0]["id"]
        self.lifecycle.record_gap_collection(
            gap, "unresolved", "collector found no relationship supplier")
        card = self.lifecycle.next_publication()
        self.lifecycle.publication_sent(card["id"], "kanban://shared-gap")

        first_incident, first_occurrence = occurrences[0]
        self.graph(
            resource, [("BUILD_DISPOSITION", "fixed", "build:repeated-gap-a")],
            scope="scanner:repeated-gap-a", occurrences=[first_occurrence])
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])
        first_update = self.lifecycle.next_publication()
        self.assertEqual("gap_scope_update", first_update["kind"])
        self.assertEqual([occurrences[1][1]], [item["occurrence"] for item in
            first_update["payload"]["links"]])

        second_incident, second_occurrence = occurrences[1]
        unchanged = self.lifecycle.evaluate(
            second_incident, second_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])
        self.assertEqual("gap", unchanged["result"])
        retained_update = self.lifecycle.next_publication()
        self.assertIsNotNone(retained_update)
        self.assertEqual(first_update["id"], retained_update["id"])
        self.assertEqual("pending", retained_update["state"])
        self.lifecycle.publication_sent(
            retained_update["id"], "kanban://shared-gap")

        self.graph(
            resource,
            [("BUILD_DISPOSITION", "affected", "build:repeated-gap-a")],
            scope="scanner:repeated-gap-a", occurrences=[first_occurrence])
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v3", dependency_scopes=[scope])
        expanded = self.lifecycle.next_publication()
        self.assertEqual({item["occurrence"] for item in expanded["payload"]["links"]},
                         {item[1] for item in occurrences})
        self.lifecycle.publication_sent(expanded["id"], "kanban://shared-gap")

        self.graph(
            resource, [("BUILD_DISPOSITION", "fixed", "build:repeated-gap-a")],
            scope="scanner:repeated-gap-a", occurrences=[first_occurrence])
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v4", dependency_scopes=[scope])
        repeated = self.lifecycle.next_publication()
        self.assertEqual([second_occurrence], [item["occurrence"] for item in
            repeated["payload"]["links"]])
        self.assertNotEqual(first_update["id"], repeated["id"])

    def test_duplicate_reopen_receipt_preserves_later_scope_update(self):
        resource = "deployment:duplicate-reopen-receipt"
        scope = "paths:" + resource
        first_incident = self.incident
        first_occurrence = "occ-duplicate-reopen-a"
        self.lifecycle.add_occurrence(
            first_incident, first_occurrence, resource, service="shared",
            host="host", deployment="shared")
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1", dependency_scopes=[scope])
        gap = self.lifecycle.pending_gap_collections()[0]["id"]
        self.lifecycle.record_gap_collection(
            gap, "unresolved", "collector found no relationship supplier")
        card = self.lifecycle.next_publication()
        self.lifecycle.publication_sent(card["id"], "kanban://shared-gap")

        self.graph(
            resource, [("BUILD_DISPOSITION", "fixed", "build:duplicate-reopen-a")],
            scope="scanner:duplicate-reopen-a", occurrences=[first_occurrence])
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])
        self.graph(
            resource,
            [("BUILD_DISPOSITION", "affected", "build:duplicate-reopen-a")],
            scope="scanner:duplicate-reopen-a", occurrences=[first_occurrence])
        self.lifecycle.evaluate(
            first_incident, first_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v3", dependency_scopes=[scope])
        self.lifecycle.record_gap_collection(
            gap, "unresolved", "relationship evidence is still missing")
        reopen = self.lifecycle.next_publication()
        self.assertEqual("gap_reopen", reopen["kind"])
        self.lifecycle.publication_sent(reopen["id"], "kanban://shared-gap")

        with self.store.db:
            second_incident = self.store._incident("CVE-2026-7602")
        second_occurrence = "occ-duplicate-reopen-b"
        self.lifecycle.add_occurrence(
            second_incident, second_occurrence, resource, service="shared",
            host="host", deployment="shared")
        second = self.lifecycle.evaluate(
            second_incident, second_occurrence, rule_version="rules/v1",
            advisory_version="advisory/v1", dependency_scopes=[scope])
        self.assertEqual("gap", second["result"])
        scope_update = self.lifecycle.next_publication()
        self.assertEqual("gap_scope_update", scope_update["kind"])
        self.assertEqual({first_occurrence, second_occurrence},
                         {item["occurrence"] for item in
                          scope_update["payload"]["links"]})

        duplicate = self.lifecycle.record_gap_collection(
            gap, "unresolved", "relationship evidence is still missing")

        self.assertEqual("ready", duplicate["gap_work_state"])
        retained = self.lifecycle.next_publication()
        self.assertIsNotNone(retained)
        self.assertEqual(scope_update["id"], retained["id"])
        self.assertEqual("pending", retained["state"])

    def test_recurring_gap_reopens_collection_without_identity_failure(self):
        resource = "deployment:recurring-gap"
        occurrence = "occ-recurring-gap"
        scope = "paths:" + resource
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="recurring",
            host="host", deployment="recurring")
        first = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a1", dependency_scopes=[scope])
        self.assertEqual("gap", first["result"])
        gap = self.lifecycle.pending_gap_collections()[0]["id"]
        self.lifecycle.record_gap_collection(
            gap, "unresolved", "first collection found no supplier")
        self.lifecycle.record_gap_collection(gap, "resolved", "collector supplied coverage")
        self.graph(resource, [("CONSTRAINT_EXCLUDES", True, "constraint:recurring")],
                   scope=scope)
        quiet = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a2", dependency_scopes=[scope])
        self.assertEqual("quiet", quiet["result"])
        self.graph(resource, [], scope=scope, complete=False)
        recurring = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a3", dependency_scopes=[scope])
        self.assertEqual("gap", recurring["result"])
        self.assertEqual(gap, self.lifecycle.pending_gap_collections()[0]["id"])
        reopened = self.lifecycle.record_gap_collection(
            gap, "unresolved", "collector still reports incomplete coverage")
        self.assertEqual("ready", reopened["gap_work_state"])

    def test_later_incomplete_coverage_is_the_collection_receipt(self):
        resource = "deployment:collection-receipt"
        occurrence = "occ-collection-receipt"
        scope = "paths:" + resource
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="receipt",
            host="host", deployment="receipt")
        self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a1", dependency_scopes=[scope])
        self.assertEqual(0, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gap_work").fetchone()[0])

        self.graph(resource, [], scope=scope, complete=False)

        self.assertEqual(1, self.store.db.execute(
            "SELECT count(*) FROM lifecycle_gap_work").fetchone()[0])
        collection = self.store.db.execute(
            "SELECT state,detail FROM lifecycle_gap_collections").fetchone()
        self.assertEqual("unresolved", collection["state"])
        self.assertIn("fixture", collection["detail"])

    def test_later_complete_coverage_is_the_resolution_receipt(self):
        resource = "deployment:collection-resolution"
        occurrence = "occ-collection-resolution"
        scope = "paths:" + resource
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="resolution",
            host="host", deployment="resolution")
        self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a1", dependency_scopes=[scope])

        self.graph(resource, [], scope=scope, complete=True)

        collection = self.store.db.execute("""SELECT state,collector,receipt,
            attempt_revision FROM lifecycle_gap_collections""").fetchone()
        self.assertEqual("resolved", collection["state"])
        self.assertEqual("fixture", collection["collector"])
        self.assertTrue(json.loads(collection["receipt"])["complete"])
        self.assertEqual(self.lifecycle._revision(), collection["attempt_revision"])

    def test_supplier_registry_promotes_a_gap_with_no_configured_supplier(self):
        resource = "deployment:no-supplier"
        occurrence = "occ-no-supplier"
        scope = "unmapped:" + occurrence
        self.lifecycle.add_occurrence(
            self.incident, occurrence, resource, service="no-supplier",
            host="host", deployment="no-supplier")
        self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="a1", dependency_scopes=[scope])

        completed = self.lifecycle.record_unsupplied_gap_collections(
            ["runtime:", "paths:", "build:"], self.lifecycle._revision())

        self.assertEqual(1, len(completed))
        self.assertEqual("ready", completed[0]["gap_work_state"])
        collection = self.store.db.execute("""SELECT state,collector,receipt
            FROM lifecycle_gap_collections""").fetchone()
        self.assertEqual("unresolved", collection["state"])
        self.assertEqual("supplier-registry", collection["collector"])
        self.assertEqual("no_supplier", json.loads(collection["receipt"])["kind"])

    def test_cycles_count_only_successful_relevant_missed_opportunities(self):
        tracked, _, _ = self.occurrence(
            60, [("BUILD_DISPOSITION", "fixed", "build:60")])
        package = "apt:bookworm:openssl"
        args = {"owner": "ansible:media", "package_key": package,
                "affected_scope": [self.incident], "update_available": True,
                "expected": "3.0.18", "relevant": True,
                "affected_occurrences": [tracked]}
        first = self.lifecycle.record_cycle(
            "cycle-1", status="success", outcome="noop", attempt_id="attempt-1",
            receipt={"pin": "3.0.17", "result": "unchanged"}, **args)
        self.assertEqual(1, first["missed"])
        retry = self.lifecycle.record_cycle(
            "cycle-1", status="success", outcome="noop", attempt_id="attempt-1-retry",
            receipt={"pin": "3.0.17", "result": "unchanged"}, **args)
        self.assertEqual(1, retry["missed"])
        failed = self.lifecycle.record_cycle(
            "cycle-failed", status="failed", outcome="failed", attempt_id="attempt-failed",
            receipt={"result": "failed"}, **args)
        self.assertEqual(1, failed["missed"])
        unrelated = self.lifecycle.record_cycle(
            "cycle-unrelated", status="success", outcome="noop", relevant=False,
            attempt_id="attempt-unrelated", receipt={"result": "other change"},
            **{k: v for k, v in args.items() if k != "relevant"})
        self.assertEqual(1, unrelated["missed"])
        second = self.lifecycle.record_cycle(
            "cycle-2", status="success", outcome="missed", attempt_id="attempt-2",
            receipt={"pin": "3.0.17", "result": "unchanged"}, **args)
        self.assertEqual(2, second["missed"])
        self.assertEqual(1, len(second["maintenance_work"]))
        reset = self.lifecycle.record_cycle(
            "cycle-3", status="success", outcome="updated", attempt_id="attempt-3",
            receipt={"observed": "3.0.18"}, **args)
        self.assertEqual(0, reset["missed"])

        retry_args = {**args, "package_key": "apt:bookworm:retry-package"}
        failed_attempt = self.lifecycle.record_cycle(
            "logical-retry", status="failed", outcome="failed",
            attempt_id="logical-retry-1", receipt={"result": "failed"},
            **retry_args)
        self.assertEqual(0, failed_attempt["missed"])
        successful_retry = self.lifecycle.record_cycle(
            "logical-retry", status="success", outcome="missed",
            attempt_id="logical-retry-2",
            receipt={"pin": "3.0.17", "result": "unchanged"}, **retry_args)
        self.assertEqual(1, successful_retry["missed"])
        retry_second = self.lifecycle.record_cycle(
            "logical-retry-next", status="success", outcome="noop",
            attempt_id="logical-retry-next-1",
            receipt={"pin": "3.0.17", "result": "unchanged"}, **retry_args)
        self.assertEqual(2, retry_second["missed"])

    def test_quiet_occurrence_is_in_maintenance_investigation_scope(self):
        occurrence, decision, _ = self.occurrence(
            61, [("BUILD_DISPOSITION", "fixed", "build:61")])
        self.assertEqual("quiet", decision["result"])
        args = {"owner": "ansible:media", "package_key": "apt:bookworm:quiet",
                "affected_scope": [self.incident], "update_available": True,
                "expected": "2", "status": "success", "outcome": "noop",
                "relevant": True, "receipt": {"pin": "1"},
                "affected_occurrences": [occurrence]}
        self.lifecycle.record_cycle("quiet-cycle-1", attempt_id="quiet-attempt-1", **args)
        second = self.lifecycle.record_cycle(
            "quiet-cycle-2", attempt_id="quiet-attempt-2", **args)
        work = second["maintenance_work"][0]
        investigation = self.lifecycle.scope(work, "investigation")
        self.assertEqual([occurrence], [item["id"] for item in investigation["occurrences"]])

    def test_provisioning_run_freezes_candidates_and_records_observed_noop(self):
        occurrence, decision, _ = self.occurrence(
            63, [("CONSTRAINT_EXCLUDES", True, "constraint:63")])
        self.assertEqual("quiet", decision["result"])
        finding = {"installation": "deployment:service-63",
                   "ecosystem": "Debian", "package": "openssl",
                   "installed": "3.0.17", "fixed": "3.0.18"}
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "host-0", "packages", "[]",
                 "affected", json.dumps(finding), "material", self.clock(), 1))
        opportunity = [{"installation": "deployment:service-63",
                        "ecosystem": "Debian", "package": "openssl",
                        "candidate": "3.0.18", "available": True,
                        "source": "stable-channel", "channel": "apt:bookworm",
                        "platform": "debian:bookworm:x86_64",
                        "provenance": "fixture", "observed_at": self.clock(),
                        "reason": ""}]
        for number in (1, 2):
            cycle = "provisioning-" + str(number)
            begun = self.lifecycle.begin_provisioning_cycle(
                cycle, "ansible:host-0", ["host-0"],
                ["deployment:service-63"], opportunity,
                self.availability_receipt())
            self.assertEqual(1, len(begun["candidates"]))
            finished = self.lifecycle.finish_provisioning_cycle(
                cycle, "attempt-" + str(number), "success",
                {"play": "service", "scanner": "accepted",
                 "post_availability": {"observations": [{
                     **opportunity[0], "installed": "3.0.17",
                     "provenance": "post-fixture",
                 }]}})
            self.assertEqual("saved", finished["status"])
            self.assertEqual("noop", self.store.db.execute(
                "SELECT outcome FROM lifecycle_cycles ORDER BY created DESC LIMIT 1").fetchone()[0])
        work = self.lifecycle.work(self.incident)
        self.assertEqual([occurrence], [item["id"] for item in
            self.lifecycle.scope(work["id"], "investigation")["occurrences"]])

    def test_expected_artifact_update_resets_misses_while_cve_remains_affected(self):
        occurrence, decision, _ = self.occurrence(
            70, [("CONSTRAINT_EXCLUDES", True, "constraint:70")])
        self.assertEqual("quiet", decision["result"])
        finding = {"installation": "binary:/usr/bin/caddy",
                   "ecosystem": "gobinary", "package": "stdlib",
                   "installed": "go1.26.6", "fixed": "go1.26.7"}
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "host-0", "packages", "[]",
                 "affected", json.dumps(finding), "material", self.clock(), 1))
        opportunity = [{
            "installation": "binary:/usr/bin/caddy", "ecosystem": "gobinary",
            "package": "stdlib", "candidate": "2.11.5", "installed": "2.11.4",
            "available": True, "source": "configured-release-channel",
            "channel": "stable", "platform": "linux-amd64",
            "provenance": "pre-fixture", "observed_at": self.clock(), "reason": "",
        }]
        self.lifecycle.begin_provisioning_cycle(
            "artifact-update", "ansible:host-0", ["host-0"],
            ["binary:/usr/bin/caddy"], opportunity,
            self.availability_receipt())

        finished = self.lifecycle.finish_provisioning_cycle(
            "artifact-update", "artifact-update-attempt", "success", {
                "play": "caddy", "scanner": "accepted",
                "post_availability": {"observations": [{
                    **opportunity[0], "installed": "2.11.5",
                    "candidate": "unknown", "available": False,
                    "provenance": "post-fixture",
                    "reason": "channel_query_failed",
                }], "receipt": {"status": "incomplete"}},
            })

        self.assertEqual("updated", self.store.db.execute(
            "SELECT outcome FROM lifecycle_cycles WHERE id LIKE 'artifact-update:%'"
        ).fetchone()[0])
        self.assertEqual(0, finished["results"][0]["missed"])
        self.assertEqual("affected", self.store.db.execute(
            "SELECT state FROM occurrences WHERE id=?", (occurrence,)).fetchone()[0])

    def test_unobserved_expected_artifact_update_counts_as_a_miss(self):
        occurrence, _, _ = self.occurrence(
            71, [("CONSTRAINT_EXCLUDES", True, "constraint:71")])
        finding = {"installation": "binary:/opt/pocket-id/pocket-id",
                   "ecosystem": "gobinary", "package": "golang.org/x/net",
                   "installed": "v0.42.0", "fixed": "v0.43.0"}
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "host-1", "packages", "[]",
                 "affected", json.dumps(finding), "material", self.clock(), 1))
        opportunity = [{
            "installation": "binary:/opt/pocket-id/pocket-id",
            "ecosystem": "gobinary", "package": "golang.org/x/net",
            "candidate": "2.15.0", "installed": "2.14.0", "available": True,
            "source": "configured-release-channel", "channel": "stable",
            "platform": "linux-amd64", "provenance": "pre-fixture",
            "observed_at": self.clock(), "reason": "",
        }]
        self.lifecycle.begin_provisioning_cycle(
            "artifact-missed", "ansible:host-1", ["host-1"],
            ["binary:/opt/pocket-id/pocket-id"], opportunity,
            self.availability_receipt())

        finished = self.lifecycle.finish_provisioning_cycle(
            "artifact-missed", "artifact-missed-attempt", "success", {
                "play": "pocket-id", "scanner": "accepted",
                "post_availability": {"observations": [{
                    **opportunity[0], "provenance": "post-fixture",
                }]},
            })

        self.assertEqual("noop", self.store.db.execute(
            "SELECT outcome FROM lifecycle_cycles WHERE id LIKE 'artifact-missed:%'"
        ).fetchone()[0])
        self.assertEqual(1, finished["results"][0]["missed"])

    def test_missing_post_artifact_observation_preserves_existing_miss(self):
        occurrence, _, _ = self.occurrence(
            72, [("CONSTRAINT_EXCLUDES", True, "constraint:72")])
        finding = {"installation": "binary:/usr/bin/caddy",
                   "ecosystem": "gobinary", "package": "stdlib",
                   "installed": "go1.26.6", "fixed": "go1.26.7"}
        with self.store.db:
            self.store.db.execute(
                "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                (occurrence, self.incident, "host-0", "packages", "[]",
                 "affected", json.dumps(finding), "material", self.clock(), 1))
        opportunity = [{
            "installation": "binary:/usr/bin/caddy", "ecosystem": "gobinary",
            "package": "stdlib", "candidate": "2.11.5", "installed": "2.11.4",
            "available": True, "source": "configured-release-channel",
            "channel": "stable", "platform": "linux-amd64",
            "provenance": "pre-fixture", "observed_at": self.clock(), "reason": "",
        }]
        for number, post in (
                (1, {"observations": [{**opportunity[0],
                                       "provenance": "unchanged-fixture"}]}),
                (2, {"observations": [], "receipt": {"status": "incomplete"}})):
            cycle = "artifact-evidence-" + str(number)
            self.lifecycle.begin_provisioning_cycle(
                cycle, "ansible:host-0", ["host-0"],
                ["binary:/usr/bin/caddy"], opportunity,
                self.availability_receipt())
            finished = self.lifecycle.finish_provisioning_cycle(
                cycle, "artifact-evidence-attempt-" + str(number), "success",
                {"play": "caddy", "scanner": "accepted",
                 "post_availability": post})

        self.assertEqual(1, finished["results"][0]["missed"])
        self.assertEqual([], finished["results"][0]["maintenance_work"])
        self.assertEqual("unobserved", self.store.db.execute(
            "SELECT outcome FROM lifecycle_cycles WHERE id LIKE 'artifact-evidence-2:%'"
        ).fetchone()[0])

        reconciled = self.lifecycle.finish_provisioning_cycle(
            "artifact-evidence-2", "artifact-evidence-reconciled", "success", {
                "play": "caddy", "scanner": "accepted",
                "post_availability": {"observations": [{
                    **opportunity[0], "installed": "2.11.5",
                    "provenance": "reconciled-fixture",
                }]},
            })

        self.assertEqual(0, reconciled["results"][0]["missed"])
        self.assertEqual("updated", self.store.db.execute(
            "SELECT outcome FROM lifecycle_cycles WHERE id LIKE 'artifact-evidence-2:%'"
        ).fetchone()[0])

    def test_provisioning_uses_only_owned_installations_with_observed_availability(self):
        owned, _, _ = self.occurrence(
            64, [("CONSTRAINT_EXCLUDES", True, "constraint:64")])
        unrelated, _, _ = self.occurrence(
            65, [("CONSTRAINT_EXCLUDES", True, "constraint:65")])
        for occurrence, installation, package in (
                (owned, "deployment:owned", "owned-package"),
                (unrelated, "deployment:unrelated", "other-package")):
            finding = {"installation": installation, "ecosystem": "Debian",
                       "package": package, "installed": "1", "fixed": "2"}
            with self.store.db:
                self.store.db.execute(
                    "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (occurrence, self.incident, "host-1", "packages", "[]",
                     "affected", json.dumps(finding), "material", self.clock(), 1))
        begun = self.lifecycle.begin_provisioning_cycle(
            "owned-cycle", "ansible:host-1", ["host-1"],
            ["deployment:owned"], [{
                "installation": "deployment:owned", "ecosystem": "Debian",
                "package": "owned-package", "candidate": "2",
                "available": True, "source": "stable-channel",
                "channel": "apt:bookworm",
                "platform": "debian:bookworm:x86_64",
                "provenance": "fixture", "observed_at": self.clock(),
                "reason": ""}], self.availability_receipt())
        self.assertEqual([owned], begun["candidates"][0]["occurrences"])
        self.assertEqual("stable-channel",
                         begun["candidates"][0]["availability"]["source"])

    def test_missed_counts_are_separate_for_the_same_package_in_two_installations(self):
        occurrences = []
        for number, installation in ((68, "deployment:first"),
                                     (69, "deployment:second")):
            occurrence, _, _ = self.occurrence(
                number, [("CONSTRAINT_EXCLUDES", True, f"constraint:{number}")])
            occurrences.append(occurrence)
            finding = {"installation": installation, "ecosystem": "Debian",
                       "package": "shared-package", "installed": "1", "fixed": "2"}
            with self.store.db:
                self.store.db.execute(
                    "INSERT INTO occurrences VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (occurrence, self.incident, "host-2", "packages", "[]",
                     "affected", json.dumps(finding), "material", self.clock(), 1))

        results = []
        for index, (occurrence, installation) in enumerate(zip(
                occurrences, ("deployment:first", "deployment:second")), 1):
            cycle = "separate-installation-" + str(index)
            opportunity = [{
                "installation": installation, "ecosystem": "Debian",
                "package": "shared-package", "candidate": "2",
                "available": True, "source": "stable-channel",
                "channel": "apt:bookworm",
                "platform": "debian:bookworm:x86_64",
                "provenance": "fixture", "observed_at": self.clock(),
                "reason": ""}]
            self.lifecycle.begin_provisioning_cycle(
                cycle, "ansible:host-2", ["host-2"], [installation], opportunity,
                self.availability_receipt())
            results.append(self.lifecycle.finish_provisioning_cycle(
                cycle, "separate-attempt-" + str(index), "success",
                {"play": installation, "scanner": "accepted",
                 "post_availability": {"observations": [{
                     **opportunity[0], "installed": "1",
                     "provenance": "post-fixture",
                 }]}})["results"][0])

        self.assertEqual([1, 1], [result["missed"] for result in results])
        self.assertEqual([], [work for result in results
                              for work in result["maintenance_work"]])

    def test_maintenance_investigation_excludes_other_quiet_occurrences(self):
        first, _, _ = self.occurrence(
            66, [("BUILD_DISPOSITION", "fixed", "build:66")])
        second, _, _ = self.occurrence(
            67, [("BUILD_DISPOSITION", "fixed", "build:67")])
        args = {"owner": "ansible:host-1", "package_key": "Debian:host-1:pkg",
                "affected_scope": [self.incident], "affected_occurrences": [first],
                "update_available": True, "expected": "2", "status": "success",
                "outcome": "noop", "relevant": True, "receipt": {"pin": "1"}}
        self.lifecycle.record_cycle("scoped-cycle-1", attempt_id="scoped-attempt-1", **args)
        promoted = self.lifecycle.record_cycle(
            "scoped-cycle-2", attempt_id="scoped-attempt-2", **args)
        work = promoted["maintenance_work"][0]
        investigation = self.lifecycle.scope(work, "investigation")
        self.assertEqual([first], [item["id"] for item in investigation["occurrences"]])
        self.assertEqual({first, second}, {item["id"] for item in
            self.lifecycle.scope(work, "remediation")["occurrences"]})

    def test_constraint_evidence_cannot_be_recorded_as_fixed_or_removed(self):
        occurrence, _, _ = self.occurrence(
            62, [("TARGETABLE_PATH", True, "path:62")])
        work = self.lifecycle.work(self.incident)
        resource = "deployment:service-62"
        scope, evidence = self.graph(resource, [
            ("BUILD_DISPOSITION", "affected", "build:62"),
            ("CONSTRAINT_EXCLUDES", True, "constraint:62"),
        ])
        quiet = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/v2", dependency_scopes=[scope])
        self.assertEqual("quiet", quiet["result"])
        for outcome in ("fixed", "removed"):
            with self.subTest(outcome=outcome), self.assertRaisesRegex(
                    ValueError, "outcome_not_observed"):
                self.lifecycle.record_deployment_outcome(
                    work["id"], occurrence, outcome, "not an update observation",
                    evidence, quiet["id"])

    def test_publication_retry_is_stable_and_pr_does_not_resolve_deployment(self):
        occurrence, _, _ = self.occurrence(
            30, [("TARGETABLE_PATH", True, "path:30")])
        work = self.lifecycle.work(self.incident)
        card = self.lifecycle.next_publication()
        self.assertEqual("card", card["kind"])
        self.assertFalse(card["payload"]["wake"])
        self.assertFalse(card["payload"]["subscribe"])
        self.lifecycle.publication_uncertain(card["id"])
        retry = self.lifecycle.next_publication()
        self.assertEqual(card["transaction_id"], retry["transaction_id"])
        self.lifecycle.publication_sent(card["id"], "kanban://card/42")
        root = self.lifecycle.next_publication()
        self.assertEqual("matrix_root", root["kind"])
        self.lifecycle.publication_sent(root["id"], "$root")
        self.assertIsNone(self.lifecycle.next_publication())
        self.assertNotIn("@", self.lifecycle.alert(work["id"]))

        proposal = self.lifecycle.propose(
            work["id"], None, repository="homelab", branch="fix/cve-2026-7001",
            changes=[{"path": "apps/service.yml", "version": "2"}],
            validation=[{"command": "test", "status": "passed"}], blockers=[],
            occurrences=[occurrence], pr="https://example.invalid/pr/1")
        self.assertEqual("saved", proposal["status"])
        self.lifecycle.record_outcome(work["id"], occurrence, "proposed", "PR 1")
        result = self.lifecycle.complete_round(work["id"])
        self.assertEqual("incomplete", result["status"])

    def test_restart_and_import_retry_preserve_identities(self):
        occurrence, decision, evidence = self.occurrence(
            40, [("BUILD_DISPOSITION", "fixed", "build:40")])
        repeated = self.lifecycle.evaluate(
            self.incident, occurrence, rule_version="rules/v1",
            advisory_version="advisory/sha256:one",
            dependency_scopes=["paths:deployment:service-40"])
        self.assertEqual(decision["id"], repeated["id"])
        self.assertEqual(1, self.lifecycle.decision(decision["id"])["current"])
        work = self.lifecycle.ensure_work(self.incident, "manual maintenance", "manual:40")
        self.lifecycle.set_link(work["id"], "ticket", "kanban://card/40")
        self.lifecycle.set_link(work["id"], "thread", "$thread-40")
        imported = self.lifecycle.import_legacy("legacy-v1")
        again = self.lifecycle.import_legacy("legacy-v1")
        self.assertEqual("imported", imported["status"])
        self.assertEqual("duplicate", again["status"])
        self.assertEqual(imported["occurrences"], again["occurrences"])
        self.store.close()
        self.store = IncidentStore(self.path, clock=self.clock)
        self.lifecycle = self.store.lifecycle
        self.assertEqual(evidence, self.lifecycle.evidence(evidence)["id"])
        self.assertEqual(decision["evaluation_identity"],
                         self.lifecycle.decision(decision["id"])["evaluation_identity"])
        self.assertEqual(occurrence, self.lifecycle.scope(
            self.lifecycle.work(self.incident)["id"], "remediation")["occurrences"][0]["id"])
        restored = self.lifecycle.work(self.incident)
        self.assertEqual("kanban://card/40", restored["ticket"])
        self.assertEqual("$thread-40", restored["thread"])

    def test_evaluator_implementation_changes_decision_identity(self):
        occurrence, first, _ = self.occurrence(
            68, [("BUILD_DISPOSITION", "unaffected", "build:68")])
        first_row = self.lifecycle.decision(first["id"])
        replacement = "cve_lifecycle.py:sha256:" + "f" * 64

        with mock.patch.object(
                type(self.lifecycle), "_evaluator_version", create=True,
                return_value=replacement):
            second = self.lifecycle.evaluate(
                self.incident, occurrence, rule_version="rules/v1",
                advisory_version="advisory/sha256:one",
                dependency_scopes=["paths:deployment:service-68"])

        second_row = self.lifecycle.decision(second["id"])
        self.assertNotEqual(first["id"], second["id"])
        self.assertNotEqual(first["evaluation_identity"],
                            second["evaluation_identity"])
        self.assertEqual(replacement, second["evaluator_version"])
        self.assertEqual("rules/v1", second_row["rule_version"])
        self.assertEqual("advisory/sha256:one",
                         second_row["advisory_version"])
        self.assertEqual(0, self.lifecycle.decision(first_row["id"])["current"])
        self.assertEqual(1, second_row["current"])

    def test_evaluate_all_binds_evaluator_version(self):
        occurrence, _, _ = self.occurrence(
            69, [("BUILD_DISPOSITION", "unaffected", "build:69")])
        expected = "cve_lifecycle.py:sha256:" + "e" * 64

        with mock.patch.object(
                type(self.lifecycle), "_evaluator_version", create=True,
                return_value=expected):
            result = next(item for item in self.lifecycle.evaluate_all()
                          if self.lifecycle.decision(item["id"])["occurrence"] ==
                          occurrence)

        stored = self.lifecycle.decision(result["id"])
        self.assertEqual(expected, result["evaluator_version"])
        self.assertEqual(expected, stored["evaluator_version"])
        self.assertEqual("cve-lifecycle/v1", stored["rule_version"])
        self.assertTrue(stored["advisory_version"].startswith("incident:"))

    def test_old_decision_rows_receive_an_explicit_legacy_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute("""CREATE TABLE lifecycle_decisions (
                id TEXT PRIMARY KEY, incident TEXT NOT NULL,
                occurrence TEXT NOT NULL, result TEXT NOT NULL,
                reason TEXT NOT NULL, rule_version TEXT NOT NULL,
                advisory_version TEXT NOT NULL, evaluated REAL NOT NULL,
                evaluation_identity TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, predicates TEXT NOT NULL,
                dependency_scopes TEXT NOT NULL,
                assertion_versions TEXT NOT NULL,
                coverage_versions TEXT NOT NULL, evidence_ids TEXT NOT NULL,
                current INTEGER NOT NULL)""")
            connection.execute(
                "INSERT INTO lifecycle_decisions VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("decision-legacy", "incident-legacy", "occ-legacy", "pending",
                 "prerequisite_evidence_missing", "rules/legacy",
                 "advisory/legacy", 1, "identity-legacy", 1, "{}", "[]",
                 "[]", "[]", "[]", 0))
            connection.commit()
            connection.close()

            store = IncidentStore(path, clock=self.clock)
            try:
                decision = store.lifecycle.decision("decision-legacy")
                self.assertEqual("legacy:unrecorded",
                                 decision["evaluator_version"])
                self.assertEqual("rules/legacy", decision["rule_version"])
                self.assertEqual("advisory/legacy",
                                 decision["advisory_version"])
            finally:
                store.close()

    def test_legacy_thread_import_does_not_publish_or_start_work(self):
        with self.store.db:
            legacy = self.store._incident("CVE-2026-7999")
            self.store.db.execute(
                "UPDATE incidents SET root=? WHERE id=?", ("$legacy-root", legacy))
            self.store.db.execute(
                "INSERT INTO alias_evidence VALUES (?,?,?,?,?)",
                ("aliases-v1", json.dumps(["CVE-2026-7999"]), "osv",
                 "osv-revision", self.clock()))
            self.store.db.execute(
                "INSERT INTO assessments VALUES (?,?,?,?,?,?)",
                ("legacy-assessment", legacy, 1, self.clock(),
                 json.dumps({"summary": "historical agent conclusion"}), 1))
            snapshot = json.dumps(
                {"source": "legacy-source", "sequence": 1},
                sort_keys=True, separators=(",", ":")).encode()
            self.store.db.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?)",
                ("legacy-source", "generation", 1,
                 hashlib.sha256(snapshot).hexdigest(), zlib.compress(snapshot),
                 self.clock()))
        imported = self.lifecycle.import_legacy("thread-mapping-v1")
        self.assertEqual(1, imported["links"])
        self.assertGreaterEqual(imported["aliases"], 1)
        self.assertEqual(1, imported["assessments"])
        retained_scan = self.store.db.execute(
            "SELECT id FROM lifecycle_evidence WHERE kind='legacy_scan_reference'").fetchone()[0]
        self.assertEqual("legacy-source",
                         self.lifecycle.evidence(retained_scan)["content"]["source"])
        retained_assessment = self.store.db.execute(
            "SELECT id FROM lifecycle_evidence WHERE kind='authored_assessment'").fetchone()[0]
        self.assertEqual("historical agent conclusion",
                         self.lifecycle.evidence(retained_assessment)["content"]["summary"])
        work = self.lifecycle.work(legacy)
        self.assertEqual(0, work["round"])
        self.assertEqual("legacy", work["state"])
        self.assertEqual("$legacy-root", work["thread"])
        self.assertIsNone(self.lifecycle.next_publication())

        resource = "deployment:legacy-target"
        self.lifecycle.add_occurrence(
            legacy, "occ-legacy", resource, service="legacy", host="host",
            deployment="container")
        scope, _ = self.graph(
            resource, [("TARGETABLE_PATH", True, "path:legacy")])
        decision = self.lifecycle.evaluate(
            legacy, "occ-legacy", rule_version="rules/v1",
            advisory_version="advisory/legacy", dependency_scopes=[scope])
        self.assertEqual("work", decision["result"])
        self.assertEqual(1, self.lifecycle.work(legacy)["round"])
        self.assertEqual("card", self.lifecycle.next_publication()["kind"])

    def test_graph_changes_are_ordered_and_immutable_identities_are_enforced(self):
        first = self.lifecycle.stage_graph_change(
            "ordered-1", evidence=[{
                "id": "immutable-evidence", "kind": "declaration",
                "scope": "route:one", "source": "fixture",
                "provenance": "inventory/one", "status": "complete",
                "content": {"value": 1}}])
        second = self.lifecycle.stage_graph_change("ordered-2")
        with self.assertRaisesRegex(ValueError, "dependency_pending"):
            self.lifecycle.acknowledge_graph_change("ordered-2")
        self.lifecycle.acknowledge_graph_change("ordered-1")
        self.assertEqual({"value": 1},
                         self.lifecycle.evidence("immutable-evidence")["content"])
        self.lifecycle.acknowledge_graph_change("ordered-2")
        self.lifecycle.stage_graph_change(
            "identity-conflict", evidence=[{
                "id": "immutable-evidence", "kind": "declaration",
                "scope": "route:one", "source": "fixture",
                "provenance": "inventory/one", "status": "complete",
                "content": {"value": 2}}])
        with self.assertRaisesRegex(ValueError, "identity_conflict"):
            self.lifecycle.acknowledge_graph_change("identity-conflict")
        self.assertEqual({"value": 1},
                         self.lifecycle.evidence("immutable-evidence")["content"])

    def test_occurrence_scoped_build_assertions_do_not_leak_across_a_deployment(self):
        resource = "deployment:shared"
        self.lifecycle.add_occurrence(
            self.incident, "occ-shared-fixed", resource, service="shared",
            host="host", deployment="container")
        self.lifecycle.add_occurrence(
            self.incident, "occ-shared-affected", resource, service="shared",
            host="host", deployment="container")
        self.lifecycle.stage_graph_change(
            "scoped-builds", evidence=[{
                "id": "scoped-evidence", "kind": "observation",
                "scope": "scanner:host", "source": "fixture",
                "provenance": "scan:one", "status": "complete",
                "content": {"scan": 1}}], assertions=[{
                    "logical_key": "build:fixed", "version": "one",
                    "subject": resource, "relation": "BUILD_DISPOSITION",
                    "value": "fixed", "kind": "observation",
                    "scope": "scanner:fixed", "source": "fixture",
                    "provenance": "scan:one", "evidence_id": "scoped-evidence",
                    "occurrences": ["occ-shared-fixed"]}, {
                    "logical_key": "build:affected", "version": "one",
                    "subject": resource, "relation": "BUILD_DISPOSITION",
                    "value": "affected", "kind": "observation",
                    "scope": "scanner:affected", "source": "fixture",
                    "provenance": "scan:one", "evidence_id": "scoped-evidence",
                    "occurrences": ["occ-shared-affected"]}], coverage=[{
                    "logical_key": "coverage:fixed", "version": "one",
                    "scope": "scanner:fixed", "relationship": "build",
                    "producer": "fixture", "complete": True,
                    "status": "valid", "evidence_id": "scoped-evidence"}, {
                    "logical_key": "coverage:affected", "version": "one",
                    "scope": "scanner:affected", "relationship": "build",
                    "producer": "fixture", "complete": True,
                    "status": "valid", "evidence_id": "scoped-evidence"}])
        self.lifecycle.acknowledge_graph_change("scoped-builds")
        fixed = self.lifecycle.evaluate(
            self.incident, "occ-shared-fixed", rule_version="rules/v1",
            advisory_version="advisory/fixed",
            dependency_scopes=["scanner:fixed"])
        affected = self.lifecycle.evaluate(
            self.incident, "occ-shared-affected", rule_version="rules/v1",
            advisory_version="advisory/affected",
            dependency_scopes=["scanner:affected"])
        self.assertEqual("quiet", fixed["result"])
        self.assertEqual("pending", affected["result"])


if __name__ == "__main__":
    unittest.main()
