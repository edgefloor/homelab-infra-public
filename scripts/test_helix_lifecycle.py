from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest import mock
from urllib import error


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/vulnerability_incidents/files"
sys.path.insert(0, str(FILES))

from helix_lifecycle import HelixError, HelixLifecycleClient, _hash
from incident_store import IncidentStore


class CapturingHelix(HelixLifecycleClient):
    def __init__(self):
        super().__init__("http://unused.invalid")
        self.calls = []

    def call(self, payload, durable=False):
        self.calls.append((payload, durable))
        if payload["query_name"] == "lifecycle_change_exists":
            return {"count": 0}
        return {}


class SnapshotGraph:
    def __init__(self, snapshot):
        self.value = snapshot
        self.calls = []

    def snapshot(self, revision):
        self.calls.append(revision)
        return self.value

    def search_evidence(self, text, limit):
        return [{"id": "ev-helix", "content": {"text": text}, "score": 1.0}]

    def relationship_records(self, resource_key, revision, occurrence=None):
        self.calls.append(revision)
        return [item for item in self.value["assertions"]
                if item.get("subject") == resource_key and
                (occurrence is None or not item.get("occurrences") or
                 occurrence in item["occurrences"])]

    def prime_relationship_records(self, resource_keys, revision):
        self.calls.append(("prime_relationships", tuple(sorted(resource_keys)), revision))

    def evidence_record(self, identifier, revision):
        self.calls.append(("evidence", identifier, revision))
        return next((item for item in self.value["evidence"]
                     if item["id"] == identifier), None)

    def coverage_records(self, scopes, revision):
        self.calls.append(("coverage", tuple(scopes), revision))
        return [item for item in self.value["coverage"]
                if item["scope"] in scopes]

    def prime_coverage_records(self, scopes, revision):
        self.calls.append(("prime_coverage", tuple(sorted(scopes)), revision))


class ScopedGraph(SnapshotGraph):
    def snapshot(self, revision):
        raise AssertionError("evaluation must not request an unbounded graph snapshot")


class HelixLifecycleTests(unittest.TestCase):
    def test_native_dependency_scopes_exclude_withdrawn_relationship_rows(self):
        installation = 'installation:package'
        live_scope = 'consumer:host:installation:live'
        retired_scope = 'consumer:host:host:host-os'
        snapshot = {
            'revision': 1,
            'resources': [],
            'evidence': [{
                'id': 'ev-live', 'status': 'complete', 'valid_from': 1,
            }, {
                'id': 'ev-retired', 'status': 'complete', 'valid_from': 1,
            }],
            'assertions': [{
                'id': 'a-live', 'logical_key': 'consumer-live',
                'version': 'v2', 'subject': installation,
                'relation': 'PACKAGE_CONSUMER_COVERAGE', 'value': True,
                'scope': live_scope, 'status': 'valid', 'valid_from': 1,
                'evidence_id': 'ev-live',
            }, {
                'id': 'a-retired', 'logical_key': 'consumer-retired',
                'version': 'withdrawn', 'subject': installation,
                'relation': 'PACKAGE_CONSUMER_COVERAGE', 'value': False,
                'scope': retired_scope, 'status': 'withdrawn', 'valid_from': 1,
                'evidence_id': 'ev-retired',
            }],
            'coverage': [],
        }
        graph = ScopedGraph(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / 'db', clock=lambda: 100,
                                  graph=graph)
            try:
                with store.db:
                    incident = store._incident('CVE-2026-7993')
                    store.lifecycle.add_occurrence(
                        incident, 'occ-package', installation,
                        service='os', host='host', deployment='os')
                    store.db.execute(
                        "UPDATE lifecycle_meta SET value='1' "
                        "WHERE key='graph_revision'")

                scopes = store.lifecycle.dependency_scopes('occ-package')

                self.assertIn(live_scope, scopes)
                self.assertNotIn(retired_scope, scopes)
            finally:
                store.close()

    def test_http_errors_keep_native_detail_without_changing_the_stable_code(self):
        response = error.HTTPError(
            'http://unused.invalid', 500, 'error', {}, io.BytesIO(json.dumps({
                'error': 'active_text_mutation_limit_exceeded',
                'msg': ('db error: Active text mutation exceeds analysis_bytes: '
                        'observed 67109177, limit 67108864'),
            }).encode()))
        with mock.patch('helix_lifecycle.request.urlopen', side_effect=response):
            with self.assertRaises(HelixError) as raised:
                HelixLifecycleClient('http://unused.invalid').call({})

        self.assertEqual('active_text_mutation_limit_exceeded', raised.exception.code)
        self.assertIn('observed 67109177, limit 67108864', str(raised.exception))

    def test_availability_is_not_a_helix_assessment_path(self):
        installation = 'installation:available-tool'
        capability = 'command-capability:host:inspection'
        application = 'application:diagnostic-agent'
        input_source = 'input-source:operators'
        scope = 'consumer:host:available-tool'
        control_scope = 'input-paths:' + application
        evidence_id = 'ev-available-tool'
        relations = [
            (installation, 'AVAILABLE_TO', capability, scope),
            (capability, 'USED_BY', application, scope),
            (application, 'RECEIVES_MESSAGES_FROM', input_source, control_scope),
            (input_source, 'TARGETABLE_PATH', None, control_scope),
        ]
        snapshot = {
            'revision': 1,
            'resources': [],
            'evidence': [{
                'id': evidence_id, 'kind': 'observation', 'scope': scope,
                'source': 'fixture', 'provenance': 'fixture',
                'status': 'complete', 'valid_from': 1,
                'content': {'available': True},
            }],
            'assertions': [{
                'id': 'a-available-' + str(index),
                'logical_key': 'available:' + str(index), 'version': 'v1',
                'subject': subject, 'relation': relation,
                'object_key': object_key, 'value': True,
                'scope': relation_scope, 'source': 'fixture',
                'provenance': 'fixture', 'evidence_id': evidence_id,
                'status': 'valid', 'valid_from': 1,
            } for index, (subject, relation, object_key, relation_scope)
            in enumerate(relations)],
            'coverage': [{
                'id': 'c-available', 'logical_key': 'coverage:available',
                'version': 'v1', 'scope': scope, 'complete': True,
                'status': 'valid', 'valid_from': 1,
                'evidence_id': evidence_id,
            }],
        }
        graph = ScopedGraph(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / 'db', clock=lambda: 100,
                                  graph=graph)
            try:
                with store.db:
                    incident = store._incident('CVE-2026-7994')
                    store.lifecycle.add_occurrence(
                        incident, 'occ-available', installation,
                        service='os', host='host', deployment='os')
                    store.db.execute(
                        "UPDATE lifecycle_meta SET value='1' "
                        "WHERE key='graph_revision'")

                decision = store.lifecycle.evaluate(
                    incident, 'occ-available', rule_version='r1',
                    advisory_version='a1', dependency_scopes=[scope])

                self.assertEqual('pending', decision['result'])
                self.assertEqual('prerequisite_evidence_missing',
                                 decision['reason'])
                self.assertEqual('AVAILABLE_TO', store.lifecycle.relationships(
                    installation)['relationships'][0]['relation'])
                self.assertIn(control_scope,
                              store.lifecycle.dependency_scopes('occ-available'))
            finally:
                store.close()

    def test_scoped_lookup_indexes_are_non_unique_and_independent(self):
        client = CapturingHelix()
        client.ensure_indexes()
        scoped = [(payload, durable) for payload, durable in client.calls
                  if payload["query_name"] in {
                      "lifecycle_resource_stable_key_index",
                      "lifecycle_evidence_stable_key_index",
                      "lifecycle_coverage_scope_index",
                  }]
        self.assertEqual(3, len(scoped))
        for payload, durable in scoped:
            self.assertTrue(durable)
            entries = payload["query"]["write"]["entries"]
            self.assertEqual(1, len(entries))
            spec = entries[0]["query"]["root"]["create_index"]["spec"]
            self.assertFalse(spec["node_equality"]["unique"])

    def test_scoped_records_select_latest_acknowledged_version(self):
        class FixtureClient(HelixLifecycleClient):
            def __init__(self):
                super().__init__("http://unused.invalid")

            def exact_records(self, label, key, value, properties=None):
                del key, properties
                fixtures = {
                    ("Evidence", "ev-1"): [
                        {"payload": json.dumps({"id": "ev-1", "revision": 1,
                                                "status": "complete"})},
                        {"payload": json.dumps({"id": "ev-1", "revision": 3,
                                                "status": "withdrawn"})},
                    ],
                    ("Coverage", "paths:a"): [
                        {"payload": json.dumps({"logical_key": "coverage:a",
                                                "version": "v1", "revision": 1,
                                                "scope": "paths:a", "complete": True})},
                        {"payload": json.dumps({"logical_key": "coverage:a",
                                                "version": "v2", "revision": 3,
                                                "scope": "paths:a", "complete": False})},
                    ],
                }
                return fixtures.get((label, value), [])

            def prime_coverage_records(self, scopes, maximum_revision):
                for scope in scopes:
                    rows = self._records(self.exact_records(
                        "Coverage", "scope", scope))
                    self._coverage_cache[(scope, maximum_revision)] = (
                        self._current_records(
                            rows, maximum_revision,
                            lambda item: item["logical_key"]))

        client = FixtureClient()
        self.assertEqual("complete", client.evidence_record("ev-1", 2)["status"])
        coverage = client.coverage_records(["paths:a"], 2)
        self.assertEqual("v1", coverage[0]["version"])

    def test_unbounded_snapshot_is_disabled(self):
        with self.assertRaisesRegex(RuntimeError, "unbounded_graph_snapshot_disabled"):
            HelixLifecycleClient("http://unused.invalid").snapshot(1)

    def test_relationship_cache_is_scoped_and_bounded(self):
        class FixtureClient(HelixLifecycleClient):
            def __init__(self):
                super().__init__("http://unused.invalid")
                self.reads = 0

            def call(self, payload, durable=False):
                del durable
                self.reads += 1
                resource = payload["query"]["read"]["entries"][0]["query"][
                    "root"]["value_map"]["input"]["out_e"]["input"][
                        "nodes_where"]["predicate"]["and"]["predicates"][1][
                            "eq"]["right"]["constant"]["string"]
                assertion = {
                    "id": "assertion:" + resource,
                    "logical_key": "logical:" + resource,
                    "version": "v1", "subject": resource,
                    "relation": "RUNS_AS", "value": True, "revision": 1,
                }
                return {"relationships": [{"payload": json.dumps(assertion)}]}

        client = FixtureClient()
        first = client.relationship_records("deployment:a", 1)
        self.assertEqual(first, client.relationship_records("deployment:a", 1))
        self.assertEqual(1, client.reads)
        for index in range(20):
            client.relationship_records("deployment:" + str(index), 1)
        self.assertLessEqual(len(client._relationship_cache), 64)

    def test_scoped_prefetches_keep_each_helix_query_bounded(self):
        client = CapturingHelix()
        client.prime_relationship_records(
            ["deployment:" + str(index) for index in range(40)], 1)
        relationship_calls = [payload for payload, _ in client.calls
                              if payload["query_name"] ==
                              "lifecycle_relationship_records"]
        self.assertEqual([25, 15], [len(payload["query"]["read"]["entries"])
                                    for payload in relationship_calls])
        client.prime_coverage_records(
            ["scanner:scope:" + str(index) for index in range(201)], 1)
        coverage_calls = [payload for payload, _ in client.calls
                          if payload["query_name"] ==
                          "lifecycle_coverage_records"]
        self.assertEqual([100, 100, 1], [len(payload["query"]["read"]["entries"])
                                        for payload in coverage_calls])

    def test_coverage_cache_retains_requested_hits_while_adding_misses(self):
        class FixtureClient(HelixLifecycleClient):
            def __init__(self):
                super().__init__("http://unused.invalid")
                self.reads = 0

            def call(self, payload, durable=False):
                del durable
                self.reads += 1
                self.assert_query(payload)
                return {"scope_0": [{"payload": json.dumps({
                    "logical_key": "coverage:miss", "version": "v1",
                    "scope": "scope:miss", "revision": 7,
                    "complete": True})}]}

            @staticmethod
            def assert_query(payload):
                if payload["query_name"] != "lifecycle_coverage_records":
                    raise AssertionError("unexpected query")

        client = FixtureClient()
        requested_hit = {"logical_key": "coverage:hit", "version": "v1",
                         "scope": "scope:hit", "revision": 7,
                         "complete": True}
        client._coverage_cache[("scope:hit", 7)] = [requested_hit]
        client._coverage_cache[("scope:hit", 6)] = [{
            **requested_hit, "version": "historical", "revision": 6}]
        for index in range(2046):
            client._coverage_cache[("old:" + str(index), 7)] = []

        rows = client.coverage_records(["scope:hit", "scope:miss"], 7)

        self.assertEqual({"coverage:hit", "coverage:miss"}, {
            item["logical_key"] for item in rows})
        self.assertEqual({7}, {item["revision"] for item in rows})
        self.assertEqual(1, client.reads)
        self.assertEqual(2048, len(client._coverage_cache))
        self.assertIn(("scope:hit", 7), client._coverage_cache)
        self.assertIn(("scope:miss", 7), client._coverage_cache)

    def test_evaluation_uses_only_scoped_graph_reads(self):
        scope = "paths:scoped"
        snapshot = {
            "revision": 1,
            "resources": [],
            "evidence": [{"id": "ev-scoped", "kind": "observation",
                          "status": "complete",
                          "valid_from": 1, "valid_until": 200}],
            "assertions": [
                {"id": "a-path", "logical_key": "path", "version": "v1",
                 "subject": "deployment:scoped", "relation": "RUNS_AS",
                 "object_key": "consumer:scoped", "value": True,
                 "scope": scope, "evidence_id": "ev-scoped",
                 "status": "valid", "valid_from": 1},
                {"id": "a-quiet", "logical_key": "quiet", "version": "v1",
                 "subject": "consumer:scoped", "relation": "CONSTRAINT_EXCLUDES",
                 "value": True, "scope": scope, "evidence_id": "ev-scoped",
                 "status": "valid", "valid_from": 1},
            ],
            "coverage": [{"id": "c-scoped", "logical_key": "coverage",
                          "version": "v1", "scope": scope, "complete": True,
                          "status": "valid", "valid_from": 1,
                          "evidence_id": "ev-scoped"}],
        }
        graph = ScopedGraph(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "db", clock=lambda: 100,
                                  graph=graph)
            try:
                with store.db:
                    incident = store._incident("CVE-2026-7995")
                    store.lifecycle.add_occurrence(
                        incident, "occ-scoped", "deployment:scoped",
                        service="scoped", host="host", deployment="scoped")
                    store.db.execute(
                        "UPDATE lifecycle_meta SET value='1' WHERE key='graph_revision'")
                decision = store.lifecycle.evaluate(
                    incident, "occ-scoped", rule_version="r1",
                    advisory_version="a1", dependency_scopes=[scope])
                self.assertEqual("quiet", decision["result"])
                self.assertEqual({"a-path", "a-quiet"},
                                 set(store.lifecycle.decision(
                                     decision["id"])["assertion_versions"]))
                self.assertEqual("ev-scoped",
                                 store.lifecycle.evidence("ev-scoped")["id"])
            finally:
                store.close()

    def test_write_batch_contains_typed_relationship_and_evidence_edges(self):
        client = CapturingHelix()
        client.write_change({
            "id": "change-1", "revision": 1,
            "record_ids": ["r-resource", "r-consumer", "r-evidence", "r-assertion", "r-coverage"],
            "payload": {
                "resources": [
                    {"resource_key": "deployment:a", "kind": "deployment", "name": "a"},
                    {"resource_key": "consumer:a", "kind": "consumer", "name": "a"},
                ],
                "evidence": [{"id": "ev-1", "kind": "observation", "scope": "paths:a",
                              "source": "fixture", "provenance": "fixture", "status": "complete",
                              "valid_from": 1, "content": {"note": "decoder configuration"}}],
                "assertions": [{"logical_key": "runs:a", "version": "v1",
                                "subject": "deployment:a", "relation": "RUNS_AS",
                                "object_key": "consumer:a", "value": True,
                                "scope": "paths:a", "source": "fixture",
                                "provenance": "fixture", "evidence_id": "ev-1",
                                "valid_from": 1}],
                "coverage": [{"logical_key": "coverage:a", "version": "v1",
                              "scope": "paths:a", "relationship": "*",
                              "producer": "fixture", "complete": True,
                              "status": "valid", "valid_from": 1,
                              "evidence_id": "ev-1"}],
            },
        })
        graph_write = next(payload for payload, _ in client.calls
                           if payload["query_name"] == "lifecycle_graph_change")
        encoded = json.dumps(graph_write)
        for label in ("CONTAINS", "RUNS_AS", "SUPPORTED_BY"):
            self.assertIn('"label": "' + label + '"', encoded)

    def test_large_evidence_uses_resumable_chunks_and_keeps_exact_parent_payload(self):
        client = CapturingHelix()
        evidence = {
            "id": "ev-large", "kind": "observation", "scope": "runtime:test",
            "source": "fixture", "provenance": "fixture", "status": "complete",
            "valid_from": 1, "content": {"report": "needle " * 100000},
        }
        change = {
            "id": "change-large", "revision": 1, "record_ids": ["r-evidence"],
            "payload": {"resources": [], "evidence": [evidence],
                        "assertions": [], "coverage": []},
        }

        client.write_change(change)

        chunk_writes = [payload for payload, _ in client.calls
                        if payload["query_name"] == "lifecycle_evidence_text_chunk"]
        self.assertGreater(len(chunk_writes), 1)
        parent_write = next(payload for payload, _ in client.calls
                            if payload["query_name"] == "lifecycle_graph_change")
        entries = parent_write["query"]["write"]["entries"]
        parent = next(entry["query"]["root"]["add_n"] for entry in entries
                      if entry["query"]["root"].get("add_n", {}).get("label") ==
                      "Evidence")
        properties = {name: value["value"] for name, value in parent["properties"]}
        self.assertNotIn("body", properties)
        expected = {**evidence, "id": evidence["id"], "revision": 1}
        self.assertEqual(json.dumps(expected, sort_keys=True, separators=(",", ":")),
                         properties["payload"]["string"])
        self.assertIn('"label": "EVIDENCE_FOR"', json.dumps(parent_write))

    def test_large_evidence_keeps_v1_partition_ids(self):
        client = CapturingHelix()
        resources = [{"resource_key": "resource:" + str(index), "kind": "fixture",
                      "name": str(index)} for index in range(128)]
        evidence = {"id": "ev-large", "scope": "runtime:test",
                    "content": {"report": "needle " * 100000}}
        record_ids = ["record:" + str(index) for index in range(129)]
        change = {
            "id": "change-partitioned", "revision": 2, "record_ids": record_ids,
            "payload": {"resources": resources, "evidence": [evidence],
                        "assertions": [], "coverage": []},
        }

        client.write_change(change)

        requested = []
        for payload, _ in client.calls:
            if payload["query_name"] != "lifecycle_change_exists":
                continue
            predicates = payload["query"]["read"]["entries"][0]["query"]["root"][
                "count"]["input"]["nodes_where"]["predicate"]["and"]["predicates"]
            requested.append(predicates[1]["eq"]["right"]["constant"]["string"])
        expected = [
            "part_v1_" + _hash([change["id"], 0, record_ids[:128]]),
            "part_v1_" + _hash([change["id"], 128, record_ids[128:]]),
        ]
        self.assertTrue(set(expected).issubset(requested))

    def test_large_evidence_retry_skips_durable_chunks_before_parent_marker(self):
        class InterruptedHelix(HelixLifecycleClient):
            def __init__(self):
                super().__init__("http://unused.invalid")
                self.parts = set()
                self.chunk_writes = []
                self.fail_next_chunk = True
                self.parent_written = False

            def call(self, payload, durable=False):
                del durable
                name = payload["query_name"]
                if name == "lifecycle_change_exists":
                    root = payload["query"]["read"]["entries"][0]["query"]["root"]
                    predicates = root["count"]["input"]["nodes_where"]["predicate"][
                        "and"]["predicates"]
                    identifier = predicates[1]["eq"]["right"]["constant"]["string"]
                    return {"count": int(identifier in self.parts)}
                if name == "lifecycle_evidence_text_chunk":
                    entries = payload["query"]["write"]["entries"]
                    marker = entries[0]["query"]["root"]["add_n"]["properties"]
                    identifier = next(value["value"]["string"] for key, value in marker
                                      if key == "change_id")
                    if self.fail_next_chunk and self.chunk_writes:
                        self.fail_next_chunk = False
                        raise HelixError("injected_interruption", True)
                    self.chunk_writes.append(identifier)
                    self.parts.add(identifier)
                elif name == "lifecycle_graph_change":
                    self.parent_written = True
                return {}

        client = InterruptedHelix()
        change = {
            "id": "change-retry", "revision": 3, "record_ids": ["record-evidence"],
            "payload": {"resources": [], "evidence": [{
                "id": "ev-retry", "scope": "runtime:test",
                "content": {"report": "recovery " * 100000},
            }], "assertions": [], "coverage": []},
        }

        with self.assertRaisesRegex(HelixError, "injected_interruption"):
            client.write_change(change)
        first_part = client.chunk_writes[0]
        self.assertFalse(client.parent_written)

        result = client.write_change(change)

        self.assertEqual("written", result["status"])
        self.assertEqual(1, client.chunk_writes.count(first_part))
        self.assertTrue(client.parent_written)

    def test_evidence_search_combines_legacy_and_chunks_and_returns_full_parent(self):
        full_parent = {"id": "ev-shared", "revision": 7,
                       "content": {"report": "the exact complete report"}}
        legacy_only = {"id": "ev-legacy", "revision": 6,
                       "content": {"report": "legacy report"}}

        class SearchFixture(HelixLifecycleClient):
            def __init__(self):
                super().__init__("http://unused.invalid")
                self.search_payload = None

            def call(self, payload, durable=False):
                del durable
                if payload["query_name"] == "lifecycle_evidence_search":
                    self.search_payload = payload
                    return {
                        "legacy_matches": [
                            {"payload": json.dumps(full_parent), "$score": 0.4},
                            {"payload": json.dumps(legacy_only), "$score": 0.6},
                        ],
                        "chunk_matches": [
                            {"payload": json.dumps({"parent_record_id": "record-shared"}),
                             "$score": 0.9},
                            {"payload": json.dumps({"parent_record_id": "record-shared"}),
                             "$score": 0.8},
                        ],
                    }
                if payload["query_name"] == "lifecycle_evidence_chunk_parents":
                    return {"parent_0": [{"payload": json.dumps(full_parent)}]}
                raise AssertionError(payload["query_name"])

        client = SearchFixture()
        results = client.search_evidence("complete report", 10)

        self.assertEqual(["ev-shared", "ev-legacy"],
                         [item["id"] for item in results])
        self.assertEqual(0.9, results[0]["score"])
        self.assertEqual(full_parent["content"], results[0]["content"])
        roots = [entry["query"]["root"] for entry in
                 client.search_payload["query"]["read"]["entries"]]
        labels = [root["value_map"]["input"]["text_search_nodes"]["label"]
                  for root in roots]
        self.assertEqual(["Evidence", "EvidenceTextChunk"], labels)

    def test_assertion_only_update_looks_up_existing_edge_endpoints(self):
        client = CapturingHelix()
        client.write_change({
            "id": "change-update", "revision": 2,
            "record_ids": ["r-evidence", "r-assertion"],
            "payload": {
                "resources": [],
                "evidence": [{"id": "ev-2", "kind": "observation",
                              "scope": "paths:a", "source": "fixture",
                              "provenance": "fixture", "status": "complete",
                              "valid_from": 2, "content": {"withdrawn": True}}],
                "assertions": [{"logical_key": "runs:a", "version": "v2",
                                "subject": "deployment:a", "relation": "RUNS_AS",
                                "object_key": "consumer:a", "value": True,
                                "status": "withdrawn", "scope": "paths:a",
                                "source": "fixture", "provenance": "fixture",
                                "evidence_id": "ev-2", "valid_from": 2}],
                "coverage": [],
            },
        })
        graph_write = next(payload for payload, _ in client.calls
                           if payload["query_name"] == "lifecycle_graph_change")
        encoded = json.dumps(graph_write)
        self.assertIn('"property": "stable_key"', encoded)
        self.assertIn('"string": "deployment:a"', encoded)
        self.assertIn('"string": "consumer:a"', encoded)
        self.assertIn('"label": "RUNS_AS"', encoded)

    def test_evaluation_relationships_evidence_and_search_read_the_graph_adapter(self):
        assertion_id = "assertion-helix"
        snapshot = {
            "revision": 1,
            "resources": [{"resource_key": "deployment:helix", "kind": "deployment",
                           "name": "helix", "revision": 1}],
            "evidence": [{"id": "ev-helix", "kind": "observation", "scope": "paths:helix",
                          "source": "helix", "provenance": "graph", "status": "complete",
                          "valid_from": 1, "content_hash": "f" * 64,
                          "content": {"constraint": True}, "revision": 1}],
            "assertions": [{"id": assertion_id, "logical_key": "constraint:helix",
                            "version": "v1", "subject": "deployment:helix",
                            "relation": "CONSTRAINT_EXCLUDES", "value": True,
                            "scope": "paths:helix", "source": "helix",
                            "provenance": "graph", "evidence_id": "ev-helix",
                            "valid_from": 1, "status": "valid", "revision": 1}],
            "coverage": [{"id": "coverage-helix", "logical_key": "coverage:helix",
                          "version": "v1", "scope": "paths:helix", "relationship": "*",
                          "producer": "helix", "complete": True, "status": "valid",
                          "valid_from": 1, "evidence_id": "ev-helix", "revision": 1}],
        }
        graph = SnapshotGraph(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "db", clock=lambda: 100, graph=graph)
            try:
                with store.db:
                    incident = store._incident("CVE-2026-7998")
                    store.lifecycle.add_occurrence(
                        incident, "occ-helix", "deployment:helix",
                        service="helix", host="host", deployment="helix")
                    store.db.execute(
                        "UPDATE lifecycle_meta SET value='1' WHERE key='graph_revision'")
                decision = store.lifecycle.evaluate(
                    incident, "occ-helix", rule_version="r1", advisory_version="a1",
                    dependency_scopes=["paths:helix"])
                self.assertEqual("quiet", decision["result"])
                self.assertEqual(assertion_id, store.lifecycle.relationships(
                    "deployment:helix")["relationships"][0]["id"])
                self.assertEqual("helix", store.lifecycle.evidence("ev-helix")["source"])
                self.assertEqual("ev-helix", store.lifecycle.search_evidence(
                    "decoder", 10)["evidence"][0]["id"])
                self.assertGreaterEqual(len(graph.calls), 3)
            finally:
                store.close()

    def test_snapshot_graph_keeps_shared_gap_until_the_last_member_resolves(self):
        resource = "deployment:helix-shared-gap"
        scope = "paths:" + resource
        snapshot = {
            "revision": 1,
            "resources": [{"resource_key": resource, "kind": "deployment",
                           "name": "helix-shared-gap", "revision": 1}],
            "evidence": [], "assertions": [], "coverage": [],
        }
        graph = SnapshotGraph(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "db", clock=lambda: 100,
                                  graph=graph)
            try:
                occurrences = []
                with store.db:
                    for suffix in ("one", "two"):
                        incident = store._incident("CVE-2026-73" +
                                                   ("01" if suffix == "one" else "02"))
                        occurrence = "occ-helix-gap-" + suffix
                        occurrences.append((incident, occurrence))
                        store.lifecycle.add_occurrence(
                            incident, occurrence, resource, service="shared",
                            host="host", deployment="shared")
                    store.db.execute(
                        "UPDATE lifecycle_meta SET value='1' WHERE key='graph_revision'")
                for incident, occurrence in occurrences:
                    decision = store.lifecycle.evaluate(
                        incident, occurrence, rule_version="r1",
                        advisory_version="a1", dependency_scopes=[scope])
                    self.assertEqual("gap", decision["result"])

                gap = store.lifecycle.pending_gap_collections()[0]["id"]
                for index, (incident, occurrence) in enumerate(occurrences, 1):
                    evidence_id = "ev-helix-fixed-" + str(index)
                    graph.value["evidence"].append({
                        "id": evidence_id, "kind": "observation",
                        "scope": "scanner:helix:" + str(index),
                        "source": "helix", "provenance": "fixture",
                        "status": "complete", "valid_from": 1,
                        "content": {"fixed": True}, "revision": 1,
                    })
                    graph.value["assertions"].append({
                        "id": "assertion-helix-fixed-" + str(index),
                        "logical_key": "build:helix:" + str(index),
                        "version": "v1", "subject": resource,
                        "relation": "BUILD_DISPOSITION", "value": "fixed",
                        "scope": "scanner:helix:" + str(index),
                        "source": "helix", "provenance": "fixture",
                        "evidence_id": evidence_id, "valid_from": 1,
                        "status": "valid", "revision": 1,
                        "occurrences": [occurrence],
                    })
                    quiet = store.lifecycle.evaluate(
                        incident, occurrence, rule_version="r1",
                        advisory_version="a2", dependency_scopes=[scope])
                    self.assertEqual("quiet", quiet["result"])
                    remaining = store.db.execute(
                        "SELECT count(*) FROM lifecycle_gap_occurrences WHERE gap=?",
                        (gap,)).fetchone()[0]
                    self.assertEqual(1 if index == 1 else 0, remaining)
                    current = store.db.execute(
                        "SELECT current FROM lifecycle_gaps WHERE id=?",
                        (gap,)).fetchone()[0]
                    self.assertEqual(1 if index == 1 else 0, current)
            finally:
                store.close()

    @unittest.skipUnless(os.environ.get("HELIX_LIFECYCLE_TEST_ENDPOINT"),
                         "set HELIX_LIFECYCLE_TEST_ENDPOINT for the pinned server check")
    def test_pinned_server_executes_graph_evaluation_and_text_retrieval(self):
        endpoint = os.environ["HELIX_LIFECYCLE_TEST_ENDPOINT"]
        suffix = uuid.uuid4().hex
        resource = "deployment:integration:" + suffix
        consumer = "consumer:integration:" + suffix
        evidence = "evidence-integration-" + suffix
        scope = "paths:integration:" + suffix
        client = HelixLifecycleClient(endpoint)
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(
                Path(directory) / "db", clock=lambda: 100, graph=client)
            try:
                with store.db:
                    incident = store._incident("CVE-2026-7996")
                store.lifecycle.add_occurrence(
                    incident, "occ-integration", resource, service="integration",
                    host="local", deployment="integration")
                store.lifecycle.stage_graph_change(
                    "integration-" + suffix, resources=[
                        {"resource_key": resource, "kind": "deployment", "name": "integration"},
                        {"resource_key": consumer, "kind": "consumer", "name": "integration"},
                    ], evidence=[{
                        "id": evidence, "kind": "observation", "scope": scope,
                        "source": "pinned-helix-test", "provenance": suffix,
                        "status": "complete", "valid_from": 1,
                        "content": {"note": "pinned helix lifecycle retrieval " + suffix},
                    }], assertions=[
                        {"logical_key": "edge:" + suffix, "version": "v1",
                         "subject": resource, "relation": "RUNS_AS", "object_key": consumer,
                         "value": True, "kind": "observation", "scope": scope,
                         "source": "pinned-helix-test", "provenance": suffix,
                         "evidence_id": evidence, "valid_from": 1},
                        {"logical_key": "constraint:" + suffix, "version": "v1",
                         "subject": consumer, "relation": "CONSTRAINT_EXCLUDES",
                         "value": True, "kind": "observation", "scope": scope,
                         "source": "pinned-helix-test", "provenance": suffix,
                         "evidence_id": evidence, "valid_from": 1},
                    ], coverage=[{
                        "logical_key": "coverage:" + suffix, "version": "v1",
                        "scope": scope, "relationship": "*", "producer": "pinned-helix-test",
                        "complete": True, "status": "valid", "valid_from": 1,
                        "evidence_id": evidence,
                    }])
                change = store.lifecycle.pending_graph_change()
                client.write_change(change)
                store.lifecycle.acknowledge_graph_change(change["id"])
                decision = store.lifecycle.evaluate(
                    incident, "occ-integration", rule_version="r1",
                    advisory_version="a1", dependency_scopes=[scope])
                self.assertEqual("quiet", decision["result"])
                self.assertEqual(2, len(store.lifecycle.decision(
                    decision["id"])["assertion_versions"]))
                relationships = store.lifecycle.relationships(resource)["relationships"]
                self.assertEqual(1, len(relationships))
                self.assertEqual("RUNS_AS", relationships[0]["relation"])
                self.assertEqual(evidence, store.lifecycle.evidence(evidence)["id"])
                self.assertTrue(store.lifecycle.search_evidence(
                    suffix, 10)["evidence"])

                store.lifecycle.stage_graph_change(
                    "integration-update-" + suffix, evidence=[{
                        "id": evidence + "-withdrawn", "kind": "observation",
                        "scope": scope, "source": "pinned-helix-test",
                        "provenance": suffix + "-withdrawn", "status": "complete",
                        "valid_from": 2, "content": {"withdrawn": True},
                    }], assertions=[{
                        "logical_key": "edge:" + suffix, "version": "v2",
                        "subject": resource, "relation": "RUNS_AS",
                        "object_key": consumer, "value": True, "status": "withdrawn",
                        "kind": "observation", "scope": scope,
                        "source": "pinned-helix-test",
                        "provenance": suffix + "-withdrawn",
                        "evidence_id": evidence + "-withdrawn", "valid_from": 2,
                    }])
                update = store.lifecycle.pending_graph_change()
                client.write_change(update)
                store.lifecycle.acknowledge_graph_change(update["id"])
                current = store.lifecycle.relationships(resource)["relationships"]
                self.assertEqual("v2", current[0]["version"])
                self.assertEqual("withdrawn", current[0]["status"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
