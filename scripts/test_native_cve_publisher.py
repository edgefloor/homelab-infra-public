import importlib.util
import contextlib
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/vulnerability_incidents/files"
sys.path.insert(0, str(FILES))

fake_db = types.ModuleType("hermes_cli.kanban_db")


def create_task(connection, title, body, assignee, created_by, idempotency_key,
                initial_status):
    old = connection.execute(
        "SELECT id FROM tasks WHERE idempotency_key=?", (idempotency_key,)).fetchone()
    if old:
        return old[0]
    identifier = "t_" + str(connection.execute("SELECT count(*) FROM tasks").fetchone()[0] + 1)
    connection.execute("""INSERT INTO tasks (
        id,title,body,assignee,created_by,idempotency_key,status
    ) VALUES (?,?,?,?,?,?,?)""",
                       (identifier, title, body, assignee, created_by,
                        idempotency_key, initial_status))
    connection.commit()
    return identifier


fake_db.create_task = create_task


def add_comment(connection, task_id, author, body):
    nested = connection.in_transaction
    connection.execute("INSERT INTO task_comments(task_id,author,body) VALUES (?,?,?)",
                       (task_id, author, body))
    if not nested:
        connection.commit()


fake_db.add_comment = add_comment


@contextlib.contextmanager
def write_txn(connection):
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


fake_db.write_txn = write_txn
hermes = types.ModuleType("hermes_cli")
hermes.kanban_db = fake_db
sys.modules.setdefault("hermes_cli", hermes)
sys.modules.setdefault("hermes_cli.kanban_db", fake_db)
spec = importlib.util.spec_from_file_location("cve_native_publisher_test", FILES / "cve_native_publisher.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

from incident_store import IncidentStore


class Client:
    def __init__(self, store):
        self.store = store
        self.lose_ack = True

    def call(self, action, **values):
        if action == "next_publication":
            return {"publication": self.store.lifecycle.next_publication()}
        if action == "get":
            return {"incident": self.store.get_incident(values["incident"])}
        if action == "work":
            return {"work": self.store.lifecycle.work(values["work"])}
        if action in {"investigation_scope", "remediation_scope"}:
            return self.store.lifecycle.scope(
                values["work"], action.removesuffix("_scope"),
                limit=values.get("limit", 100),
                continuation=values.get("continuation"))
        if action == "publication_uncertain":
            return self.store.lifecycle.publication_uncertain(values["publication"])
        if action == "publication_sent":
            if self.lose_ack:
                self.lose_ack = False
                raise TimeoutError("lost acknowledgement")
            return self.store.lifecycle.publication_sent(
                values["publication"], values["external_id"])
        raise AssertionError(action)


class NativePublisherTests(unittest.TestCase):
    def test_reopen_receipt_matches_an_exact_machine_owned_line(self):
        board = sqlite3.connect(":memory:")
        board.execute("""CREATE TABLE tasks (
            id TEXT PRIMARY KEY, body TEXT, status TEXT, result TEXT,
            completed_at TEXT)""")
        board.execute("""CREATE TABLE task_comments (
            id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
        future = "publication_" + "b" * 64
        board.execute(
            "INSERT INTO tasks VALUES (?,?,?,?,?)",
            ("task-receipt", "body", "done",
             "Authored conclusion quotes\u2028Lifecycle change: " + future +
             "\u0085between Unicode separators",
             "t0"))
        board.commit()
        publisher._reopen_gap_card(
            board, "task-receipt",
            "First recurrence\nLifecycle change: publication_first",
            "publication_first")
        board.execute("""UPDATE tasks SET status='done', result=?,
            completed_at=? WHERE id='task-receipt'""",
                      ("new completed work", "t1"))
        board.commit()

        publisher._reopen_gap_card(
            board, "task-receipt",
            "Second recurrence\nLifecycle change: " + future, future)

        self.assertEqual(
            ("ready", None, None), board.execute(
                "SELECT status,result,completed_at FROM tasks").fetchone())
        self.assertEqual(2, board.execute(
            "SELECT count(*) FROM task_comments").fetchone()[0])
        board.close()

    def test_gap_reference_update_retries_around_a_concurrent_note_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kanban.db"
            primary = sqlite3.connect(path)
            writer = sqlite3.connect(path)
            primary.execute(
                "CREATE TABLE tasks (id TEXT PRIMARY KEY, body TEXT)")
            old = {"gap": "gap-race", "scope": "paths:race",
                   "relationship": "relationships", "links": [{
                       "incident": "vuln-old", "occurrence": "occ-old",
                   }]}
            body = publisher._gap_card_body(old).replace(
                "Current linked CVE occurrences:",
                "lifecycle-owned edit that may be replaced\n"
                "Current linked CVE occurrences:")
            body += "\n\nZig note before update: preserve."
            primary.execute("INSERT INTO tasks VALUES (?,?)", ("task-race", body))
            primary.commit()

            class ConcurrentEditConnection:
                def __init__(self):
                    self.injected = False

                def execute(self, sql, parameters=()):
                    if (not self.injected and
                            sql.startswith("UPDATE tasks SET body=? WHERE id=? AND")):
                        self.injected = True
                        writer.execute(
                            "UPDATE tasks SET body=body || ? WHERE id=?",
                            ("\nZig note during update: preserve.", "task-race"))
                        writer.commit()
                    return primary.execute(sql, parameters)

                def commit(self):
                    primary.commit()

            current = {"links": [{
                "incident": "vuln-current", "occurrence": "occ-current",
            }]}
            publisher._update_gap_card_references(
                ConcurrentEditConnection(), "task-race", current)

            updated = primary.execute(
                "SELECT body FROM tasks WHERE id='task-race'").fetchone()[0]
            self.assertNotIn("lifecycle-owned edit that may be replaced", updated)
            self.assertNotIn("occ-old", updated)
            self.assertIn("occ-current", updated)
            self.assertIn("Zig note before update: preserve.", updated)
            self.assertIn("Zig note during update: preserve.", updated)
            self.assertEqual(1, updated.count(publisher._GAP_REFERENCES_START))
            self.assertEqual(1, updated.count(publisher._GAP_REFERENCES_END))
            writer.close()
            primary.close()

    def test_legacy_gap_card_adds_one_managed_reference_section(self):
        board = sqlite3.connect(":memory:")
        board.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, body TEXT)")
        legacy = "\n".join([
            "Shared evidence gap: gap-legacy",
            "Scope: paths:legacy",
            "Relationship: relationships",
            "Linked CVE occurrences:",
            "- vuln-old · occ-old",
            "",
            "Zig note: keep this analysis unchanged.",
            "Unpaired marker text: " + publisher._GAP_REFERENCES_START,
        ])
        board.execute("INSERT INTO tasks VALUES (?,?)", ("task-legacy", legacy))
        payload = {"links": [{
            "incident": "vuln-current", "occurrence": "occ-current",
        }]}

        publisher._update_gap_card_references(board, "task-legacy", payload)
        publisher._update_gap_card_references(board, "task-legacy", payload)

        updated = board.execute(
            "SELECT body FROM tasks WHERE id='task-legacy'").fetchone()[0]
        self.assertTrue(updated.startswith(legacy))
        self.assertIn("Zig note: keep this analysis unchanged.", updated)
        self.assertIn("Current linked CVE occurrences:", updated)
        self.assertIn("occ-current", updated)
        self.assertEqual(2, updated.count(publisher._GAP_REFERENCES_START))
        self.assertEqual(1, updated.count(publisher._GAP_REFERENCES_END))
        board.close()

    def test_gap_updates_preserve_notes_outside_lifecycle_references(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                resource = "deployment:edited-gap-card"
                scope = "paths:edited-gap-card"
                occurrences = []
                with store.db:
                    for suffix in ("a", "b"):
                        incident = store._incident(
                            "CVE-2026-82" + suffix.upper())
                        occurrence = "occ-edited-gap-" + suffix
                        occurrences.append((incident, occurrence))
                        store.lifecycle.add_occurrence(
                            incident, occurrence, resource, service="shared",
                            host="host", deployment="container")
                        store.lifecycle.evaluate(
                            incident, occurrence, rule_version="r1",
                            advisory_version="a1", dependency_scopes=[scope])
                gap = store.lifecycle.pending_gap_collections()[0]["id"]
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "mechanical collectors exhausted")
                client = Client(store)
                client.lose_ack = False
                self.assertTrue(publisher.publish_one(client, board))
                card = board.execute("SELECT id FROM tasks").fetchone()[0]
                note = "\n\nZig investigation notes:\n- retain this native analysis"
                board.execute(
                    "UPDATE tasks SET body=body || ? WHERE id=?", (note, card))
                board.commit()

                first_incident, first_occurrence = occurrences[0]
                store.lifecycle.stage_graph_change(
                    "fixed-edited-gap-card", evidence=[{
                        "id": "ev-fixed-edited-gap-card", "kind": "observation",
                        "scope": "scanner:edited-gap-card", "source": "fixture",
                        "provenance": "fixture", "status": "complete",
                        "content": {"fixed": True},
                    }], assertions=[{
                        "logical_key": "build:edited-gap-card", "version": "v1",
                        "subject": resource, "relation": "BUILD_DISPOSITION",
                        "value": "fixed", "kind": "observation",
                        "scope": "scanner:edited-gap-card", "source": "fixture",
                        "provenance": "fixture",
                        "evidence_id": "ev-fixed-edited-gap-card",
                        "occurrences": [first_occurrence],
                    }])
                store.lifecycle.acknowledge_graph_change("fixed-edited-gap-card")
                store.lifecycle.evaluate(
                    first_incident, first_occurrence, rule_version="r1",
                    advisory_version="a2", dependency_scopes=[scope])
                client.lose_ack = True
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertTrue(publisher.publish_one(client, board))

                updated = board.execute(
                    "SELECT body FROM tasks WHERE id=?", (card,)).fetchone()[0]
                self.assertIn(note.strip(), updated)
                self.assertNotIn(first_occurrence, updated)
                self.assertIn(occurrences[1][1], updated)
                self.assertEqual(1, updated.count(
                    publisher._GAP_REFERENCES_START))
                self.assertEqual(1, updated.count(
                    publisher._GAP_REFERENCES_END))

                store.lifecycle.record_gap_collection(
                    gap, "resolved", "collector supplied coverage")
                second_incident, second_occurrence = occurrences[1]
                recurring = store.lifecycle.evaluate(
                    second_incident, second_occurrence, rule_version="r1",
                    advisory_version="a2", dependency_scopes=[scope])
                self.assertEqual("gap", recurring["result"])
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "coverage is missing again")
                self.assertEqual("gap_reopen",
                                 store.lifecycle.next_publication()["kind"])
                client.lose_ack = True
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertTrue(publisher.publish_one(client, board))

                reopened = board.execute(
                    "SELECT body FROM tasks WHERE id=?", (card,)).fetchone()[0]
                self.assertIn(note.strip(), reopened)
                self.assertNotIn(first_occurrence, reopened)
                self.assertIn(second_occurrence, reopened)
                self.assertEqual(1, reopened.count(
                    publisher._GAP_REFERENCES_START))
                self.assertEqual(1, reopened.count(
                    publisher._GAP_REFERENCES_END))
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM tasks").fetchone()[0])
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM task_comments").fetchone()[0])
            finally:
                board.close()
                store.close()

    def test_unresolved_shared_gap_publishes_one_linked_gap_card(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                with store.db:
                    first = store._incident("CVE-2026-8100")
                    second = store._incident("CVE-2026-8101")
                    for incident, occurrence in ((first, "occ-first"),
                                                  (second, "occ-second")):
                        store.lifecycle.add_occurrence(
                            incident, occurrence, "deployment:shared",
                            service="shared", host="host", deployment="container")
                        store.lifecycle.evaluate(
                            incident, occurrence, rule_version="r1",
                            advisory_version="a1", dependency_scopes=["paths:shared"])
                gap = store.lifecycle.pending_gap_collections()[0]
                store.lifecycle.record_gap_collection(
                    gap["id"], "unresolved", "mechanical collectors exhausted")
                client = Client(store)
                client.lose_ack = False
                self.assertTrue(publisher.publish_one(client, board))
                tasks = board.execute(
                    "SELECT title,body,status FROM tasks").fetchall()
                self.assertEqual(1, len(tasks))
                self.assertEqual("Evidence gap · paths:shared", tasks[0][0])
                self.assertIn("occ-first", tasks[0][1])
                self.assertIn("occ-second", tasks[0][1])
                self.assertEqual("ready", tasks[0][2])
                self.assertIsNone(store.lifecycle.next_publication())
            finally:
                board.close()
                store.close()

    def test_recurring_gap_reopens_its_existing_completed_card(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT,
                result TEXT, completed_at TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                with store.db:
                    incident = store._incident("CVE-2026-8102")
                    store.lifecycle.add_occurrence(
                        incident, "occ-recurring", "deployment:recurring",
                        service="recurring", host="host", deployment="container")
                decision = store.lifecycle.evaluate(
                    incident, "occ-recurring", rule_version="r1",
                    advisory_version="a1", dependency_scopes=["paths:recurring"])
                self.assertEqual("gap", decision["result"])
                gap = store.lifecycle.pending_gap_collections()[0]["id"]
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "first collection exhausted")
                client = Client(store)
                client.lose_ack = False
                self.assertTrue(publisher.publish_one(client, board))
                card = board.execute("SELECT id FROM tasks").fetchone()[0]
                board.execute("""UPDATE tasks SET status='done', result=?,
                    completed_at=? WHERE id=?""",
                              ("original conclusion", "t0", card))
                board.commit()

                store.lifecycle.record_gap_collection(
                    gap, "resolved", "coverage became complete")
                recurrence = store.lifecycle.evaluate(
                    incident, "occ-recurring", rule_version="r1",
                    advisory_version="a2", dependency_scopes=["paths:recurring"])
                self.assertEqual("gap", recurrence["result"])
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "later collection exhausted")

                client.lose_ack = True
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertEqual("ready", board.execute(
                    "SELECT status FROM tasks WHERE id=?", (card,)).fetchone()[0])
                board.execute("""UPDATE tasks SET status='done', result=?,
                    completed_at=? WHERE id=?""",
                              ("Zig finished recurring work", "t1", card))
                board.commit()
                self.assertTrue(publisher.publish_one(client, board))
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM tasks").fetchone()[0])
                self.assertEqual(
                    ("done", "Zig finished recurring work", "t1"),
                    board.execute("""SELECT status,result,completed_at FROM tasks
                        WHERE id=?""", (card,)).fetchone())
                comments = board.execute(
                    "SELECT body FROM task_comments WHERE task_id=?", (card,)).fetchall()
                self.assertEqual(1, len(comments))
                self.assertIn("recurred", comments[0][0])
                self.assertIn(
                    '{"result":"original conclusion","completed_at":"t0"}',
                    comments[0][0])
                self.assertNotIn("Zig finished recurring work", comments[0][0])
                self.assertIsNone(store.lifecycle.next_publication())
            finally:
                board.close()
                store.close()

    def test_gap_link_update_reconciles_lost_card_and_update_acks(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                with store.db:
                    incident = store._incident("CVE-2026-8103")
                    occurrence = "occ-lost-gap-update"
                    resource = "deployment:lost-gap-update"
                    scope = "paths:lost-gap-update"
                    store.lifecycle.add_occurrence(
                        incident, occurrence, resource, service="shared",
                        host="host", deployment="container")
                decision = store.lifecycle.evaluate(
                    incident, occurrence, rule_version="r1",
                    advisory_version="a1", dependency_scopes=[scope])
                self.assertEqual("gap", decision["result"])
                gap = store.lifecycle.pending_gap_collections()[0]["id"]
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "mechanical collectors exhausted")
                client = Client(store)

                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertEqual("uncertain", store.lifecycle.next_publication()["state"])

                store.lifecycle.stage_graph_change(
                    "fixed-lost-gap-update", evidence=[{
                        "id": "ev-fixed-lost-gap-update", "kind": "observation",
                        "scope": "scanner:lost-gap-update", "source": "fixture",
                        "provenance": "fixture", "status": "complete",
                        "content": {"fixed": True},
                    }], assertions=[{
                        "logical_key": "build:lost-gap-update", "version": "v1",
                        "subject": resource, "relation": "BUILD_DISPOSITION",
                        "value": "fixed", "kind": "observation",
                        "scope": "scanner:lost-gap-update", "source": "fixture",
                        "provenance": "fixture",
                        "evidence_id": "ev-fixed-lost-gap-update",
                        "occurrences": [occurrence],
                    }])
                store.lifecycle.acknowledge_graph_change("fixed-lost-gap-update")
                quiet = store.lifecycle.evaluate(
                    incident, occurrence, rule_version="r1",
                    advisory_version="a2", dependency_scopes=[scope])
                self.assertEqual("quiet", quiet["result"])
                publications = [tuple(row) for row in store.db.execute("""SELECT
                    kind,state FROM lifecycle_publications ORDER BY sequence,created""")]
                self.assertEqual(
                    [("gap_card", "uncertain"),
                     ("gap_scope_update", "pending")], publications)

                self.assertTrue(publisher.publish_one(client, board))
                update = store.lifecycle.next_publication()
                self.assertEqual("gap_scope_update", update["kind"])
                self.assertEqual([], update["payload"]["links"])
                self.assertEqual("t_1", update["payload"]["ticket"])

                client.lose_ack = True
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertNotIn(occurrence, board.execute(
                    "SELECT body FROM tasks WHERE id='t_1'").fetchone()[0])
                self.assertEqual("uncertain", store.lifecycle.next_publication()["state"])
                self.assertTrue(publisher.publish_one(client, board))

                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM tasks").fetchone()[0])
                self.assertEqual(0, board.execute(
                    "SELECT count(*) FROM task_comments").fetchone()[0])
                self.assertIsNone(store.lifecycle.next_publication())
            finally:
                board.close()
                store.close()

    def test_gap_recurrence_reuses_an_uncertain_original_card(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                with store.db:
                    incident = store._incident("CVE-2026-8104")
                    occurrence = "occ-uncertain-gap-recurrence"
                    resource = "deployment:uncertain-gap-recurrence"
                    scope = "paths:uncertain-gap-recurrence"
                    store.lifecycle.add_occurrence(
                        incident, occurrence, resource, service="shared",
                        host="host", deployment="container")
                store.lifecycle.evaluate(
                    incident, occurrence, rule_version="r1",
                    advisory_version="a1", dependency_scopes=[scope])
                gap = store.lifecycle.pending_gap_collections()[0]["id"]
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "mechanical collectors exhausted")
                client = Client(store)
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)

                store.lifecycle.stage_graph_change(
                    "fixed-uncertain-gap", evidence=[{
                        "id": "ev-fixed-uncertain-gap", "kind": "observation",
                        "scope": "scanner:uncertain-gap", "source": "fixture",
                        "provenance": "fixed", "status": "complete",
                        "content": {"fixed": True},
                    }], assertions=[{
                        "logical_key": "build:uncertain-gap", "version": "fixed",
                        "subject": resource, "relation": "BUILD_DISPOSITION",
                        "value": "fixed", "kind": "observation",
                        "scope": "scanner:uncertain-gap", "source": "fixture",
                        "provenance": "fixed",
                        "evidence_id": "ev-fixed-uncertain-gap",
                        "occurrences": [occurrence],
                    }])
                store.lifecycle.acknowledge_graph_change("fixed-uncertain-gap")
                quiet = store.lifecycle.evaluate(
                    incident, occurrence, rule_version="r1",
                    advisory_version="a2", dependency_scopes=[scope])
                self.assertEqual("quiet", quiet["result"])

                store.lifecycle.stage_graph_change(
                    "affected-uncertain-gap", evidence=[{
                        "id": "ev-affected-uncertain-gap", "kind": "observation",
                        "scope": "scanner:uncertain-gap", "source": "fixture",
                        "provenance": "affected", "status": "complete",
                        "content": {"affected": True},
                    }], assertions=[{
                        "logical_key": "build:uncertain-gap", "version": "affected",
                        "subject": resource, "relation": "BUILD_DISPOSITION",
                        "value": "affected", "kind": "observation",
                        "scope": "scanner:uncertain-gap", "source": "fixture",
                        "provenance": "affected",
                        "evidence_id": "ev-affected-uncertain-gap",
                        "occurrences": [occurrence],
                    }])
                store.lifecycle.acknowledge_graph_change("affected-uncertain-gap")
                recurrence = store.lifecycle.evaluate(
                    incident, occurrence, rule_version="r1",
                    advisory_version="a3", dependency_scopes=[scope])
                self.assertEqual("gap", recurrence["result"])
                store.lifecycle.record_gap_collection(
                    gap, "unresolved", "relationship evidence is still missing")

                self.assertTrue(publisher.publish_one(client, board))
                followup = store.lifecycle.next_publication()
                self.assertEqual("gap_reopen", followup["kind"])
                self.assertEqual("t_1", followup["payload"]["ticket"])
                self.assertTrue(publisher.publish_one(client, board))
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM tasks").fetchone()[0])
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM task_comments").fetchone()[0])
                self.assertIsNone(store.lifecycle.next_publication())
            finally:
                board.close()
                store.close()

    def test_lost_card_ack_reconciles_native_idempotency_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.db")
            board = sqlite3.connect(Path(directory) / "kanban.db")
            board.execute("""CREATE TABLE tasks (
                id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT,
                created_by TEXT, idempotency_key TEXT UNIQUE, status TEXT)""")
            board.execute("""CREATE TABLE task_comments (
                id INTEGER PRIMARY KEY, task_id TEXT, author TEXT, body TEXT)""")
            try:
                with store.db:
                    incident = store._incident("CVE-2026-8000")
                store.lifecycle.ensure_work(incident, "targetable_path", "decision:one")
                client = Client(store)
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertEqual(1, board.execute("SELECT count(*) FROM tasks").fetchone()[0])
                task = board.execute("SELECT body,status FROM tasks").fetchone()
                self.assertIn("Remediation (0):", task[0])
                self.assertEqual("ready", task[1])
                self.assertTrue(publisher.publish_one(client, board))
                self.assertEqual(1, board.execute("SELECT count(*) FROM tasks").fetchone()[0])
                card = store.lifecycle.work(incident)["ticket"]
                self.assertEqual("t_1", card)
                root = store.lifecycle.next_publication()
                self.assertEqual("matrix_root", root["kind"])
                self.assertEqual(root["id"], root["transaction_id"])
                store.lifecycle.publication_sent(root["id"], "$root")
                store.lifecycle.add_occurrence(
                    incident, "occ-added", "deployment:added", service="added",
                    host="host", deployment="container")
                client.lose_ack = True
                with self.assertRaises(TimeoutError):
                    publisher.publish_one(client, board)
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM task_comments").fetchone()[0])
                self.assertTrue(publisher.publish_one(client, board))
                self.assertEqual(1, board.execute(
                    "SELECT count(*) FROM task_comments").fetchone()[0])
                self.assertIsNone(store.lifecycle.next_publication())
            finally:
                board.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
