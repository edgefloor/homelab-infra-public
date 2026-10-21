#!/usr/bin/env python3
"""Local contract tests. No torch import, weights, GPU, or external requests."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from worker import DIMENSIONS, MAX_TOKENS, EmbeddingWorker, Settings, TorchBackend, WorkerError, create_server, digest, render_request


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.loaded = False
        self.releases = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.active = 0
        self.peak_active = 0
        self.bad = None

    def token_count(self, text):
        return MAX_TOKENS + 1 if "TOO_LONG" in text else len(text.split()) + 2

    def encode(self, texts):
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)
        self.entered.set()
        self.release.wait(3)
        self.calls.append(texts)
        self.loaded = True
        self.active -= 1
        if self.bad == "nan":
            return [[float("nan")] * DIMENSIONS for _ in texts]
        if self.bad == "norm":
            return [[0.0] * DIMENSIONS for _ in texts]
        if self.bad == "count":
            return []
        if self.bad == "failure":
            raise RuntimeError("Private article text must not enter the public error")
        return [[1.0] + [0.0] * (DIMENSIONS - 1) for _ in texts]

    def provenance(self):
        return {"device": "fake-cuda", "fallback_reason": None}

    def status(self):
        return {"loaded": self.loaded, "device": "fake-cuda" if self.loaded else None}

    def unload(self):
        if self.loaded:
            self.releases += 1
        self.loaded = False


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workers = []
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for worker in self.workers:
            worker.close()
        self.temp.cleanup()

    def worker(self, backend=None, versions=None, **options):
        settings = Settings(Path(self.temp.name), "secret-token-" + "x" * 32, port=0, idle_seconds=0.05, **options)
        worker = EmbeddingWorker(settings, backend or FakeBackend(), runtime_versions=versions or {"test": "1"})
        self.workers.append(worker)
        return worker

    @staticmethod
    def request(task="SearchQuery", texts=None, **other):
        return {"task": task, "texts": texts or ["Tegnap elfogadták a törvényt."], **other}

    def test_task_prefixes_are_explicit_and_titles_render_once(self):
        settings = Settings(Path(self.temp.name), "x" * 32)
        expected = {
            "SearchQuery": "task: search result | query: A",
            "FactChecking": "task: fact checking | query: A",
            "SentenceSimilarity": "task: sentence similarity | query: A",
            "Document": "title: none | text: A",
        }
        for task, rendered in expected.items():
            self.assertEqual(render_request(self.request(task, ["A"]), settings), (task, [rendered]))
        self.assertEqual(render_request(self.request("Document", ["A", "B"], titles=["Cím", None]), settings)[1], ["title: Cím | text: A", "title: none | text: B"])
        with self.assertRaises(WorkerError):
            render_request(self.request("SearchQuery", titles=["Wrong"]), settings)
        for value in [None, {}, [], 4, False]:
            with self.assertRaises(WorkerError):
                render_request({"task": value, "texts": ["A"]}, settings)

    def test_cuda_selection_requires_native_architecture_and_explicit_fallback(self):
        class Cuda:
            available = True
            arches = ["sm_60", "sm_70", "sm_80"]
            @classmethod
            def is_available(cls):
                return cls.available
            @classmethod
            def get_arch_list(cls):
                return cls.arches
            @staticmethod
            def get_device_capability(_):
                return (6, 1)
        class Torch:
            cuda = Cuda
        settings = Settings(Path(self.temp.name), "x" * 32)
        backend = TorchBackend(settings)
        backend.torch = Torch
        self.assertEqual(backend._select_device(), "cuda:0")
        Cuda.arches = ["sm_80", "sm_90"]
        with self.assertRaises(WorkerError) as raised:
            backend._select_device()
        self.assertEqual(raised.exception.code, "native_cuda_architecture_unavailable")
        from dataclasses import replace
        backend.settings = replace(settings, allow_cpu_fallback=True)
        self.assertEqual(backend._select_device(), "cpu")
        self.assertEqual(backend.fallback_reason, "native_cuda_architecture_unavailable")
        Cuda.available = False
        self.assertEqual(backend._select_device(), "cpu")
        self.assertEqual(backend.fallback_reason, "cuda_unavailable")

    def test_cached_inputs_survive_restart_and_do_not_warm_encoder(self):
        first = self.worker()
        result = first.submit(self.request())
        self.assertEqual(len(first.backend.calls), 1)
        self.assertFalse(result["artifacts"][0]["cache_hit"])
        first.close()
        self.workers.remove(first)
        second = self.worker()
        replay = second.submit(self.request())
        self.assertEqual(replay["embeddings"], result["embeddings"])
        self.assertEqual(replay["artifacts"][0]["id"], result["artifacts"][0]["id"])
        self.assertTrue(replay["artifacts"][0]["cache_hit"])
        self.assertEqual(second.backend.calls, [])
        self.assertFalse(second.backend.loaded)
        self.assertEqual((Path(self.temp.name) / "embeddings.sqlite").stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(self.temp.name).stat().st_mode & 0o777, 0o700)

    def test_identity_includes_task_title_and_runtime_version(self):
        first = self.worker()
        ids = [first.submit(self.request(task, ["Same"] , **extra))["artifacts"][0]["id"] for task, extra in [
            ("SearchQuery", {}), ("Document", {}), ("Document", {"titles": ["Title"]}), ("FactChecking", {})
        ]]
        self.assertEqual(len(set(ids)), 4)
        first.close()
        self.workers.remove(first)
        second = self.worker(versions={"test": "2"})
        self.assertNotEqual(second.submit(self.request("SearchQuery", ["Same"]))["artifacts"][0]["id"], ids[0])

    def test_budget_checks_entire_batch_before_encoding_or_persistence(self):
        worker = self.worker()
        with self.assertRaises(WorkerError) as raised:
            worker.submit(self.request(texts=["Valid", "TOO_LONG"]))
        self.assertEqual(raised.exception.code, "input_too_long")
        self.assertEqual(worker.backend.calls, [])
        self.assertEqual(worker.status()["artifacts"], 0)
        self.assertEqual(worker.status()["jobs"], {})
        with self.assertRaises(WorkerError) as raised:
            worker.submit(self.request(texts=["X"] * 9))
        self.assertEqual(raised.exception.code, "batch_too_large")

    def test_repeated_text_in_batch_encodes_once_and_preserves_output_order(self):
        worker = self.worker()
        result = worker.submit(self.request(texts=["A", "B", "A"]))
        self.assertEqual(len(worker.backend.calls), 2)
        self.assertEqual(len(result["embeddings"]), 3)
        self.assertEqual(result["artifacts"][0]["id"], result["artifacts"][2]["id"])
        self.assertNotEqual(result["artifacts"][0]["id"], result["artifacts"][1]["id"])

    def test_invalid_output_never_becomes_cached_success(self):
        worker = self.worker()
        for bad in ["nan", "norm", "count", "failure"]:
            worker.backend.bad = bad
            with self.assertRaises(WorkerError) as raised:
                worker.submit(self.request(texts=[bad]))
            self.assertNotIn("Private article", str(raised.exception))
            self.assertEqual(worker.status()["artifacts"], 0)
        self.assertEqual(worker.status()["jobs"], {"failed": 4})

    def test_admission_is_bounded_and_singleflight_reuses_saved_artifact(self):
        backend = FakeBackend()
        backend.release.clear()
        worker = self.worker(backend, max_pending=1)
        results, failures = [], []
        def run():
            try:
                results.append(worker.submit(self.request()))
            except Exception as error:
                failures.append(error)
        first = threading.Thread(target=run)
        first.start()
        self.assertTrue(backend.entered.wait(1))
        second = threading.Thread(target=run)
        second.start()
        deadline = time.monotonic() + 1
        while worker.queue.qsize() != 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        with self.assertRaises(WorkerError) as raised:
            worker.submit(self.request(texts=["Another"]))
        self.assertEqual(raised.exception.status, 429)
        backend.release.set()
        first.join(2)
        second.join(2)
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.peak_active, 1)
        self.assertEqual(sum(r["artifacts"][0]["cache_hit"] for r in results), 1)

    def test_idle_release_preserves_vectors_and_cache_hit_keeps_gpu_cold(self):
        worker = self.worker()
        worker.submit(self.request())
        deadline = time.monotonic() + 1
        while worker.backend.loaded and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(worker.backend.loaded)
        self.assertEqual(worker.backend.releases, 1)
        self.assertTrue(worker.submit(self.request())["artifacts"][0]["cache_hit"])
        self.assertFalse(worker.backend.loaded)

    def test_unfinished_durable_job_recovers_without_original_http_request(self):
        first = self.worker()
        rendered = "task: search result | query: Recover"
        identifier = digest({"configuration_hash": first.configuration_hash, "task": "SearchQuery", "rendered": rendered})
        first.stop.set()
        first.thread.join()
        with first.db:
            first.db.execute("INSERT INTO jobs(id,configuration_hash,task,rendered,token_count,status,updated_at) VALUES(?,?,?,?,?,'running',?)", (identifier, first.configuration_hash, "SearchQuery", rendered, 9, time.time()))
        first.close()
        self.workers.remove(first)
        second = self.worker()
        deadline = time.monotonic() + 2
        while second.status()["artifacts"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(second.status()["artifacts"], 1)
        self.assertEqual(second.status()["jobs"], {"completed": 1})
        with second.database_lock:
            self.assertIsNone(second.db.execute("SELECT rendered FROM jobs WHERE id=?", (identifier,)).fetchone()[0])

    def test_state_directory_has_one_process_owner(self):
        first = self.worker()
        with self.assertRaisesRegex(RuntimeError, "already owns"):
            EmbeddingWorker(first.settings, FakeBackend(), runtime_versions={"test": "1"})

    def test_health_is_minimal_status_requires_auth_and_http_returns_contract(self):
        worker = self.worker()
        server = create_server(worker)
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        def request(method, path, body=None, token=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            headers = {"Authorization": "Bearer " + token} if token else {}
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            status, payload = response.status, json.loads(response.read())
            connection.close()
            return status, payload
        self.assertEqual(request("GET", "/healthz"), (200, {"status": "ok"}))
        self.assertEqual(request("GET", "/v1/status")[0], 401)
        status, payload = request("GET", "/v1/status", token=worker.settings.token)
        self.assertEqual(status, 200)
        self.assertFalse(payload["backend"]["loaded"])
        self.assertNotIn(worker.settings.token, json.dumps(payload))
        status, encoded = request("POST", "/v1/embeddings", json.dumps(self.request()), worker.settings.token)
        self.assertEqual(status, 200)
        self.assertEqual(encoded["configuration_hash"], payload["configuration_hash"])
        self.assertEqual(encoded["dimensions"], 768)
        self.assertEqual(request("POST", "/v1/embeddings", "not json", worker.settings.token)[0], 400)


if __name__ == "__main__":
    unittest.main()
