#!/usr/bin/env python3
"""Private, versioned text embeddings. Semantic decisions belong to the caller."""

from __future__ import annotations

import gc
import fcntl
import hashlib
import hmac
import importlib.metadata
import json
import math
import os
from pathlib import Path
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MODEL = "google/embeddinggemma-2"
REVISION = "914f7f89142e33e77833254d9c9b90c3cef7303b"
DIMENSIONS = 768
MAX_TOKENS = 8192
CONTRACT_VERSION = 2
TASKS = {
    "SearchQuery": "task: search result | query: ",
    "FactChecking": "task: fact checking | query: ",
    "SentenceSimilarity": "task: sentence similarity | query: ",
}


def stable(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(stable(value).encode("utf-8")).hexdigest()


class WorkerError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass(frozen=True)
class Settings:
    directory: Path
    token: str = field(repr=False)
    bind: str = "127.0.0.1"
    port: int = 5690
    device: str = "cuda"
    allow_cpu_fallback: bool = False
    idle_seconds: float = 30.0
    max_batch: int = 8
    encode_batch_size: int = 1
    max_pending: int = 2
    max_request_bytes: int = 1_000_000
    request_timeout: float = 900.0
    torch_threads: int = 2
    local_files_only: bool = False

    def __post_init__(self):
        if len(self.token) < 32:
            raise ValueError("The private bearer token must contain at least 32 characters")
        if self.device not in {"cuda", "cpu"}:
            raise ValueError("Device must be cuda or cpu")
        if self.idle_seconds <= 0 or self.request_timeout <= 0:
            raise ValueError("Timeouts must be positive")
        if min(self.max_batch, self.encode_batch_size, self.max_request_bytes, self.torch_threads) < 1 or self.max_pending < 0:
            raise ValueError("Invalid worker capacity")

    @classmethod
    def environment(cls):
        boolean = lambda name, default="false": os.environ.get(name, default).lower() == "true"
        return cls(
            directory=Path(os.environ.get("NEWS_EMBEDDINGS_STATE_DIRECTORY", "/var/lib/news-embeddings")),
            token=os.environ.get("NEWS_EMBEDDINGS_TOKEN", ""),
            bind=os.environ.get("NEWS_EMBEDDINGS_BIND", "127.0.0.1"),
            port=int(os.environ.get("NEWS_EMBEDDINGS_PORT", "5690")),
            device=os.environ.get("NEWS_EMBEDDINGS_DEVICE", "cuda"),
            allow_cpu_fallback=boolean("NEWS_EMBEDDINGS_ALLOW_CPU_FALLBACK"),
            idle_seconds=float(os.environ.get("NEWS_EMBEDDINGS_IDLE_SECONDS", "30")),
            max_batch=int(os.environ.get("NEWS_EMBEDDINGS_MAX_BATCH", "8")),
            encode_batch_size=int(os.environ.get("NEWS_EMBEDDINGS_ENCODE_BATCH_SIZE", "1")),
            max_pending=int(os.environ.get("NEWS_EMBEDDINGS_MAX_PENDING", "2")),
            max_request_bytes=int(os.environ.get("NEWS_EMBEDDINGS_MAX_REQUEST_BYTES", "1000000")),
            request_timeout=float(os.environ.get("NEWS_EMBEDDINGS_REQUEST_TIMEOUT", "900")),
            torch_threads=int(os.environ.get("NEWS_EMBEDDINGS_TORCH_THREADS", "2")),
            local_files_only=boolean("NEWS_EMBEDDINGS_LOCAL_FILES_ONLY"),
        )


def render_request(body, settings):
    if not isinstance(body, dict) or set(body) - {"texts", "task", "titles"}:
        raise WorkerError(400, "invalid_request", "Provide texts, task, and optional Document titles only")
    texts, task = body.get("texts"), body.get("task")
    if not isinstance(task, str) or task not in {*TASKS, "Document"}:
        raise WorkerError(400, "invalid_task", "Use SearchQuery, Document, FactChecking, or SentenceSimilarity")
    if not isinstance(texts, list) or not texts or any(not isinstance(s, str) or not s.strip() for s in texts):
        raise WorkerError(400, "invalid_texts", "texts must be a nonempty array of nonempty strings")
    if len(texts) > settings.max_batch:
        raise WorkerError(413, "batch_too_large", "Split the request into smaller batches; no input was encoded")
    titles = body.get("titles")
    if titles is not None and (task != "Document" or not isinstance(titles, list) or len(titles) != len(texts) or any(t is not None and not isinstance(t, str) for t in titles)):
        raise WorkerError(400, "invalid_titles", "titles must match texts and are supported only for Document")
    try:
        if task == "Document":
            rendered = [f"title: {(titles[i] or 'none') if titles is not None else 'none'} | text: {text}" for i, text in enumerate(texts)]
        else:
            rendered = [TASKS[task] + text for text in texts]
        for text in rendered:
            text.encode("utf-8")
    except UnicodeError:
        raise WorkerError(400, "invalid_unicode", "Text must contain valid Unicode") from None
    return task, rendered


class TorchBackend:
    """Imports the native runtime lazily and never guesses CUDA compatibility."""

    def __init__(self, settings):
        self.settings = settings
        self.model = self.tokenizer = self.torch = None
        self.device = None
        self.fallback_reason = None
        self.last_used = 0.0
        self.loaded_parameters = None
        self.parameter_dtypes = None

    def token_count(self, text):
        if self.tokenizer is None:
            from transformers import AutoTokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                MODEL, revision=REVISION, cache_dir=str(self.settings.directory / "models"),
                local_files_only=self.settings.local_files_only, trust_remote_code=False,
            )
        return len(self.tokenizer(text, add_special_tokens=True, truncation=False, padding=False)["input_ids"])

    def _select_device(self):
        torch = self.torch
        if self.settings.device == "cpu":
            return "cpu"
        reason = None
        if not torch.cuda.is_available():
            reason = "cuda_unavailable"
        else:
            major, minor = torch.cuda.get_device_capability(0)
            native = {tuple(map(int, name[3:])) for name in torch.cuda.get_arch_list() if name.startswith("sm_") and len(name[3:]) == 2 and name[3:].isdigit()}
            if not any(a == major and b <= minor for a, b in native):
                reason = "native_cuda_architecture_unavailable"
        if reason:
            if not self.settings.allow_cpu_fallback:
                raise WorkerError(503, reason, "Configured CUDA execution is unavailable; CPU fallback is disabled")
            self.fallback_reason = reason
            return "cpu"
        self.fallback_reason = None
        return "cuda:0"

    def _load(self):
        if self.model is not None:
            return
        import torch
        from transformers import AutoConfig, AutoModel
        self.torch = torch
        torch.set_num_threads(self.settings.torch_threads)
        self.device = self._select_device()
        def construct():
            common = {"revision": REVISION, "cache_dir": str(self.settings.directory / "models"),
                      "local_files_only": self.settings.local_files_only, "trust_remote_code": False}
            config = AutoConfig.from_pretrained(MODEL, vision_config=None, audio_config=None, **common)
            # The checkpoint's ST modules are Transformer -> mean Pooling (including
            # the prompt) -> Normalize. Native AutoModel retains its learned 768d
            # projection; no multimodal AutoProcessor or alternative head is needed.
            return AutoModel.from_pretrained(
                MODEL, config=config, torch_dtype=torch.float32,
                attn_implementation="eager", **common,
            ).to(self.device)
        try:
            self.model = construct()
        except RuntimeError as error:
            if not self._compatibility_fallback(error):
                raise
            self.model = construct()
        self.model.float()
        self.model.eval()
        self.loaded_parameters = sum(parameter.numel() for parameter in self.model.parameters())
        self.parameter_dtypes = sorted({str(parameter.dtype) for parameter in self.model.parameters()})

    def _compatibility_fallback(self, error):
        # A capacity failure is not permission to change execution policy.
        compatibility = ("no kernel image", "invalid device function", "not compiled with cuda", "driver version is insufficient")
        if not self.settings.allow_cpu_fallback or not self.device or not self.device.startswith("cuda") or not any(text in str(error).lower() for text in compatibility):
            return False
        self.unload()
        self.device = "cpu"
        self.fallback_reason = "cuda_runtime_incompatible"
        return True

    def encode(self, rendered):
        self._load()
        def run():
            with self.torch.inference_mode():
                # Reuse exactly the tokenizer used for budget validation. Never
                # truncate inputs, including prefixes, BOS, EOS, or padding.
                if self.tokenizer is None:
                    self.token_count(rendered[0])
                encoded = self.tokenizer(rendered, add_special_tokens=True, padding=True,
                                         truncation=False, return_tensors="pt")
                if encoded["input_ids"].shape[1] > MAX_TOKENS:
                    raise WorkerError(422, "input_too_long", "The complete tokenized input exceeds the supported window")
                inputs = {name: encoded[name].to(self.device) for name in ["input_ids", "attention_mask"]}
                hidden = self.model(**inputs, return_dict=True).last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                return self.torch.nn.functional.normalize(pooled, p=2, dim=1).cpu()
        try:
            result = run()
        except RuntimeError as error:
            if not self._compatibility_fallback(error):
                raise
            # _load uses the original device policy, so make this retry explicitly CPU.
            from dataclasses import replace
            previous_settings = self.settings
            self.settings = replace(self.settings, device="cpu")
            try:
                self._load()
                result = run()
            finally:
                self.settings = previous_settings
        self.last_used = time.monotonic()
        return result.tolist()

    def provenance(self):
        result = {"device": self.device, "fallback_reason": self.fallback_reason}
        if self.torch is not None:
            result.update(torch_version=str(self.torch.__version__), cuda_runtime=self.torch.version.cuda)
            if self.device and self.device.startswith("cuda"):
                result.update(gpu_name=self.torch.cuda.get_device_name(0), capability=list(self.torch.cuda.get_device_capability(0)))
        return result

    def status(self):
        result = {"loaded": self.model is not None, "loaded_parameters": self.loaded_parameters,
                  "parameter_dtypes": self.parameter_dtypes, **self.provenance()}
        if self.model is not None and self.device and self.device.startswith("cuda"):
            result.update(allocated_bytes=self.torch.cuda.memory_allocated(0), reserved_bytes=self.torch.cuda.memory_reserved(0), peak_allocated_bytes=self.torch.cuda.max_memory_allocated(0))
        return result

    def unload(self):
        self.model = None
        self.loaded_parameters = None
        self.parameter_dtypes = None
        gc.collect()
        if self.torch is not None and self.device and self.device.startswith("cuda"):
            self.torch.cuda.empty_cache()
        self.device = None


@dataclass
class Ticket:
    task: str
    rendered: list[str]
    event: threading.Event = field(default_factory=threading.Event)
    result: dict | None = None
    error: Exception | None = None


class EmbeddingWorker:
    def __init__(self, settings, backend=None, runtime_versions=None):
        self.settings = settings
        self.backend = backend or TorchBackend(settings)
        self.directory = settings.directory
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.process_lock = (self.directory / ".worker.lock").open("a")
        (self.directory / ".worker.lock").chmod(0o600)
        try:
            fcntl.flock(self.process_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.process_lock.close()
            raise RuntimeError("An embedding worker already owns this state directory") from None
        versions = {}
        for name in ["torch", "transformers", "numpy", "tokenizers", "safetensors"]:
            try:
                versions[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                versions[name] = "not-installed"
        self.contract = {
            "model": MODEL, "revision": REVISION, "dimensions": DIMENSIONS,
            "precision": "float32", "normalized": True, "contract_version": CONTRACT_VERSION,
            "runtime": runtime_versions if runtime_versions is not None else versions,
            "prefixes": {**TASKS, "Document": "title: {title or none} | text: {text}"},
            "device_policy": settings.device, "allow_cpu_fallback": settings.allow_cpu_fallback,
            "attention": "eager", "vision": False, "audio": False,
            "adapter": "transformers-native-text", "pooling": "attention-masked-mean-including-prompt",
        }
        self.configuration_hash = digest(self.contract)
        self.database_lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "embeddings.sqlite", check_same_thread=False)
        (self.directory / "embeddings.sqlite").chmod(0o600)
        with self.db:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.execute("CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, configuration_hash TEXT NOT NULL, task TEXT NOT NULL, text_digest TEXT NOT NULL, token_count INTEGER NOT NULL, vector TEXT NOT NULL, provenance TEXT NOT NULL, created_at REAL NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, configuration_hash TEXT NOT NULL, task TEXT NOT NULL, rendered TEXT, token_count INTEGER NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, error_code TEXT, updated_at REAL NOT NULL)")
            self.db.execute("UPDATE jobs SET status='pending' WHERE configuration_hash=? AND status='running'", (self.configuration_hash,))
        for filename in ["embeddings.sqlite-wal", "embeddings.sqlite-shm"]:
            if (self.directory / filename).exists():
                (self.directory / filename).chmod(0o600)
        self.admission = threading.BoundedSemaphore(settings.max_pending + 1)
        self.queue = queue.Queue()
        self.stop = threading.Event()
        self.active = False
        self.last_activity = time.monotonic()
        self.thread = threading.Thread(target=self._loop, name="embedding-worker", daemon=True)
        self.thread.start()

    def submit(self, body):
        task, rendered = render_request(body, self.settings)
        if self.stop.is_set():
            raise WorkerError(503, "worker_stopping", "The embedding worker is stopping")
        if not self.admission.acquire(blocking=False):
            raise WorkerError(429, "worker_busy", "Embedding capacity is occupied; retry the unchanged request")
        ticket = Ticket(task, rendered)
        self.queue.put(ticket)
        if not ticket.event.wait(self.settings.request_timeout):
            raise WorkerError(504, "embedding_timeout", "Encoding is still in progress; retry the unchanged request to reuse saved work")
        if ticket.error:
            raise ticket.error
        return ticket.result

    def _artifact(self, identifier):
        with self.database_lock:
            row = self.db.execute("SELECT text_digest,token_count,vector,provenance FROM artifacts WHERE id=?", (identifier,)).fetchone()
        if row is None:
            return None
        vector = json.loads(row[2])
        self._validate_vector(vector)
        return {"id": identifier, "text_digest": row[0], "token_count": row[1], "vector": vector, "provenance": json.loads(row[3])}

    @staticmethod
    def _validate_vector(vector):
        if not isinstance(vector, list) or len(vector) != DIMENSIONS or any(isinstance(v, bool) or not isinstance(v, (float, int)) or not math.isfinite(v) for v in vector):
            raise WorkerError(502, "invalid_embedding", "The encoder returned a non-finite or incorrectly sized vector")
        norm = math.sqrt(math.fsum(v * v for v in vector))
        if not math.isfinite(norm) or abs(norm - 1.0) > 0.001:
            raise WorkerError(502, "invalid_embedding_norm", "The encoder returned a vector without unit normalization")

    def _encode_jobs(self, jobs):
        identifiers = [job[0] for job in jobs]
        with self.database_lock, self.db:
            for identifier in identifiers:
                self.db.execute("UPDATE jobs SET status='running',attempts=attempts+1,updated_at=? WHERE id=?", (time.time(), identifier))
        try:
            vectors = self.backend.encode([job[2] for job in jobs])
            if not isinstance(vectors, list) or len(vectors) != len(jobs):
                raise WorkerError(502, "invalid_embedding_batch", "The encoder returned the wrong number of vectors")
            for vector in vectors:
                self._validate_vector(vector)
            provenance = self.backend.provenance()
            with self.database_lock, self.db:
                for (identifier, task, rendered, count), vector in zip(jobs, vectors):
                    self.db.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?,?,?)", (identifier, self.configuration_hash, task, digest(rendered), count, stable(vector), stable(provenance), time.time()))
                    self.db.execute("UPDATE jobs SET status='completed',rendered=NULL,error_code=NULL,updated_at=? WHERE id=?", (time.time(), identifier))
        except Exception as error:
            code = error.code if isinstance(error, WorkerError) else "encoding_failed"
            with self.database_lock, self.db:
                for identifier in identifiers:
                    self.db.execute("UPDATE jobs SET status='failed',error_code=?,updated_at=? WHERE id=?", (code, time.time(), identifier))
            if isinstance(error, WorkerError):
                raise
            raise WorkerError(503, code, "Encoding failed; retry the unchanged request to reuse completed artifacts") from None
        finally:
            self.last_activity = time.monotonic()

    def _process(self, ticket):
        counts = [self.backend.token_count(text) for text in ticket.rendered]
        oversized = [i for i, count in enumerate(counts) if count > MAX_TOKENS]
        if oversized:
            raise WorkerError(422, "input_too_long", f"Inputs at indices {oversized} exceed {MAX_TOKENS} tokens including prefixes and special tokens; split complete inputs without truncation")
        identifiers = [digest({"configuration_hash": self.configuration_hash, "task": ticket.task, "rendered": text}) for text in ticket.rendered]
        cached = [self._artifact(identifier) for identifier in identifiers]
        missing = {}
        with self.database_lock, self.db:
            for identifier, text, count, artifact in zip(identifiers, ticket.rendered, counts, cached):
                if artifact is None:
                    missing[identifier] = (identifier, ticket.task, text, count)
                    self.db.execute("INSERT INTO jobs(id,configuration_hash,task,rendered,token_count,status,updated_at) VALUES(?,?,?,?,?,'pending',?) ON CONFLICT(id) DO UPDATE SET rendered=excluded.rendered,status='pending',error_code=NULL,updated_at=excluded.updated_at", (identifier, self.configuration_hash, ticket.task, text, count, time.time()))
        jobs = list(missing.values())
        for start in range(0, len(jobs), self.settings.encode_batch_size):
            self._encode_jobs(jobs[start:start + self.settings.encode_batch_size])
        artifacts = [self._artifact(identifier) for identifier in identifiers]
        return {
            "embeddings": [artifact["vector"] for artifact in artifacts],
            "artifacts": [{k: value for k, value in artifact.items() if k != "vector"} | {"cache_hit": hit is not None} for artifact, hit in zip(artifacts, cached)],
            "model": MODEL, "revision": REVISION, "configuration_hash": self.configuration_hash,
            "task": ticket.task, "dimensions": DIMENSIONS, "precision": "float32", "normalized": True,
        }

    def _recover_one(self):
        with self.database_lock:
            rows = self.db.execute("SELECT id,task,rendered,token_count FROM jobs WHERE configuration_hash=? AND status='pending' ORDER BY updated_at LIMIT ?", (self.configuration_hash, self.settings.encode_batch_size)).fetchall()
        if not rows:
            return False
        self._encode_jobs(rows)
        return True

    def _loop(self):
        while not self.stop.is_set():
            try:
                ticket = self.queue.get(timeout=min(self.settings.idle_seconds, 0.25))
            except queue.Empty:
                try:
                    self.active = True
                    if self._recover_one():
                        continue
                except WorkerError:
                    pass  # Durable job records contain a non-sensitive error code.
                finally:
                    self.active = False
                if time.monotonic() - self.last_activity >= self.settings.idle_seconds and self.backend.status().get("loaded"):
                    self.backend.unload()
                continue
            try:
                self.active = True
                ticket.result = self._process(ticket)
            except WorkerError as error:
                ticket.error = error
            except Exception:
                ticket.error = WorkerError(503, "worker_error", "Embedding preparation failed; retry the unchanged request")
            finally:
                self.active = False
                if time.monotonic() - self.last_activity >= self.settings.idle_seconds and self.backend.status().get("loaded"):
                    self.backend.unload()
                ticket.event.set()
                self.admission.release()
                self.queue.task_done()
        self.backend.unload()

    def status(self):
        with self.database_lock:
            artifacts = self.db.execute("SELECT count(*) FROM artifacts WHERE configuration_hash=?", (self.configuration_hash,)).fetchone()[0]
            jobs = dict(self.db.execute("SELECT status,count(*) FROM jobs WHERE configuration_hash=? GROUP BY status", (self.configuration_hash,)).fetchall())
        return {"status": "ok" if self.thread.is_alive() and not self.stop.is_set() else "stopping", "model": MODEL, "revision": REVISION, "configuration_hash": self.configuration_hash, "contract": self.contract,
                "dimensions": DIMENSIONS, "precision": "float32", "normalized": True,
                "active": self.active, "queued_requests": self.queue.qsize(), "artifacts": artifacts, "jobs": jobs,
                "backend": self.backend.status()}

    def close(self):
        self.stop.set()
        self.thread.join()
        while True:
            try:
                ticket = self.queue.get_nowait()
            except queue.Empty:
                break
            ticket.error = WorkerError(503, "worker_stopping", "The worker stopped before processing this request")
            ticket.event.set()
            self.admission.release()
            self.queue.task_done()
        self.db.close()
        self.process_lock.close()


def create_server(worker):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NewsEmbeddings/1"

        def log_message(self, *_):
            pass  # Never log article text, bearer credentials, or request bodies.

        def _send(self, status, body):
            payload = stable(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            if status == 429:
                self.send_header("Retry-After", "5")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _authorize(self):
            received = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(received, ("Bearer " + worker.settings.token).encode("utf-8")):
                raise WorkerError(401, "unauthorized", "Private bearer authentication is required")

        def do_GET(self):
            try:
                route = urlsplit(self.path).path
                if route == "/healthz":
                    healthy = worker.thread.is_alive() and not worker.stop.is_set()
                    return self._send(200 if healthy else 503, {"status": "ok" if healthy else "stopping"})
                self._authorize()
                if route == "/v1/status":
                    return self._send(200, worker.status())
                raise WorkerError(404, "not_found", "Unknown endpoint")
            except WorkerError as error:
                self._send(error.status, {"error": {"code": error.code, "message": error.message}})

        def do_POST(self):
            try:
                self._authorize()
                if urlsplit(self.path).path != "/v1/embeddings":
                    raise WorkerError(404, "not_found", "Unknown endpoint")
                if self.headers.get("Transfer-Encoding"):
                    raise WorkerError(400, "invalid_body", "Use a Content-Length JSON request")
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    raise WorkerError(400, "invalid_length", "Provide a valid Content-Length") from None
                if length < 1 or length > worker.settings.max_request_bytes:
                    raise WorkerError(413, "request_too_large", "Split the JSON request into smaller batches")
                self.connection.settimeout(15)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise WorkerError(400, "incomplete_body", "The JSON request body was incomplete")
                try:
                    body = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise WorkerError(400, "invalid_json", "Provide valid UTF-8 JSON") from None
                self._send(200, worker.submit(body))
            except WorkerError as error:
                self._send(error.status, {"error": {"code": error.code, "message": error.message}})
            except (TimeoutError, OSError):
                self.close_connection = True

    return ThreadingHTTPServer((worker.settings.bind, worker.settings.port), Handler)


def main():
    os.umask(0o077)
    settings = Settings.environment()
    worker = EmbeddingWorker(settings)
    server = create_server(worker)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        worker.close()


if __name__ == "__main__":
    main()
