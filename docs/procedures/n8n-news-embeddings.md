# Private news embedding helper

The helper is a native Python service on protected, unprivileged LXC 217 at
`10.42.0.217`. The guest and its backup membership were verified on
13 October 2026. Authenticated CUDA inference, finite normalized vectors, cache
replay, and idle GPU release have passed. The container is retained independently
of the removed news pipeline.

The helper produces vectors for retrieval.

## Runtime

| Setting | Value |
| --- | --- |
| Guest | 217, `news-embeddings`, two vCPUs, 4 GiB RAM, 32 GiB root disk |
| Service | `news-embeddings.service`, user `news-embeddings` |
| Firewall | `news-embeddings-firewall.service`, table `inet news_embeddings` |
| Model | `google/embeddinggemma-2` |
| Model revision | `914f7f89142e33e77833254d9c9b90c3cef7303b` |
| Active encoders | Text only; vision and audio disabled |
| Vector | 768 dimensions, float32, unit normalized |
| GPU | Shared Quadro P2200, Pascal compute capability 6.1 |
| CUDA runtime | PyTorch `2.14.0+cu126` |
| Host and guest userspace driver | `580.178.04` |
| CPU fallback | Disabled by default |
| Idle unload | 30 seconds |
| Request batch | At most eight inputs, encoded one at a time |
| Pending request capacity | One active and two waiting requests |
| Maximum input | 8,192 tokens including prefixes and special tokens |

PyTorch's CUDA 12.6 build retains Pascal support. Unqualified Torch upgrades can
remove support for this GPU. The role installs hashed binary dependencies from
`requirements.lock`. It installs matching NVIDIA userspace libraries inside the
guest with `--no-kernel-module` and leaves the host driver unchanged.
The role downloads the pinned checkpoint once before serving. Subsequent model
loads use only the local cache, so inference does not depend on Hugging Face
metadata requests. A missing or damaged cache fails visibly instead of switching
models.

Float16 is unsuitable for this model. The pinned worker uses float32 on the
P2200. Text-only model weights account for roughly 1.08 GB before runtime and
activation memory. Actual peak RAM and VRAM depend on the workload and must be
measured. A GPU capacity failure does not enable CPU fallback or truncate input.

The adapter uses native Transformers `AutoTokenizer` and `AutoModel`. It retains
the checkpoint's learned projection, applies attention-masked mean pooling
including the prompt, and normalizes the output. This avoids Sentence
Transformers' automatic initialization of a multimodal processor.

The GPU is also available to Jellyfin. The helper has one inference worker and
unloads model weights after idle time. No scheduler reserves GPU capacity or
coordinates the helper with Jellyfin.

## Measured validation on 13 October 2026

The P2200 loaded 271,002,624 parameters, all float32. A cold query completed in
6.45 seconds. Peak allocated GPU memory for that short query was 1,095,988,224
bytes. This is a short-input measurement, not a maximum-window capacity result.
The authenticated two-document probe completed in 7.15 seconds. Its model
unloaded after 30.13 seconds; replaying the cached batch took 0.113 seconds and
left the model unloaded.

## Private API and authentication

TCP 5690 accepts `10.42.0.216` and guest loopback. Other IPv4 and IPv6 sources
are dropped by the helper's own nftables table. There is no Caddy, Pangolin,
Cloudflare, or public DNS route. The listener requires a bearer token except for
the minimal health endpoint.

| Request | Meaning |
| --- | --- |
| `GET /healthz` | Worker-thread liveness; does not load the model or prove CUDA inference |
| `GET /v1/status` | Authenticated model contract, runtime state, cache counts, and queue state |
| `POST /v1/embeddings` | Authenticated `texts`, `task`, and optional document `titles` |

Tasks include `Document`, `SearchQuery`, `FactChecking`, and `SentenceSimilarity`.
Each response identifies the model, revision, configuration hash, dimensions,
precision, and normalization contract.
Clients should validate every vector and batch against that pinned contract.

## State and recovery

| Path | Contents |
| --- | --- |
| `/opt/news-embeddings/worker.py` | Worker application |
| `/opt/news-embeddings/requirements.lock` | Hashed Python dependency lock |
| `/opt/news-embeddings/venv` | Isolated Python runtime |
| `/etc/news-embeddings/token` | Persistent bearer credential, root-owned mode 0600 |
| `/etc/news-embeddings/environment` | Service environment, root-owned mode 0600 |
| `/var/lib/news-embeddings/models` | Model and tokenizer cache |
| `/var/lib/news-embeddings/embeddings.sqlite` | Cached vectors and recoverable encoding jobs |

The state directory is owned by `news-embeddings` with mode 0700. A process lock
prevents two workers from using the same state directory. Cached artifacts include
the model configuration and task. Completed artifacts survive request interruption
and service restart. Pending jobs resume under the same configuration.

LXC 217 is included in `managed-weekly` snapshot backups. Its model cache and
vectors are replaceable derived data. Preserve the protected configuration with
the guest backup. The helper stores model files and derived vectors.

The deployment entry points are `news-embeddings-provision.yml` and
`news-embeddings.yml` in `ansible/playbooks`. The provisioning guard accepts only
creation of the declared LXC 217 or a converged plan. Backup reconciliation adds
217 without removing existing members.
