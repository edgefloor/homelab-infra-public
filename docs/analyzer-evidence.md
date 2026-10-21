# Analyzer evidence contract

The artifact gateway runs `govulncheck` in binary mode with JSON output and
symbol-level analysis. It binds each result to the executable's SHA-256.
The tool does not decide whether a deployment is exposed or compromised.

## Reported evidence

`evidence_level` describes the strongest report for the requested advisory.
`checks` distinguishes `reported`, `not_reported`, and `not_checked` for each
level. A lower-detail scan cannot establish that a deeper check found nothing.

| Level | Meaning |
| --- | --- |
| `module` | An affected module version was reported. |
| `package` | An affected package was reported. |
| `symbol` | An affected symbol was reported. |
| `call_path` | Source analysis reported a multi-frame path to an affected symbol. The binary-only gateway cannot produce this level. |
| `none` | No matching finding was reported at the configured scan level. |

Statuses use `module_reported`, `package_reported`, `symbol_reported`,
`call_path_reported`, or `not_reported`. These replace the previous `*_present`
labels. The wrapper leaves `artifact_applicability` as `not_established`.
Deployment exposure, compromise evidence, and replacement verification remain
`not_assessed`.

Binary analysis cannot compute call paths. Go's analyzer can also fall back to
conservative reports when symbol extraction is incomplete. The analyzer wrapper
does not independently verify symbol provenance. The separate `prove_symbols`
read provides supporting artifact evidence before a `binary affected` assessment.
[Go binary analyzer implementation](https://github.com/golang/vuln/blob/v1.1.4/internal/vulncheck/binary.go).

The parser requires a recognized protocol, explicit mode and scan level, and a
module inventory. Malformed traces and findings without their advisory record
fail validation. Advisory records retain their modification time, withdrawal
field, and content hash. Warnings remain visible. Source traces identify the
vulnerable function from the first frame, not the application entry point.
[Go JSON protocol](https://github.com/golang/vuln/blob/v1.1.4/internal/govulncheck/govulncheck.go).

The gateway also checks process completion, timeout, and output truncation.
An exit code of zero in JSON mode does not mean that no vulnerability was found.
Listed fixed versions are advisory metadata, not verified replacement artifacts.
[Govulncheck command reference](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

## Reuse validity

The cache identity includes:

- Requested advisory identifier.
- Exact executable SHA-256 and analyzer executable SHA-256.
- Wrapper version and fixed analyzer options, including mode and scan level.
- Database URL, modification marker, and metadata content hash.

The result also retains the analyzer's reported version and advisory content
hashes. Exact analyzer bytes distinguish builds that share a version string.

Before reuse, the gateway hashes the current executable and analyzer and reads
the fixed public `https://vuln.go.dev/index/db.json` endpoint. Fresh analyses must
have consistent database markers before the run, in analyzer output, and after
the run. The probe reads at most 8 KiB with a five-second network timeout. It does
not download the vulnerability database.

Missing or inconsistent database provenance, warnings, or truncated summaries
disable caching. The gateway can return a fresh uncached report with an explicit
limitation, but it cannot present an older cached report as current evidence.
Changes to executable or analyzer bytes during analysis discard the result.

The database marker is compared for equality, not age. Publication delays mean
wall-clock comparisons are unsuitable for this cache boundary.
[Go database metadata specification](https://go.dev/doc/security/vuln/database#api).

Cache entries contain binary research, not host paths, listeners, process state,
enabled features, or exposure conclusions. The current request supplies its path
and build observation. Container and artifact authorization still runs on every
request.

## Shared storage and publisher trust

The incident API stores reusable artifact reports in SQLite. An enrolled source
gateway publishes with its own root-owned credential. Worker, reader, and operator
API credentials cannot publish or acquire cache entries. The service records the
publisher and enrollment generation. Restarting with revoked or changed source
enrollment removes that publisher's cached reports.

The trust boundary is an authenticated, root-managed source gateway, not remote
execution attestation. A compromised enrolled root can falsify its reports.
The cache validates report identity, analyzer configuration, completeness, and
uncertainty fields. It rejects host paths and deployment conclusions.

Reports expire after seven days. Storage holds at most 512 reports of 64 KiB each,
about 32 MiB of report payload, plus SQLite overhead. Eviction removes the oldest
reusable report, not incident history or source snapshots. A 390-second fenced
lease permits one producer for each identity. At most eight leases exist globally
and two per publisher. Busy requests return without queuing or starting duplicate
analysis. Failed and abandoned leases expire. An unavailable shared service fails
the request rather than silently starting another analysis.

A capability can also retain sixteen bounded reports during its lifetime.
Neither cache stores executable bytes, personal profiles, Honcho conclusions, or
runtime exposure decisions. Each reader extracts and hashes its current artifact
before reuse and attaches its current path and build metadata.

## Snapshot-bound reads and investigation output

`deployment_coverage` adds `snapshot_sha256` and `finding_sha256` binding references
to retained findings. `homelab-agentctl snapshot-artifact` accepts those references,
an exact reported path, and one recorded container when applicable. The target
checks the acknowledged snapshot hash, source generation, age, finding identity,
path, and current container image. Native artifacts require an executable hash.
Both bare and `sha256:`-prefixed native hashes are enforced.

Native Zig uses this snapshot route for `extract_file`, `inspect_executable`,
`run_analyzer`, `prove_symbols`, and `verify_replacement`. `extract_file` returns
at most 64 KiB. Host extraction reads a stable captured file only after its
digest matches the selected finding. Missing or stale bindings are unavailable
evidence and do not authorize an alert-scoped fallback.

Each new scanner occurrence contains only its own container binding. Older
snapshots that repeated every user of an image remain intact, but readers select
the container named by the occurrence's location. A sibling container cannot be
selected through that occurrence's binding.

The retired bounded investigation worker could invoke `inspect_executable`,
`run_analyzer`, `prove_symbols`, `verify_replacement`, and `advisory_record`
through its typed evidence tool. That worker did not define the native Zig CLI
workflow or expose `extract_file`. Advisory reads use a fixed OSV endpoint,
reject redirects and caller-selected URLs, and expose pagination and content hashes.
These reads consume the same durable evidence and tool allowances as operational
observations. No provider output-token parameter enforces the budget.

The worker requests a structured journal with a claim, presented evidence hashes,
confidence, source, exact finding scope, classification, and visibility gap.
Only evidence presented in that run can be referenced. Invalid journals become
an explicit visibility gap. Retained assessments include the bounded evidence
envelopes, so references remain inspectable after the worker exits.

Classifications are `scanner_match`, `binary_affected`, `non_reachable`,
`contained_non_exposed`, `actionable_exposure`, `compromise_evidence`, and
`visibility_gap`. Investigator assessments are not operator verification.
Shared image identity groups scanner evidence but does not prove identical
mounted code or independent attack paths.

## Independent symbol proof

`prove_symbols` reads the exact executable's ELF Go function table without using
the vulnerability analyzer. It accepts one to twenty exact function names and
normalizes pointer-receiver notation. A positive result includes the function's
address range inside an executable load segment. The report binds this observation
to both the executable SHA-256 and the reader SHA-256.
[Go function-table reader](https://pkg.go.dev/debug/gosym).

The reader is compiled on the controller with the standard library only; targets
do not need a Go toolchain. Input is limited to 256 MiB and the function table to
64 MiB. A request has a twenty-second command timeout.

`present_in_function_table` is evidence of a compiled function, not invocation or
attacker reachability. `not_observed` does not prove absence: inlining, assembly,
linker transformations, or unsupported formats can hide code. Unsupported input
returns unavailable evidence, never a safe verdict.

## Replacement artifact comparison

`verify_replacement` accepts a tag or immutable SHA-256 digest in the currently
deployed container's repository. Public Docker Hub and GHCR Linux/amd64 images are
supported. Private registries, native release downloads, other platforms, and
link-based executable paths return an explicit visibility gap.

The reader resolves a tag, verifies the index and platform-manifest digests,
downloads that immutable image anonymously with TLS verification, and verifies
the configuration and layer hashes. It applies only the exact executable's layer
history, including whiteouts. It never imports an image into Docker, executes
candidate code, or extracts arbitrary archive paths.
[Skopeo inspection](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-inspect.1.md),
[Skopeo copy](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-copy.1.md).

Requests allow at most 32 layers, 256 MiB of declared compressed blobs, 1 GiB of
declared expanded members, and 100,000 archive members. At least 2 GiB of free
temporary storage is required. Registry output and command time are bounded;
a polled 512 MiB temporary-storage threshold terminates excessive downloads but
is not a filesystem quota. Temporary layers and executables are removed when the
request exits. Candidate analysis uses the existing shared artifact-report cache.
No image layers or executables are retained in that cache.

Both exact executable hashes, candidate image identity, and comparison status
survive the evidence tool's bounded projection. Full module inventories do not
crowd out this comparison. Statuses are:

| Status | Meaning |
| --- | --- |
| `same_executable` | Identical executable bytes; no binary remediation. |
| `match_retained` | The candidate still has an analyzer report for the advisory. |
| `match_removed` | Comparable analysis no longer reports this advisory. |
| `no_demonstrated_improvement` | Neither artifact has a report at the checked level. |
| `visibility_gap` | Analysis failed or analyzer/database provenance differs. |

`verified_fix` remains false. Removing an analyzer match does not establish
runtime safety, compatibility, or absence of other vulnerabilities. The tool
cannot label a candidate fixed merely because a newer image or fixed version exists.

## Verification

`scripts/test_analyzer_contract.py` exercises evidence levels, malformed output,
database and analyzer changes, unavailable metadata, bounded revision reads, and
the exclusion of deployment paths from cached results. The full suite passes
300 tests on 2026-09-08. Additional regressions cover snapshot binding, bare native
hashes, cross-source reuse, cache capacity, lease fencing, revoked publishers,
scoped journals, bounded urgent notification overflow, replacement comparisons,
archive whiteouts and links, descriptor limits, and bounded comparison projection.
The Go reader test compiles a stripped Linux ELF fixture and checks both a retained
function and a nonexistent name.

The gateway update is deployed to all thirteen enrolled targets. Live acceptance
analyzed NeroCD's retained Caddy executable for `GHSA-gcjh-h69q-9w9g`, published
its symbol-level report, and reused it from a fresh capability. The executable
SHA-256 was `b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9`.
Exposure remained unassessed.

Live replacement acceptance independently proved `main.main` in that executable
and reported a nonexistent function as not observed. Reconstructing the deployed
image by immutable digest returned identical executable bytes. The `latest` tag
resolved to a different index digest, but the same Linux/amd64 manifest
`sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a`
and executable. Both comparisons reported `same_executable`, not a fix.
Temporary storage was clean afterward; container identity and process state were
unchanged.

The actual `zag-ops` account passed retained finding lookup, shared
analyzer reuse, official advisory retrieval, independent symbol proof, replacement
comparison, and journal validation. Five reads reserved 20,000 evidence bytes.
No model was invoked. The central preflight confirmed thirteen current source
snapshots, no pending investigations, and database integrity. The native-agent
memory and tool catalog self-test passed, and manual-request execution was
restored after rollout. Automatic investigation admission remains disabled.
