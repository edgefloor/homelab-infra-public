# Managed software inventories

This role sends standard CycloneDX documents to Dependency-Track. It collects
OS packages, explicitly declared native binaries and installed library roots,
and the images used by running Docker containers. Image projects use Compose
project/service names where available and scan the running image's content ID.
Library release symlinks resolve to the installed release before scanning.

The collector runs daily, with randomized scheduling. The hourly freshness
check fails when any declared scope failed, the configuration changed, or the
last complete upload is older than 36 hours. A failed or empty scan never
uploads a replacement inventory. An import counts as successful only when
Dependency-Track reports its native workflow status as `COMPLETED`.

LAN clients use verified HTTPS and curl's `--resolve` with the canonical Caddy
address from `inventory/routes.yml`. The VPS uses its restricted loopback SSH
forward. API keys stay in a root-owned mode-0600 header file and are not command
arguments. The role reads the native parent portfolio identity prepared by the
Dependency-Track server role.

## Dependency-Track's own inventory

The pinned Dependency-Track 5.2.0 release publishes an official
[CycloneDX BOM](https://github.com/DependencyTrack/dependency-track/releases/download/5.2.0/bom.json).
Its SHA-256 is
`ba2d41806d09e235a433a7a55860bbb00d92f32fdf595bb520083637de22a665`.
This BOM contains 237 components with package URLs.

Before each upload, the collector checks the BOM checksum and release version,
the cached backend distribution checksum, and the complete installed JAR set
against that distribution. Missing, changed, or additional JARs fail the scope.
No archive is extracted by this verification. Update the BOM checksum along
with the pinned server release when upgrading Dependency-Track.

This publisher BOM avoids Trivy's Java-index download. Trivy 0.74 initializes
that index for every JAR analysis, even in offline mode, and cannot skip the
download when the index is absent. Other artifact scopes use the checksum-pinned
Trivy CLI directly.

## Rust source candidates

Tuwunel 1.9.0 and MatrixRTC JWT 0.7.0 lack supported embedded Rust dependency
metadata. Their separate `/source-lock-candidates` projects contain packages
from checksum-pinned Cargo lockfiles at reviewed immutable source revisions.
These are conservative candidate inventories; compiled membership is unverified.
They include development, optional and other-platform dependencies and omit
native libraries and the Rust toolchain. A finding needs artifact-specific
review before it can be treated as affecting the running service.

Before each upload and hourly freshness check, the collector verifies the lock
checksum and deployed artifact identity. Tuwunel must match the reviewed binary
SHA-256; JWT must match the reviewed running Docker image content ID. An upgrade,
missing container or edited lock fails collection/freshness until the source
association is reviewed. This check verifies the recorded association, not a
reproducible build or the compiled dependency set.

The CycloneDX document and local status carry the evidence mode, limitations,
source revision and artifact identity. Registry packages have Cargo package URLs
and crate-archive checksums. Git forks and workspace crates retain their origins
without misleading crates.io package URLs. The document declares composition
completeness unknown. Source candidates never replace artifact inventories.
See the [coverage procedure](../../../docs/procedures/dependency-track.md#rust-source-associations)
for the release evidence and update rules.

## Readback

`/var/lib/homelab-sbom/status.json` records the last attempt, last complete
success, uploaded scope names, failed scope names, and evidence mode for each
scope. It contains no API key or package inventory. `homelab-sbom-freshness.service` checks that state against
the current collector configuration. Uploaded scopes on a partially covered
host remain available in Dependency-Track; the host's completeness check stays
failed until every declared scope succeeds.

Collection freshness means that every declared inventory was accepted in its
recorded evidence mode. It does not prove full artifact coverage. For Rust source
candidates, `--check` explicitly reports that compiled membership is unverified.
Unsupported binaries without a reviewed source association remain failed scopes.
