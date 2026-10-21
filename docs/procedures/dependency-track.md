# Dependency-Track

OWASP Dependency-Track replaces the custom CVE incident API, Helix graph,
correlation rules, and Zig investigation workflow. Personal Hermes, Beszel,
CrowdSec, release notifications, and the native Trivy server remain separate.

The dashboard is `https://vulns.homelab.example`, available on the private LAN.
LXC 214 keeps its infrastructure name `incident` to preserve its existing
OpenTofu identity and data volume. Dependency-Track has its own directory at
`/var/lib/homelab-incidents/dependency-track`; the old SQLite files stay in place.

## Runtime and credentials

The pinned upstream JVM distribution runs as `dependency-track.service` with
Temurin Java 25. PostgreSQL 17 runs in a dedicated cluster on loopback port 5433.
An nginx instance serves the upstream frontend and proxies the API on port 8080.
Only the main Caddy host can reach that listener. The Java API and management
health listener bind to loopback ports 8081 and 9000.

The role rotates the default administrator password before starting the
frontend. Root can retrieve the saved login from
`/root/.config/dependency-track/admin.json` on LXC 214. Keep that file private;
do not paste it into logs, issues, or chat. The separate SBOM service account has
upload and portfolio-read permissions, without administrator permissions.

Native release artifacts are an explicit source-build exception. The deployment
pins their SHA-256 digests and source release, and keeps executables root-owned.
No custom backend or vulnerability database implementation is maintained here.

## Deploy

Run the playbooks with the pinned Ansible version from `ansible/`:

```sh
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/dependency-track-resources.yml
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/dependency-track.yml
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/dependency-track-portfolio.yml
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/dependency-track-routing.yml
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/dependency-track-tunnel.yml
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/sbom-upload.yml -e sbom_upload_run_now=true
```

The resources playbook saves a full-root OpenTofu plan and refuses changes
outside the existing guest's reviewed CPU and memory settings. It does not
create, replace, or remove a guest or disk.

The separate SSH tunnel exposes the authenticated API only on VPS loopback port
8791. It lets the VPS upload inventories without exposing the dashboard publicly.
All LAN collectors use verified HTTPS. The upload key is kept root-only on each
collector; rerun the fleet play after renewing that key in the server role.

`homelab-sbom.timer` collects OS packages, declared native executables and library
roots, and running container images daily. The hourly freshness check fails when
the last complete upload is missing, failed, or more than 36 hours old. Check it
with `systemctl status homelab-sbom-freshness.service` on the relevant host.
The last attempt, failed scope names, and per-scope evidence modes are in
`/var/lib/homelab-sbom/status.json`. For source-associated inventories, freshness
also verifies the pinned lockfile and current binary or image identity. Collection
freshness does not establish that source candidates are compiled dependencies.
Failed or empty scans do not replace the previous Dependency-Track inventories.

Trivy performs matching through the existing authenticated central server.
Dependency-Track's duplicate NVD, OSV, GitHub and JVN mirrors and internal analyzer
are disabled; both OS and library matching are enabled in its native Trivy
integration, including findings that have no fix yet. The scheduler remains on
for reanalysis, portfolio metrics, and notification digests.

Before retiring the legacy pipeline, verify that actual host, library, and image
inventories have been processed by Dependency-Track. HTTP health alone does not
prove collection or matching works. Follow the separate
[retirement procedure](retire-custom-cve.md) after those checks.

## Verified coverage on 2026-10-15

All 18 managed hosts have the daily collector installed. Seventeen completed every
declared scope and passed freshness checks. The portfolio accepted 71 nonempty
inventories. Successful imports and native vulnerability-analysis completion
were checked independently; finding counts represent component occurrences,
not unique CVEs or proven exploitable vulnerabilities.

The missing Beszel agents on `n8n` and `firecrawl` were enrolled with separate
per-system credentials after approval. Both connected using outbound WebSockets.
Their refreshed collectors completed all 3 and 8 scopes respectively; native
analysis completed after every new import, including both Beszel inventories.

Only `pangolin` retains partial coverage. It imported 11 scopes, but the Tuwunel
executable and MatrixRTC JWT image expose no supported Rust dependency metadata.
Neither has a verified publisher SBOM configured. Empty results do not replace
inventories or count as complete scans.

Dependency-Track's own Java scope uses its checksum-pinned official release BOM,
containing 237 components. Every upload verifies the installed JAR set against
the pinned distribution before accepting that BOM. See the
[collector notes](../../ansible/roles/sbom_upload/README.md) for verification.

The custom pipeline was stopped across all 18 hosts. Independent checks found
109 installed legacy units with no running processes and none enabled. Personal
Hermes kept the same running process, and the standard monitoring services
remained healthy. Nineteen retired units retain historical systemd failure
records; those units have no active process.

The [daily Matrix summary](dependency-track-matrix.md) is active after approval.
Native read-back confirmed its enabled 08:00 UTC schedule and published n8n
workflow. The brief n8n restart completed while no executions were active.

## Rust source associations

As of 2026-10-17, the collector supports separate source-candidate projects for
Tuwunel 1.9.0 and MatrixRTC JWT 0.7.0. Their binaries do not expose a usable Rust
dependency inventory, and the JWT publisher's SPDX attestation contains only the
application package with no package URLs. This compiled-dependency coverage gap
remains. The new inventories make conservative source dependency matching
possible without rebuilding or restarting either service.

| Release | Source evidence | Candidate packages | Cargo package URLs |
| --- | --- | ---: | ---: |
| Tuwunel 1.9.0 | Reviewed official release asset and immutable release-tag revision | 600 | 567 |
| MatrixRTC JWT 0.7.0 | Publisher OCI BuildKit SLSA statement associates the pinned image with its source revision | 351 | 347 |

Tuwunel's [v1.9.0 release](https://github.com/matrix-construct/tuwunel/releases/tag/v1.9.0)
tag resolves to commit `5b3669144219d5d4c0774743c84191b476f1b54f`.
The installed binary matches the binary inside the pinned official Debian asset.
This is a reviewed release-source association, not a build attestation. Its
[immutable Cargo.lock](https://raw.githubusercontent.com/matrix-construct/tuwunel/5b3669144219d5d4c0774743c84191b476f1b54f/Cargo.lock)
has SHA-256 `71992452faf3d964ba26779ab68adbef0803593d7f406112a70610779089f69e`.
The 33 entries without package URLs are 25 Git dependencies and 8 workspace crates.

JWT's pinned OCI index includes the amd64 manifest and a publisher BuildKit SLSA
statement naming commit `6c761252522bdc0d3d9db176e933096d19a1ccbe`.
The [Dockerfile at that revision](https://github.com/element-hq/lk-jwt-service/blob/6c761252522bdc0d3d9db176e933096d19a1ccbe/Dockerfile)
builds the application with `cargo build --locked`. Its
[immutable Cargo.lock](https://raw.githubusercontent.com/element-hq/lk-jwt-service/6c761252522bdc0d3d9db176e933096d19a1ccbe/Cargo.lock)
has SHA-256 `a653e4bb75b62f7e74dffdca6966ab264a05e0f0a358fdfd0bcad139c739d3e3`.
That lock still declares application version 0.6.0 despite release 0.7.0 and
contains 4 workspace crates without package URLs. These recorded source versions
are preserved. The OCI statement is publisher provenance; it is not independent
proof of reproducibility or compiled membership.

The exact binary digest, image content ID, source revisions, official asset
digest, OCI manifest and statement digests are recorded in
[`inventory/security-runtime.yml`](../../inventory/security-runtime.yml).
Both inventories use separate `/source-lock-candidates` project names, mark
compiled membership unverified in CycloneDX properties, and declare composition
completeness unknown. Registry package checksums describe the crate archives,
not bytes found in the executable. Git forks are not mislabeled as crates.io
packages. Source candidates include development, optional and other-platform
packages; native libraries and the Rust toolchain remain outside their scope.
Finding counts therefore do not establish installed or exploitable vulnerabilities.

An upgrade must review the source-to-release evidence, pin a new immutable lock
URL and checksum, and update the binary digest or running image content ID.
Do not update only the artifact digest to silence freshness failure. Missing or
changed artifacts and locks fail collection and the hourly check. Keep the
source candidate projects distinct from any future publisher or artifact SBOM.

On 2026-10-17, all 18 collectors completed 78 declared inventories with no failed
scopes and passed freshness checks against the deployed configuration. Of these,
76 are artifact inventories and two are explicitly labeled Rust source-candidate
inventories. Native readback confirmed 600 Tuwunel candidates and 351 JWT
candidates, with provenance and coverage limits retained on every component;
their compiled membership remains unverified. Personal Hermes now has 113
installed Python distributions inventoried under `library/diagnostic-agent`.
Its earlier duplicate project is inactive with history retained. Native analysis
produced metrics for these inventories; candidate findings do not prove vulnerable
code is present in the deployed Rust executables.

## Recovery

The weekly `managed-weekly` Proxmox job includes LXC 214. Its 64 GiB mount at
`/var/lib/homelab-incidents` has `backup=1`, covering the new PostgreSQL and
application data together with retained legacy state. Root-disk configuration
and credential files are included in the guest archive. These are local backups;
the owner declined an additional off-site copy.

Before the cutover, snapshots named `pre-cve-retirement-20261015` were created
for LXCs 201, 212, and 214. Restoring an entire guest snapshot also restores its
other services and data to that point; review the affected guest before rollback.
Do not delete the old databases, encrypted archives, or guest disks as part of
service retirement.

Use Dependency-Track's component and finding views for review. A successful
inventory upload proves only the packages present in that inventory. It does not
establish exploitability, discover every unsupported binary dependency, or
authorize automatic production changes.

Upstream references: [native installation](https://dependencytrack.github.io/docs/next/),
[analyzers](https://dependencytrack.github.io/docs/next/reference/analyzers/), and
[notification configuration](https://dependencytrack.github.io/docs/next/guides/user/configuring-notifications/).
