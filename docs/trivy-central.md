# Shared Trivy database

The scheduled vulnerability monitors use Trivy 0.74.0 in client/server mode.
Hosts inspect installed packages and local images. Pangolin matches that package
inventory against one vulnerability database in `/var/cache/homelab-trivy/db`.
This does not send scan data to an LLM, create agent sessions, or write Honcho memory.
Incident correlation and delivery remain separate from matching.

## Authentication and failure behavior

Clients use `https://matrix.homelab.example/_trivy` with verified TLS and a dedicated
scanner token. The token resides in root-only configuration files, not command
arguments or repository variables. Trivy requires the nested `server.addr` and
`server.token` configuration keys. Both direct and proxied unauthenticated RPC
requests must return HTTP 401 before client migration.

The backend listens on Pangolin's Docker bridge address, `172.30.0.1:4954`.
The firewall permits that port from Docker bridges only. Traefik limits concurrent
requests to sixteen and request bodies to 32 MiB. Scanner credentials confer matching
and scan-cache access, not incident admission, Matrix posting, or memory access.
The fleet currently shares one dedicated scanner token. Individual source
credentials still authenticate incident snapshot ingestion.

`homelab-cve-monitor` validates its central configuration and always passes
`--skip-db-update`. It removes inherited `TRIVY_*` overrides from scanner
subprocesses. Missing credentials or an unreachable matcher fail the scan.
The monitor retains previous findings and reports unknown coverage through the
existing health mechanism. It never retries in standalone mode.
Temporary proxy overload responses receive at most three remote attempts within
the original scan deadline. Authentication failures are not retried.

## Storage and availability

The matcher updates its database in the background. Its package-analysis cache
uses memory, not an indefinitely growing disk cache. The process has a one-GiB
memory limit, a 150-percent CPU limit, and a daily restart to expire that cache.
The daily restart briefly interrupts matching. A failed scan remains unknown and
the next scheduled scan can recover. The matcher is a single availability
dependency, not a highly available cluster.

The off-host incident health timer also checks the matcher version and database
timestamps. It rejects a database older than 72 hours or more than 24 hours past
its advertised next update. Health notifications are deliver-only.

Trivy's separate Java index database is still client-side in this version.
This migration centralizes the vulnerability database. It does not disable Java
analysis or claim that future Java workloads need no local index.
Ad-hoc bare `trivy` commands outside the monitor also remain standalone unless
they use the managed client configuration. Do not download another database for
an investigation. Use the managed scanner or an explicitly configured client.

## Deployment and validation

From `ansible`, run
`uvx --from ansible-core==2.19.4 ansible-playbook playbooks/trivy-central.yml`.
The playbook deploys the matcher, checks authentication, migrates clients in small
batches, and scans OS packages and local images with a separate empty cache.
Only after a successful scan and an absent local database does it run
`trivy clean --vuln-db` against the old monitor cache. The deleted database is
re-downloadable. Reports, findings, source trees, and agent history are untouched.
The playbook never targets containers below 200.

Deploy this playbook before enrolling a new host through `update_monitor`.
The role requires the central credential and installs client configuration as
part of normal enrollment. The matcher currently requires the pinned Trivy binary
already installed on Pangolin.

The scanner's regression tests cover mandatory central configuration, invalid
credentials, environment overrides, and failure without local fallback.
The migration scans do not emit CVE notifications or invoke investigators.

On 2026-09-08, all thirteen enrolled hosts passed database-free OS and local-image
scans. Their obsolete copies occupied 16.6 GiB in total. The shared cache occupied
1.3 GiB, for approximately 15.3 GiB net reclaimed. Hermes had 6.7 GiB free afterward
on its unchanged 32-GiB root disk. Hermes's missing declared Beszel installation
remains a separate full-coverage failure.
After correcting the proxy concurrency limit, all twelve other hosts also passed
the full declared-artifact audit, including native Go binaries and installed
library roots. The local suite passed 242 tests. The central-only and overload
retry regression tests failed before their fixes and passed afterward.

Sources: [Trivy client/server mode](https://trivy.dev/docs/v0.72/guide/references/modes/client-server/)
and [the pinned configuration keys](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/flag/remote_flags.go).
