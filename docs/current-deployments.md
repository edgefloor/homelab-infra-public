# Current deployments

The general inventory was checked on 2026-09-20. Vulnerability management,
backup membership, and the affected security boundaries were checked again on
2026-10-17. Service health, monitoring, backup execution, storage and the fixes
recorded below were checked on 2026-10-20.
Refresh the affected system before changing it. Exact desired versions and
image digests live in the Ansible defaults and application manifests.
LXC 217 guest creation and backup membership were checked separately on
2026-10-13. CUDA inference and idle release passed. The n8n embedding bridge
has not been activated.

The owner set the current audit scope on 2026-10-20: containers with IDs 200 and
above, the Proxmox host, the VPS, and their shared storage, backup, DNS, routing
and identity infrastructure. Lower-ID guests remain in the topology for context
but are outside audit and remediation work. Intentional backup exclusions remain.

## Proxmox

`node1` runs Proxmox VE 9.2.18 on kernel 7.0.14-16-pve as checked on October 20.
All 16 managed LXCs were running on October 20. The storage readings below
were refreshed after the October 20 retired-data and n8n cleanup; backup and media datasets share
the same ZFS pool and therefore show the same remaining pool space.
The private news embedding helper was added as unprivileged LXC 217 on 13 October.
Omarchy VM 300 and its 64 GiB guest disk and EFI disk were removed through
OpenTofu on 2026-10-12 at the owner's request. No QEMU VMs remain on `node1`.
The checksum-pinned Omarchy 4.0.4 ISO remains in the Proxmox library.

| Storage | Used | Available | Notes |
| --- | ---: | ---: | --- |
| `data` | 75.72% | 2.18 TiB | ZFS application and media storage |
| `data-backup` | 5.12% | 2.18 TiB | Guest backups and verified retired-data cold archives |
| `local` | 29.83% | 61.10 GiB | Host filesystem storage |
| `local-lvm` | 67.06% | ~114.90 GiB | Managed LXC root disks; automatic extension policy below |

The weekly `managed-weekly` job runs at 03:00 on Sunday and keeps the last two
snapshots for LXCs 200 through 207 and 210 through 217. Large bind mounts
remain outside those archives where their mount declares `backup=0`. Guests below
200 are intentionally excluded from backups.

The October 20 check initially found `local-lvm` 75.98% used. Retired-data
cleanup and guest root filesystem trim first reduced it to about 72.7%.
After the n8n candidate and build-cache cleanup, trimming LXC 216 reported
26.9 GiB discarded. The 01:43 UTC host check measured thinpool data usage
falling from 72.80% to 67.06% and metadata from 2.98% to 2.81%. The attached
`homelab-thinpool` metadata profile extends the pool by 3% at 80% usage. With
16 GiB of VG free space, one extension uses about 10.46 GiB and leaves 5.54 GiB.
The deployment checks a 5 GiB reserve; it does not allocate new capacity.

Tuwunel state leaves the VPS through a forced SSH export every Sunday at 00:30
UTC. LXC 200 encrypts the stream with `age`, keeps four copies, and is itself
part of the later Proxmox backup job. All 16 managed guests have successful
October 18 archives. That Sunday's encrypted Tuwunel export passed decryption and
compression integrity checks on October 20 after the receiver-space repair. The exporter restores only services that were active before backup;
it cannot restart the retired CVE timer. Receiver preflight and bounded retries
protect the next scheduled run.

Beszel checks `/dev/sda` and `/dev/nvme0n1` SMART data every hour. It also reads
the Quadro P2200 through `nvidia-smi`. The Proxmox boot order creates the NVIDIA
device nodes before Beszel and the Jellyfin guest start. The October 20 native
test in a private `/dev` mount proved that core device creation needs minors
`0` and `255`, while UVM requires a separate `-u -c 0` call. The boot unit checks
all four character devices before completing.

The Proxmox firewall is disabled and the inspected guest nftables policies
accept LAN traffic. Access reviews should check the actual listeners,
authentication and routing on the scoped systems; private addressing alone
does not establish access control.

## Home guests

| ID | Name | Address | Current job |
| ---: | --- | --- | --- |
| 112 | NextPlaid | `10.42.0.7` from DHCP | Rust API and index storage. Outside the OpenTofu root. |
| 115 | EU Law | `10.42.0.115` | PostgreSQL 17 with a 200 GiB ZFS-backed data mount. Outside the OpenTofu root. |
| 200 | Plan runner | `10.42.0.200` | Root-only OpenTofu state and encrypted VPS Matrix backups. Actions runner disabled. |
| 201 | Hermes Agent | `10.42.0.201` | Personal Hermes runtime and native Matrix/Honcho profile; evidence access retired. |
| 202 | Caddy | `10.42.0.202` | Caddy 2.11.4, CrowdSec 1.8.1, and nftables bouncer 0.0.36. Home HTTP and HTTPS edge. |
| 203 | Jellyfin | `10.42.0.203` | Jellyfin 12.0.0 with Quadro P2200 hardware transcoding and `/data` mounted at `/storage`. |
| 204 | Media automation | `10.42.0.204` | Seerr OIDC preview, Radarr 6.3.0.10514, Sonarr 4.0.19.2979, Prowlarr 2.5.2.5491, and Shelfmark 1.3.15. |
| 205 | Downloads | `10.42.0.205` | Transmission 4.1.3 and File Browser 2.63.23 with `/data` mounted at `/storage`. |
| 206 | Miniflux | `10.42.0.206` | Miniflux 2.3.3, PostgreSQL 17.11, the MCP server, and the outbound OpenAI tunnel client. |
| 207 | Pocket ID | `10.42.0.207` | Pocket ID 2.14.0. OIDC provider for applications and Pangolin. |
| 210 | Pangolin connector | `10.42.0.210` | Newt 1.16.0. Outbound connector for the Home site. |
| 211 | Network operations | `10.42.0.211` | CoreDNS 1.14.7 and the Cloudflare DNS reconciliation timer. |
| 212 | Retained HelixDB guest | `10.42.0.212` | Custom CVE graph stopped and disabled. Database and guest retained for recovery. |
| 213 | NeroCD | `10.42.0.213` | NeroCD 0.3.23 with PostgreSQL and a local Caddy sidecar. Internal-only. |
| 214 | Dependency-Track | `10.42.0.214` | Native Dependency-Track 5.2.0 and PostgreSQL 17; 4 cores, 8 GiB RAM, retained 64 GiB data volume. Legacy SQLite history remains on disk. |
| 215 | Firecrawl and SearXNG | `10.42.0.215` | Fresh Firecrawl 2.11.373 and SearXNG 2026.9.20-2e624bed4 stack. No legacy state imported. |
| 216 | n8n | `10.42.0.216` | n8n 2.43.8 workflow automation, native systemd service. |
| 217 | News embeddings | `10.42.0.217` | Private native EmbeddingGemma helper sharing the P2200. CUDA inference and idle release verified. |

OpenTofu owns LXCs 200 through 207 and 210 through 217. NextPlaid and EU Law
are deliberate external workloads, not half-managed OpenTofu resources.

The Mac at `10.42.0.51` runs Caddy 2.11.4 as the
`fun.example.exposure-proxy` LaunchAgent. It listens on LAN TCP 8090 for the
persistent Newt connector and proxies exact on-demand hostnames to loopback
applications. Its mode-0600 Pangolin Integration API key is provisioned. A
temporary exposure verified the authenticated public path on 2026-09-16, then
the test resource and local route were removed. Traefik serves a DNS-01-issued
wildcard certificate for unused one-label subdomains, redirects their HTTP
requests to HTTPS, and routes otherwise unmatched hosts to the isolated Bun
Rickroll fallback on the VPS. The fallback returns the supplied HTML with HTTP
404 for every path. It runs as a non-root, read-only container with no host
ports or mounts and a firewall-blocked egress network.

NeroCD currently uses Docker inside LXC 213. Native Ansible source deployment is
the desired direction. The pinned source can build a standalone Go executable
with its web assets, but its production configuration requires
`NEROCD_IMAGE_REF=repository@sha256:...` in both database startup and `doctor`.
This is an artifact-validation assumption, not evidence that the server needs
a Docker daemon. The upstream production guide and acceptance workflow use
Compose. Source: [`production_config.go` at the pinned revision](https://github.com/edgefloor/NeroCD/blob/8224d9e99980e5370c730c1a0d29f2115d9b42d1/cmd/nerocd/production_config.go).

A native migration must represent the actual source-built artifact rather than
claiming the old image digest or switching to development mode. Build the pinned
Go and web sources, preserve distinct owner/application database credentials,
run PostgreSQL 17 natively, and retain the application's backup scheduler.
Rehearse an application-aware backup and restore into an isolated empty database
before cutover. Keep the old volumes and deployment files for rollback. Replacing
the sidecar requires a tested host ingress rule allowing the main proxy while
rejecting other LAN clients; the current guest firewall alone does not do that.
This migration has not been performed.

## VPS

The Example Hosting VPS at `198.51.100.24` runs Debian 13. Its 40 GiB root
filesystem was 28.85% used on October 20. No failed systemd units or unhealthy
containers were present. The service versions below were checked on that date.

| Service | Version | Runtime |
| --- | --- | --- |
| Pangolin Enterprise | 1.22.2 | Docker Compose |
| Gerbil | 1.5.1 | Docker Compose |
| Traefik | 3.7.13 | Docker Compose |
| CrowdSec | 1.8.1 | Docker Compose |
| Beszel Hub | 0.19.0 | Docker Compose |
| Tuwunel | 1.9.0 | Native systemd service |
| LiveKit | 1.13.6 | Docker Compose |
| MatrixRTC JWT service | 0.7.0 | Docker Compose |
| Matrix notification bridge | Repository version | Native systemd service |

Traefik terminates Matrix client, federation, and MatrixRTC signaling routes.
LiveKit exposes TCP 7881 and 5349, UDP 3478 and 7882, plus UDP 50300 through
50400. Its private HTTP services bind only on the Compose gateway.

On 2026-09-16, the Alagut management endpoint was verified through the connected
Mac at `https://alagut-api.homelab.example/v1`. Public DNS inherits the VPS
wildcard. Pangolin's native private-resource placeholder is disabled, so public
HTTPS requests receive the supplied Rickroll HTML with HTTP 404 for API,
documentation, and frontend asset paths. Public HTTP redirects to HTTPS.
Private HTTPS, API-key enforcement, and Swagger access passed. The DNS
reconciliation timer retains wildcard inheritance.

The old incident reverse forward is disabled. A separate restricted SSH tunnel
binds the Dependency-Track API only to VPS loopback port 8791 for authenticated
SBOM uploads. The dashboard has no public Pangolin resource.

## n8n

Upgraded and verified on 2026-10-20.

The free registration key was activated on 2026-10-12. The instance reports
Registered Community, with debug-in-editor and advanced execution filters
enabled. Native OIDC, SAML, and LDAP entitlements remain disabled. The license
certificate is stored in n8n's database and included in its existing backup;
the activation key is not stored in the repository or service environment.

Protected LXC 216 at `10.42.0.216` runs n8n 2.43.8 as a native systemd
service with checksum-pinned Node.js 24.21.0. The official npm release includes
the compiled editor; this deployment uses that package instead of a source
build. Its manifest and dependency integrity lock are versioned in the role.
The release directory includes the lock hash, builds run as `n8n-build`, and
completed releases are root-owned and immutable to the service and build users.
Prepare a release with `-e n8n_activate_release=false` before activation.
Upstream marks native installations and internal task runners as
deprecated, so revisit the runtime before upgrading to a release that removes
them. JavaScript execution uses the internal runner; Python Code nodes need an
external runner and are not configured by this deployment.

`https://n8n.homelab.example` follows Pangolin, Newt, and Caddy remotely. The
Infrastructure role and Pocket ID protect every path. LAN DNS resolves the
same name to Caddy. For remote browser access, Caddy maps Pangolin's
`Remote-User` Pocket ID subject to the existing n8n owner ID through
`auth_proxy_user_mappings` in `inventory/routes.yml`. It sets `X-N8n-User` only
for Newt-originated requests and strips that header from other clients.
Unmapped gateway identities receive 403, even with an existing n8n cookie.

The managed `pangolin-auth.js` external hook accepts that header only from
Caddy's socket address and only for explicitly mapped account IDs. It uses
n8n's own cookie issuer and normal authentication middleware. It never creates
users, links by email, edits roles, or marks local MFA as satisfied. The owner
account and its workflows remain the same. LAN access retains the native
password/MFA recovery login because it bypasses Pangolin. Signing out of n8n
alone does not end the Pangolin session; opening n8n again signs the mapped
user back in. End the gateway session to stop remote automatic sign-in.

This is a locally maintained hook, tested against exactly 2.42.6, 2.43.7 and 2.43.8.
It uses native cookie authentication and does not provide licensed OIDC. The
hook refuses unreviewed versions or a mismatch with the configured version.
The October 20 checks exercised 14 cases using the installed release's native
authentication classes, including token purpose and audience, MFA, browser
binding, revocation and trusted headers. Run
`node --test scripts/test_n8n_pangolin_auth.cjs` before deployment. Live tests
verified the native owner session through the Newt-to-Caddy hop, session reuse,
unmapped identity denial, and rejected spoofing through LAN and direct backend
requests. Webhooks and API keys keep native handling; the gateway continues to
protect every public path until an operator adds a deliberate path policy.

The npm install retains 111 reviewed upstream dependency overrides and six
additional pins. The October 17 fixes were Handlebars 4.7.10, qs 6.16.0, Hono
4.13.7 and ip-address 10.7.1. The October 20 update adds Nodemailer 10.1.7 and
Snowflake SDK 3.4.0, which brings TOML 5.0.1. Eleven checks against the installed
consumers passed, including native email composition and policy, MIME parsing,
Snowflake configuration loading, and native node/module loading. Snowflake 3.4.0
changes its OCSP default; no current workflow or credential uses Snowflake.
The provenance file distinguishes these checks from inherited earlier evidence
and records omitted upstream pnpm rules and patches.

The direct npm advisory count fell from 29 to 19, with ten removed and none
added. The remaining matches are 2 critical, 3 high, 12 moderate and 2 low.
Both critical matches and two high matches are in the installed simple-git
packages. The Git node and the source-control and promotions modules remain
disabled; native loader tests confirm their exclusion. The existing Execute
Command and Local File Trigger exclusions remain. The active workflow's
Webhook, If and Matrix nodes still load. This contains the known Git entry
points without claiming that the packages are patched or arbitrary custom-code
imports are blocked. The remaining high-severity braces advisory has no patched
release. The actual file-selector helper rejected a deeply nested pattern in a
bounded worker without blocking the main process.

The October 20 native Dependency-Track analysis completed after the new inventory
arrived and reduced its count from 53 to 43 findings: 18 npm findings and 25 Go
findings in TypeScript's bundled compiler. The pre-upgrade count included 28 npm
findings. The direct npm feed has one additional moderate sprintf-js advisory,
which accounts for its current count of 19. The compiler is not the n8n HTTP
server and is not used by the active workflow; its findings remain visible.
See `dependency-audit.json` and `dependency-provenance.json` in the selected
n8n role version for individual advisories, compatibility evidence and limits.

The October 17 isolated restore passed SQLite integrity, HTTP readiness and
decryption of both credentials. All 14 schema migrations (277 to 291) completed.
A second run used a fresh temporary UID with no supplementary groups or
capabilities. Before executing candidate code, nine checks proved isolation
from production state, configuration, process signaling and the retained
backup, with only loopback networking. It preserved the live service and
database, and removed its temporary account, group, processes and data.
The October 20 patch rehearsal preserved all 291 migrations, the owner, one
workflow and both credentials, including successful decryption. Nine isolation
checks again passed with a temporary UID, no extra groups or capabilities, and
loopback-only networking. The prepared immutable release also passed all 14
native authentication checks and 11 dependency checks at its final path.

The live patch upgrade used a fresh cold backup of the complete state,
encryption configuration, environment, hook, account binding and service unit
at `/var/backups/n8n/cutover-20261020T013459Z-86f403d1`. The old immutable 2.43.7
release remains available locally. Its role artifacts remain in Git history;
the current tree contains the selected release only. Rollback must restore the
old database, encryption configuration and service configuration together with
that release. Changing only the symlink is unsafe.

The live service preserved the owner, one active workflow, both encrypted
credentials, all 291 migrations and the corresponding content hashes. The
encryption key and proxy binding stayed unchanged apart from the reviewed
version field. Native readiness returned 200 directly and through Caddy. The
service was ready about 21 seconds after stopping the old process. Validation
did not execute the workflow or send a synthetic notification.

Removing the disposable candidate and npm build cache reclaimed 3.47 GiB while
preserving the active release, previous release and cold backup. LXC 216 then
had 27,028,185,088 bytes available, about 25.17 GiB. After its filesystem trim,
the 01:43:37 UTC check confirmed the same live PID 5395 and HTTP 200 readiness
directly and through Caddy.

`/var/lib/n8n/.n8n` contains the SQLite database, generated encryption key,
settings, and workflow state. LXC 216 belongs to the weekly managed backup job.
Keep the whole directory together when restoring. Before an upgrade, take a
fresh guest backup and preserve the current release and dependency lock.

Deploy a fresh guest, the application, then routing with
`n8n-provision.yml`, `n8n.yml`, and `n8n-routing.yml` from `ansible/`.
On a fresh database, complete owner setup using the LAN recovery login and bind
its new user ID to the intended Pocket ID subject in `inventory/routes.yml`.
Apply both `n8n.yml` and the Caddy portion of `n8n-routing.yml` after changing a
binding. A pre-change SQLite backup is retained under `/var/backups/n8n` on the
guest for the 2026-10-12 session integration.

## Routing and identity

Caddy routes come from `inventory/routes.yml`. CoreDNS returns its address for local
names that set `internal_dns`. Public gateway records point to the VPS. Pocket
ID and Jellyfin point home. Matrix and MatrixRTC point to the VPS without using
Pangolin authentication.

Firecrawl and SearXNG use LAN-only HTTPS at
`firecrawl.homelab.example` and `searxng.homelab.example`. CoreDNS resolves both
names to Caddy. Neither name has a public route or Pangolin resource.

Pangolin roles control remote reachability. Pocket ID handles normal sign-in.
Pangolin keeps one local TOTP administrator for recovery. Applications either
use their own OIDC session, accept a narrowly trusted proxy identity, or retain
their own login. [`access-design.md`](access-design.md) has the exact behavior
for each service.

## Monitoring, security, and alerts

Beszel Hub stays on the VPS so a home outage does not take the dashboard with
it. Outbound agents cover all 18 managed hosts, including LXC 200, 201, 214,
and 217. Each new agent has its own enrollment token.
The agent connection endpoint bypasses the browser access page but still uses
Beszel's agent key. Native alerts cover host status, failed systemd units and
85% disk usage for every managed system. The hourly SBOM freshness service
leaves a failed unit when collection is stale, so it participates in the
failed-service alert. Hourly backup-age and thin-pool health checks use the same
failed-unit mechanism, including space for the next extension plus the reserve.
Existing Matrix notification settings are preserved.
On October 20, all 18 systems were connected, with no failed systemd units or
unhealthy containers. All 54 Beszel rules were present and untriggered. The
notification configuration was verified without sending a synthetic message.

CrowdSec runs independently on Caddy and the VPS. Each local bouncer can keep
blocking traffic if the other site is unavailable. Both engines send filtered
decisions through the Matrix bridge. The bridge adds a country flag from a
checksum-verified local IP database and leaves the original IP untouched when
lookup fails.

The update monitor checks upstream releases every 30 minutes on the VPS.
Dependency-Track 5.2.0 at `https://vulns.homelab.example` now owns vulnerability
inventory and analysis. It is available on the private LAN through Caddy with
verified TLS and native authentication. The backend accepts frontend traffic
only from Caddy; the Java API and PostgreSQL bind to loopback.

Daily collectors on all 18 managed hosts upload standard CycloneDX inventories
for OS packages, declared native binaries and installed libraries, and running
container images. The existing authenticated Trivy server performs native
Dependency-Track analysis. Duplicate full advisory mirrors are disabled. Native
workflow completion and actual findings were verified, beyond upload acceptance.
The two external guests remain outside the rollout. See the
[operating procedure](procedures/dependency-track.md) for current coverage limits.

The daily high and critical Matrix summary is active in n8n and Dependency-Track
after approval and independent read-back. It targets the existing CVE room, runs at
08:00 UTC, and skips unchanged results. No test message was sent. Existing
CrowdSec, Beszel, and release notifications retain their independent channels.

The custom scan timers, incident API, Helix graph, Zig gateway and workers,
model proxy, and custom archive timers are stopped and disabled. The old Helix
hostname resolves to the existing 404 fallback. Deployment guards require an
explicit legacy opt-in before any old pipeline can be reactivated. The original
databases, credentials, profile histories and guest disks remain in place.
On October 20, the retired investigation work from LXC 201 and all seven
completed incident archives from LXC 200 moved to verified root-only cold
archives at `/data/backups/retired-cve/2026-10-20` on Proxmox. Removing the verified
originals reclaimed 19.61 GiB across those guests. Hermes root usage fell from
78.59% to 39.00%, and the plan runner from 70.02% to 32.85%. Personal Hermes kept
its running process. See the [retirement procedure](procedures/retire-custom-cve.md)
for archive recovery. Recovery snapshots were taken for LXCs 201,
212, and 214, and the weekly guest backup includes the Dependency-Track data mount.

Personal `hermes-gateway.service` remains active with its existing OpenAI Codex
connection, Honcho memory, and Matrix device. On October 17, the evidence gateway,
forced commands, endpoint SSH keys and sudo policies were retired across all
18 managed hosts. Former endpoint accounts are locked with `nologin` shells.
Hermes no longer has the on-call skill, agentctl, target map, or observation key.
These files are retained in root-only recovery archives; personal Hermes was
not restarted. Legacy deployment entrypoints require explicit opt-in.

Repository checks run on GitHub-hosted runners for every pull request and main
push. LXC 200's Actions runner is disabled. Production provider credentials,
OpenTofu state and its wrapper are root-only, and operator provisioning continues
through the owning Ansible playbooks. The Actions apply workflow refuses
deployment until a separate production boundary is implemented.

Hermes' installed Python environment now contributes its own library inventory.
All newly enrolled Beszel binaries are included in native Go dependency scans.

The Jellyfin edge rejects canonical and trailing-slash password-login paths,
including case and encoded variants. Backup membership reconciliation preserves
all declared guests through 217 and existing extra members. Provisioning now
stages the complete OpenTofu root, including retained ISO resources.

The October 17 Beszel restore rehearsal loaded a fresh backup into an isolated
container using the installed image. SQLite integrity, all 18 system records
and HTTP health passed. The test had no external network or published ports and
left the production container unchanged. File Browser also has a completed
failed-executable rollback and database-preservation exercise. The n8n rehearsal
also passed credential decryption and the 2.43.7 schema migration. Other
application restores and shared-storage recovery still need verification.

On October 20, Pocket ID recovered from its October 18 guest backup with all
seven users, seven OIDC clients, seven passkeys and its signing keys intact.
Native readiness returned 204 and OIDC discovery returned 200. Its managed
health check now uses `/healthz`; `/health` had returned the HTML application
page and could falsely pass readiness. Interactive passkey login and external
OIDC callbacks were outside that isolated restore test.

The October 18 Dependency-Track PostgreSQL backup also completed crash recovery
in isolation. All 111 public tables were readable, including 80 projects and
19,586 components, and a complete logical export passed validation. Its Java
application was not started during the database test. Both restore probes used
temporary identities with no access to production state or external networks,
left the running services unchanged and removed their disposable runtimes.

## Focused operational verification on October 21

This pass tested three guarantees against native runtime state. It did not
refresh the entire fleet inventory or extend the scope below container 200.

- Both edges enforced and removed IPv4 and IPv6 CrowdSec bans against
  disposable clients. HTTPS and SSH changed from reachable to blocked and back.
  The VPS Traefik bouncer independently returned 403 while a decision was active,
  including with forged forwarding headers. Native parsers recovered the actual
  client IP from real access logs. The [edge decision record](adr/0005-enforce-crowdsec-decisions-at-both-edges.md)
  contains the reproduction commands and network limits.
- n8n rejected unauthenticated and forged-identity requests through the public
  VPS, the LAN Caddy route and the direct backend. The trusted Newt connector
  established a native session and received an authenticated workflow response.
  A direct Internet request to the protected home route returned 403, while the
  public Jellyfin health route returned 200. No workflow was executed.
- The retained October 20 cold n8n backup recovered one owner, one workflow and
  both credentials using the installed 2.43.8 release in isolation. A wrong key
  failed native decryption; restoring the backed-up key recovered both
  credentials again. Readiness returned 200, unauthenticated workflow access
  returned 401, and account, workflow and credential content hashes matched the
  retained source. Disposable workflows were unpublished before startup.
  Production state and the retained backup were unchanged.
- Each installed firewall bouncer reconstructed both address families from an
  empty ruleset, retained bans through six failed fixture-API polls and recovered
  after a simulated ruleset loss and restart. These were private network
  namespace tests, not production restarts or full host boot tests.

The fixed public-IP trust exception remains pending owner identification. It
appears in both native parser configurations and the live Traefik middleware.
It is neither the observed home WAN address nor the VPS address. No current ban
exists for it. Its presence is an explicit limit on the enforcement conclusion,
not a demonstrated failure of the bouncers. Existing private-network and dynamic
home-address trust policies were retained.

## Known work

The current work list is in [`../PLAN.md`](../PLAN.md). Priorities are service
availability, storage capacity, working backups and recovery, and actionable
vulnerabilities on containers 200 and above, the host, the VPS and their shared
infrastructure. The retired evidence gateway and CVE agents remain retired.
