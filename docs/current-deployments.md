# Current deployments

Checked against Proxmox, the VPS, and the service processes on 2026-09-05.
Refresh the affected system before changing it. Exact desired versions and
image digests live in the Ansible defaults and application manifests.

## Proxmox

`node1` runs Proxmox VE 9.2.11 on kernel 7.0.14-14-pve with ZFS 2.4.4. It has
13 running unprivileged LXCs, no VMs, and no stopped guests.

| Storage | Used | Available | Notes |
| --- | ---: | ---: | --- |
| `data` | 64.10% | 3.30 TiB | ZFS application and media storage |
| `data-backup` | 0.76% | 3.30 TiB | Proxmox backup archives |
| `local` | 21.80% | 68.64 GiB | Host filesystem storage |
| `local-lvm` | 33.18% | 233.08 GiB | LXC root disks; thin-pool autoextend still needs a useful threshold |

The weekly `managed-weekly` job runs at 03:00 on Sunday and keeps the last two
snapshots for LXCs 200, 202 through 207, 210, 211, and 213. Large bind mounts
remain outside those archives where their mount declares `backup=0`.

Tuwunel state leaves the VPS through a forced SSH export every Sunday at 00:30
UTC. LXC 200 encrypts the stream with `age`, keeps four copies, and is itself
part of the later Proxmox backup job.

Beszel checks `/dev/sda` and `/dev/nvme0n1` SMART data every hour. It also reads
the Quadro P2200 through `nvidia-smi`. The Proxmox boot order creates the NVIDIA
device nodes before Beszel and the Jellyfin guest start.

The Proxmox firewall is disabled and the inspected guest nftables policies
accept LAN traffic. Do not mistake a private address for access control. LXC
115 PostgreSQL is the clearest listener that still needs a tighter rule.

## Home guests

| ID | Name | Address | Current job |
| ---: | --- | --- | --- |
| 112 | NextPlaid | `10.42.0.7` from DHCP | Rust API and index storage. Outside the OpenTofu root. |
| 113 | Firecrawl | `10.42.0.108` from DHCP | Docker Compose API and its databases. Outside the OpenTofu root. |
| 115 | EU Law | `10.42.0.115` | PostgreSQL 17 with a 200 GiB ZFS-backed data mount. Outside the OpenTofu root. |
| 200 | Plan runner | `10.42.0.200` | GitHub Actions runner, OpenTofu state, encrypted VPS Matrix backups, and the on-demand Codex agent. |
| 202 | Caddy | `10.42.0.202` | Caddy 2.11.4, CrowdSec 1.8.1, and nftables bouncer 0.0.36. Home HTTP and HTTPS edge. |
| 203 | Jellyfin | `10.42.0.203` | Jellyfin 10.11.11 with Quadro P2200 hardware transcoding and `/data` mounted at `/storage`. |
| 204 | Media automation | `10.42.0.204` | Seerr OIDC preview, Radarr 6.3.0.10514, Sonarr 4.0.19.2979, Prowlarr 2.5.2.5491, and Shelfmark 1.3.15. |
| 205 | Downloads | `10.42.0.205` | Transmission 4.1.3 and File Browser 2.63.23 with `/data` mounted at `/storage`. |
| 206 | Miniflux | `10.42.0.206` | Miniflux 2.3.3, PostgreSQL 17.11, the MCP server, and the outbound OpenAI tunnel client. |
| 207 | Pocket ID | `10.42.0.207` | Pocket ID 2.14.0. OIDC provider for applications and Pangolin. |
| 210 | Pangolin connector | `10.42.0.210` | Newt 1.16.0. Outbound connector for the Home site. |
| 211 | Network operations | `10.42.0.211` | CoreDNS 1.14.7 and the Cloudflare DNS reconciliation timer. |
| 213 | NeroCD | `10.42.0.213` | NeroCD 0.3.23 with PostgreSQL and a local Caddy sidecar. Internal-only. |

OpenTofu owns LXCs 200, 202 through 207, 210, 211, and 213. NextPlaid,
Firecrawl, and EU Law are deliberate external workloads, not half-managed
OpenTofu resources.

## VPS

The Example Hosting VPS at `198.51.100.24` runs Debian 13. Its 40 GiB root
filesystem is 23% used.

| Service | Version | Runtime |
| --- | --- | --- |
| Pangolin Enterprise | 1.22.2 | Docker Compose |
| Gerbil | 1.5.1 | Docker Compose |
| Traefik | 3.7 | Docker Compose |
| CrowdSec | 1.8.1 | Docker Compose |
| Beszel Hub | 0.19.0 | Docker Compose |
| Tuwunel | 1.9.0 | Native systemd service |
| LiveKit | 1.13.5 | Docker Compose |
| MatrixRTC JWT service | 0.4.4 | Docker Compose |
| Matrix notification bridge | Repository version | Native systemd service |

Traefik terminates Matrix client, federation, and MatrixRTC signaling routes.
LiveKit exposes TCP 7881 and 5349, UDP 3478 and 7882, plus UDP 50300 through
50400. Its private HTTP services bind only on the Compose gateway.

## Routing and identity

Caddy has 13 declared home routes. CoreDNS returns the Caddy address for local
names that set `internal_dns`. Public gateway records point to the VPS. Pocket
ID and Jellyfin point home. Matrix and MatrixRTC point to the VPS without using
Pangolin authentication.

Pangolin roles control remote reachability. Pocket ID handles normal sign-in.
Pangolin keeps one local TOTP administrator for recovery. Applications either
use their own OIDC session, accept a narrowly trusted proxy identity, or retain
their own login. [`access-design.md`](access-design.md) has the exact behavior
for each service.

## Monitoring, security, and alerts

Beszel Hub stays on the VPS so a home outage does not take the dashboard with
it. Outbound agents cover the Proxmox host, the VPS, and the important LXCs.
The agent connection endpoint bypasses the browser access page but still uses
Beszel's agent key.

CrowdSec runs independently on Caddy and the VPS. Each local bouncer can keep
blocking traffic if the other site is unavailable. Both engines send filtered
decisions through the Matrix bridge. The bridge adds a country flag from a
checksum-verified local IP database and leaves the original IP untouched when
lookup fails.

The update monitor checks upstream releases every 30 minutes on the VPS and
runs a randomized daily Trivy scan on monitored hosts. Matrix has separate
rooms for health, security, releases, vulnerabilities, and agent commands.
Notifications use `m.text` so Element X can deliver push notifications.

The Codex agent on LXC 200 accepts commands only from the configured owner in
the private agent room. A Beszel outage can start diagnosis, but it cannot
start a repair. Vulnerability alerts create a read-only investigation through
a short-lived evidence capability. `!fix` is a separate command and can
restart only an exact allowlisted systemd unit.

## Known work

The current work list is in [`../PLAN.md`](../PLAN.md). The important items are
a real restore test, a useful thin-pool autoextend threshold, and tighter LAN
exposure for LXC 115 PostgreSQL.
