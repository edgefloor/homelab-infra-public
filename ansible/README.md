# Ansible

The workstation applies roles over SSH. Ansible configures the Proxmox host,
managed LXCs, and the VPS. OpenTofu remains responsible for creating or
removing Proxmox guests.

## Run a playbook

Use the pinned Ansible release without installing it globally:

```sh
cd ansible
uvx --from ansible-core==2.19.4 \
  ansible-playbook playbooks/SERVICE.yml
```

A fresh LXC accepts the template root key for its first run. Later runs use the
managed administration account:

```sh
uvx --from ansible-core==2.19.4 \
  ansible-playbook -e ansible_user=root playbooks/caddy.yml

uvx --from ansible-core==2.19.4 \
  ansible-playbook playbooks/caddy.yml
```

Apply the smallest relevant playbook. A normal service change should not
reconfigure the whole homelab.

## Playbooks

| Playbook | Target |
| --- | --- |
| `plan-runner.yml` | GitHub Actions runner and OpenTofu tools on LXC 200 |
| `homelab-agent.yml` | Matrix-triggered Codex agent and evidence gateway |
| `proxmox-host.yml` | NVIDIA boot setup, `nvtop`, and Beszel prerequisites on `node1` |
| `caddy.yml` | Home Caddy edge and home CrowdSec engine |
| `network-ops.yml` | CoreDNS and Cloudflare record reconciliation |
| `newt.yml` | Home Pangolin connector |
| `jellyfin.yml` | Jellyfin and GPU runtime |
| `media-automation.yml` | Seerr, Radarr, Sonarr, Prowlarr, and Shelfmark |
| `downloads.yml` | Transmission and File Browser |
| `miniflux.yml` | Miniflux, PostgreSQL, MCP, and outbound OpenAI tunnel |
| `pocket-id.yml` | Pocket ID |
| `nerocd.yml` | Internal NeroCD stack and backups |
| `pangolin.yml` | Pangolin, Traefik, Gerbil, and VPS CrowdSec engine |
| `beszel.yml` | Beszel Hub on the VPS |
| `beszel-agents.yml` | Outbound monitoring agents |
| `tuwunel.yml` | Tuwunel and the Matrix notification bridge on the VPS |
| `matrix-rtc.yml` | LiveKit and MatrixRTC JWT service on the VPS |
| `tuwunel-backup.yml` | Encrypted VPS Matrix export to LXC 200 |
| `update-monitoring.yml` | Release watcher and daily CVE scans |

## Credentials kept outside Git

Most upgrades reuse root-owned credential files already on the target. A new
host needs the matching files before its role can start the service.

- `network-ops` needs `/etc/cloudflare-ddns.env` with `CF_API_TOKEN`.
- Caddy needs its existing Cloudflare certificate environment file.
- Newt needs `/etc/newt/newt.env` from the Pangolin site registration.
- Tuwunel needs the Matrix bridge files under
  `/etc/crowdsec-matrix-bridge/`.
- Both CrowdSec edges need `/etc/crowdsec-matrix-webhook-secret` with the same
  bridge secret.
- MatrixRTC keeps its generated LiveKit key and secret in `/etc/matrix-rtc/`.
- NeroCD generates its database and bootstrap credentials under
  `/opt/nerocd/secrets/`.

These files must belong to root and use the mode required by the role. Do not
pass their contents on a command line or add them to inventory.

The Tuwunel play should run before Caddy, Pangolin, update monitoring, or the
homelab agent when rebuilding the Matrix bridge. Those roles read the existing
bridge credential in memory and distribute only what their target needs.

## Runner registration

Runner registration uses a short-lived controller variable:

```sh
cd ansible
export GITHUB_RUNNER_REGISTRATION_TOKEN
uvx --from ansible-core==2.19.4 \
  ansible-playbook playbooks/plan-runner.yml
unset GITHUB_RUNNER_REGISTRATION_TOKEN
```

The plan-runner role can also read `PROXMOX_TOKEN_ID` and
`PROXMOX_TOKEN_SECRET` when installing its OpenTofu wrapper.

## Codex agent login

The agent keeps its own ChatGPT subscription session. Apply the role, then use
device authentication as the dedicated service account:

```sh
cd ansible
uvx --from ansible-core==2.19.4 \
  ansible-playbook playbooks/homelab-agent.yml

ssh -t homelab-admin@10.42.0.200 \
  'sudo -u homelab-agent /usr/local/bin/homelab-codex login --device-auth'
```

Do not copy a workstation `auth.json` to the runner.

## Beszel enrollment

Existing agents reuse `/etc/beszel-agent/token` and
`/etc/beszel-agent/hub-key`. Supply enrollment data only for a new agent:

```sh
cd ansible
export BESZEL_AGENT_TOKEN BESZEL_HUB_PUBLIC_KEY PROXMOX_ROOT_PW
uvx --from ansible-core==2.19.4 \
  ansible-playbook playbooks/beszel-agents.yml
unset BESZEL_AGENT_TOKEN BESZEL_HUB_PUBLIC_KEY PROXMOX_ROOT_PW
```

The universal enrollment record is closed after rollout. Do not leave a shared
token available for unknown hosts.

Beszel Hub joins the existing Pangolin frontend network and publishes no host
port. Its daily backup stops only the Beszel container long enough to copy a
consistent database.

## CrowdSec enrollment

Both engines report to one CrowdSec Console but enforce decisions locally. To
replace an engine, enroll it interactively:

```sh
sudo cscli console enroll --quick --name ENGINE_NAME
sudo systemctl restart crowdsec
```

On the VPS, run the equivalent command with `docker exec crowdsec`. The roles
also accept a short-lived `CROWDSEC_CONSOLE_ENROLLMENT_KEY` for unattended
replacement. They never store it.

## Update monitoring

`update-monitoring.yml` installs checksum-pinned Trivy on all 15 deployment
systems, including three external LXCs through Proxmox guest access. It compiles
coverage requirements and installs runtime discovery, native library scans,
candidate verification, and an empty disabled defensive action policy. Each
target runs one randomized daily scan. The VPS also checks the
release feeds every 30 minutes. Scans include host OS packages, explicitly
declared native Go executables, installed Node/Python/.NET library roots, and
running Docker images. Rust inventory gaps remain explicit. High/critical
findings are retained even without a published fix. The first regular scan
reports existing findings; `--snapshot-only` performs a separate audit without
notifications. Ordinary scan failures notify the health room and preserve
previous findings.

`cve-coverage.yml` collects fresh scans into `/tmp/homelab-cve-coverage` without
altering the regular notification baseline. See
[`CVE verification`](../docs/cve-verification.md#cross-host-detection-audit)
for cross-host reporting and coverage limits.

After installing monitoring, `defense-agent-tools.yml` enrolls all 15 bounded
agent endpoints and updates fleet queries and named-action tools. External
guests retain their existing ownership and application deployment method.
No action is enabled by default; agent-supplied commands or approval receipts
are not accepted by the runner. `homelab-defense-recovery.timer` handles
interrupted or expired actions independently of the controller.

The role initializes action policy only when missing; it preserves an existing
host-local policy. Reapplying monitoring therefore does not reset or reconcile
that policy. The action runner is not connected to a commit-bound Ansible
deployment path. Keep actions disabled until the repository ownership and
recovery requirements in
[`autonomous-defense.md`](../docs/autonomous-defense.md#repository-ownership-and-drift)
are implemented.

`defense-recovery-rehearsal.yml` restores a specified downloads backup into a
reserved disposable LXC, verifies network isolation, starts File Browser against
its restored database, and removes the test guest. Pass a current archive with
`-e defense_restore_archive=/data/backups/dump/<archive>.tar.zst`. The shared
storage is not mounted or restored by this check.

Scanner output starts an investigation. It does not settle whether a deployed
path is reachable. The Codex agent can request bounded evidence through the
target gateway, while repair remains on the separate allowlisted `!fix` path.
