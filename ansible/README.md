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

For n8n, `-e n8n_activate_release=false --limit n8n_servers` prepares the pinned
package and dependency lock without selecting the release or changing its
service configuration. npm runs as `n8n-build`; completed releases become
root-owned. The release directory includes the lock digest, so a new dependency
set cannot overwrite the files used by the running service. An incomplete
selected release or a mismatched installation receipt stops the deployment.

Before activation, verify the candidate's authentication classes and rehearse a
restore in an isolated network namespace. Retain the database, encryption key,
service configuration and previous release for rollback. Readiness failure
stops the playbook but does not automatically restore the old database.

## Playbooks

| Playbook | Target |
| --- | --- |
| `plan-runner.yml` | Root-only OpenTofu tools and state on LXC 200; Actions runner disabled by default |
| `homelab-agent.yml` | Legacy on-call and evidence endpoint deployment; explicit opt-in required |
| `hermes-agent-bootstrap.yml` | Administration baseline for a newly provisioned dedicated Hermes Agent LXC |
| `hermes-zag.yml` | Zag profile, native Honcho, OpenAI Codex auth, and dedicated Tuwunel device on LXC 201 |
| `proxmox-host.yml` | NVIDIA boot setup, `nvtop`, and Beszel prerequisites on `node1` |
| `caddy.yml` | Home Caddy edge and home CrowdSec engine |
| `network-ops.yml` | CoreDNS and Cloudflare record reconciliation |
| `coredns.yml` | Internal DNS, local ad filtering, and daily blocklist updates; see the [DNS procedure](../docs/procedures/dns.md) |
| `newt.yml` | Home Pangolin connector |
| `jellyfin.yml` | Jellyfin and GPU runtime |
| `media-automation.yml` | Seerr, Radarr, Sonarr, Prowlarr, and Shelfmark |
| `downloads.yml` | Transmission and File Browser |
| `firecrawl-provision.yml` | Create only the fresh managed Firecrawl LXC 215 through the protected OpenTofu state |
| `miniflux.yml` | Miniflux, PostgreSQL, MCP, and outbound OpenAI tunnel |
| `pocket-id.yml` | Pocket ID |
| `nerocd.yml` | Internal NeroCD stack and backups |
| `n8n-provision.yml` | Create only managed n8n LXC 216 through the protected OpenTofu state |
| `n8n-routing.yml` | Render canonical DNS, Caddy, and Pangolin routes without upgrading edge services |
| `n8n.yml` | Native n8n and weekly backup enrollment on LXC 216 |
| `news-embeddings-provision.yml` | Create only protected GPU helper LXC 217 through the guarded OpenTofu state |
| `news-embeddings.yml` | Reconcile the native CUDA helper, pinned model cache, private firewall, and backup membership |
| `firecrawl.yml` | Fresh Firecrawl and SearXNG stack on LXC 215 |
| `pangolin.yml` | Pangolin, Traefik, Gerbil, and VPS CrowdSec engine |
| `private-client-routing.yml` | Native private-resource routing and the public Rickroll 404 fallback |
| `beszel.yml` | Beszel Hub on the VPS |
| `beszel-agents.yml` | Outbound monitoring agents |
| `tuwunel.yml` | Tuwunel and the Matrix notification bridge on the VPS |
| `matrix-rtc.yml` | LiveKit and MatrixRTC JWT service on the VPS |
| `tuwunel-backup.yml` | Encrypted VPS Matrix export to LXC 200 |
| `update-monitoring.yml` | Standard Trivy client and release watcher; custom CVE scans require legacy opt-in |
| `dependency-track-resources.yml` | Guarded CPU and memory adjustment of existing LXC 214 |
| `dependency-track.yml` | Native Dependency-Track, PostgreSQL, private frontend, and Trivy integration |
| `dependency-track-portfolio.yml` | Native parent portfolio for the managed fleet |
| `dependency-track-routing.yml` | Internal DNS and private HTTPS dashboard route |
| `dependency-track-tunnel.yml` | VPS loopback upload path through a restricted SSH forward |
| `sbom-upload.yml` | Daily CycloneDX collection, native uploads, and freshness checks |
| `dependency-track-notifications-prepare.yml` | Prepare the inactive daily Matrix summary workflow and native rule |
| `dependency-track-notifications-activate.yml` | Publish the approved summary workflow, restart idle n8n, and enable the rule |
| `incident.yml` | Legacy incident service on LXC 214; explicit rollback opt-in required |
| `incident-backup.yml` | Legacy incident and Helix archives on LXC 200; explicit opt-in required |
| `incident-migrate.yml` | Historical Pangolin-to-LXC-214 migration and cleanup; explicit legacy opt-in required |
| `incident-rollback.yml` | Historical traffic rollback; explicit legacy opt-in required |
| `retire-custom-cve.yml` | Reversible shutdown of the custom pipeline after replacement and backup preflight |
| `security-audit-fixes.yml` | Retire evidence access and enforce the production credential boundary |
| `retire-evidence-access.yml` | Quarantine endpoint access and Hermes on-call tools while preserving personal Hermes |
| `beszel-monitoring.yml` | Enroll missing agents with per-system credentials and reconcile native alerts |
| `storage-policy.yml` | Attach the bounded Proxmox thin-pool autoextend policy |

## GPU host initialization

`proxmox-host.yml` creates the core NVIDIA devices and Unified Memory devices
in separate `nvidia-modprobe` calls. The core call requests minor `0` for the GPU
and minor `255` for its control device. The UVM call uses `-u -c 0` to create both
Unified Memory nodes. The unit checks all four character devices before it
reports success. Ansible repeats those checks on every run and verifies
`nvidia-smi`.

The initializer runs before `pve-guests` and the host Beszel agent. Their `Wants`
dependencies order startup without preventing every guest from starting if
GPU initialization fails. Inspect `nvidia-device-init.service` after a host
boot when diagnosing a GPU guest failure. Applying a changed unit reruns only
the initializer; it does not reboot the host or restart guests.

For a native device-creation check, copy
[`scripts/verify_nvidia_device_init.py`](../scripts/verify_nvidia_device_init.py)
to the Proxmox host and run it locally as root:

```sh
sudo python3 /path/to/verify_nvidia_device_init.py
```

The probe requires both NVIDIA modules and all four host devices to already
exist. It creates an empty, private, `nodev` `/dev` in a disposable mount
namespace, tests the native commands there, and checks that the host device
identities and permissions remain unchanged. It removes the module-loading
capability from probe commands and refuses to run without namespace isolation.
It does not restart guests, alter host devices, or test a full host boot.

## Credentials kept outside Git

Most upgrades reuse root-owned credential files already on the target. A new
host needs the matching files before its role can start the service.

- `network-ops` needs `/etc/cloudflare-ddns.env` with `CF_API_TOKEN`.
- Pangolin needs `/etc/pangolin-cloudflare-dns-api-token` with the Cloudflare
  DNS token used for wildcard certificate renewal.
- The VPS management connector uses its existing enrollment at
  `/etc/alagut-management/newt.json`. The Pangolin Compose definition retains
  this connector for Alagut's private API connection. Mac client installation
  is separate; this role does not install it or require a local provisioning key.
- Caddy needs its existing Cloudflare certificate environment file.
- Newt needs `/etc/newt/newt.env` from the Pangolin site registration.
- Tuwunel needs the Matrix bridge files under
  `/etc/crowdsec-matrix-bridge/`.
- Both CrowdSec edges need `/etc/crowdsec-matrix-webhook-secret` with the same
  bridge secret.
- MatrixRTC keeps its generated LiveKit key and secret in `/etc/matrix-rtc/`.
- NeroCD generates its database and bootstrap credentials under
  `/opt/nerocd/secrets/`.
- Firecrawl generates fresh PostgreSQL and SearXNG credentials under
  `/opt/firecrawl/secrets/`. The role never reads the external workload's files.
- Incident backup transport and `age` identities are generated on LXC 200. The
  role distributes only the public SSH key and pins each source's public host
  key; no backup secret is stored in inventory.

These files must belong to root and use the mode required by the role. Do not
pass their contents on a command line or add them to inventory.

The Tuwunel play should run before Caddy, Pangolin, update monitoring, or the
homelab agent when rebuilding the Matrix bridge. Those roles read the existing
bridge credential in memory and distribute only what their target needs.

## Production provisioning

Repository CI runs on GitHub-hosted runners. The production-adjacent Actions
runner is disabled by default (`github_runner_enabled: false`). Provider
credentials, state and `/usr/local/bin/homelab-tofu` on LXC 200 are root-only.
Use the owning provisioning playbook from the workstation; it stages the complete
OpenTofu root and runs the operation through Ansible privilege escalation.

To reconcile only the boundary on an existing host:

```sh
uvx --from ansible-core==2.19.4 ansible-playbook \
  playbooks/plan-runner.yml --tags production-boundary
```

The role reads `PROXMOX_TOKEN_ID` and `PROXMOX_TOKEN_SECRET` only when explicitly
installing provider credentials. Empty values preserve the existing secret.
The GitHub apply workflow refuses unattended production changes.

## Hermes Agent deployment

Personal Hermes is managed independently through `hermes-zag.yml`, including
its existing model authentication, Honcho memory and Matrix device. The legacy
`homelab-agent.yml` playbook and evidence endpoint roles require explicit legacy
opt-in. Do not use them for routine personal Hermes maintenance.

`retire-evidence-access.yml` revokes endpoint SSH and sudo access, locks the
endpoint accounts, and removes only the on-call skill, agentctl, target map and
observation key from Hermes. It preserves personal configuration, authentication,
memory and its running service. Removed files are retained under root-only
`/var/backups/homelab-evidence-retired/` directories.

The Zag deployment keeps its Honcho credential at
`/var/lib/hermes-agent/.hermes/secrets/honcho-api-key`. The file must be owned by
root, use mode `0600`, and contain a key scoped to the `zag` workspace. Do not
deploy a Honcho administrator key to LXC 201.

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

Run `beszel-monitoring.yml --tags enroll` to enroll missing systems through the
native Hub API using
per-system credentials, then installs their agents. Its temporary administrator
is removed after each operation. Then use `--tags alerts` to reconcile Status,
SystemdFailed and Disk alerts after all declared systems are connected. Existing
notification channels and Status delays are preserved.

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

`update-monitoring.yml` maintains checksum-pinned Trivy and authenticated client
configuration on managed systems. The two externally managed LXCs remain
excluded. The VPS release watcher keeps its existing 30-minute schedule.
`trivy-central.yml` manages the standard Trivy server and direct health check.
Beszel, CrowdSec, its Matrix alert bridge, and general Hermes remain independent
of the retired custom CVE pipeline.

The custom CVE monitor, scan watchdog, defensive recovery, incident/Helix
services, and Zig investigation runtime are disabled in normal deployment paths.
Dedicated deployment and migration playbooks fail before their tasks run unless
`homelab_legacy_cve_enabled=true` is explicitly supplied. The default is false.
Ordinary application provisioning applies its roles without incident credentials,
lifecycle API requests, or post-provisioning custom scans. Direct legacy role
entrypoints and scanner audit paths require the same opt-in.

For a reviewed rollback only, pass an explicit boolean for that invocation:

```sh
ansible-playbook playbooks/investigation-runtime.yml \
  -e '{"homelab_legacy_cve_enabled":true}'
```

Do not store this flag in shared inventory. Historical migration and cleanup
plays retain their original behavior after opt-in. See the
[retirement and rollback procedure](../docs/procedures/retire-custom-cve.md)
for retained state, shutdown order, and the exact scope of the guards.
`defense-agent-tools.yml` and the evidence installation entrypoints require the
same legacy opt-in. The evidence gateway was separately retired on October 17.

`defense-recovery-rehearsal.yml` restores a specified downloads backup into a
reserved disposable LXC, verifies network isolation, injects a failing executable, restores the original with
an unchanged database hash, verifies File Browser health and removes the test guest. Pass a current archive with
`-e defense_restore_archive=/data/backups/dump/<archive>.tar.zst`. The shared
storage is not mounted or restored by this check.

Scanner output identifies dependencies needing review; it does not prove that a
vulnerability is reachable. Inspect current service configuration through the
ordinary administration path before deploying an owning Ansible change.
