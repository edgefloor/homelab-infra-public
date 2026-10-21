# Retire the custom CVE pipeline

`ansible/playbooks/retire-custom-cve.yml` is a reversible shutdown procedure.
Preparing it does not deploy a replacement or change any live service.
The replacement is [Dependency-Track 5.2.0](dependency-track.md). An HTTP health
response alone does not establish that the replacement has useful scan coverage.
Verify at least one real scan, the intended managed-host inventory, access control,
and its operational recovery procedure first.

The playbook covers the inventory's managed evidence endpoints, including Proxmox,
managed guests 200 and above, and the Pangolin VPS. It also includes the declared
news embeddings guest if it has not joined the endpoint group. It never runs
`pct exec` and never targets external guests 112 or 115.

## Before shutdown

1. Resolve disk-space or backup failures. Verify retained incident and Helix
   archives and a recent guest backup, then take recovery snapshots before the
   cutover. Keep the original databases and their encryption identity. An extra
   application archive is useful only when its staging and verification fit the
   receiver's enforced free-space reserve. Do not invoke the old destructive
   `incident-pangolin-cleanup.yml` procedure.
2. Verify the replacement's real scan coverage. Record its product/version and
   health URL with the cutover review.
3. Use the repository revision with the legacy activation guards described below
   before normal provisioning resumes. The shutdown playbook does not change
   activation roles on the controller or stop an older checkout from being used.
4. Save the Ansible output. It records each installed custom service's prior state
   and the installed timers' enablement state for rollback. It does not print
   credential contents.

The preflight requires an explicit HTTP(S) health URL, rejects redirects, requires
HTTP 200 with normal TLS certificate verification, and invokes the existing
read-only `homelab-incident-backup-status` on the plan runner. That backup verifier
checks decryptability, compression integrity, partial files, and the archive size
budget. It does not prove freshness; inspect the guest backups and snapshot
timestamps separately. A failed preflight stops the play before unit changes.

The 2026-10-15 preparation verified the October 11 weekly guest archives and
created `pre-cve-retirement-20261015` snapshots for LXCs 201, 212, and 214.
Receiver cleanup removed abandoned verification directories and one incomplete
transfer. All seven completed encrypted archives were retained unchanged.

From `ansible/`, preview the selected hosts and then check the play. Substitute the
verified replacement's health endpoint; no default endpoint is provided.

```sh
ansible-playbook playbooks/retire-custom-cve.yml --list-hosts
ansible-playbook playbooks/retire-custom-cve.yml --check \
  -e cve_replacement_health_url=https://replacement.homelab.example/health
ansible-playbook playbooks/retire-custom-cve.yml \
  -e cve_replacement_health_url=https://replacement.homelab.example/health
```

The read-only health and backup checks run in check mode too. All timer stop tasks
finish before service stop tasks begin. Missing units are skipped using discovered
service facts and timer unit names. Existing masked units are not unmasked.

## What stops

The exact allowlist is in the playbook. The following table explains the units;
each name ending in `{service,timer}` denotes both named units.

| Component | Units stopped and disabled |
| --- | --- |
| Fleet custom scan orchestration | `homelab-cve-monitor.{service,timer}`, `homelab-scan-watchdog.{service,timer}`, `homelab-defense-recovery.{service,timer}` |
| Incident API and independent health | `homelab-incidents.service`, `homelab-incidents-health.{service,timer}` |
| Incident aliases and graph synchronization | `homelab-incidents-aliases.{service,timer}`, `homelab-incidents-helix-sync.{service,timer}` |
| Helix database and forwarding | `helix-cve.service`, `helix-cve-reverse-tunnel.service`, `homelab-incidents-reverse-tunnel.service` |
| Custom application archives | `homelab-incident-backup.{service,timer}` and the legacy plural `homelab-incidents-backup.{service,timer}` |
| Zig conversation and publication | `hermes-gateway-zig.service`, `cve-native-publisher.{service,timer}`, `zig-observation-credential-check.service` |
| Investigation workers and scoped model access | `zag-ops-worker.service`, `zig-investigation-replies.service`, `zag-model.service`, `zag-model-access.{service,timer}` |
| Repository broker and scratch retention | `homelab-repository-broker.service`, `homelab-workspace-cleanup.{service,timer}` |
| Previously retired compatibility paths, if present | `homelab-agent.service`, `homelab-memory-sync.{service,timer}`, `zag-router.service`, `zag-ops-gateway.service` |

The personal `hermes-gateway.service`, general Hermes configuration, Beszel,
CrowdSec and its firewall bouncer, the Matrix alert bridge, upstream release
notifications, `homelab-trivy.service`, Docker, network services, and ordinary
guest backups remain outside the stop allowlist. The Trivy binary and standard
Trivy server remain available, but the old incident-health timer's combined Trivy
health check stops with that custom timer. The replacement should own any needed
scanner health check.

No Matrix notification or publication command is called. No service is started.
This procedure retires the custom scheduled pipeline and its Zig runtime.
The separate `retire-evidence-access.yml` playbook subsequently retired the
evidence endpoint and on-call tools on October 17. It quarantines access files
in root-only recovery archives, revokes SSH and sudo access, and locks endpoint
accounts. Personal Hermes remains active with its configuration and memory.

## Deployment after retirement

`homelab_legacy_cve_enabled` defaults to `false`. The `legacy_cve_guard` role
rejects dedicated CVE, incident, Helix, and Zig deployment and migration plays
before their tasks run. Each play has its own guard, including when a host limit
skips an earlier play. Direct incident, Helix, backup, repository-broker, and
custom scan role entrypoints are guarded too. The guard is tagged `always` so
ordinary task-tag selection still checks it.

Normal app provisioning applies its owning roles directly. It does not read
incident credentials, call the old incident API, or trigger a custom scan.
`update-monitoring.yml` retains the standard Trivy binary and authenticated client
configuration plus enabled release notifications. It skips the custom CVE,
watchdog, and recovery tasks. `trivy-central.yml` still manages the native Trivy
server and its health check, while skipping the old custom-scanner migration.
`homelab-agent.yml`, `defense-agent-tools.yml`, and direct evidence installation
entrypoints also require legacy opt-in. Personal Hermes uses `hermes-zag.yml`.
Beszel, CrowdSec, the alert bridge, and general Hermes roles have no legacy guard.

For a reviewed rollback that needs an old deployment playbook, opt in explicitly
for that invocation, for example:

```sh
ansible-playbook playbooks/investigation-runtime.yml \
  -e '{"homelab_legacy_cve_enabled":true}'
```

Do not set this flag in shared inventory or bypass the guard with task-skipping
options. An opt-in permits the original legacy tasks, including their existing
activation and migration behavior. Review the selected playbook before using it;
the flag does not make destructive historical cleanup procedures reversible.
The guards prevent accidental repository-driven reactivation; they do not mask
installed units or replace the shutdown procedure.

## State retained and rollback

The October 20 cleanup moved two retired data trees to root-only cold archives
on Proxmox at `/data/backups/retired-cve/2026-10-20`:

- `lxc-201-work.tar.zst` contains the complete `work` tree formerly under
  `/var/lib/homelab-investigator` on LXC 201.
- `lxc-200-incident-backups.tar.zst` contains `incident-backups`, including all
  seven completed encrypted archives formerly under `/var/lib` on LXC 200.

Each archive has an adjacent SHA-256 file and verification receipt. Compression
integrity and a native tar comparison passed before removing either original.
The cleanup reclaimed 19.61 GiB across the two guest filesystems and did not
restart personal Hermes or alter current Tuwunel backups. The encryption
identities and original application databases remain in place.

Inspect or restore these archives before a historical rollback that expects
their old paths. In particular, the old incident-backup preflight expects
`/var/lib/incident-backups`; it cannot validate the cold archive directly.
Verify the adjacent checksum and extract into an empty temporary directory for
inspection. Then restore the required tree to its original guest and parent
directory. Preserve numeric ownership, permissions, ACLs and xattrs. Do not
reactivate the retired timers merely to inspect archived data.

The playbook does not delete or rewrite databases, archives, source snapshots,
credentials, unit files, profile histories, Kanban cards, or guest disks. In
particular, it retains `/var/lib/homelab-incidents`, `/var/lib/helix-cve`,
`/var/lib/incident-backups`, `/var/lib/zig`, `/var/lib/zag-ops`,
`/var/lib/homelab-investigator`, `/var/cache/homelab-investigations`, and
`/var/lib/hermes-kanban`, together with their configuration and original secret
files. Stopping Helix uses its existing `docker stop` action; the ephemeral
container may be removed by its existing `--rm` setting, while its database bind
mount and image remain. Systemd may discard ephemeral credential copies under
`/run`, while the original credential files remain.

Disablement is reversible. Use the recorded prior states to restore only units
that were active or enabled before retirement. Start Helix and the incident API
before their clients; restore required model services before Zig. Restore timers
last, after checking dependencies and the retained data. Some timers are
`Persistent=true` and may immediately run missed work when restarted. Do not
blindly enable every listed unit: some are legacy or intentionally disabled.

If the post-shutdown replacement health check fails, Ansible reports failure and
leaves the retired services stopped. Review the failure and choose recovery
explicitly; the playbook does not automatically restart notification producers.
