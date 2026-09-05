# Deployment coverage and defensive actions

Detection is active across all 15 systems. Autonomous patches and emergency
measures are disabled. The installed action runner has local verification and
recovery checks, but does not enforce repository ownership of changes.

## Coverage

[`security-coverage.yml`](../inventory/security-coverage.yml) declares required
evidence for all 21 application manifests and additional deployments.
[`security-runtime.yml`](../inventory/security-runtime.yml) supplies bounded
scan roots. CI checks that profiles exist; it does not attest live coverage.

The collector records services, processes, executable and loaded-file identities,
listeners, container mounts and changes, configuration hashes, and scheduled-file
hashes. Scans cover OS packages, declared native Go binaries, running Docker
images, and installed Node/Python/.NET dependencies. Fleet queries compare live
Proxmox guest IDs with the expected inventory and retain missing systems as
unknown. NextPlaid, Firecrawl, and EU Law use a bounded Proxmox guest router;
monitoring enrollment does not transfer ownership of those applications.

A completed scan covers its declared artifacts only. Rust dependency inventories
are missing for NextPlaid, Tuwunel, and the agent's bundled Codex executable.
Plugins, shipped browser assets, application/runtime advisories, operational
tools, scheduled-job payloads, and mounted or changed container code have
incomplete coverage. Stopped containers are inventoried but their images are not
scanned. Discovery and artifact hashes do not establish effective exposure or
build provenance. Abrupt scan termination can leave stale status without a health
notification; an independent stale-scan watchdog is not implemented.

The two Caddy installations retain separate identities and exposure assessments.
NeroCD identifies one installation's location. Its restricted ingress cannot
settle the main HTTPS proxy's exposure. The fleet lookup finds other component
matches; it does not transfer reachability conclusions between installations.
See [CVE investigation and alerts](cve-verification.md) for scanner behavior,
evidence scope, and the alert contract.

## Installed action boundary

[`homelab_defense.py`](../ansible/roles/update_monitor/files/homelab_defense.py)
accepts a named action from `/etc/homelab-update-monitor/defense-policy.json`.
The agent cannot supply commands, candidate paths, or verification receipts.
`prepare_defensive_action` reports blockers; `execute_defensive_action` uses
fixed handlers and root-owned evidence. Every deployed policy is disabled and
empty. The inventory's autonomy flags do not enable the runner.

The runner checks target, artifact, candidate, and runtime identities; receipt
expiry and prior use; and the required verification checks. It serializes its
own actions and persists recovery handlers before calling the apply handler.
Failed apply or health checks invoke recovery. Emergency actions have a maximum
one-hour expiry, handled by `homelab-defense-recovery.timer` independently of the
agent. A failed recovery remains recorded and returns failure; automatic
escalation is not implemented. This mechanism does not provide general emergency
actions: a real action still needs its fixed handlers and verified evidence.

The candidate verifier scans a native artifact without executing it. Absence of
an advisory counts only when the expected package and analyzer are present.
This does not prove source provenance, application compatibility, or recoverability.
The [backup inventory](../inventory/backup-plan.yml) records the successful
File Browser database/startup restore in an isolated disposable LXC. Shared
storage, candidate migration compatibility, and other deployments remain untested.

## Repository ownership and drift

[ADR 0001](adr/0001-separate-infrastructure-and-guest-configuration.md) keeps
Ansible responsible for host and application configuration. Defensive actions
must use that ownership model. Root ownership of an action policy is not proof
that its contents agree with the repository.

The current runner does not bind an action to a Git commit, require an Ansible
handler, verify convergence against desired state, or coordinate its lock with
ordinary deployments. Its runtime fingerprint detects changes since an
observation; it does not compare the machine with repository intent. Rollback
restores local artifacts but does not reconcile Git. Normal deployments do not
recognize active emergency overrides.

The monitoring role initializes policy only when absent (`force: false` in its
[direct-target tasks](../ansible/roles/update_monitor/tasks/main.yml), an existence
check in its [external-guest tasks](../ansible/roles/update_monitor/tasks/external_guest.yml)). A locally edited policy
therefore survives another playbook run. There is no repository-managed enabled
policy or policy-drift check. The defense rollout was verified against working-tree
file hashes, but no immutable deployment revision was recorded.

[`homelab-production-deploy`](../scripts/homelab-production-deploy) is a separate
wrapper whose deployment payload is not implemented in this repository. Its
fixed repository and branch parameters do not supply the missing commit
verification or Ansible integration. The existing Proxmox apply workflow manages
guests through OpenTofu; it is not an application patch pipeline.

These gaps block enabling defensive actions. Permanent fixes must be represented
in a repository revision and applied through the owning deployment mechanism.
Temporary containment must have a recorded scope and expiry that deployments
recognize, then be removed or represented as a permanent repository change.
Implementation and acceptance work is in [`PLAN.md`](../PLAN.md).

## Operation

[Ansible instructions](../ansible/README.md#update-monitoring) describe installing
monitoring and agent endpoints, collecting an audit, and rehearsing a restore.
[Operational scripts](../scripts/README.md) describe the generated readiness
report. Reports and investigation records are evidence, not desired state.
They retain unknown, failed, stale, partial, and unsupported coverage explicitly;
a clean finding list cannot substitute for missing evidence.
