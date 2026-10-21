# Deployment coverage and defensive actions

> Superseded on 2026-10-15. The owner chose conventional vulnerability
> management through [Dependency-Track](procedures/dependency-track.md).
> This document retains the custom pipeline design and historical results
> for recovery reference. Follow the [retirement procedure](procedures/retire-custom-cve.md),
> not the activation instructions below. The evidence gateway and Hermes on-call
> tools were also retired on 2026-10-17; their descriptions below are historical.

Hermes consumes the `homelab-oncall` capability to investigate incidents, diagnose
failures, and prepare fixes in a private repository copy. Established scanners detect findings. Ansible remains the
production deployment mechanism. Autonomous production changes are disabled.

## Investigation and delivery

The version-pinned Hermes deployment owns reasoning, sessions, Matrix, and native
memory. `homelab-oncall` is an installed skill, not another agent service. It gives
Hermes a maintained repository snapshot plus `homelab-agentctl`, a typed client for
forced read-only endpoints across managed systems. The capability does not choose or
proxy Hermes's model, provider, personality, memory, or messaging configuration.

Hermes can prepare a patch and run local checks in a private copy beneath
`/var/lib/homelab-investigator/work/`. Production changes remain operator-run through
Ansible. The retired relay queue and recursive socket worker are archived root-only
and are not runnable. Deterministic monitoring continues independently. Vulnerability
notifications use the incident service's Matrix transport without an agent run. See the
[Hermes Agent repository](https://github.com/NousResearch/hermes-agent).

As of 2026-09-08, vulnerability snapshots enter a central incident service, keyed
by vulnerability across hosts. Notifications do not mention personal Zag or start
agent sessions. The separate native Zig profile answers operational questions with
memory disabled and admits explicit user commands into durable incident jobs. Zag
keeps its original personal gateway. Manual investigations are enabled, with evidence and work
budgets in the glue. Automatic investigations remain disabled. See the [deployment reference](vulnerability-incidents.md)
for the current notification, evidence, and personal-memory boundaries. The native
personal Hermes capability described below is not the operational alert handler.

## Independent production permissions

The Hermes account cannot read monitoring Matrix credentials, the production
checkout, or operator credentials. Its SSH key reaches only forced read-only
endpoints. Those endpoints reject shell, restart and defensive execution requests;
the Proxmox guest router enforces the same restriction. Target sudoers permit only
bounded evidence access. This boundary does not prove a production change safe.

The root evidence gateway retains checks that protect production: enrolled guests,
current artifact/container identity, approved paths, secret redaction, bounded
reads and scanner work, expiry, and revocation. A thin native-shell client passes
requests to it. Operational reads can follow dependencies across managed hosts
without scanner-bound authorization; remote host policy still controls paths,
services, redaction and resource use. Only binary-specific extraction and analysis
require a scanner artifact binding. The two unmanaged guests are excluded.
Operational decisions and private fix preparation are delegated to Hermes; production
execution is independently denied. Public advisory and source research uses the tools
enabled in the general Hermes deployment.

The root defensive runner retains its lock, durable rollback journal, independent
recovery timer and recovery checks, but rejects execution. Its policy remains
repository-owned, empty and disabled. The existing production wrapper's lock and
credential boundary are preserved; its deployment payload is still unimplemented.
Neither lock currently coordinates all ordinary Ansible deployments. Enabling a
production experiment requires that integration, rather than an agent assertion
that a local sandbox or successful test makes it safe.

## Detection and production prerequisites

[`security-coverage.yml`](../inventory/security-coverage.yml) declares required
coverage; [`security-runtime.yml`](../inventory/security-runtime.yml) supplies scan
roots. OS, native Go, installed library and container-image scans remain separate.
The [deployment inventory reference](deployment-inventory.md) defines the
execution, privilege, and selected filesystem observations retained with scans.
The scanner now includes stopped-container images and rejects inventory changes
during scanning. Unsupported analyzers, missing evidence and discovery failures
remain explicit gaps. Enrollment and a completed scan do not establish coverage
of every application dependency or effective route.

Before any specific production action, verify target and affected dependencies,
including shared storage, databases, identity, networking and management access.
Evidence, notification and recovery paths must survive. Bind the candidate and
owning Ansible deployment to a committed revision, reject drift, verify backups
and candidate-specific recovery, and test convergence after rollback. Unknown
coverage or dependencies block the relevant action. No service/action has been
selected for autonomous activation. Remaining work is in [`PLAN.md`](../PLAN.md).

## Evaluation

On 2026-09-06 the operational-access rollout passed on all 12 managed hosts.
Historical incident exercises showed that the forced endpoints could follow an
ingress path across CoreDNS, Caddy, Newt, and NeroCD while rejecting credential-path
reads and restart requests. Those exercise sessions belonged to the retired runner;
the reusable evidence boundary and target client remain active in the Hermes skill.


On 2026-09-06 the 12 managed systems completed fresh scans after a missing
Traefik webhook path rewrite was repaired. The deployed watchdog passed a live
systemd exercise using separate test state: overdue scan, refused connection,
accepted notification with a deliberately lost acknowledgement, identical-payload
retry, and recovery after fresh completion. Matrix retained exactly one failure
and one recovery event; repeated checks were silent and production findings stayed
unchanged. The two externally managed LXCs are outside this rollout. Off-host
verification when a host or its watchdog disappears remains outstanding.

The 2026-09-06 Caddy investigation used native execution, live read-only SSH and
official source research. It distinguished the DNS-parser precondition from HTTP
exposure, assessed the main and NeroCD Caddys separately, and retained the missing
scanner-bound configuration as uncertainty. It also found NeroCD's failed scan
service instead of treating old findings as a clean current scan. Earlier runs
correctly reported unavailable evidence when namespace support, SSH configuration,
or historical container identities prevented access; those reports remain retained.

The NeroCD replay opened a capability against current full container identities
and read its live route, listener and build metadata. It exposed an accidentally
removed analyzer dispatch that helper-only tests missed. After restoring the
dispatch and testing through the gateway entry point, a live `govulncheck` call
succeeded and reported affected symbols in the exact deployed binary. Symbol
presence still does not establish runtime invocation or external exploitability.

An isolated historical delivery-failure exercise reproduced repeated investigation
after a failed Matrix send in committed snapshot `2953c6f`. Its artifacts are retained
only in the retired root-owned archive; that relay is no longer part of the active
architecture.

The 2026-09-06 File Browser exercise restored the existing backup into a disconnected
LXC, injected an executable that exited 70, restored the original executable,
verified an unchanged database hash and HTTP 200, then removed the clone. Production
networking and shared mounts were absent. This proves that exercise's restoration;
a real candidate's schema compatibility and shared-storage recovery remain untested.
