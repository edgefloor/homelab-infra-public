# Zig investigation profile

> Superseded on 2026-10-15. The owner chose conventional vulnerability
> management through [Dependency-Track](procedures/dependency-track.md).
> This document retains the custom pipeline design and historical results
> for recovery reference. Follow the [retirement procedure](procedures/retire-custom-cve.md),
> not the activation instructions below. The evidence gateway and Hermes on-call
> tools were also retired on 2026-10-17; their descriptions below are historical.

> This page describes the implemented CVE lifecycle profile. The repository has
> not activated or deployed this version. See [CVE lifecycle](cve-lifecycle.md)
> for migration and activation requirements.

Zig is a native Hermes profile and Matrix identity,
`@zig:matrix.homelab.example`. Zag keeps its personal Hermes gateway. No
classifier or custom gateway intercepts either profile's messages.

## Native conversation

Zig accepts the configured operator's direct messages and mentions in the
vulnerability room. A message starts an ordinary Hermes conversation. In a CVE
thread, the native session supplies the thread root to the lifecycle tools.

The profile enables these toolsets for Matrix:

```yaml
platform_toolsets:
  matrix: [zig_incidents, kanban, terminal, file, web]
```

The `zig_incidents` plugin provides eight tools:

- `cve_lookup` reads CVE records and linked work identity.
- `cve_work_scope` pages either the worthy investigation scope or the complete
  remediation scope.
- `cve_relationships` pages exact retained graph assertions.
- `cve_evidence` resolves an evidence identity to retained content and
  provenance.
- `cve_record_outcome` records an authored per-occurrence result.
- `cve_propose_change` links repository changes and validation to covered
  occurrences.
- `cve_repository_checkout` creates a brokered writable branch.
- `cve_create_pr` validates and pushes the branch, creates the provider PR, and
  records broker-derived proposal facts for the covered occurrences.

Read tools accept typed named values and return structured envelopes. Pagination
returns a continuation value and a completeness flag. Mutation tools require the
configured operator's authenticated native Matrix turn. The plugin adds no system
prompt, role prompt, or workflow text.

The managed `homelab-oncall` skill contains the workflow and the meaning of each
tool. `zig.yml` installs the skill at
`/var/lib/zig/.hermes/profiles/zig/skills/homelab-oncall/SKILL.md`.

## Passive Kanban

Zig and Zag use the native board under `/var/lib/hermes-kanban`. The Zag role
copies the prior default board with SQLite's backup API when the shared board
does not exist. Both gateway services then use this passive Kanban behavior:

```yaml
kanban:
  dispatch_in_gateway: false
  auto_decompose: false
  auto_subscribe_on_create: false
  review_dispatch: false
```

The lifecycle publisher creates an unclaimed `ready` card assigned to Zig. Card
creation, scan ingestion, and mechanical lifecycle updates do not start an agent.
Provisioning removes existing wake-capable subscriptions through the native
Kanban database operations.

A card, a proposal, and a reviewed pull request are progress records. They do not
establish a deployed fix. Only collector observations and a current deterministic
decision can close the deployment round.

## Filesystem and credential boundary

Zig runs as the `zig` OS account. Its supplementary `hermes-agent` group grants
access to brokered investigation workspaces. Systemd supplies a private copy of
the observation credential to Zig; the source key remains controller-owned. The
service can read
`/etc/homelab-investigator` and can write only the Zig profile, investigation job
storage, and the shared artifact cache.

The profile can use the repository broker to create a branch checkout, edit files,
run configured validation, push the branch, and create a PR. The broker owns the
provider credential and private Git metadata. Zig has no direct production write,
merge, or deployment capability.

Zig's profile keeps separate configuration, Matrix credentials, recovery key,
sessions, and logs. Native memory, user-profile extraction, Honcho, and background
review are disabled. The process cannot read Zag's home. The deployment copies
only the configured web credentials from Zag.

The local model proxy accepts only Zig's `zig-chat:` credential. It no longer
checks or mutates investigation-job budgets. The profile retains the existing
hourly and daily native chat limits.

## Retired execution paths

`zig.yml` stops, disables, and removes `zag-ops-worker.service` and
`zig-investigation-replies.service` from the host. It also removes the installed
worker and reply runtime files. `investigation-runtime.yml` does not install or
start either service.

The repository retains the old source and one-off rollout artifacts for rollback
review until lifecycle migration and restore checks pass. No active role or
current deployment entry point installs those runtimes.

## Verification

Run the local suite from the repository root:

```sh
uv run --with PyYAML==6.0.3 python -m unittest discover -s scripts -p 'test_*.py'
```

`scripts/test_zig_profile.py` checks native thread context, typed lifecycle tools,
operator-only mutations, and the absence of prompt injection.
`scripts/test_native_cve_publisher.py` checks passive card publication and
lost-acknowledgement recovery against a temporary native-shaped Kanban database.

During provisioning, `scripts/verify_zig_profile.py` loads the installed Hermes
profile. The verifier checks the six lifecycle tools, passive Kanban settings, the
managed skill, memory isolation, and the absence of retired dispatch tools. Its
optional `--live` mode runs one read-only native Matrix-thread conversation and
rejects lifecycle mutations at the client boundary.
