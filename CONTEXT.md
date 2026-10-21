# Homelab infrastructure

This context describes the boundaries used to manage and expose the homelab.
The terms matter because a route, a guest, and an application have different
owners even when they live on the same machine.

## Language

**Managed guest**:
An LXC whose lifecycle is declared in this repository and reconciled by
OpenTofu.
_Avoid_: Managed service, managed host

**External workload**:
A guest that shares the Proxmox host but is outside this repository's OpenTofu
root.
_Avoid_: Unmanaged guest, legacy guest

**Home edge**:
The HTTPS entry point for services reached directly through the home network.
_Avoid_: Internal proxy, local proxy

**Remote edge**:
The VPS entry point that authenticates remote browser users before carrying a
request home.
_Avoid_: Cloud proxy, public proxy

**Direct-home route**:
A public route that reaches the home edge without passing through the remote
edge.
_Avoid_: Bypass route

**Gateway route**:
A public route that reaches a service through the remote edge and its access
policy.
_Avoid_: Tunnel route, Pangolin route

**Internal route**:
A name that resolves to the home edge for trusted local clients. It may have a
different public destination or no public record.
_Avoid_: Private route

**Access session**:
The remote edge session that decides whether a person may reach a gateway
route. It does not log that person into the application.
_Avoid_: SSO session

**Application session**:
The session created by an application after native OIDC or local
authentication.
_Avoid_: Gateway session

**Recovery account**:
A local account kept outside the normal identity dependency so the operator
can repair that dependency.
_Avoid_: Admin user, fallback user

**Desired inventory**:
Configuration that declares the state automation must converge.
_Avoid_: Snapshot, observed inventory

**Observed inventory**:
A dated record of what was running when the system was inspected. It can
confirm reality but does not tell automation what to create.
_Avoid_: Desired state, source of truth

**Evidence capability**:
A short-lived permission that lets the diagnostic agent make bounded,
read-only observations on one target.
_Avoid_: Shell access, agent token

**Vulnerability record**:
The retained history of a vulnerability and its occurrences across monitored
systems, including occurrences that require no agent work or notification.
_Avoid_: Alert, work ticket

**Deterministic triage**:
The mechanical evaluation of vulnerability occurrences against recorded
observations, resource relationships, evidenced architectural constraints, and
explicit rules to determine whether work is required. Exclusion of an exploit
prerequisite is a derived conclusion; missing evidence remains unknown.
_Avoid_: Agent investigation, personal risk preference

**Infrastructure graph**:
The lifecycle system's maintained HelixDB graph of stable resource identities and typed
relationships, with scoped architectural constraints and supporting evidence.
Declarations, observations, and derived conclusions remain distinguishable.
Deterministic triage evaluates this graph; missing edges do not establish absent
paths without evidence of completeness.
Operational evaluation uses the current graph. Retained evidence, coverage,
immutable decisions, provisioning receipts, and lifecycle events support its
history; full historical graph replay is optional.
_Avoid_: Static architecture diagram, assumed topology

**Work ticket**:
A linked record of work identified by deterministic triage on a vulnerability or
a CVE-tracked package that remains stale across provisioning cycles. Kanban owns
the work; the lifecycle database retains the vulnerability, deployment facts,
need for work, and authoritative ticket and thread links. A ticket can exist
before Zig is asked to work on it.
_Avoid_: Vulnerability record, agent session

**Work disposition**:
A vulnerability occurrence's current need for work: quiet, requires work, or
awaiting evidence. It is separate from whether the vulnerability applies.
_Avoid_: Severity, applicability, remediation status

**Current execution domain**:
A finite declaration of the entry points, input classes, package-owned files,
and file-authority boundaries that may currently reach one operational action.
It becomes complete only when a separate observation accounts for every
declared member and contains no unassigned current member.
_Avoid_: Installed capability, whole-host certification, absence of use

**Execution availability**:
An installed command or granted permission that makes an action possible. It
does not prove that the action is a current workflow or that an input reached it.
_Avoid_: Current use, observed execution

**Declared linkage**:
A binary's recorded dependency on another artifact. It identifies a loader
candidate but does not prove that a process loaded the artifact.
_Avoid_: Loaded library, observed runtime use

**Current use**:
A configured or observed command, service, job, or broker operation with its
current input class and exact artifact ownership. Permission or installation
alone does not establish current use.
_Avoid_: Availability, possible use

**Package consumer scope**:
The consumer-coverage boundary for one stable package installation. The
installation identity includes the source, deployment slot, ecosystem, package,
and location, but excludes the advisory and installed version. Shared discovery
failures remain separate dependencies instead of merging package conclusions.
_Avoid_: Host-wide package coverage, vulnerability occurrence scope

**Scheduler selection**:
The jobs that the installed scheduler selects from current configuration and
file metadata. A directory entry that fails the scheduler's filename or
executable rules is observed but is not a current execution route.
_Avoid_: Every file in a scheduler directory, shell-script inference

**Snapshot artifact input**:
A scanner-bound artifact that the evidence broker currently admits for an exact
namespace, absolute path, and content hash. A finite tool domain is complete only
while each admitted artifact has matching current content and controlled path
authority.
_Avoid_: Any installed file, future command input

**Administrative input boundary**:
A quiet work disposition for an occurrence whose complete current execution
domain admits only bounded, administratively supplied input. It is not a claim
that the vulnerability is unaffected or that an exploit prerequisite is absent.
_Avoid_: Not affected, constraint exclusion, package deferral

**Quiet occurrence**:
A retained vulnerability occurrence that does not independently require an
investigation or alert, with its reason and history preserved. It remains in the
remediation scope when its CVE group receives a fix. Quiet does not imply fixed
or not affected.
_Avoid_: Resolved vulnerability, ignored finding

**Investigation brief**:
The work-relevant occurrences, reasons, and evidence presented to Zig for an
investigation. Quiet occurrences do not set its scope or priorities.
_Avoid_: Complete vulnerability record, patch context

**Patch context**:
Every occurrence in the CVE group, with the deployment relationships and histories
needed to implement and validate the fix. Quiet occurrences are included in the
remediation scope even though they do not drive the investigation.
_Avoid_: Investigation brief, new investigation request

**Provisioning cycle**:
One distinct run of the provisioning path responsible for a package or its
containing image in a deployment. Retries belong to that same cycle.
_Avoid_: Scan sequence, retry attempt, elapsed maintenance interval

**Missed update opportunity**:
A successful relevant provisioning cycle that leaves a CVE-tracked deployment
stale despite a suitable update available before the cycle. An old version pin
does not exempt the deployment.
_Avoid_: Failed provisioning attempt, scan finding, package age
