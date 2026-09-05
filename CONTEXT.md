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
