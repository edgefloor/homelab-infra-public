# Deployment inventory observations

[`homelab_deployment_inventory.py`](../ansible/roles/update_monitor/files/homelab_deployment_inventory.py)
records execution and privilege facts in the existing runtime discovery snapshot.
The snapshot retains its observation time, host, and compiled configuration hash.
The lifecycle converter retains the snapshot as evidence and links derived graph
assertions to that evidence.
The graph evidence retains `path_access` and a process witness list containing
PID, start time, executable, hash, cgroup, and privilege fields. This list resolves
service identity references without duplicating the full process memory maps.

## Units and processes

`services[].execution_settings` contains effective `systemctl show` values. These
are observations of systemd, not deployment declarations. The collector retains
only `UNIT_PRIVILEGE_FIELDS`, including user, group, capability sets, filesystem
restrictions, and `NoNewPrivileges`. `executables` contains paths extracted from
the four supported execution properties. Command arguments and environment
properties are discarded. Unit fragment hashes and deployment ownership remain
separate facts.

`processes[].privileges` contains allowlisted fields from `/proc/<pid>/status`:

- `Uid` and `Gid`, each in kernel order: real, effective, saved, and filesystem.
- `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb`, as hexadecimal masks.
- `NoNewPrivs` and `Seccomp`, as kernel numeric values.

Missing, malformed, or unreadable fields stay missing. The observation names
them in `missing_fields` and remains incomplete. Other process facts survive an
unreadable status file. A process that disappears, changes its executable, or
changes its start time during collection produces a gap and no positive sample.
The collector reads neither process environment files nor process command lines.

Running containers retain the same fields in `process_privileges`. Exact
package-to-process observations also retain those process privilege facts.
Container credentials do not produce host principal edges because this collector
does not establish a container account namespace mapping.

## Service identity relationships

`services[].execution_identity` is a derived comparison under
`service-process-identity/v1`. A service's `MainPID` must match an observed
process whose cgroup matches the service's `ControlGroup`. Missing or idle main
processes remain unknown. Numeric unit identities and nonsecret account-name
resolutions remain in `identity_resolution` with their sources.

The comparison records differences between effective process IDs and unit
settings. A difference can result from an application dropping privileges after
systemd starts it. It does not establish a configuration defect. Unresolved unit
identities remain unknown; an empty `User` value does not become an observed
root identity. Capability masks and systemd capability names remain separate
observations. `matched_identity` does not claim that every privilege setting was
verified.

A bound main process with an observed effective UID and one declared deployment
owner adds this derived relationship:

```text
service:<host>:<unit> --EXECUTES_AS--> principal:<host>:uid:<uid>
```

The UID comes from the process even when it differs from the unit setting.
The derivation references the unit and process observations. The lifecycle
converter attaches their retained evidence ID. A later snapshot without that
positive binding withdraws the previous edge while preserving its history.

## Selected filesystem metadata

`path_access` records metadata for already selected configuration files and the
exact executable and fragment paths of deployment-owned units. Collection adds
no directory walk. Each entry records ownership, mode, inode, device, and file
type. The collector follows each path component and retains every intermediate
symlink and directory. Relative targets and `..` resolve after preceding links,
in filesystem order. Cycles produce an incomplete record.

The collector reads only the `system.posix_acl_access` and
`security.capability` extended attributes. Present values remain hexadecimal
bytes. An explicit no-attribute response records absence; unsupported or denied
reads remain unknown. File contents, password records, and keys are not added.

Collection is bounded to 256 selected paths, 64 component traversals per selection,
64 KiB per extended attribute, and 1 MiB of retained permission metadata. Limits,
unavailable paths, and changes during a metadata read produce explicit gaps.

These facts describe the collector's filesystem namespace. They do not establish
the filesystem view inside a service's mount namespace or chroot. A complete
metadata record means its selected fields were read. It does not establish
effective write access, default directory ACLs, complete input coverage, or a
complete execution boundary.

## Drift and lifecycle decisions

Privilege facts for tracked application services, container processes, and exact
package consumers enter the runtime fingerprint. Selected permission metadata
also enters that fingerprint. Untracked transient units remain in the retained
evidence without changing the application fingerprint. Stable comparisons omit
process IDs and start times, so a
restart with unchanged privileges does not itself change that part of the
fingerprint. Changed or missing credentials invalidate the old observation.

This collection step adds no administrative deferral rule, applicability claim,
or new coverage assertion. Host access policy, SSH admission, untrusted data
paths, and enforced architectural constraints still need their own evidence.
The [CVE lifecycle](cve-lifecycle.md) owns work decisions.
