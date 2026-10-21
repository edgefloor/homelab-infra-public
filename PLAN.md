# Homelab plan

This file contains unfinished work. Current design belongs in `docs/`.
The custom CVE, Helix, Zig, and autonomous-action plans are retired.
[Dependency-Track](docs/procedures/dependency-track.md) is the active inventory
and advisory system. Historical design remains in
[autonomous-defense.md](docs/autonomous-defense.md); keep its state for recovery
and do not resume the retired agents or evidence gateway.

## Scope

The owner narrowed audit and remediation work on 2026-10-20 to containers with
IDs 200 and above, the Proxmox host, the VPS, and shared infrastructure those
systems depend on, including storage, backups, DNS, routing and identity.
Guests below 200, including PostgreSQL on LXC 115, are outside this work.
Their presence in historical inventories does not make them remediation tasks.
Keep the existing intentional backup exclusions.

## Next

Refresh live evidence before changing a service. The October 20 health,
recovery and remediation results are in `docs/current-deployments.md` and
`inventory/backup-plan.yml`.

The October 21 native edge and recovery probes passed. Identify the owner of
the fixed public-IP CrowdSec trust exception before retaining or removing it;
it is separate from the observed home WAN address and the VPS. Both native
parsers demonstrably skip that source, and the VPS HTTP bouncer also trusts it.

1. Keep n8n's Git node, source-control and promotions modules disabled until
   its consumers support a patched simple-git release. The reviewed 2.43.8
   dependency set has 19 npm advisory matches, including two critical Git
   findings and an unpatched high-severity braces finding. Native loader and
   bounded file-selector checks establish the current containment limits.
   Revisit those packages when compatible fixes exist; do not suppress the
   findings or force an incompatible major version into production.
2. Extend application-aware recovery checks before changing the remaining
   stateful services or shared storage. Pocket ID, Beszel, File Browser and
   n8n have passed isolated application checks; Dependency-Track has passed
   database recovery and a complete logical export. External identity flows,
   full Matrix recovery and shared media/data recovery remain untested.
3. Plan host capacity before a second automatic thin-pool extension. The
   current 16 GiB VG reserve permits one 3% extension while retaining the
   configured 5 GiB reserve. Keep the existing storage-health alert active.

## Later

- Migrate NeroCD to a native Ansible source build after adapting its production
  artifact validation and rehearsing PostgreSQL restore. Preserve the main
  proxy-only ingress restriction and existing backups. See the migration notes
  in `docs/current-deployments.md`; Docker is not the default for LXC applications.
- Replace the ASUS router with OPNsense when the N100 is ready. Keep the
  existing split DNS policy.
- Add VLANs when a real isolation need is worth the routing and recovery work.
- Revisit device identity when the Pangolin client is reliable enough for
  daily use.

## Not planned

- Additional off-site backup storage, declined by the owner on 2026-10-15.
- Resuming the custom CVE/Helix incident engine, Zig pipeline, or evidence gateway.
- Auditing or modifying guests below container ID 200 as part of this work.
- Adding backups for deliberately excluded guests below container ID 200.
- Cloudflare Tunnel, Gatus, `jf-tunnel`, or a WireGuard dashboard.
- Automatic failover between home and the VPS.
- A second login page where a service can use its own OIDC flow.
- Multi-operator approval processes for a one-person homelab.
