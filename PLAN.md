# Homelab plan

This file contains unfinished work. Current design belongs in `docs/`, and
completed work belongs in Git history.

## Next

- Close the remaining defensive coverage gaps: Rust build inventories, shipped
  browser assets, plugins, vendor advisories, operational tools, scheduled-job
  classification, stopped images, changed or mounted container code, and effective
  exposure. Add independent detection of stale or abruptly terminated scans.
  Require current evidence or an explicit gap for each deployment and adapter;
  test that an undeclared service is reported and the two Caddys retain separate
  exposure conclusions.
- Enforce repository ownership before enabling any defensive action. Bind the
  target, build inputs, candidate hash, policy, and owning Ansible deployment to
  an exact committed revision. Reject unexpected target or policy drift and
  verify managed artifacts and configuration afterward, including an Ansible
  rerun without unexpected changes. Do not treat the existing production wrapper
  as an implemented deployment pipeline.
- Coordinate emergency actions, normal deployments, and rollback. Use a shared
  deployment lock; make active temporary overrides visible
  to it; reconcile Git after rollback or permanent containment. Test a normal
  deployment during containment, expiry, interrupted apply, failed recovery,
  and retry after rollback. Verify control access survives, failed recovery
  escalates, and the next deployment cannot reintroduce a reverted patch.
  [Current implementation and limits](docs/autonomous-defense.md).

1. Exercise recovery for Beszel and the other stateful applications, shared
   storage, and candidate schema compatibility before enabling a patch policy.
   Inject a failed candidate and verify restoration with application data intact.
2. Set a useful `local-lvm` thin-pool autoextend threshold before capacity
   becomes tight.
3. Restrict PostgreSQL on LXC 115 to the clients that use it.
4. Tighten secret-bearing files that remain world-readable after checking the
   service account for each file.

## Later

- Migrate NeroCD to a native Ansible source build after adapting its production
  artifact validation and rehearsing PostgreSQL restore. Preserve the main
  proxy-only ingress restriction and existing backups. See the migration notes
  in `docs/current-deployments.md`; Docker is not the default for LXC applications.
- Replace the ASUS router with OPNsense when the N100 is ready. Keep the
  existing split DNS policy.
- Add VLANs when a real isolation need is worth the routing and recovery work.
- Add off-site backup storage after choosing a target and retention policy.
- Revisit device identity when the Pangolin client is reliable enough for
  daily use.

## Not planned

- Cloudflare Tunnel, Gatus, `jf-tunnel`, or a WireGuard dashboard.
- Automatic failover between home and the VPS.
- A second login page where a service can use its own OIDC flow.
- Multi-operator approval processes for a one-person homelab.
