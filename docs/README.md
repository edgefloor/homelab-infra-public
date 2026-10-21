# Documentation

- [`procedures/dns.md`](procedures/dns.md) describes DNS ad filtering and its
  local blocklists, exceptions, and verification commands.

- [`procedures/dependency-track.md`](procedures/dependency-track.md) describes the
  conventional vulnerability inventory, daily collection, and recovery.
- [`procedures/dependency-track-matrix.md`](procedures/dependency-track-matrix.md)
  describes the prepared daily high and critical Matrix summary.
- [`procedures/retire-custom-cve.md`](procedures/retire-custom-cve.md) records the
  custom pipeline's shutdown procedure, retained data, and rollback guards.
- [`cve-lifecycle.md`](cve-lifecycle.md) and
  [`cve-lifecycle-implementation.md`](cve-lifecycle-implementation.md) retain the
  superseded custom design for recovery reference.
- [`current-deployments.md`](current-deployments.md) records the live systems
  and the date they were checked.
- [`access-design.md`](access-design.md) explains DNS, ingress, sign-in, and
  failure behavior.
- [`on-demand-exposures.md`](on-demand-exposures.md) records the retained Mac
  proxy and the retirement of the Python exposure command.
- [`cve-verification.md`](cve-verification.md) and
  [`autonomous-defense.md`](autonomous-defense.md) retain historical custom
  evidence and action-runner verification.
- [`adr/`](adr/) records decisions that would otherwise look accidental.
- [`../PLAN.md`](../PLAN.md) lists unfinished work.
- [`../inventory/routes.yml`](../inventory/routes.yml) is the routing source of
  truth.
- [`../ansible/README.md`](../ansible/README.md) contains deployment commands.

Start with the current deployment and Dependency-Track procedures. Historical
custom pipeline documents are marked as superseded and are not activation plans.
