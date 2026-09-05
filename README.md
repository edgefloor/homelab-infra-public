> [!NOTE]
> This is a generated, sanitized snapshot of a private homelab repository.
> Addresses, domains, identities, host keys, and provider details are examples.
> Changes made here are overwritten by the next publication.

# Homelab infrastructure

This repository manages a personal Proxmox homelab and the VPS in front of it.
The setup is small enough to understand in one sitting, but important enough
that a failed disk or careless upgrade should not turn into archaeology.

## Where to look

- [`docs/current-deployments.md`](docs/current-deployments.md) records the live
  hosts and services.
- [`inventory/routes.yml`](inventory/routes.yml) defines DNS, ingress, Pangolin
  resources, and access roles.
- [`docs/access-design.md`](docs/access-design.md) explains how requests and
  sign-ins reach each service.
- [`docs/adr/`](docs/adr/) records decisions whose reason is not obvious from
  the configuration.
- [`PLAN.md`](PLAN.md) contains unfinished work only.
- [`architecture/likec4/`](architecture/likec4/) contains the interactive
  architecture diagrams.
- [`ansible/README.md`](ansible/README.md) has deployment commands.

## What manages what

OpenTofu owns Proxmox guests. Ansible configures the Proxmox host, the guests,
and the VPS. Applications own their mutable data. Backup jobs own recovery.

Inside LXCs, deploy applications natively with Ansible, building from pinned
source by default. Docker inside an LXC is an exception that needs a concrete
application requirement and a recorded reason. An upstream Compose example or
deployment convenience alone is not that reason. Existing container deployments
must be evaluated individually, with state preserved during any migration.

`inventory/routes.yml` is the routing source of truth. It renders the Caddy
routes, CoreDNS answers, Newt Blueprint, and Cloudflare records. The validator
rejects paths that disagree.

The rest of the design is deliberately plain. Caddy is the home edge. Pangolin
is the remote edge for ordinary browser applications. Pocket ID provides OIDC.
Jellyfin and Matrix avoid Pangolin because their traffic and protocols do not
fit a browser access gateway.

## Repository layout

- `ansible/` contains playbooks and roles.
- `apps/` contains one manifest per managed application.
- `architecture/likec4/` contains diagrams generated from a hand-maintained
  model.
- `docs/` contains current-state notes and ADRs.
- `inventory/` contains non-secret topology, routes, and backup policy.
- `scripts/` contains validators and operational helpers.
- `tofu/` contains the Proxmox OpenTofu root.

## Validate a change

Create and populate the local Python environment with `uv`:

```sh
uv venv
uv pip sync requirements-dev.txt
```

Run the local checks before pushing:

```sh
uv run python -m unittest discover -s scripts -p 'test_*.py'
uv run python scripts/validate_app_manifests.py
uv run python scripts/validate_routes.py
uv run python scripts/validate_infrastructure_ownership.py
./scripts/test-production-wrapper
bun run diagrams:validate
git diff --check
```

See [`ansible/README.md`](ansible/README.md) for the pinned Ansible command.
