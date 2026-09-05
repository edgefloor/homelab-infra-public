# Operational scripts

This directory contains validators and scripts installed by systemd roles.
Scripts must read secrets from restricted files or encrypted configuration.
They must not embed credentials.

`cve_coverage_report.py` correlates a CVE across snapshots collected by
`ansible/playbooks/cve-coverage.yml`. It reads all observed workloads and Ansible hosts,
keeps missing/failed/stale scans unknown, and lists matching artifact/package
occurrences. It does not claim runtime exploitability or send notifications.
The collection and report commands are in
[`docs/cve-verification.md`](../docs/cve-verification.md#cross-host-detection-audit).

`homelab-production-deploy` is the fail-closed deployment wrapper. Test its
contract from a normal checkout:

```sh
./scripts/test-production-wrapper
```

`install-production-wrapper` writes root-owned system files. Run it only when
installing or repairing the runner.

`cloudflare_ddns_v1.py` reconciles the DNS records declared in
`inventory/routes.yml`. Its generated JSON configuration names an absolute
credential file. That file contains only the Cloudflare token and must not be
readable by group or other users.

Run every script test with:

```sh
uv run python -m unittest discover -s scripts -p 'test_*.py'
```

`validate_infrastructure_ownership.py` compares OpenTofu guests, Ansible hosts,
and route targets. It does not read `inventory/workloads.yml`, which is an
observed snapshot rather than desired state.

Preview CVE alerts from synthetic saved investigations without model calls or
sending notifications:

```sh
python3 scripts/replay_cve_investigations.py --output /tmp/cve-alert-preview.md
```

The replay reports assessment coverage, observation failures, message counts,
and word counts. Fixtures and expected alert text are in `scripts/fixtures/cve/`.
See [`docs/cve-verification.md`](../docs/cve-verification.md) for the record and
alert contracts and live rollout checks.

`validate_security_coverage.py` checks that every application manifest and system
has declared coverage requirements in `inventory/security-coverage.yml`. CI runs
it; a passing result does not attest live scan coverage. Run it locally with
`uv run --with pyyaml python scripts/validate_security_coverage.py`.

`build_security_config.py` compiles the requirements and bounded runtime roots
into per-host configuration and the complete agent target map.
`defense_readiness.py --directory /tmp/homelab-cve-coverage --output /tmp/homelab-cve-coverage/defense-readiness.json`
emits JSON evidence-layer and adapter statuses plus a short Markdown overview.
Configuration drift invalidates an otherwise recent scan.

`rehearse_lxc_restore.py` runs only on Proxmox and supports the downloads backup
fixture. Use its Ansible playbook; it removes networking and shared mounts,
checks a private network namespace before starting File Browser, and removes
the disposable guest. Its receipt does not certify a candidate patch or shared
storage recovery.
