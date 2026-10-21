# Operational scripts

This directory contains validators and scripts installed by systemd roles.
Scripts must read secrets from restricted files or encrypted configuration.
They must not embed credentials.

`verify_alagut_private_api.py` checks the deployed management endpoint from a
connected Mac. It verifies public wildcard DNS, HTTP redirects, and the exact
Rickroll HTML with HTTP 404 for HTTPS requests to the VPS, including API and
frontend asset paths. It also checks private HTTPS health, API-key enforcement,
and documentation access.

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

The Python Mac exposure proof of concept is retired from the generic `expose`
command. Its frozen source and historical installer are in
[`legacy/mac_exposure/`](legacy/mac_exposure/README.md). The installed
`expose-legacy` command remains available for deliberate recovery until Alagut
has a verified provider replacement. The existing Caddy service is unchanged.
See [`docs/on-demand-exposures.md`](../docs/on-demand-exposures.md).

Run every script test with:

```sh
uv run python -m unittest discover -s scripts -p 'test_*.py'
```

Tests should protect observable outcomes and concrete failure modes. Share repeated
fixtures and exercise callers when a helper check cannot establish the claimed
behavior. Prompt wording, today's inventory counts, and incidental implementation
details are not test contracts. These tests use synthetic scanner/model responses
and mocked transports; passing them does not verify live systemd behavior, model
judgment, Matrix delivery, or production recovery. Those require separate workflow
verification, with explicit authorization before sending test Matrix messages.

`validate_infrastructure_ownership.py` compares OpenTofu guests, Ansible hosts,
and route targets. It does not read `inventory/workloads.yml`, which is an
observed snapshot rather than desired state.

`validate_security_coverage.py` checks that every application manifest and system
has declared coverage requirements in `inventory/security-coverage.yml`. CI runs
it; a passing result does not attest live scan coverage. Run it locally with
`uv run --with pyyaml python scripts/validate_security_coverage.py`.

`build_security_config.py` compiles the requirements and bounded runtime roots
into per-host configuration, the complete agent target map, and a retained
HelixDB lifecycle batch for declared route relationships. Declarations in that
batch do not claim effective enforcement.
`defense_readiness.py --directory /tmp/homelab-cve-coverage --output /tmp/homelab-cve-coverage/defense-readiness.json`
emits JSON evidence-layer and adapter statuses plus a short Markdown overview.
Configuration drift invalidates an otherwise recent scan.

`rehearse_lxc_restore.py` runs only on Proxmox and supports the downloads backup
fixture. Run it on Proxmox with an explicit `--archive`, reserved `--test-vmid`,
private `--output`, and `--exercise-recovery` to inject a failing executable and
verify rollback with the database unchanged. It removes networking and shared mounts,
checks a private network namespace before starting File Browser, and removes
the disposable guest. Its receipt does not certify a candidate patch or shared
storage recovery.

`verify_n8n_auth_compatibility.cjs RELEASE_DIR [HOOK_FILE]` imports a separately
installed n8n release's authentication classes and tests the Pangolin hook with
synthetic identities. It checks native token issuance, validation and MFA
enforcement without reading the live database or starting an HTTP listener.

`rehearse_n8n_restore.py --release CANDIDATE_DIR --output RECEIPT_PATH` runs as
root on the n8n host. It retains a private, consistent SQLite and encryption-key
backup, disables workflows only in a disposable copy, and starts the candidate
with loopback networking only under a fresh disposable system UID. The candidate
has no supplementary groups, capabilities or ability to gain privileges. Before
running it, the script verifies that production state, service secrets and the
production process are inaccessible under that identity. It checks database integrity, account and
workflow preservation, credential decryption and HTTP readiness, then removes
the disposable runtime and account. Its receipt records the isolation checks and whether production's process and
release stayed unchanged. The candidate must be under `/opt/n8n/candidates` and
use the explicitly reviewed version; this command does not activate it.
