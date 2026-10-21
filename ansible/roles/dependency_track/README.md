# Native Dependency-Track

This role installs Dependency-Track 5.2.0 on the existing `incident` guest. It
requires Debian 13 amd64, 8 GB RAM, and the existing 64 GB mount at
`/var/lib/homelab-incidents`. The new application, PostgreSQL cluster, and secret
encryption keyset live only below its `dependency-track/` subdirectory. Legacy
files remain untouched. Execute-only ACLs let the two new service accounts
traverse the legacy mount without reading its existing contents.

Run from `ansible/`:

```sh
ansible-playbook playbooks/dependency-track.yml --limit incident
```

The play delegates one read to `pangolin` for the existing Trivy token. That
credential is written root-only and imported into Dependency-Track's native
managed-secret store. No notification rule or message is created.

The API listens on `127.0.0.1:8081`, management on `127.0.0.1:9000`, and a
dedicated nginx process serves the frontend on `10.42.0.214:8080`. Both nginx
and a separate nftables table accept frontend traffic only from the main Caddy
host, `10.42.0.202`. The public URL is `https://vulns.homelab.example`; routing
is managed separately. nginx preserves the `/api/` prefix. A newly installed
default nginx service is masked; an existing installation is left alone.

Bootstrap runs against loopback before the frontend starts. It changes the
upstream default administrator password, verifies that login, enables the
existing authenticated Trivy analyzer for OS and language packages, and creates
the `homelab-sbom` service account. It uses standard APIs and does not implement
vulnerability matching, findings storage, or notification aggregation.

The scheduler stays disabled during first bootstrap. Native extension settings
disable the duplicate NVD, OSV, GitHub and JVN mirrors and the internal analyzer,
then enable Trivy with both `scanOs` and `scanLibrary`. This matters because the
NVD mirror and internal analyzer default to enabled in 5.2.0, and initial feed
jobs normally start within a minute. Normal scheduled metrics, reanalysis and
notification dispatch resume after configuration; the role does not disable
the whole scheduler permanently. Trivy supplies the matched vulnerability
records. EPSS/KEV enrichment keeps its upstream defaults.

Root-only credentials on `incident`:

- `/root/.config/dependency-track/admin.json`: administrator URL, username and
  generated password. This is an initial local account; configure the existing
  identity provider before broadening access.
- `/root/.config/dependency-track/upload-key.json`: the `key` field is the SBOM
  API key; `expires_at` is milliseconds since epoch. The account has only
  `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, and `VIEW_PORTFOLIO`. Keys last 365
  days. A role rerun renews a key with less than seven days remaining; distribute
  the resulting credential to uploaders after that rerun.

The bootstrap stops on errors without printing credentials or response bodies.
If an administrator changes the saved password separately, reconcile the
root-only file before rerunning; the role never resets a previously initialized
account using the default password. Preserve the credentials and PostgreSQL
backup together with `application/keys/secret-management-kek.json`. A database
backup without that keyset cannot recover the encrypted integration secrets.

The dedicated PostgreSQL 17 cluster is named `dtrack`, runs as
`postgresql@17-dtrack.service`, and uses port 5433 and its own data directory.
Distribution APT signatures verify PostgreSQL and nginx packages. The API's
heap is capped at 2 GB because it shares the guest with PostgreSQL. Monitor
memory, disk usage, and initial feed ingestion before raising scan concurrency.
The role validates configuration and waits for `/health/ready` to report `UP`.
Acceptance still requires uploading a real BOM and checking completed findings.

## Upstream artifact exception

The repository prefers native builds from pinned source. This deployment uses
the official native release distributions, explicitly selected for this
migration: the API archive carries the tested Java dependency set, the frontend
is its matching static release, and the Java runtime is an official Temurin
build. All three archives have fixed SHA-256 digests in `defaults/main.yml`;
executables are root-owned and services cannot rewrite them. No Docker runtime
or source build toolchain is installed. The backend release commit is
`d67a6a3a28006e95dcc7611553469bf89c6c9e0a`.

Verified upstream references:

- [5.2.0 release](https://github.com/DependencyTrack/dependency-track/releases/tag/5.2.0)
- [Native distribution layout](https://github.com/DependencyTrack/dependency-track/blob/5.2.0/apiserver/src/main/assembly/dist.xml)
- [Native Java launcher](https://github.com/DependencyTrack/dependency-track/blob/5.2.0/apiserver/src/main/docker/Dockerfile)
- [Java 25 requirement](https://github.com/DependencyTrack/dependency-track/blob/5.2.0/docs/adr/024-java-25-baseline.md)
- [Application configuration](https://dependencytrack.github.io/docs/next/reference/configuration/application/)
- [Database hosting and sizing](https://dependencytrack.github.io/docs/next/guides/administration/configuring-database/)
- [Trivy analyzer schema](https://github.com/DependencyTrack/dependency-track/blob/5.2.0/vuln-analysis/trivy/src/main/resources/org/dependencytrack/vulnanalysis/trivy/trivy-vuln-analyzer-config-v1.schema.json)
- [v5.2 API schemas](https://github.com/DependencyTrack/dependency-track/tree/5.2.0/api/src/main/openapi/resources)

The current v5 documentation is at `dependencytrack.github.io/docs/next/`;
the older `docs.dependencytrack.org` installation instructions describe v4.
