# Retired investigation storage

The custom CVE investigation pipeline and its cleanup timer are retired.
Personal Hermes uses `/var/lib/hermes-agent/.hermes` and remains active.
The lifecycle below documents the old storage format for recovery; it is not
an instruction to redeploy the investigation services. Legacy entrypoints
require explicit opt-in. See [the retirement procedure](procedures/retire-custom-cve.md).

## Workspace lifecycle

`homelab-workspace create INCIDENT_ID` creates a registered directory beneath
`/var/lib/homelab-investigator/jobs/` with `evidence` and `scratch` directories.
Reports, patches, evidence references and hashes, and essential reproduction
material belong in `evidence`. Downloads, extracted trees, build outputs, and tool
caches belong in `scratch`.

`homelab-workspace run JOB_ID -- COMMAND ARGUMENTS` runs from scratch and redirects
temporary files and common tool caches there. Output goes to `scratch/run.log`.
Before `homelab-workspace finish JOB_ID`, preserve the relevant output in evidence.
The cleanup timer removes completed scratch after twenty-four hours. It never
expires evidence, unfinished jobs, or legacy workspaces.

The helper admits at most four unfinished workspaces. It reserves one GiB per
unfinished workspace when admitting new work and requires three GiB of root-disk
headroom beyond those reservations. Each command has a twenty-minute deadline,
a one-GiB file-size limit, and checks for one GiB of job scratch, four GiB of total
scratch, and the three-GiB free-space threshold. Crossing a limit stops its process
group. Descendants cannot intentionally remain running after the command returns
within that process group.

These are admission checks and sampled usage limits, not filesystem quotas.
Commands can briefly overshoot aggregate limits between checks. Commands run
outside the helper are not constrained by it. The capability instructs Zag to use
the helper for investigation downloads and builds and to report refused budgets.
The isolated investigation worker still has no arbitrary shell tool or access to these
personal capability workspaces. Model execution remains disabled.

## Shared archives

`homelab-workspace cache-add ABSOLUTE_PATH SHA256` verifies an archive and returns
its content-addressed path in `/var/cache/homelab-investigations`. Archives are
read-only and shared through hard links on the same filesystem. Reuse the returned
path instead of downloading another copy. Never modify shared objects.

The cache admits at most two GiB and rejects artifacts larger than one GiB.
Cleanup removes an unused cache object after seven days only when it has no other
hard links. Existing references therefore remain valid. Cache limits refuse new
objects rather than breaking references. Evidence is not an eviction candidate.

## Existing workspaces

The pre-policy directories under `/var/lib/homelab-investigator/work/` have no
reliable completion or disposable-file manifest. Automatic cleanup cannot safely
classify them. On October 20, the entire retired tree was archived instead of
classifying individual files as disposable. Its root-only cold archive is
`/data/backups/retired-cve/2026-10-20/lxc-201-work.tar.zst` on Proxmox.
The adjacent SHA-256 and JSON receipt record integrity and a complete native tar
comparison against the source, including ownership, modes, ACLs and xattrs.
Only after those checks passed was the original tree removed from LXC 201.
The guest reclaimed 12.35 GiB; personal Hermes remained on the same process and
kept its state, tools, and memory. No open file references or nested mounts were
present in the removed tree. Restore into a temporary directory for inspection;
restoring files does not require restarting the retired pipeline.

The reviewed Actions Runner 2.337.0 archive occurred nine times with SHA-256
`70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613`.
`homelab-workspace consolidate-runner` replaced these copies with hard links to
one verified object. Every original path retains identical bytes. The operation
records references in `jobs/legacy-runner-artifact.json`. No legacy source tree,
patch, report, or session history was deleted.

On 2026-09-08, consolidation, Go build-cache cleanup, and Grype database-cache
cleanup reclaimed about 5.4 GiB. The Go cache was cleared with `go clean -cache`.
Grype's `db delete` removed the cached v6.1.9 database built on 2026-09-07.
The download archive's SHA-256 was
`73fb33bdf73a355ff5d4e6d86cb3671ced44437d1579524d8d7874c93ba23a44`.
Its download reference is retained below for reproducibility:
`https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-07T00:35:55Z_1788763100.tar.zst`.
These caches can be rebuilt or downloaded again. Source modules and investigation
reports were not removed. Trivy's subsequent successful database download used
about 1.3 GiB, leaving about 5.4 GiB free on the unchanged 32-GiB root disk.
The subsequent [shared Trivy migration](trivy-central.md) removed that local
database again. Hermes then had about 6.7 GiB free. Zag's capability now prohibits
standalone Trivy and Grype database downloads into investigation workspaces.

## Verification

Before retirement, the cleanup service ran as the Hermes account, without
network access, personal Hermes-home access, or legacy-workspace access. Its
writable paths were the new workspace root and shared archive cache. Its hourly
timer is now disabled.

Regression tests cover evidence preservation, unfinished and locked jobs, symlink
escapes, hash mismatch, admission limits, and oversized command output. Use
`homelab-workspace status` for current storage usage. Service failures remain
visible in systemd. Retention never replaces the requirement to review completed
investigation output before marking it finished.
