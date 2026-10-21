# Storage and backup problems

Check capacity, mounts and relevant service logs through approved reads. Distinguish a missing mount, full filesystem, failed backup and failed restore. Preserve the known-good backup. A successful backup exit does not prove recovery. Use existing backup and isolated recovery records, and identify candidate-specific recovery checks before any proposed deployment.

The Tuwunel receiver refuses a backup before contacting the VPS when free space
is below 128 MiB or twice the largest retained archive, whichever is larger.
It keeps the last four verified encrypted copies. A failed attempt retries after
15 minutes, with at most three starts in six hours. The receiver has a 20-minute
deadline and the remote archive command has a 10-minute deadline. The exporter
stops only services that were active and restores those same services afterward.
It never starts the retired CVE scanner. Watch both the unit result and archive
freshness; a successful LXC 200 snapshot can contain stale VPS backups.

`tuwunel-backup-health.timer` runs an hourly read-only check with up to five
minutes of jitter. Its service fails when no completed nonempty archive exists,
the newest archive is more than eight days old, or the backup service retains a
failure. Partial files and symlinks do not satisfy freshness. This check neither
starts backups nor clears their failures. It has a 30-second deadline and does
not decrypt archives during hourly checks.

Run `ansible-playbook playbooks/storage-policy.yml` from `ansible/` to apply the
pool-specific LVM policy in `inventory/backup-plan.yml`. The `homelab-thinpool`
metadata profile belongs to `pve/data`; the global LVM defaults may still show
100 percent. Inspect the effective values with
`lvmconfig --metadataprofile homelab-thinpool --type full activation/thin_pool_autoextend_threshold activation/thin_pool_autoextend_percent`.

The October 17 policy triggers at 80 percent and requests a 3-percent extension.
At 348.82 GiB, that needs about 10.46 GiB of the 16 GiB free volume-group space,
leaving about 5.54 GiB. The playbook requires a 5 GiB reserve before applying the
policy. This provides room for one automatic extension, not indefinite growth.
Plan capacity before a second extension is needed. No pool resize or disk
reallocation is part of the playbook.

`homelab-thinpool-health.timer` also runs hourly with up to five minutes of
jitter and a 30-second deadline. It fails at 80 percent data or metadata use,
when the managed profile or LVM monitoring is missing, or when VG space cannot
fund the next 3-percent extension plus the 5 GiB reserve. The required extension
rounds up to an actual VG extent. After the first extension, the remaining
5.54 GiB therefore triggers a capacity warning before another extension is
needed. Both health services expose failures through the existing Beszel
`SystemdFailed` alerts; they send no notifications themselves. Fixture tests
cover stale, absent, empty and partial backups, unresolved backup failure,
capacity boundaries, extent rounding and missing LVM monitoring. Both live
checks passed on 2026-10-17 and both timers are enabled.

`scripts/rehearse_beszel_restore.py` accepts a scheduled Beszel archive on the
VPS and starts its extracted database with the installed container image. It
checks SQLite integrity and application health inside a disposable container
with no external network, no published ports, a read-only root filesystem and
a writable private copy of the backup. It removes the container and copy when
finished and writes a receipt. This verifies same-version startup, not candidate
upgrade compatibility, agent collection, identity-provider login or alert delivery.
Run it after `beszel-backup.service` finishes, and pass explicit `--archive` and
`--output` paths. Never mount `/opt/beszel/data` into the rehearsal container.
