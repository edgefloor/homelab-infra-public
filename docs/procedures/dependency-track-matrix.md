# Dependency-Track daily summaries in Matrix

On 2026-10-15, after approval, the n8n workflow was published and the native
Dependency-Track rule enabled. n8n had no active executions before its brief
restart and returned healthy afterward. Independent read-back confirmed the
published workflow, enabled rule, expected destination and filter, and next
trigger at `2026-10-15T08:00:00Z`. No test message was sent. Earlier read-only
checks confirmed that the existing bot token is valid and the bot belongs to
the existing CVE room. The backend timezone correction was applied the same day.

The integration uses Dependency-Track's scheduled notification and the
existing n8n instance. Dependency-Track owns the daily schedule, selection of
projects, suppression of unchanged results, and high/critical filter. The n8n
workflow uses only built-in Webhook, If, and Matrix nodes. It formats counts and
links to the dashboard; it does not scan hosts, store a second findings database,
or run an investigation agent.

## Prepare an inactive draft

Use `ansible/playbooks/dependency-track-notifications-prepare.yml` after reviewing
`ansible/files/dependency-track-matrix-workflow.json` and
`ansible/files/dependency-track-notification-rule.json`. The first imported playbook creates or verifies the native `homelab/current`
collection and retains its UUID in root-only
`/root/.config/dependency-track/portfolio.json`. The summary targets that
collection with active children, so native BOM publishers use its `uuid` as the
`parentUUID` form field when creating host projects.

```sh
cd ansible
ansible-playbook playbooks/dependency-track-notifications-prepare.yml
```

The playbook imports an inactive workflow and saves a disabled notification rule.
It does not publish, activate, execute, or send a test message. An existing
workflow is left unchanged unless `dtrack_notification_refresh_inactive=true` is
explicitly supplied for a reviewed draft update. An active workflow or
notification rule causes the preparer to fail. A changed project list cannot silently retain unreviewed
existing projects.

The preparation reuses the bot token and room from Pangolin's root-owned
`/etc/crowdsec-matrix-bridge/matrix-access-token` and `matrix-room-vulnerabilities`.
It never prints either value. A dedicated webhook token is generated once at
`/etc/n8n/dependency-track-webhook-secret`, root-owned mode 0600. The n8n native
credential importer encrypts both credentials using the existing n8n encryption
key; temporary plaintext imports are removed in an `always` cleanup block.
Dependency-Track stores its copy as the managed secret `homelab-dtrack-n8n`.
The existing CrowdSec bridge and its credentials remain in place.

The webhook uses `X-Dependency-Track-Token` header authentication over HTTPS.
Its endpoint is `https://n8n.homelab.example/webhook/dependency-track-daily`.
Dependency-Track must resolve this name to the internal Caddy address and its
outbound allowlist must permit exactly `n8n.homelab.example`. The public Pangolin
login page is not a machine webhook endpoint. Check `/healthz/readiness` from the
incident guest through the internal HTTPS route before activation.

## Review and activation

In n8n, review **Dependency-Track daily summary to Matrix** and verify that its
room and credential references point at the existing vulnerability room. In
Dependency-Track, review **Homelab daily high and critical summary**:

- Publisher: native Webhook, using the managed secret for its authentication
  header and the default JSON template.
- Trigger: Schedule; group: `NEW_VULNERABILITIES_SUMMARY`.
- Projects: the reviewed list, with active child projects included.
- Schedule: `0 8 * * *`. Dependency-Track's JVM runs with `TZ=UTC` and
  `-Duser.timezone=UTC`, so the native scheduler evaluates this as 08:00 UTC.
  This is 09:00 in Budapest in winter and 10:00 in summer.
- Skip if unchanged: enabled. The CEL filter requires at least one new,
  unsuppressed high or critical finding.

Publish the n8n workflow first through its native UI/API, then enable the native
Dependency-Track alert. Confirm the next trigger is the intended next 08:00 UTC
run. Do not invoke a test publication to verify setup. Read back the active
workflow, enabled alert, project selection, and next trigger instead.

The prepared `dependency-track-notifications-activate.yml` performs that sequence
through the native CLI and API. It first checks for running or new executions,
publishes only `homelabDTrackDaily`, restarts n8n once to register the webhook,
and checks readiness before enabling the one prepared alert. Its read-back
reports the native next trigger timestamp. Run it only after reviewing the
destination and approving the one-time n8n restart. It does not call a Matrix
send endpoint or native test-alert endpoint.

The native scheduler uses the JVM default timezone; the cron expression alone
does not select UTC. The pinned [Dependency-Track scheduler](https://github.com/DependencyTrack/dependency-track/blob/5.2.0/apiserver/src/main/java/org/dependencytrack/model/NotificationRule.java)
calls javacron 1.4.0, whose `Date` methods use that default timezone.
`dependency-track-timezone.yml` corrects an existing backend
after its native jobs are idle, restarts only that backend, and recomputes the
prepared rule while leaving it disabled. Its acceptance check requires the
native API timestamp to be a future 08:00:00 UTC. The activation playbook applies
the same check before enabling and after read-back; it disables the rule if the
enabled read-back fails that check.

Each summary contains the native high/critical counts, up to 25 affected project
names with their counts, and the dashboard URL. No advisory description is
interpolated as HTML. A Matrix delivery error fails the workflow so that the
sender sees a failed request. Native delivery may be retried; this integration
does not add a separate delivery state machine.

Only new findings since the native scheduler's retained reporting boundary are
included. The existing backlog remains visible in Dependency-Track. This digest
does not report failed SBOM collection or prove every host has recent coverage;
those require separate standard operational monitoring.

To stop delivery, disable the Dependency-Track rule, then unpublish the n8n
workflow. Preserve the native workflow, rule, and encrypted credentials for
review or rollback. Do not re-enable the retired CVE stack to stop or repair this
integration.

## Upstream contracts

The implementation was checked against the pinned Dependency-Track 5.2.0 and n8n
2.42.6 source. The relevant upstream interfaces are the
[scheduled notification configuration](https://dependencytrack.github.io/docs/next/guides/user/configuring-notifications/),
[Webhook publisher](https://dependencytrack.github.io/docs/next/reference/notifications/publishers/#webhook),
[scheduled-summary CEL filters](https://dependencytrack.github.io/docs/next/reference/notifications/filter-expressions/#scheduled-alerts-only-when-critical-vulnerabilities-exist),
and [n8n native workflow/credential import](https://docs.n8n.io/hosting/cli-commands/#import-workflows-and-credentials).
