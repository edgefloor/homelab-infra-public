# Investigation evidence budget

Status: deployed on 2026-09-08. The controlled investigation's evidence-projection
and coverage-consistency defects are fixed and verified through live read-only
checks. The manual-request worker is now enabled after artifact-tool acceptance.
Automatic investigations remain disabled. This revision replaces the API output-token gate.

## Ownership

`investigation_evidence.py` owns what evidence enters the investigation.
The worker presents a compact incident overview and exposes one typed evidence
tool. Raw snapshots, personal history, and whole tool dumps are not prompt input.
The provider adapter handles credentials, job admission, and transport. It removes
output-limit parameters instead of adding `max_output_tokens`.

`IncidentStore.authorize_work` owns durable counters. The worker charges evidence
before returning it to the model. Each remote read charges one tool call and
reserves its full 4,000-byte response allowance before execution. Failed reads,
duplicate responses, and unused reserved bytes remain charged. A denied
reservation prevents the remote read.
The proxy authorizes each model call against the active job lease. Every charge
requires the current fence and deadline. Restarting a process cannot reset a
claimed job's counters. The old `reserve` action is no longer accepted.

## Limits

Each investigation receives at most 20,000 UTF-8 bytes of serialized evidence.
This is a conservative textual token allowance, not exact tokenizer accounting.
The initial evidence envelope is at most 6,000 bytes and each tool response is at
most 4,000 bytes. Small budget-denial notices and fixed prompt instructions are
outside the evidence allowance.

The initial overview lists affected sources, coverage uncertainty, and occurrence
counts, observation times, and source scan sequences. It removes duplicate projected
rows and excludes verbose advisory text. Large responses preserve nested receipt
structure, prioritizing metadata and matching findings over broad inventories.
Lists retain complete entries. JSON-pointer paths identify omitted fields and
omitted entry counts. A content hash identifies the original result.
Repeated evidence returns a reference rather than another full copy. Hashes are
identifiers, not an assertion that the underlying evidence was complete or safe.

Each job permits at most twenty tool calls and twenty model calls, with a fifteen-minute
outer deadline. The native runner also limits iterations and run duration.
The evidence allowance usually limits successful remote reads to fewer than
twenty. Idle workers exit without waiting, so idle time does not consume a later
job's process deadline. Systemd supplies the restart delay.
Admission allows five started jobs per UTC day, one running job, ten queued jobs,
and deferred overflow. These preserve the previous effective five-job daily
admission ceiling without describing it as a provider token reservation.

## What this does not guarantee

Evidence limits do not cap generated reasoning or provider-billed output tokens.
They also do not count repeated transmission of the conversation, tool schemas,
or framework prompts. The proxy retains a 60,000-byte request transport limit.
That is a request safety limit, not a promised total-token ceiling.

When evidence admission fails, the tool returns no evidence and instructs the
agent to conclude with uncertainty. Call limits and the process deadline bound
further work. They do not guarantee that the model voluntarily follows that
instruction or that closing a stream cancels all provider computation.

Memory isolation is unchanged. Operational evidence never enters personal Honcho
through this workflow. The worker has no personal profile, memory provider,
arbitrary terminal tool, or personal-home access.

## Verification and rollout

Tests cover bounded valid JSON, explicit omissions, duplicate references,
budget exhaustion before remote execution, durable counters, role checks,
stale fences, deadlines, and the absence of provider output-limit parameters.
The provider-adapter and durable-budget tests failed before implementation.

The coordinated [runtime rollout](../ansible/playbooks/incident-runtime-rollout.yml)
updated the incident API, worker, evidence module, and proxy with the worker
stopped. It also deployed reviewed advisory-withdrawal and alias-correction support.
The migration rehearsal preserved all existing record counts. Production SQLite
passed integrity and foreign-key checks after deployment.

The initial rollout's local suite passed 254 tests. Three new regression tests failed
before the review fixes: exhausted evidence still allowed a remote read, idle
waiting consumed the process deadline, and new aliases left withdrawal
assessments current. All pass after the fixes.

The deployed worker passed its no-model-call constructor and memory-isolation
self-test against installed Hermes. The check inspects the actual agent tool
catalog and valid tool names. Implicit tool-search helpers are disabled in the
operational profile. Personal Zag and Honcho settings were not changed by this rollout.

Live probes verified role denial, invalid-job rejection before provider access,
and rejection of the removed `reserve` action. No jobs or model calls were created.
These probes were followed by the controlled investigation described below.

### Controlled investigation

The operator-approved canary for `CVE-2026-2303` completed on 2026-09-08 as
`job_f8317c22788f4084b605c1bebe221a16`. It covered the firewall-bouncer binary on
Caddy and Pangolin. Replaying the admission request ID retained one job.

The native runner made two evidence calls and three model calls. Durable counters
recorded 9,646 reserved evidence bytes out of 20,000. The single-job service used
the deployed worker's isolation settings with `Restart=no` and exited successfully.
The normal worker remained stopped and disabled. One current assessment was
delivered as a reply to the incident's Matrix root. The model kept the two
installation conclusions separate and made no claim that either was safe or fixed.

Provider compatibility, duplicate admission, durable accounting, and assessment
delivery passed this test. Evidence quality did not pass activation review:

- The formatter omitted Pangolin's nested response entirely. A read-only
  diagnostic reproduced a roughly 6.8 KB response whose nested `result` cannot
  fit as one field in the 4,000-byte envelope. This was corrected by nested
  projection with explicit omissions, described below.
- Caddy's coverage response had no matching finding despite its affected incident
  occurrence. The model reported the discrepancy. The old local scan-state files
  retained only HIGH and CRITICAL findings, while incidents retained every severity.
  The acknowledged snapshot reader described below corrects this mismatch.

The [canary playbook](../ansible/playbooks/incident-canary.yml) requires an explicit
`canary_job_id` and refuses competing pending or running jobs. It creates no
investigation request and does not enable the normal worker. Personal Zag and
Honcho configuration were unchanged by the test.

### Evidence correction rollout

The [evidence rollout](../ansible/playbooks/incident-evidence-rollout.yml) deployed
the snapshot writer and coverage reader to all thirteen enrolled hosts. It also
updated the isolated worker's projection module. Containers below 200 were not
deployment targets and are rejected by the playbook.

After central upload acknowledgement, each source atomically replaces
`/var/lib/homelab-update-monitor/cve-state.incident-snapshot.json`. This retains one
snapshot, bounded by the existing 32 MiB payload limit plus its hash envelope.
Failed uploads preserve the preceding acknowledged snapshot. No local history
accumulates. The migration restored the twelve existing source snapshots from
central records without new scans, overwriting local receipts, or enrolling sources.
At migration, Hermes had no successful snapshot. Its later scanner declaration
correction restored uploads, and all thirteen sources now have accepted snapshots.

Coverage responses validate the snapshot hash and configured source generation.
They expose the source, generation, sequence, hash, and observation time. Snapshots
older than 36 hours and later scan failures cannot establish fresh coverage.
Positive findings remain visible. Missing or corrupt acknowledged snapshots never
fall back to severity-filtered state on enrolled hosts. Empty scan matches do not
prove remediation or erase incident history.

The full suite passed 263 tests. Failing-before checks reproduced nested receipt
loss, the severity-filtered mismatch, missing acknowledged evidence retention,
and unsafe fallback after corruption. Additional checks cover stale evidence,
source-generation mismatch, upload failure, and UTF-8 byte bounds.

Live checks as `zag-ops` retained the MEDIUM `CVE-2026-2303` finding for both
Caddy and Pangolin. Their projected envelopes measured 3,775 and 3,904 bytes.
Both retained observation IDs, complete matching findings, central-matching
snapshot hashes, and explicit omitted inventory counts. No new model calls or
investigations were created. The normal worker remained stopped and disabled.

Private rollback copies are retained on Pangolin at
`/var/backups/homelab-incidents/runtime-rollout-w_v0_1ee` and on Hermes at
`/var/backups/zag-runtime-rollout-obhgpoyw`. The Pangolin copy includes a consistent
database backup. Restoring that database after new uploads would lose subsequent
state, so rollback requires a separate decision rather than an automatic restore.

The distinction between an evidence allowance and generated-token limits follows
the [Responses API definition of output limits and usage](https://developers.openai.com/api/reference/typescript/resources/beta/subresources/responses/methods/create).
