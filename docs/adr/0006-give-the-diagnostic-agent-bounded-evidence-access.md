# Give the diagnostic agent bounded evidence access

Status: retired on 2026-10-17 with the custom CVE agent. Endpoint SSH and sudo
access is revoked; the on-call tools are removed from personal Hermes. See the
[retirement procedure](../procedures/retire-custom-cve.md). The rationale below
is retained as historical context.

Scanners provide normalized findings, then the agent chooses typed read-only
checks. For artifact analysis, the client identifies a retained CVE alert and
the gateway owns a short-lived capability bound to its target and scanner scope.
The agent never handles the capability token. The gateway redacts secrets,
limits resources, and records attributable observations. Mutation stays on a
separate allowlisted command path. The agent can investigate without a general
shell over the homelab.
