# Architecture decisions

- [0001: Separate infrastructure and guest configuration](0001-separate-infrastructure-and-guest-configuration.md)
- [0002: Use explicit ingress paths and split DNS](0002-use-explicit-ingress-paths-and-split-dns.md)
- [0003: Keep access and application authentication separate](0003-keep-access-and-application-authentication-separate.md)
- [0004: Run Matrix and MatrixRTC on the VPS](0004-run-matrix-and-matrixrtc-on-the-vps.md)
- [0005: Enforce CrowdSec decisions at both edges](0005-enforce-crowdsec-decisions-at-both-edges.md)
- [0006: Give the diagnostic agent bounded evidence access](0006-give-the-diagnostic-agent-bounded-evidence-access.md)

Record a decision only when it is hard to reverse, surprising without context,
and the result of a real trade-off. Use a short title and 1–3 sentences explaining
the context, decision, and reason. Add optional sections only when they explain
something the paragraph cannot.

Current behavior belongs in the operational docs, unfinished work in
[`PLAN.md`](../../PLAN.md), and routine configuration beside its code.
