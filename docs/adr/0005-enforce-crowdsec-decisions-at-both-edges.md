# Enforce CrowdSec decisions at both edges

The VPS and Caddy host run independent CrowdSec engines with local bouncers.
Each edge can still detect and block hostile traffic when the other site is
down. Both engines report to one console and one Matrix bridge, but neither
depends on the other to enforce a decision.
