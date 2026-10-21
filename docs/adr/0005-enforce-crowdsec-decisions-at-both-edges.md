# Enforce CrowdSec decisions at both edges

The VPS and Caddy host run independent CrowdSec engines with local bouncers.
Each edge can still detect and block hostile traffic when the other site is
down. Both engines report to one console and one Matrix bridge, but neither
depends on the other to enforce a decision.

## Verification on 2026-10-21

The live Caddy and VPS engines each accepted short-lived manual decisions for
disposable IPv4 and IPv6 sources. HTTPS and SSH worked before each decision,
timed out after its firewall set update, and recovered after removal. Updates
arrived in about 1.3 to 10.2 seconds, consistent with ten-second polling. Forged
`X-Forwarded-For` and `X-Real-IP` headers did not bypass enforcement. Real access
logs and native `cscli explain` runs attributed requests to the disposable
source, rather than the forged loopback address.

The VPS HTTP bouncer was tested separately. Temporary HTTPS-only exceptions for
the disposable IPv4 source let requests reach Traefik while the decision remained
active. Traefik returned 403, including with forged forwarding headers, then
returned 200 after decision removal and its stream refresh. The exceptions were
removed with the fixture. Ordinary client traffic was never exempted.
The fixture's temporary rule counters recorded 339 forwarded packets and no
input-chain packets during the independent IPv4 HTTPS test, confirming that
the request traversed Docker's forwarding path.

The installed firewall binaries were also run in private network namespaces
with a fixture decision API. Both created effective IPv4 and IPv6 rules from an
empty ruleset, retained enforcement through six failed API polls, and rebuilt
the rules after a simulated ruleset loss and process restart. Live bouncers and
application services were not restarted for those failure tests.

Copy the applicable verifier to an edge and run it there as root:

```sh
python3 verify_crowdsec_ban.py --edge home --hostname jf.homelab.example
python3 verify_crowdsec_ban.py --edge vps --hostname matrix.homelab.example --http-bouncer
python3 verify_crowdsec_lifecycle.py
```

The ban verifier uses only `198.18.255.2` and `2001:db8:ffff:214::2`, refuses
existing decisions or conflicting routes, creates isolated clients, and removes
its decisions, temporary rules and interfaces. Decisions also expire after
three minutes. Its JSON receipt separates kernel enforcement from the optional
Traefik check. The lifecycle verifier uses synthetic decisions only inside its
private namespace and never contacts the production API.

The live ban verifier's manual decisions also produce Matrix security alerts.
The October 21 run delivered 14 alerts for its reserved fixture addresses;
these have no geographic country or flag. The verifier now uses the explicit
`homelab-ban-verification-` rule prefix. Read-back of real Matrix events from
both edges confirmed that ordinary public-IP alerts still contain their country
name and flag. The country database updater and renderer were healthy.

These tests prove native edge enforcement, client attribution and bounded
lifecycle behavior. They do not prove Internet IPv6 reachability, router port
forwarding under a ban, an unlimited API outage, or a host reboot. Actual IPv4
requests separately reached the home public Jellyfin route and the VPS route.
The protected home n8n route rejected a direct Internet request with HTTP 403.

One public-address trust exception remains unverified: both engines and the VPS
HTTP bouncer trust a fixed address whose current owner is not documented. The
owner was asked to identify it. It is not certified by these ban tests, and no
claim is made that trusted addresses are subject to the same policy as ordinary
Internet clients. Private-network and current home-DDNS exceptions are separate.
