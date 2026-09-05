# Access design

The same application name may take a different path on the LAN and the public
internet. That is intentional. It keeps local access independent of the VPS
without pretending DNS can provide safe automatic failover.

The canonical route list is [`../inventory/routes.yml`](../inventory/routes.yml).
This document explains the rules behind it.

## Request paths

### Gateway routes

Pangolin protects ordinary remote browser applications. Public DNS points to
the VPS. Newt carries an allowed request to Caddy, and Caddy accepts that route
only from the trusted local network or Newt.

Current gateway routes are Beszel, Miniflux, Proxmox, Prowlarr, Radarr, Seerr,
Shelfmark, Sonarr, and Transmission.

### Direct-home routes

Pocket ID and Jellyfin reach Caddy through the home WAN. Pocket ID must remain
available when Pangolin is down because applications use it as their identity
provider. Jellyfin stays direct because media traffic does not belong on the
VPS.

### Direct VPS protocols

Matrix client traffic, federation, and MatrixRTC signaling terminate at
Traefik on the VPS. LiveKit exposes its required media ports directly. None of
these paths use Pangolin browser authentication.

### Internal routes

CoreDNS points local application names at Caddy. The ASUS UI, File Browser, and
NeroCD have no normal public application path. NeroCD is internal-only and its
containers publish no application or database port on the LXC address. Its
Caddy sidecar accepts traffic only from the main Caddy host.

## DNS

The router advertises CoreDNS as the primary LAN resolver. CoreDNS answers only
the exact local names rendered from `inventory/routes.yml` and forwards every
other query to its configured upstream resolvers.

Do not advertise a public resolver as a second DHCP server. Clients may use it
while CoreDNS is healthy, which makes the same name switch between its local
and public path.

The Cloudflare timer reconciles each declared A record. It discovers the home
WAN address only for direct-home records. Gateway and Matrix records keep the
declared VPS address. Records intentionally used only inside the network keep
their declared internal destination or remain absent from public DNS.

There is no DNS failover. If Pangolin is down, a local client still resolves a
gateway application to Caddy. A remote client waits for Pangolin to return.
Changing that automatically would blur the access boundary and could expose a
backend that was meant to require a Pangolin role.

## TLS and forwarded identity

Caddy terminates home TLS. Pangolin resources that travel through Newt connect
to Caddy with the application hostname as both SNI and the HTTP Host header.
Using only the tunnel IP breaks the TLS handshake.

Caddy accepts forwarded client and identity headers only from Newt, then
overwrites them at that boundary. A request arriving directly from the
internet cannot supply its own identity header.

## Sign-in model

Pangolin creates an access session. The application creates an application
session. These are separate jobs.

One Pocket ID session usually makes the second OIDC redirect silent, so a user
does not type credentials twice. Pangolin can also send a user directly to the
Pocket ID provider instead of showing its provider chooser. It cannot invent
an application session for software that supports neither OIDC nor a trusted
identity header.

The live services use these patterns:

| Service | Remote access | Application sign-in |
| --- | --- | --- |
| Pangolin | Direct VPS dashboard | Pocket ID for normal use; local TOTP administrator for recovery |
| Pocket ID | Direct home | Passkey or local identity flow |
| Jellyfin | Direct home | Native Pocket ID OIDC with retained local users |
| Beszel | Pangolin Infrastructure role | Native Pocket ID OIDC; password and trusted-header login disabled |
| Proxmox | Pangolin Infrastructure role | Native Pocket ID OIDC through the `sso` realm; `root@pam` retained for recovery |
| Seerr | Pangolin Media or Jellyfin role | Native Pocket ID OIDC starts after gateway authentication; the main user remains linked to its existing Jellyfin-backed record |
| Shelfmark | Pangolin Media role | Native Pocket ID OIDC with a local recovery administrator |
| Miniflux web | Pangolin Media role | Newt identity maps to an existing Miniflux user; LAN users use native Pocket ID OIDC |
| Miniflux APIs | Pangolin path exception | Native API or Google Reader credentials, without an interactive gateway page |
| Radarr, Sonarr, Prowlarr | Pangolin Media role | Forms login remains enabled; trusted local addresses bypass it |
| Transmission web | Pangolin Downloads role | No application password; the gateway protects remote browser use and LAN RPC stays local |
| File Browser | Internal only | Local application login |
| Tuwunel and MatrixRTC | Direct VPS protocols | Matrix password, token, and application-service flows |

The exact Beszel agent endpoint bypasses the Pangolin browser page and keeps
Beszel's agent-key authentication. The Miniflux API exceptions are equally
narrow. Neither exception opens the rest of the application.

Miniflux MCP is different again. Its outbound OpenAI tunnel connects directly
to the local MCP listener. Caddy and Pangolin do not publish it.

## Roles

Pocket ID groups map to Pangolin roles with the same job:

- `infrastructure` grants Beszel and Proxmox.
- `media` grants Miniflux and the media automation applications.
- `downloads` grants Transmission.
- `jellyfin` grants Seerr without granting the rest of media automation.

There are no direct per-user Pangolin resource grants. No OIDC group grants
Pangolin server administration. The local TOTP administrator remains outside
Pocket ID so an identity outage does not lock out the gateway itself.

## Failure behavior

| Failure | What still works | Recovery |
| --- | --- | --- |
| VPS or Pangolin | LAN applications through CoreDNS and Caddy | Repair the VPS; do not flip DNS |
| Pocket ID | Existing sessions and Pangolin's local administrator | Restore Pocket ID through LAN or Proxmox; use retained local application accounts where available |
| Newt | Pangolin administration and all LAN paths | Repair the connector on LXC 210 |
| CoreDNS | Services by private address | Repair LXC 211; use the documented workstation hosts file when a name is required |
| Caddy | Private application listeners and Proxmox by address | Repair LXC 202 from Proxmox or SSH |
| Home connection | VPS administration, Matrix, MatrixRTC, and Beszel Hub | Restore the home connection |

## Checks that define success

- A remote user can move among resources allowed by their roles without
  entering Pocket ID credentials again.
- A user without a role never reaches the backend.
- A direct request to the home WAN cannot bypass Pangolin for a gateway route.
- A LAN client resolves its application names to Caddy and does not depend on
  the VPS.
- Pangolin administration remains possible while Pocket ID or the home network
  is down.
- Jellyfin media, Matrix, MCP, and internal APIs never pass through browser
  authentication by accident.

The reasons behind the path and session boundaries are recorded in
[`adr/0002-use-explicit-ingress-paths-and-split-dns.md`](adr/0002-use-explicit-ingress-paths-and-split-dns.md)
and
[`adr/0003-keep-access-and-application-authentication-separate.md`](adr/0003-keep-access-and-application-authentication-separate.md).
