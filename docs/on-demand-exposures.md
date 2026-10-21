# Mac exposure migration

The Python proof of concept is retired from the generic `expose` command.
Its installed executable was renamed to `~/.local/bin/expose-legacy` without
changing its bytes. No Go executable has been installed in its place.

Alagut is developed separately in `/Users/bubble/Documents/Dev/expose`. Its
provider and Caddy lifecycle are not yet a verified replacement for live exposure
operations. The legacy command remains a deliberate recovery tool while that
work continues. It is not a product transport fallback.

## Retained assets

The following assets remain unchanged:

- Caddy at `/opt/homebrew/bin/caddy`.
- LaunchAgent `fun.example.exposure-proxy`.
- Ingress `10.42.0.51:8090` and admin `127.0.0.1:2019`.
- Configuration, state, logs, and credentials in
  `~/Library/Application Support/homelab-exposure`.
- The Home Newt connector on LXC 210 at `10.42.0.210`.
- Pangolin, Pocket ID, wildcard DNS, and wildcard certificates.
- The isolated VPS Rickroll fallback for unused subdomains.

The LaunchAgent starts Caddy directly. It does not call the Python wrapper.
Existing application routes require an exact Host and the Home Newt source IP.
The user removed `learning.homelab.example`. Read-only checks confirmed that local
exposure state is empty and resource 25, target 25, and policy 10 are absent.
That exposure no longer needs preservation.

Unused one-label subdomains return the Rickroll page with HTTP status 404 over
valid HTTPS. HTTP redirects to HTTPS. No per-exposure DNS record is needed.

## Retired source

[`../scripts/legacy/mac_exposure/`](../scripts/legacy/mac_exposure/README.md)
contains the frozen Python implementation and its historical installer.
The installer has a `.retired` suffix and is not an installation entrypoint.
It would overwrite configuration and restart Caddy.

## Inspect or recover the retained proxy

Read local exposure state with `expose-legacy list`. That command does not call
Pangolin or read the API key. Mutation commands remain legacy operations and use
the old SSH transport. They are outside Alagut's management contract.

Inspect the running service with:

```sh
	launchctl print "gui/$(id -u)/fun.example.exposure-proxy"
	lsof -nP -iTCP:8090 -iTCP:2019 -sTCP:LISTEN
```

Recovery instructions for the old executable name are in the legacy directory.
Do not overwrite a newly installed Alagut executable with the legacy copy.

## Management API replacement

The Pangolin Integration API is available to the connected Mac at
`https://alagut-api.homelab.example/v1`. Private HTTPS terminates at the VPS
management connector. The documentation is at `/v1/docs/`; the root `/` has no
API route. Protected operations require a separate API key. The old `caddy-mac`
credential is not reused.

Public requests receive the Rickroll fallback with HTTP 404. Pangolin's
placeholder and frontend assets are not served at this hostname.
[`access-design.md`](access-design.md#client-private-resources) describes its
DNS and certificate maintenance. This management endpoint does not install or
complete the Go Alagut application.

Alagut must not adopt this Caddy process, LaunchAgent, state, or credentials.
Its test paths and listeners are separate. Home Newt and its blueprint remain
unchanged during preparation.
