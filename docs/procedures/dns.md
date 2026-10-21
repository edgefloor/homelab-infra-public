# Manage local DNS ad filtering

CoreDNS at `10.42.0.211` blocks domains locally with its built-in `hosts`
plugin. A daily systemd timer downloads the StevenBlack base hosts list. The
updater generates both IPv4 and IPv6 sinkhole records and retains a cached copy
of the source domains. Failed downloads and implausibly small lists leave the
last valid files in place.

Internal homelab names come from `/etc/coredns/internal.hosts`. The updater
excludes the whole `homelab.example` domain from blocking, so those records cannot
collide with generated sinkhole records. CoreDNS 1.14.7 combines duplicate file
and inline answers; the protected-domain rule provides this isolation.
Unblocked public requests go to Cloudflare's ordinary resolvers over
DNS-over-TLS with certificate verification for `cloudflare-dns.com`. Filtering
and exceptions do not depend on an upstream filtering provider.

## Change sources, exceptions, and extra blocked names

Edit `ansible/inventory/group_vars/network_ops.yml` in this repository:

```yaml
coredns_adblock:
  sources:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  allowlist:
    - needed.example
  extra_domains:
    - unwanted.example
```

Allowlist entries exempt the named domain and all its subdomains. They take
precedence over downloaded and extra blocked domains. Extra blocked names match
exactly. Use plain domain names without URLs or wildcard characters.

Sources must be HTTPS hosts-format files containing at least 10,000 valid
blocking domains each. The updater accepts up to ten sources and rejects files
larger than 16 MiB. Every redirect must also use HTTPS; an insecure hop is
rejected before it is followed. It does not accept browser extension filter
syntax.

Apply the rules from `ansible/`:

```sh
uvx --from ansible-core==2.19.4 ansible-playbook playbooks/coredns.yml
```

The playbook manages CoreDNS and its local updater. It verifies service health,
all internal names over UDP and TCP, public forwarding, and a blocked domain's
A and AAAA answers. It chooses the blocked test domain from the generated list,
so allowing an individual advertising domain does not break deployment checks.
The blocking check waits for the hosts reload and any previously cached answer
to expire, without requiring a DNS restart.

## Apply an urgent exception on the DNS host

For an immediate change, edit `/etc/coredns/adblock.json` on `network-ops`, then
rebuild from the cached source without downloading anything:

```sh
sudo -u coredns /usr/local/libexec/coredns-adblock-update
```

Record the same change in the repository before the next Ansible deployment,
which replaces this generated JSON configuration.

CoreDNS reloads the hosts file within five seconds. Existing answers can remain
cached for up to their TTL. CoreDNS's own cache and generated records use a
60-second TTL. A DNS restart clears the resolver's cache if an urgent exception
needs to take effect immediately:

```sh
sudo systemctl restart coredns.service
```

## Check filtering and update health

From a LAN client, run:

```sh
dig @10.42.0.211 doubleclick.net A +short
dig @10.42.0.211 doubleclick.net AAAA +short
dig @10.42.0.211 jf.homelab.example A +short
```

With the default rules, the answers are `0.0.0.0`, `::`, and `10.42.0.202`.
An allowlist exception for `doubleclick.net` changes the first two answers.

On the DNS host, inspect the daily timer and its last result:

```sh
systemctl list-timers coredns-adblock-update.timer
systemctl status coredns-adblock-update.service
journalctl -u coredns-adblock-update.service -n 20
```

The timer runs daily with up to one hour of jitter and catches up after downtime.
An unsuccessful refresh leaves the last valid list serving DNS and marks the
update service failed. Check the service result even when the timer is active.
Trigger a download and rebuild now with:

```sh
sudo systemctl start coredns-adblock-update.service
```

The generated list is `/var/lib/coredns/adblock/blocked.hosts`. The cached source
is `/var/lib/coredns/adblock/source-domains.txt`. Do not edit these files;
update the rules or source configuration instead.

Devices must use `10.42.0.211` to receive this filtering. A browser using its
own DNS resolver can bypass it. DNS filtering cannot remove advertising served
from the same hostname as wanted content, such as many YouTube ads.

References: [CoreDNS hosts plugin](https://coredns.io/plugins/hosts/),
[StevenBlack hosts](https://github.com/StevenBlack/hosts), and
[Cloudflare DNS-over-TLS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/).
