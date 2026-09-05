# Use explicit ingress paths and split DNS

Browser applications use the Pangolin remote edge and the Caddy home edge,
while bandwidth-heavy or protocol-specific services have an explicit direct
route. CoreDNS returns the home path to local clients and public DNS returns
the declared remote or direct destination. There is no automatic failover
because a quiet DNS switch can bypass access policy or send clients to an
unhealthy copy of a service.
