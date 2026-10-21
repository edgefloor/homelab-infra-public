# Private VPS upload tunnel

Run `ansible-playbook playbooks/dependency-track-tunnel.yml --limit incident`
from `ansible/` after the Dependency-Track role completes. Tasks on the VPS are
explicitly delegated to `pangolin` through the existing Ansible connection.

`dependency-track-upload-tunnel.service` forwards VPS `127.0.0.1:8791` to
incident `127.0.0.1:8081`. VPS uploads use
`http://127.0.0.1:8791/api/v1/bom` and still require a Dependency-Track API key.
There is no public HTTP route or external listener.

The client key, local account, remote account, known-hosts file, SSH Match block
and systemd unit are separate from the retired incident tunnel. The remote
account permits only remote TCP forwarding to the exact loopback listener.
Local forwarding, Unix socket forwarding, shells, PTYs, agent forwarding and
password authentication are disabled. The VPS host key is read over the
existing trusted administration connection; the role does not trust
`ssh-keyscan` output. The play validates the complete SSH configuration and its
effective account restrictions before reloading SSH. Final checks require an
unauthenticated API request to return 401 and the socket to bind only loopback.

The old `homelab-incidents-reverse-tunnel.service` and its accounts are untouched
by this role and can be retired independently.
