# Proxmox guest lifecycle

This root owns the active production LXCs on `node1`. NextPlaid, Firecrawl,
and EU Law share the host but remain outside this root.

## Ownership

OpenTofu owns each Proxmox object and everything set from outside the guest.
That includes the VMID, hostname, CPU, memory, disk, host mounts, device
passthrough, network interface, boot order, and protection flag.

Ansible owns operating system and service configuration after the guest is
reachable. It also configures the physical Proxmox host where needed. Ansible
may create application directories and set permissions, but the application
owns the contents of its database and runtime state.

Proxmox backup jobs own guest recovery. The OpenTofu state lives on protected
and backed-up LXC 200.

`scripts/validate_infrastructure_ownership.py` checks both directions. Every
ordinary Ansible guest must match one OpenTofu guest by name and address, and
every OpenTofu guest must have an Ansible host. Route targets must resolve to
inventory unless the route declares why it cannot. The validator ignores
`inventory/workloads.yml` because that file is an observed snapshot.

Every guest has `prevent_destroy`. Removing one is a deliberate operation.
Back it up, remove the guard in the same reviewed change that removes the
resource, and inspect the plan before applying it.

The full ownership decision is in
[`../../docs/adr/0001-separate-infrastructure-and-guest-configuration.md`](../../docs/adr/0001-separate-infrastructure-and-guest-configuration.md).

## Run OpenTofu

Run this root on LXC 200. Its state stays outside the Actions checkout at:

```text
/var/lib/homelab-tofu/proxmox/terraform.tfstate
```

The provider reads credentials from the runner environment. Do not commit
them:

```sh
export PROXMOX_VE_ENDPOINT='https://10.42.0.99:8006/'
export PROXMOX_VE_API_TOKEN='root@pam!token-id=secret'
export PROXMOX_VE_INSECURE='true'
```

Use the installed wrapper. It loads the protected runner environment and the
external state path:

```sh
cd /opt/actions-runner/_work/homelab-infra/homelab-infra/tofu/proxmox
homelab-tofu init
homelab-tofu plan -out=/tmp/proxmox.tfplan
homelab-tofu show /tmp/proxmox.tfplan
homelab-tofu apply /tmp/proxmox.tfplan
```

Never apply a plan that replaces an adopted guest. Host mounts and some feature
changes require the current `root@pam` token. The token stays in
`/etc/homelab-tofu-proxmox.env`, readable only by root and the runner group.

Pull requests from the repository owner run a live, read-only plan. Nothing
applies on push. After a change reaches `main`, start the `Apply Proxmox`
workflow manually. It creates a fresh plan and applies that exact saved file.

## Adopt an existing LXC

1. Add its exact live configuration to `local.managed_containers`.
2. Initialize this root on LXC 200.
3. Import the guest:

   ```sh
   homelab-tofu import \
     'proxmox_virtual_environment_container.managed["name"]' node1/VMID
   ```

4. Reconcile the declaration until `homelab-tofu plan` shows no unintended
   change. Importing a guest does not authorize its recreation.
