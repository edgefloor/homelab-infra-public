# Proxmox guest lifecycle

This root owns the active production LXCs on `node1`. NextPlaid and EU Law
share the host but remain outside this root.

`virtual-machines.tf` retains the checksum-pinned Omarchy 4.0.4 installer
ISO in the Proxmox library. Desktop VM 300 and its disks were retired on
2026-10-12 at the owner's request.

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

The provider credentials in `/etc/homelab-tofu-proxmox.env`, the state tree,
and `/usr/local/bin/homelab-tofu` are readable and executable only by root.
Run the owning Ansible provisioning playbook from the workstation. It stages
this complete root in a protected work directory and invokes the wrapper with
privilege escalation. Review the plan guard for the intended guest before use.

For an operator-run investigation, stage a reviewed checkout outside the old
Actions work directory and invoke the wrapper as root. Never apply a plan that
replaces an adopted guest. Host mounts and some feature changes require the
current `root@pam` token; its scope is not a reason to expose it to CI.

Pull requests and main pushes run static checks on GitHub-hosted runners without
production credentials. The old LXC 200 Actions service is disabled. The
`Apply Proxmox` workflow refuses deployment until a separate production boundary
is implemented; normal provisioning remains available through Ansible.

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

Managed n8n LXC 216 uses a native runtime with nesting disabled. Provision it
with `ansible/playbooks/n8n-provision.yml`; the guard permits only its creation
and preserves retained installer media in the complete OpenTofu root.
