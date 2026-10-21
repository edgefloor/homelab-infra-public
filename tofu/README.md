# OpenTofu

OpenTofu owns the Proxmox objects declared in this repository. Ansible takes
over after the host or guest is reachable.

The active root is [`proxmox/`](proxmox/). It adopted existing LXCs by import.
Bringing a guest under management never grants permission to recreate it.
