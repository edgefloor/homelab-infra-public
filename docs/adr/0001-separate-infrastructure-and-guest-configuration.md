# Separate infrastructure and guest configuration

OpenTofu owns each Proxmox guest and the settings applied from outside it;
Ansible owns host and guest configuration after the machine is reachable.
Applications own mutable data, while backup automation owns recovery. This
keeps guest replacement decisions out of ordinary service deployments and
stops configuration tools from claiming database contents they cannot safely
recreate.
