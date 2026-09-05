output "managed_containers" {
  description = "Managed LXC IDs and static addresses."
  value = {
    for name, container in proxmox_virtual_environment_container.managed : name => {
      vm_id   = container.vm_id
      address = local.managed_containers[name].address
    }
  }
}
