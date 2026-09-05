resource "proxmox_virtual_environment_container" "managed" {
  for_each = local.managed_containers

  node_name = var.node_name
  vm_id     = each.value.vm_id

  started       = true
  start_on_boot = true
  protection    = each.value.protection
  unprivileged  = true

  console {
    enabled   = true
    tty_count = 2
    type      = "tty"
  }

  dynamic "cpu" {
    for_each = each.value.cores == 1 ? [] : [each.value.cores]
    content {
      architecture = "amd64"
      cores        = cpu.value
    }
  }

  memory {
    dedicated = each.value.memory
    swap      = each.value.swap
  }

  disk {
    datastore_id = "local-lvm"
    size         = each.value.disk_size
  }

  operating_system {
    template_file_id = var.debian_template_file_id
    type             = "debian"
  }

  initialization {
    hostname = each.value.hostname

    dns {
      domain  = each.value.dns_domain
      servers = try(each.value.dns_servers, ["10.42.0.1"])
    }

    ip_config {
      ipv4 {
        address = each.value.address
        gateway = "10.42.0.1"
      }
    }
  }

  network_interface {
    name        = "eth0"
    bridge      = "vmbr0"
    firewall    = each.value.firewall
    mac_address = each.value.mac_address
  }

  dynamic "features" {
    for_each = each.value.nesting || each.value.keyctl ? [1] : []
    content {
      nesting = each.value.nesting
      keyctl  = each.value.keyctl
    }
  }

  dynamic "startup" {
    for_each = each.value.startup_order == null ? [] : [each.value.startup_order]
    content {
      order = startup.value
    }
  }

  dynamic "mount_point" {
    for_each = each.value.mount_points
    content {
      volume = mount_point.value.volume
      path   = mount_point.value.path
      backup = mount_point.value.backup
    }
  }

  dynamic "device_passthrough" {
    for_each = each.value.devices
    content {
      path = device_passthrough.value.path
      mode = device_passthrough.value.mode
    }
  }

  lifecycle {
    prevent_destroy = true

    # Proxmox does not retain which template originally created an existing
    # container. The value remains meaningful for new containers only.
    ignore_changes = [operating_system]
  }
}
