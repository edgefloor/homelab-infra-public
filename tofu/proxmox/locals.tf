locals {
  managed_containers = {
    plan_runner = {
      vm_id         = 200
      hostname      = "plan-runner"
      address       = "10.42.0.200/24"
      mac_address   = "02:00:00:00:02:00"
      cores         = 2
      memory        = 2048
      swap          = 512
      disk_size     = 20
      dns_domain    = "node1.local"
      protection    = true
      startup_order = null
      firewall      = false
      nesting       = false
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    caddy = {
      vm_id         = 202
      hostname      = "caddy"
      address       = "10.42.0.202/24"
      mac_address   = "02:00:00:00:02:02"
      cores         = 1
      memory        = 1024
      swap          = 512
      disk_size     = 8
      dns_domain    = "lan"
      protection    = true
      startup_order = 2
      firewall      = false
      nesting       = true
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    jellyfin = {
      vm_id         = 203
      hostname      = "jellyfin"
      address       = "10.42.0.203/24"
      mac_address   = "02:00:00:00:02:03"
      cores         = 4
      memory        = 8192
      swap          = 1024
      disk_size     = 32
      dns_domain    = "lan"
      protection    = true
      startup_order = 3
      firewall      = false
      nesting       = true
      keyctl        = true
      mount_points = [{
        volume = "/data"
        path   = "/storage"
        backup = false
      }]
      devices = [
        { path = "/dev/nvidia0", mode = "0666" },
        { path = "/dev/nvidiactl", mode = "0666" },
        { path = "/dev/nvidia-uvm", mode = "0666" },
        { path = "/dev/nvidia-uvm-tools", mode = "0666" },
      ]
    }
    media_automation = {
      vm_id         = 204
      hostname      = "media-automation"
      address       = "10.42.0.204/24"
      mac_address   = "02:00:00:00:02:04"
      cores         = 4
      memory        = 8192
      swap          = 1024
      disk_size     = 32
      dns_domain    = "lan"
      protection    = true
      startup_order = 4
      firewall      = false
      nesting       = true
      keyctl        = false
      mount_points = [{
        volume = "/data"
        path   = "/storage"
        backup = false
      }]
      devices = []
    }
    downloads = {
      vm_id         = 205
      hostname      = "downloads"
      address       = "10.42.0.205/24"
      mac_address   = "02:00:00:00:02:05"
      cores         = 2
      memory        = 2048
      swap          = 512
      disk_size     = 16
      dns_domain    = "lan"
      protection    = true
      startup_order = 4
      firewall      = false
      nesting       = false
      keyctl        = false
      mount_points = [{
        volume = "/data"
        path   = "/storage"
        backup = false
      }]
      devices = []
    }
    miniflux = {
      vm_id         = 206
      hostname      = "miniflux"
      address       = "10.42.0.206/24"
      mac_address   = "02:00:00:00:02:06"
      cores         = 2
      memory        = 2048
      swap          = 512
      disk_size     = 16
      dns_domain    = "lan"
      protection    = true
      startup_order = 5
      firewall      = false
      nesting       = false
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    pocket_id = {
      vm_id         = 207
      hostname      = "pocket-id"
      address       = "10.42.0.207/24"
      mac_address   = "02:00:00:00:02:07"
      cores         = 2
      memory        = 2048
      swap          = 512
      disk_size     = 8
      dns_domain    = "lan"
      protection    = true
      startup_order = 6
      firewall      = false
      nesting       = true
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    pangolin_connector = {
      vm_id         = 210
      hostname      = "pangolin-connector"
      address       = "10.42.0.210/24"
      mac_address   = "02:00:00:00:02:10"
      cores         = 1
      memory        = 512
      swap          = 512
      disk_size     = 8
      dns_domain    = "homelab.example"
      protection    = true
      startup_order = 9
      firewall      = true
      nesting       = true
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    network_ops = {
      vm_id         = 211
      hostname      = "network-ops"
      address       = "10.42.0.211/24"
      mac_address   = "02:00:00:00:02:11"
      cores         = 1
      memory        = 512
      swap          = 512
      disk_size     = 8
      dns_domain    = "homelab.example"
      protection    = true
      startup_order = 10
      firewall      = true
      nesting       = false
      keyctl        = false
      mount_points  = []
      devices       = []
    }
    nerocd = {
      vm_id         = 213
      hostname      = "nerocd"
      address       = "10.42.0.213/24"
      mac_address   = "02:00:00:00:02:13"
      cores         = 2
      memory        = 2048
      swap          = 512
      disk_size     = 12
      dns_domain    = "lan"
      dns_servers   = ["10.42.0.211", "10.42.0.1"]
      protection    = true
      startup_order = 12
      firewall      = false
      nesting       = true
      keyctl        = false
      mount_points  = []
      devices       = []
    }
  }
}
