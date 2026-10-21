variable "node_name" {
  description = "Proxmox node that owns the managed containers."
  type        = string
  default     = "node1"
}

variable "debian_template_file_id" {
  description = "Template used only when creating a new managed Debian container."
  type        = string
  default     = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
}
