# Retained installer media. The Omarchy desktop VM was retired on 2026-10-12.
resource "proxmox_download_file" "omarchy_iso" {
  node_name           = var.node_name
  datastore_id        = "local"
  content_type        = "iso"
  file_name           = "omarchy-4.0.4.iso"
  url                 = "https://iso.omarchy.org/omarchy-4.0.4.iso"
  checksum            = "ddeded2758c48318d201dfdac905ecb28f570441883f0c052ea3cd5d05acf92d"
  checksum_algorithm  = "sha256"
  upload_timeout      = 1800
  overwrite           = false
  overwrite_unmanaged = false

  lifecycle {
    prevent_destroy = true
  }
}
