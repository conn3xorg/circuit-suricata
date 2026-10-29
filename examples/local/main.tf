variable "port" {
  type    = number
  default = 2222
}

module "suricata" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  # Podman's default network. With no interfaces given, Suricata watches
  # the one the default route leaves by, the container's eth0.
  home_net = ["10.88.0.0/16"]

  rule_sources = ["et/open", "oisf/trafficid"]

  # Fires on any DNS lookup of suricata-check.example.com, which
  # getent hosts suricata-check.example.com makes on the host.
  custom_rules = [
    "alert dns any any -> any any (msg:\"Conn3x example: lookup of suricata-check.example.com\"; dns.query; content:\"suricata-check.example.com\"; nocase; sid:9000001; rev:1;)",
  ]
}
