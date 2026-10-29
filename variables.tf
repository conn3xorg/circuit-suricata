variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "centos", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel, centos or fedora."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "suricata_series" {
  type        = string
  default     = "8.0"
  description = "Suricata release series to install from OISF's repositories. Hosts get the latest release in it and keep up with it on upgrades."

  validation {
    condition     = contains(["8.0"], var.suricata_series)
    error_message = "suricata_series must be \"8.0\", the current stable series."
  }
}

variable "interfaces" {
  type        = list(string)
  default     = []
  description = "Network interfaces Suricata watches with AF_PACKET, such as [\"eth0\"] or [\"ens3\", \"ens4\"]. When empty, the interface each host's default IPv4 route leaves by."

  validation {
    condition     = length(distinct(var.interfaces)) == length(var.interfaces) && alltrue([for i in var.interfaces : can(regex("^[A-Za-z0-9_.@-]{1,15}$", i))])
    error_message = "interfaces must list distinct interface names, such as \"eth0\"."
  }
}

variable "home_net" {
  type        = list(string)
  default     = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
  description = "Networks Suricata treats as yours, HOME_NET in its rules. Everything else is EXTERNAL_NET."

  validation {
    condition     = length(var.home_net) > 0 && alltrue([for ip in var.home_net : can(cidrhost(strcontains(ip, "/") ? ip : "${ip}/${strcontains(ip, ":") ? 128 : 32}", 0))])
    error_message = "home_net must list one or more IP addresses or CIDR networks, such as \"10.0.0.0/8\" or \"2001:db8::/32\"."
  }
}

variable "rule_sources" {
  type        = list(string)
  default     = ["et/open"]
  description = "suricata-update sources to enable, such as [\"et/open\", \"oisf/trafficid\"]. suricata-update list-sources shows them all."

  validation {
    condition     = length(var.rule_sources) > 0 && alltrue([for s in var.rule_sources : can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", s))])
    error_message = "rule_sources must list one or more source names from suricata-update list-sources, such as \"et/open\"."
  }
}

variable "custom_rules" {
  type        = list(string)
  default     = []
  description = "Your own rules, one per item, such as [\"alert dns any any -> any any (msg:\\\"Lookup of example.org\\\"; dns.query; content:\\\"example.org\\\"; nocase; sid:1000001; rev:1;)\"]."

  validation {
    condition     = alltrue([for r in var.custom_rules : trimspace(r) != "" && !strcontains(r, "\n")])
    error_message = "Each of custom_rules must be one rule on one line."
  }
}
