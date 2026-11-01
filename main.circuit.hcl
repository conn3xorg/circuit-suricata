# Facts give each host's distribution and release, which pick where
# Suricata comes from: OISF's PPA on Ubuntu, Debian's backports, and OISF's
# COPR repository on Fedora and the Red Hat family.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
    postcondition {
      condition     = self.os_id != "ubuntu" || contains(keys(local.ubuntu_suites), self.os_version)
      error_message = "Host ${each.key} runs Ubuntu ${self.os_version}. OISF's PPA builds for Ubuntu ${join(", ", keys(local.ubuntu_suites))}."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  family = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) ? "debian" : "redhat" }

  # The PPA builds for these Ubuntu releases.
  ubuntu_suites = { "22.04" = "jammy", "24.04" = "noble", "26.04" = "resolute" }

  # Debian carries the current series in backports. Every other host gets
  # an OISF repository, one per series.
  debian_hosts = { for name, h in var.hosts : name => h if local.os[name] == "debian" }
  repo_hosts   = { for name, h in var.hosts : name => h if local.os[name] != "debian" }
  rpm_hosts    = { for name, h in var.hosts : name => h if local.family[name] == "redhat" }
  ubuntu_hosts = { for name, h in var.hosts : name => h if local.os[name] == "ubuntu" }

  # Rocky Linux and AlmaLinux ship epel-release in their own extras
  # repository. COPR's builds for them need EPEL for some libraries.
  epel_hosts = { for name, h in var.hosts : name => h if contains(["rocky", "almalinux"], local.os[name]) }

  copr = "https://download.copr.fedorainfracloud.org/results/@oisf/suricata-${var.suricata_series}"
  repo = { for name in keys(local.repo_hosts) : name => (
    local.os[name] == "ubuntu" ? {
      url    = "https://ppa.launchpadcontent.net/oisf/suricata-${var.suricata_series}/ubuntu"
      key    = file("${path.module}/files/oisf-ppa.asc")
      suites = [lookup(local.ubuntu_suites, data.conn3x_host.facts[name].os_version, "unsupported")]
    } :
    local.os[name] == "fedora" ? {
      url    = "${local.copr}/fedora-$releasever-$basearch/"
      key    = file("${path.module}/files/oisf-copr-suricata-${var.suricata_series}.asc")
      suites = null
    } :
    {
      # COPR builds once per Enterprise Linux major release, as epel-10.
      url    = "${local.copr}/epel-${split(".", data.conn3x_host.facts[name].os_version)[0]}-$basearch/"
      key    = file("${path.module}/files/oisf-copr-suricata-${var.suricata_series}.asc")
      suites = null
    }
  ) }

  # With no interfaces given, the config_candidate step puts in the one
  # the host's default IPv4 route leaves by, such as eth0 or ens3.
  default_iface = "@DEFAULT_ROUTE_INTERFACE@"
  interfaces    = length(var.interfaces) > 0 ? var.interfaces : [local.default_iface]
  route_iface   = "awk '$2 == \"00000000\" { print $1; exit }' /proc/net/route"
  render        = "i=$(${local.route_iface}) && [ -n \"$i\" ] && sed \"s/${local.default_iface}/$i/\" ${local.config_file}.in"

  suricata_yaml = "/etc/suricata/suricata.yaml"
  config_file   = "/etc/suricata/conn3x.yaml"
  rules_file    = "/etc/suricata/conn3x.rules"
  rules_dir     = "/var/lib/suricata/rules"
  eve_log       = "/var/log/suricata/eve.json"
  socket        = "/run/suricata/suricata-command.socket"

  # Settings here override the same keys in the packaged suricata.yaml,
  # which includes this file last. A key replaces the packaged one whole,
  # so vars repeats Suricata 8.0's other groups around HOME_NET. Each
  # interface needs a cluster-id of its own.
  config = join("", concat(
    [
      <<-EOT
      %YAML 1.1
      ---
      # Written by Conn3x. Changes here are overwritten on the next apply.
      vars:
        address-groups:
          HOME_NET: "[${join(",", var.home_net)}]"
          EXTERNAL_NET: "!$HOME_NET"
          HTTP_SERVERS: "$HOME_NET"
          SMTP_SERVERS: "$HOME_NET"
          SQL_SERVERS: "$HOME_NET"
          DNS_SERVERS: "$HOME_NET"
          TELNET_SERVERS: "$HOME_NET"
          AIM_SERVERS: "$EXTERNAL_NET"
          DC_SERVERS: "$HOME_NET"
          DNP3_SERVER: "$HOME_NET"
          DNP3_CLIENT: "$HOME_NET"
          MODBUS_CLIENT: "$HOME_NET"
          MODBUS_SERVER: "$HOME_NET"
          ENIP_CLIENT: "$HOME_NET"
          ENIP_SERVER: "$HOME_NET"
        port-groups:
          HTTP_PORTS: "80"
          SHELLCODE_PORTS: "!80"
          ORACLE_PORTS: 1521
          SSH_PORTS: 22
          DNP3_PORTS: 20000
          MODBUS_PORTS: 502
          FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
          FTP_PORTS: 21
          GENEVE_PORTS: 6081
          VXLAN_PORTS: 4789
          TEREDO_PORTS: 3544
          SIP_PORTS: "[5060, 5061]"
      default-rule-path: ${local.rules_dir}
      rule-files:
        - suricata.rules
        - ${local.rules_file}
      af-packet:
      EOT
    ],
    [for i, iface in local.interfaces : "  - interface: ${iface}\n    cluster-id: ${99 - i}\n    cluster-type: cluster_flow\n    defrag: yes\n"],
  ))

  rules = join("", concat(["# Written by Conn3x. Changes here are overwritten on the next apply.\n"], [for r in var.custom_rules : "${r}\n"]))

  # Puts a candidate in place, then has suricata -T load the whole
  # configuration with every rule. If Suricata turns it down, the previous
  # file goes back, so a typo never reaches the next reload or restart.
  # The rules test reads the settings candidate, and the settings test the
  # live settings, through --include, since suricata.yaml only includes
  # them once both have passed. The test logs to a directory of its own,
  # so it never leaves root-owned files where the suricata user writes.
  install_tested = { for f, settings in { (local.rules_file) = "${local.config_file}.new", (local.config_file) = local.config_file } : f => join(" ", [
    "cp -p ${f} ${f}.old 2>/dev/null; install -m 0644 ${f}.new ${f} && log=$(mktemp -d) &&",
    "if suricata -T -c ${local.suricata_yaml} --include ${settings} -l \"$log\"; then rm -rf \"$log\" ${f}.old; else rm -rf \"$log\";",
    "if [ -e ${f}.old ]; then mv ${f}.old ${f}; else rm -f ${f}; fi;",
    "echo 'suricata -T failed with ${f}.new in place, so ${f} was put back as it was.' >&2; exit 1; fi",
  ]) }

  sources = join(" ", sort(var.rule_sources))
}

circuit "epel" {
  hosts = local.epel_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "release" {
    package {
      name = "epel-release"
    }
  }
}

# OISF's PPA on Ubuntu, OISF's COPR repository on Fedora and the Red Hat
# family. The PPA's key doesn't expire; the COPR key expires on 7 April
# 2030.
circuit "suricata_repo" {
  hosts = local.repo_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "oisf" {
    repository {
      name   = "oisf-suricata"
      url    = local.repo[each.key].url
      key    = local.repo[each.key].key
      suites = local.repo[each.key].suites
    }
  }
}

# Debian's own release carries an older series, and backports the current
# one. Pinning suricata and suricata-update to backports lets the package
# steps install and upgrade them from there; everything else stays on the
# release.
circuit "suricata_debian" {
  hosts = local.debian_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # Cloud images often list backports already, and a second entry for the
  # same suite makes apt warn on every run.
  step "backports" {
    command {
      command = ". /etc/os-release && printf 'Types: deb\\nURIs: http://deb.debian.org/debian\\nSuites: %s-backports\\nComponents: main\\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\\n' \"$VERSION_CODENAME\" > /etc/apt/sources.list.d/conn3x-backports.sources && apt-get update -q"
      unless  = ". /etc/os-release && apt-cache policy | grep -q \" $VERSION_CODENAME-backports/main \""
    }
  }

  step "pin" {
    file {
      path    = "/etc/apt/preferences.d/suricata"
      content = "# Written by Conn3x. Changes here are overwritten on the next apply.\nPackage: suricata suricata-update\nPin: release a=/-backports$/\nPin-Priority: 500\n"
    }
  }

  # Ubuntu's and COPR's suricata packages include suricata-update; Debian
  # packages it on its own.
  step "update_tool" {
    package {
      name = "suricata-update"
    }
  }
}

# The Red Hat family's unit takes its options from /etc/sysconfig/suricata,
# which the package sets to -i eth0. --af-packet reads the interfaces from
# the configuration instead. Written before the package, which then leaves
# it alone.
circuit "suricata_rpm" {
  hosts = local.rpm_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "options" {
    file {
      path    = "/etc/sysconfig/suricata"
      content = "# Written by Conn3x. Changes here are overwritten on the next apply.\nOPTIONS=\"--af-packet --user suricata\"\n"
    }
  }
}

# The PPA's package creates /run/suricata when it installs, but nothing
# makes it again after a reboot, so Suricata comes back without its command
# socket. Debian's and COPR's packages ship a tmpfiles.d entry for it.
circuit "suricata_ubuntu" {
  hosts = local.ubuntu_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "tmpfiles" {
    depends_on = [conn3x_package.suricata__package]
    file {
      path    = "/etc/tmpfiles.d/suricata.conf"
      content = "# Written by Conn3x. Changes here are overwritten on the next apply.\nd /run/suricata 2770 suricata suricata -\n"
    }
  }

  step "run_dir" {
    command {
      command  = "systemd-tmpfiles --create /etc/tmpfiles.d/suricata.conf"
      triggers = { tmpfiles = conn3x_file.suricata_ubuntu__tmpfiles[each.key].revision }
    }
  }
}

circuit "suricata" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "package" {
    depends_on = [
      conn3x_package.epel__release,
      conn3x_repository.suricata_repo__oisf,
      conn3x_file.suricata_debian__pin,
      conn3x_package.suricata_debian__update_tool,
      conn3x_file.suricata_rpm__options,
    ]
    package {
      name = "suricata"
    }
  }

  # Ubuntu's package doesn't rotate Suricata's logs, and Debian's and
  # COPR's each do it their own way. One file in the package's place
  # keeps a week everywhere. HUP makes Suricata reopen its log files.
  step "logrotate" {
    file {
      path    = "/etc/logrotate.d/suricata"
      content = <<-EOT
        # Written by Conn3x. Changes here are overwritten on the next apply.
        /var/log/suricata/*.log /var/log/suricata/*.json {
            daily
            rotate 7
            missingok
            notifempty
            compress
            delaycompress
            sharedscripts
            postrotate
                systemctl kill -s HUP --kill-whom=main suricata.service 2>/dev/null || true
            endscript
        }
        EOT
    }
  }

  # Sources are kept by suricata-update itself, under
  # /var/lib/suricata/update. The index of sources comes first.
  step "sources" {
    command {
      command = join(" ", [
        "suricata-update update-sources -q &&",
        "for s in $(suricata-update list-enabled-sources 2>/dev/null | sed -n 's/^  - //p'); do",
        "case ' ${local.sources} ' in *\" $s \"*) ;; *) suricata-update remove-source -q \"$s\" || exit 1;; esac; done &&",
        "for s in ${local.sources}; do suricata-update enable-source -q \"$s\" || exit 1; done",
      ])
      unless = "[ \"$(suricata-update list-enabled-sources 2>/dev/null | sed -n 's/^  - //p' | sort | xargs)\" = '${local.sources}' ]"
    }
  }

  # Downloads the enabled sources' rules into one suricata.rules, which
  # suricata-update tests with suricata -T before putting it in place. The
  # settings below need it there for their own test. The daily timer
  # keeps it current.
  step "rules" {
    command {
      command  = "suricata-update -q"
      triggers = { sources = conn3x_command.suricata__sources[each.key].revision }
    }
    notify = [handler.reload]
  }

  step "config_template" {
    file {
      path    = "${local.config_file}.in"
      content = local.config
    }
  }

  step "config_candidate" {
    command {
      command  = "{ ${local.render} > ${local.config_file}.new; } || { echo 'No default IPv4 route to take the interface from. Set interfaces.' >&2; exit 1; }"
      unless   = "${local.render} | cmp -s - ${local.config_file}.new"
      triggers = { template = conn3x_file.suricata__config_template[each.key].revision }
    }
  }

  step "rules_candidate" {
    file {
      path    = "${local.rules_file}.new"
      content = local.rules
    }
  }

  step "local_rules" {
    command {
      command  = local.install_tested[local.rules_file]
      unless   = "cmp -s ${local.rules_file}.new ${local.rules_file}"
      triggers = { candidate = conn3x_file.suricata__rules_candidate[each.key].revision }
    }
    notify = [handler.reload]
  }

  step "config" {
    command {
      command  = local.install_tested[local.config_file]
      unless   = "cmp -s ${local.config_file}.new ${local.config_file}"
      triggers = { candidate = conn3x_command.suricata__config_candidate[each.key].revision }
    }
  }

  # Ubuntu's package gives /etc/suricata to the suricata user but leaves
  # suricata.yaml with root. An edit replaces the file from inside the
  # directory, so the two need one owner. The mode stays as packaged, and
  # where root owns the directory this changes nothing.
  step "yaml_owner" {
    command {
      command  = "chown -h \"$(stat -c %u /etc/suricata)\" ${local.suricata_yaml}"
      unless   = "[ \"$(stat -c %u /etc/suricata)\" = \"$(stat -c %u ${local.suricata_yaml})\" ]"
      triggers = { package = conn3x_package.suricata__package[each.key].revision }
    }
  }

  # Read last, so the settings in it win.
  step "include" {
    line {
      path = local.suricata_yaml
      line = "include: ${local.config_file}"
    }
  }

  # A new interface or HOME_NET needs a restart; a rule reload doesn't
  # read them. try-restart leaves a stopped Suricata to the next step.
  step "restart" {
    command {
      command = "systemctl try-restart suricata"
      triggers = {
        config  = conn3x_command.suricata__config[each.key].revision
        include = conn3x_line.suricata__include[each.key].revision
        options = try(conn3x_file.suricata_rpm__options[each.key].revision, null)
        run_dir = try(conn3x_command.suricata_ubuntu__run_dir[each.key].revision, null)
      }
    }
  }

  step "running" {
    service {
      name    = "suricata"
      state   = "started"
      enabled = true
    }
  }

  # Suricata opens its command socket once it has loaded its rules, which
  # takes a minute or so with ET Open on a small host. A reload before then
  # can kill it on some units. Waits only after a start or restart, so a
  # plan made while Suricata is loading after a boot shows no change.
  step "ready" {
    command {
      command = "for _ in $(seq 150); do [ -S ${local.socket} ] && exit 0; sleep 2; done; echo 'Suricata did not open ${local.socket} within five minutes. See journalctl -u suricata and /var/log/suricata/suricata.log.' >&2; exit 1"
      triggers = {
        restart = conn3x_command.suricata__restart[each.key].revision
        running = conn3x_service.suricata__running[each.key].revision
      }
    }
  }

  step "update" {
    timer {
      name        = "suricata-rules"
      description = "Update Suricata's rules and reload them"
      command     = "/bin/sh -c 'suricata-update -q && systemctl try-reload-or-restart suricata'"
      on_calendar = "daily"
      persistent  = true
    }
  }

  # Every unit the packages ship reloads rules on systemctl reload, with
  # USR2 or suricatasc, without dropping packets.
  handler "reload" {
    service {
      name   = "suricata"
      action = "reload"
    }
  }
}
