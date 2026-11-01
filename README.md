# circuit-suricata

A Conn3x circuit that installs Suricata as a network intrusion detection system, keeps its rules current with suricata-update, and writes every alert to `eve.json`. Suricata watches a host's traffic as it passes and tells you when something matches a rule: a lookup of a known malware domain, an exploit attempt against a web server, a client speaking a protocol on a port it shouldn't. It doesn't block anything. It's the part of a network you read, not the part that says no.

You pick the interfaces, your home networks, the rule sources and any rules of your own once, and the same setup lands on Ubuntu, Debian, Fedora and Rocky Linux, each from the place OISF, Suricata's maintainers, point to for it. Every change to the settings or your rules is tested with `suricata -T` before Suricata reads it, so a typo in a rule fails the apply and leaves the running sensor alone.

## Usage

```hcl
module "suricata" {
  source = "github.com/conn3xorg/circuit-suricata?ref=v0.1.1"

  hosts                = { sensor1 = "203.0.113.10" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  home_net     = ["10.0.0.0/8", "192.168.1.0/24"]
  rule_sources = ["et/open", "oisf/trafficid"]

  custom_rules = [
    "alert dns any any -> any any (msg:\"Lookup of a name we've blocked\"; dns.query; content:\"bad.example.net\"; nocase; sid:1000001; rev:1;)",
  ]
}
```

Then run `conn3x init` and `conn3x apply`. A second `conn3x plan` says `No changes.`

The first apply takes a few minutes on a small host: suricata-update downloads the ET Open rules, about 50,000 of them, and Suricata loads them several times: once to test each change, then once to start. Give Suricata 2 GB of memory; with ET Open loaded it holds about 700 MB.

For hosts created in the same plan, pass host objects with the host key you generated, so Conn3x checks it without a known_hosts entry. Give each one's distribution in `os` too: the circuit picks where Suricata comes from by distribution, and Conn3x can't ask a host that doesn't exist yet. If `os` turns out not to match the host, Conn3x stops before configuring it. Set `os` as well when you put `depends_on` on this module: `depends_on` holds back reading the hosts until the apply, so without `os` the plan fails with `Invalid for_each argument`.

```hcl
hosts = {
  for name, d in digitalocean_droplet.sensor : name => {
    address  = d.ipv4_address
    host_key = tls_private_key.host[name].public_key_openssh
    os       = "ubuntu"
  }
}
```

To try it on a throwaway container first, see [examples/local](examples/local).

### Which interface it watches

With `interfaces` left empty, Suricata watches the interface each host's default IPv4 route leaves by, which the circuit reads on every plan. On a host with one network card, that's the one you want. If the route moves to another interface, as it does on DigitalOcean's Rocky Linux 10 image, whose `ens3` comes back as `eth0` after the first reboot, the next plan shows the change and the apply restarts Suricata on the new name.

Traffic that leaves by another interface goes unseen. On a DigitalOcean droplet in a VPC, for example, DNS queries go to a resolver on the private interface, not the public one. Name every interface you want watched to cover them all:

```hcl
interfaces = ["eth0", "eth1"]
```

Suricata only sees what crosses those interfaces. To watch other machines' traffic, put the sensor where it can see it: on the router, or on a switch's mirror port.

### Your own rules

Each item in `custom_rules` is one rule in Suricata's rule language. They go into `/etc/suricata/conn3x.rules`, which Suricata loads next to the downloaded rules. Give each one a `sid` of its own; 1000000 to 1999999 is the range set aside for local rules.

Changing them reloads the rules without restarting Suricata, so it keeps watching while it switches over.

## What it does

On each host, in order:

1. Adds Suricata's repository, as OISF's installation guide describes for each distribution:
   - **Ubuntu**: OISF's PPA for the series, `ppa:oisf/suricata-8.0`. Its signing key, in [files/oisf-ppa.asc](files/oisf-ppa.asc), doesn't expire.
   - **Debian**: Debian's own backports, since Debian 13 itself carries Suricata 7. If the host doesn't list backports already, the circuit adds `/etc/apt/sources.list.d/conn3x-backports.sources`, signed by Debian's archive key. An apt pin in `/etc/apt/preferences.d/suricata` takes `suricata` and `suricata-update` from backports, and nothing else.
   - **Fedora, Rocky Linux and AlmaLinux**: OISF's COPR repository for the series, `@oisf/suricata-8.0`. Rocky Linux and AlmaLinux get `epel-release` first, which COPR's builds need for some libraries. The repository's key, in [files/oisf-copr-suricata-8.0.asc](files/oisf-copr-suricata-8.0.asc), expires on 7 April 2030.
2. Installs `suricata`, and on Debian `suricata-update`, which the other packages include. On the Red Hat family, it first writes `/etc/sysconfig/suricata` with `--af-packet`, so Suricata reads the interfaces from its configuration rather than the package's `-i eth0`. On Ubuntu, it adds a tmpfiles.d entry for `/run/suricata`, which the PPA's package doesn't recreate after a reboot, leaving Suricata without its command socket.
3. Writes `/etc/logrotate.d/suricata`, which keeps a week of `eve.json` and Suricata's other logs, compressed, and tells Suricata to reopen them. Ubuntu's package doesn't rotate them at all.
4. Enables the `rule_sources` with suricata-update and removes any others, then runs suricata-update, which downloads their rules, tests them with `suricata -T` and writes `/var/lib/suricata/rules/suricata.rules`.
5. Writes your rules to `/etc/suricata/conn3x.rules` and the settings to `/etc/suricata/conn3x.yaml`, each only after `suricata -T` has loaded the whole configuration with it in place. If the test fails, the previous file goes back and the apply stops with Suricata's error. Then adds `include: /etc/suricata/conn3x.yaml` to the end of the packaged `suricata.yaml`, so these settings win.
6. Restarts Suricata if the settings changed, starts it now and at boot, and waits for its command socket, which it opens once the rules are loaded.
7. Adds a `suricata-rules` systemd timer that runs suricata-update daily and reloads the rules. A run missed while the host was off happens at the next boot.

Changing `custom_rules` or `rule_sources` reloads the rules with `systemctl reload suricata`. Changing `interfaces` or `home_net` restarts Suricata, since a rule reload doesn't read them.

`conn3x.yaml` sets `HOME_NET`, the AF_PACKET interfaces, and the rule files. Suricata replaces a whole section when an included file sets it, so the file repeats Suricata 8.0's other address and port groups, such as `EXTERNAL_NET: "!$HOME_NET"` and `HTTP_PORTS: "80"`, alongside `HOME_NET`. Everything else, including the `eve-log` output, stays as the packaged `suricata.yaml` has it. Every package turns `eve.json` on, with alerts, DNS, HTTP, TLS and more, in `/var/log/suricata/`.

Before the circuit runs, the `conn3x_host` data source reads each host's distribution and release over SSH, which decide the repository.

### What it doesn't do

- It runs Suricata in IDS mode only. IPS mode, where Suricata sits inline with NFQUEUE or AF_PACKET in copy mode and drops what matches, is out of scope: one bad rule there stops traffic, which deserves a circuit of its own.
- It doesn't take sources that need a secret code, such as ET Pro. suricata-update can enable one with `--secret-code` by hand, and the circuit then removes it on the next apply because it isn't in `rule_sources`.
- It doesn't ship `eve.json` anywhere. Point Filebeat, Vector or the OpenSearch or Grafana stack at `/var/log/suricata/eve.json` for that.
- It doesn't disable, enable or modify individual downloaded rules. suricata-update reads `/etc/suricata/disable.conf`, `enable.conf` and `modify.conf` if you write them.
- Deleting the module leaves Suricata installed and running with the last settings, rules and timer.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, such as `ubuntu` or `rocky`, which a host created in the same plan needs. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `suricata_series` | string | `"8.0"` | Suricata series to install. Hosts get its latest release and follow it on upgrades. `8.0`, the current stable series, is the only one this release takes. |
| `interfaces` | list(string) | `[]` | Interfaces Suricata watches with AF_PACKET, such as `["eth0", "eth1"]`. When empty, the interface each host's default IPv4 route leaves by. |
| `home_net` | list(string) | `["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]` | Your networks, `HOME_NET` in Suricata's rules, as addresses or CIDR networks. Everything else is `EXTERNAL_NET`. |
| `rule_sources` | list(string) | `["et/open"]` | suricata-update sources to enable, such as `["et/open", "oisf/trafficid"]`. `suricata-update list-sources` shows them all. |
| `custom_rules` | list(string) | `[]` | Your own rules, one rule per item. |

## Outputs

| Name | Description |
| --- | --- |
| `config_file` | Path of the settings file, `/etc/suricata/conn3x.yaml`. |
| `rules_file` | Path of the file holding `custom_rules`, `/etc/suricata/conn3x.rules`. |
| `eve_log` | Path of the EVE JSON log, `/var/log/suricata/eve.json`, where alerts land. |

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with a package mirror the host can reach. Each host also needs to reach OISF's PPA or COPR repository, or Debian's backports, and the rule sources' download servers, such as `rules.emergingthreats.net`. Ubuntu needs 22.04, 24.04 or 26.04, the releases the PPA builds for.

## Tested on

Ubuntu 24.04, Debian 13, Fedora 45 and Rocky Linux 10. [examples/local](examples/local) was applied to each in arm64 Podman containers, and CI does the same on amd64: it checks that the second plan has no changes and that `suricata -T` passes, then looks up `suricata-check.example.com` in the container and checks the example's custom rule alerts on the query in `eve.json`.

On the same containers, hosts first applied at v0.1.0 and then moved to this version also had a clean second plan and passed those checks. All of it ran on Conn3x v0.6.11 and on a newer development build.

On Ubuntu 24.04 and Rocky Linux 10 droplets, with SELinux enforcing on Rocky Linux, the same checks passed by hand, with Suricata watching the interface of the default route. A DNS query for the test name to `1.1.1.1` raised the alert on each. After a reboot, Suricata came back with its command socket, the plan had no changes, and the alert fired again. The daily timer's service, started by hand, updated the rules and reloaded them on both. On Rocky Linux, COPR's package has no SELinux policy of its own, so Suricata runs as `unconfined_service_t`; the audit log had no denials.

Also tried by hand, on Ubuntu 24.04 in a container: a rule with a misspelt keyword failed the apply with Suricata's error and left `conn3x.rules` as it was, and adding a rule reloaded the rules without restarting Suricata, after which the new rule fired.

## License

MPL-2.0. See [LICENSE](LICENSE). Suricata itself is GPL-2.0.
