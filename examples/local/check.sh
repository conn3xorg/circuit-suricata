#!/usr/bin/env sh
# Runs on the host: the configuration and rules load, the extra source is
# enabled, and the example's custom rule fires on a DNS lookup of
# suricata-check.example.com, with the alert landing in eve.json. CI pipes
# it in with podman exec.
set -eu
systemctl is-active suricata suricata-rules.timer
suricata -T -c /etc/suricata/suricata.yaml -l "$(mktemp -d)"
suricata-update list-enabled-sources | grep -qx '  - oisf/trafficid'
# Only alerts after this lookup count, so a rerun can't pass on an old one.
eve=/var/log/suricata/eve.json
n=$(cat "$eve" 2>/dev/null | wc -l)
getent hosts suricata-check.example.com || true
for _ in $(seq 30); do
  tail -n +"$((n + 1))" "$eve" | grep '"signature_id":9000001' && exit 0
  sleep 1
done
exit 1
