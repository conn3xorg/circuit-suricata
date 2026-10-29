# Local example

Applies circuit-suricata to a throwaway Rocky Linux 10 container with systemd, with Suricata watching the container's `eth0`. You need Conn3x and Podman.

Suricata captures packets with AF_PACKET and then switches to its own user, which a container with Podman's default capabilities won't let it do, so the host container runs privileged. That's simplest with rootful Podman. On a Mac, use the Podman machine's root connection. On Linux, use `sudo podman`:

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # macOS
export PODMAN="sudo podman"                               # Linux
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` The first apply takes a minute or two: suricata-update downloads the ET Open and OISF traffic ID rules, and Suricata tests them before it starts.

The example adds one rule of its own, which alerts on any DNS lookup of `suricata-check.example.com`. Make one, then look for the alert:

```sh
podman exec circuit-suricata getent hosts suricata-check.example.com
podman exec circuit-suricata grep '"signature_id":9000001' /var/log/suricata/eve.json
```

The lookup fails, since the name doesn't exist, but the query still crosses `eth0`, and that's what Suricata sees.

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses.

`./down.sh` removes the container, its volumes, the key and the state.
