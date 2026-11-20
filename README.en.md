# MAX DARK TUNNEL

Encrypted tunnels between an **IRAN** and a **KHAREJ** server: a dedicated Go core (`mdt`) plus a simple menu. The kharej side is configured entirely by a **pair code** — no questions, no license.

[فارسی](README.md) · Support: [@mikakhadm](https://t.me/mikakhadm)

## Install

On **both** servers:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/darktunnelmika/max-dark-tunnel/main/install.sh)
```

Open the menu any time with `maxdark`.

## Two steps

1. **IRAN:** `[2] New tunnel - IRAN` → pick a transport and the user ports → you get a one-line command with a pair code.
2. **KHAREJ:** run that line — it installs, configures and starts:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/darktunnelmika/max-dark-tunnel/main/install.sh) --pair MDT-xxxxxxxx
```

(or `[3] New tunnel - KHAREJ` and paste only the code)

## Transports

| # | Type | What | Default port |
|---|---|---|---|
| 1 | **TCP Forward** | multiplexed streams (smux) over one encrypted carrier, reverse or direct | 443 |
| 2 | **Tun · MDTprotocol** | layer 3 over a raw IP protocol (GRE 47, ESP 50, any 1-255) | — |
| 2 | **Tun · ICMP** | looks like ping; type/code configurable | — |
| 2 | **Tun · TCP / UDP** | layer 3 inside encrypted TCP or UDP | 443 |
| 3 | **DNS** | layer 3 over DNS-shaped UDP | 53 |
| 4 | **SSH** | TCP Forward over an embedded SSH server (separate from sshd) | 2020 |

- **reverse**: IRAN listens, KHAREJ dials. **direct**: KHAREJ listens, IRAN dials.
- Tun/DNS addresses: `10.20.N.1` (iran) / `10.20.N.2` (kharej), N assigned per tunnel.
- User ports: `443` → kharej 443; `2083>8443` → iran 2083 lands on kharej 8443.

## Checking

- Menu → Manage → Status: `running · connected`.
- Log: `tail -f /var/log/max-dark-tunnel/<name>.log` — `tunnel is live` / `TUNNEL IS DOWN`.
- Tun/DNS: `ping 10.20.N.2` from iran. All tunnels: `maxdark --status`.

## No GitHub access from Iran?

Put `mdt-linux-amd64` from Releases at `/root/mdt` and use Core → Install from file, or `install.sh --mirror https://your.host/mdt`.

## Security

ChaCha20-Poly1305 with HKDF-derived keys. Streams get fresh per-direction keys per connection; packet modes use different keys per direction so reflected packets never decrypt. Peers without the PSK see 32 random bytes and are dropped. The SSH host key is derived from the PSK and pinned.

## Build

`go build -o mdt ./cmd/mdt` — push a `vX.Y.Z` tag and GitHub Actions publishes amd64/arm64 binaries.
