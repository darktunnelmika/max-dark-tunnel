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
| - | **QUIC** | native stream mux over TLS/UDP, no head-of-line blocking; strongest/fastest where UDP is open | 443 |
| 2 | **Tun · MDTprotocol** | layer 3 over a raw IP protocol (GRE 47, ESP 50, any 1-255) | — |
| 2 | **Tun · ICMP** | looks like ping; type/code configurable | — |
| 2 | **Tun · TCP / UDP** | layer 3 inside encrypted TCP or UDP | 443 |
| 3 | **DNS** | layer 3 over DNS-shaped UDP | 53 |
| 4 | **SSH** | TCP Forward over an embedded SSH server (separate from sshd) | 2020 |

- **reverse**: IRAN listens, KHAREJ dials. **direct**: KHAREJ listens, IRAN dials.
- Tun/DNS addresses: `10.20.N.1` (iran) / `10.20.N.2` (kharej), N assigned per tunnel.
- **Route filtering:** every route passes some protocols and drops others. On one real Iran-to-EU route protocol 47 (GRE) was blocked outright while 50 and 253 ran with no loss; the same 47 was fine between two non-Iran servers. If a tunnel does not connect, or Status shows a high `loss`, try another protocol or mode.
- **DNS mode:** some networks police DNS-shaped traffic. On one Iranian datacenter line the iran-to-kharej direction was cut after about 12 queries in a burst, so use DNS only when the other modes are blocked, and try a port other than 53 if it does not connect.
- User ports: `443` → kharej 443; `2083>8443` → iran 2083 lands on kharej 8443.

## Speed profile and tuning

When you create a tunnel on iran you pick a **speed profile**:

- **Balanced:** the default, fine for most links.
- **Fast:** more parallel connections and bigger buffers, for a good link (more RAM).
- **Stable:** fewer connections, small buffers, for a weak or lossy link.
- **Advanced:** set each knob yourself — parallel connections, buffer sizes, keepalive, congestion control (bbr/cubic). Every question has a default, so Enter-through works.

The profile travels in the pair code, so both ends match; change it later from `[4] Manage` -> `[8] Tuning`. It mainly affects TCP Forward and SSH (parallel connections + buffers).

## Source-IP spoof (MDTprotocol only)

If a route meters traffic by sender IP, you can forge the source address. When creating an MDTprotocol tunnel the wizard asks for a fake source IP for each server; they are cross-paired (each side's SRC = the other's DST) and carried in the pair code. Packets still go to the peer's real IP — only the sender field changes.

**Warning:** most datacenters drop spoofed-source packets and the tunnel won't come up. Build without spoof first, enable it only if needed. When spoof is on the script sets reverse-path filtering to loose mode so the packets aren't dropped locally.

- **QUIC mode:** runs over UDP with built-in multiplexing and TLS, so no HOL blocking and better than TCP on lossy links. Only works where UDP is open; fall back to TCP Forward otherwise. Auth/encryption come from the PSK (the TLS certificate is derived deterministically from the PSK and both ends pin it).

- **QUIC obfuscation:** on by default; scrambles QUIC packets so DPI cannot fingerprint them as QUIC. Needed on the Iran line, where DPI drops raw QUIC packets. Both ends must be MDT (the key comes from the PSK).

## Checking

- Menu → Manage → Status: `running · connected`.
- Log: `tail -f /var/log/max-dark-tunnel/<name>.log` — `tunnel is live` / `TUNNEL IS DOWN`.
- Tun/DNS: `ping 10.20.N.2` from iran; Status also shows packet `loss` for these modes. All tunnels: `maxdark --status`.

## No GitHub access from Iran?

Put `mdt-linux-amd64` from Releases at `/root/mdt` and use Core → Install from file, or `install.sh --mirror https://your.host/mdt`.

## Security

ChaCha20-Poly1305 with HKDF-derived keys. Streams get fresh per-direction keys per connection; packet modes use different keys per direction so reflected packets never decrypt. Peers without the PSK see 32 random bytes and are dropped. The SSH host key is derived from the PSK and pinned.

## Build

`go build -o mdt ./cmd/mdt` — every push to `main` makes GitHub Actions build amd64/arm64 and publish them as release `v<SCRIPT_VER>`.
