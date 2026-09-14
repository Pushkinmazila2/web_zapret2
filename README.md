# web_zapret2

Stage 1 — an **isolated, containerized gateway** built on **zapret2**.
It accepts **TCP/UDP** traffic via **Shadowsocks** and **SOCKS5**, pushes it
through **NFQWS2** (DPI desync), and then egresses either **directly** to the
internet or through an **upstream Shadowsocks / SOCKS5 proxy**. A lightweight
single-file **HTML panel** swaps the zapret **strategy** and restarts nfqws.

```
                 SS client / SOCKS5 apps (TCP+UDP)
                           |
        +------------------V---------------------------+
        | ACCESS   ss-server :8388   sockd (SOCKS5) :1080|
        |          (uid: proxy)                          |
        +------------------+----------------------------+
                           | egress flows
        +------------------V---------------------------+
        | DPI      iptables mangle/OUTPUT -> NFQUEUE 200 |
        |          -> nfqws (strategy) <-- panel:8080    |
        +------------------+----------------------------+
                           |
        +------------------V---------------------------+
        | EXIT    direct  -> default route               |
        |         socks5  -> redsocks + UDP relay        |
        |         ss      -> ss-local + UDP relay        |
        +------------------+----------------------------+
                           V  internet
```

## Features (Stage 1)

- **Access**: Shadowsocks server (`shadowsocks-libev`) and SOCKS5 (`dante`)
  in one container; both TCP and UDP.
- **DPI**: native `nfqws2` from `bol-van/zapret2` (pinned commit),
  NFQUEUE 200 for both TCP and UDP, desync of the first N packets per flow,
  `--fwmark` loop protection, IPv4.
- **Exit** (switchable live, persists in a docker volume):
  - `direct` — everything leaves via the container default route, desynced.
  - `socks5` — TCP via `redsocks` (SO_ORIGINAL_DST), UDP via a bundled
    `wz-udprelay` (SOCKS5 UDP-ASSOCIATE) — full TCP+UDP through the upstream.
  - `ss` — TCP via `redsocks` -> local `ss-local`, UDP via `wz-udprelay` ->
    `ss-local`. The upstream tunnel itself is desynced by nfqws.
- **Panel** (`http://<host>:8080`): strategy picker (apply = write state +
  **restart nfqws**), exit-mode radio, service status, live logs, one-click
  connection-log export (all modules, single file), optional Basic auth.

## Requirements (Docker host)

- Linux with a kernel that has `netfilter`/`nfnetlink` (standard distro kernel).
- `/dev/net/tun` available on the host (mounted into the container).
- Docker with `docker compose` support, plus the container capabilities
  declared in `docker-compose.yml` (`NET_ADMIN`, `NET_RAW`).
- Internet access **at build time** (apt + `git fetch` of zapret).

## Quick start

```bash
cp .env.example .env        # edit passwords/upstream settings
make build                  # docker compose build
make up                     # docker compose up -d
make logs                   # follow container logs
make smoke                  # run tests/smoke.sh inside the container
```

Open the panel: http://127.0.0.1:8080

Client configuration:

| Client | Host | Port | Protocol |
|---|---|---|---|
| Shadowsocks | your host IP | `SS_LISTEN_PORT` (8388) | AES-256-GCM (see `.env`) |
| SOCKS5 | your host IP | `SOCKS5_LISTEN_PORT` (1080) | none / TCP+UDP |

## Configuration

Everything lives in `.env` (see `.env.example`). Important variables:

| Variable | Default | Meaning |
|---|---|---|
| `EXIT_MODE` | `direct` | egress: direct / socks5 / ss |
| `STRATEGY` | `standard` | nfqws strategy on boot |
| `UDP_PROXY` | `relay` | `relay` = UDP via upstream, `direct` = UDP exits directly |
| `NFQ_TCP_PORTS`, `NFQ_UDP_PORTS` | `80,443`, `443` | which dest ports nfqws processes |
| `NFQWS_TCP_PKT_OUT`, `NFQWS_UDP_PKT_OUT` | `9`, `9` | desync only first N packets/flow |
| `PANEL_USER`/`PANEL_PASSWORD` | empty | panel Basic auth (set it when exposing publicly) |
| `SS_PASSWORD`, `SS_METHOD`, `SOCKS5_LISTEN_PORT`, ... | — | access layer |
| `UPSTREAM_SOCKS5_*`, `UPSTREAM_SS_*` | — | upstream proxy (for upstream modes) |
| `WAN_IFACE` | `eth0` | container egress interface |

### Strategies

`config/strategies.json` — each entry maps an id to zapret2 profile options
(`--filter-tcp=... --payload=... --lua-desync=... --new ...`). The active strategy id is
stored in `/opt/webzapret/state/strategy` (docker volume `wz-state` makes it
persistent). Changing it via the panel: writes the id, then **restarts nfqws**
with the new options (`/opt/webzapret/scripts/wz-apply.sh strategy <id>`).
`none` stops nfqws2 (pure passthrough, useful for diagnostics). Legacy
`nfqws_opt` entries are converted at startup by `src/strategy.py`; imported
zapret2 entries retain their original `--lua-desync` program.

A TLS strategy may set `"no_reasm": true` (optionally with
`"no_reasm_payloads": "tls_client_hello,quic_initial"`). This appends
`--reasm-disable=...` to the nfqws command line. Without it, nfqws buffers and
**drops every packet** of a TLS connection until the whole ClientHello has been
reassembled; if one segment of a multi-segment ClientHello is lost the
connection hangs forever (nfqws log spam: `DELAY desync until reasm is
complete`). This is typical on low-MSS paths to YouTube/Google CDN nodes and
shows up as pages/images/videos that never load while the rest of the internet
works. `no_reasm` makes nfqws desync the first ClientHello segment immediately
and pass the rest of the segments through. The bundled YouTube strategies and
all strategies imported through the panel are flagged this way automatically.
### Lua scripts

The image includes `zapret-lib.lua`, `zapret-antidpi.lua`, and
`zapret-auto.lua` from the same pinned zapret2 revision. Every nfqws2 process
loads these libraries with `--lua-init=@...`; strategy profiles invoke their
functions through `--lua-desync`. Additional project Lua files can be copied
into the image and referenced by a strategy's `lua_init` field when custom
profiles are added.

`lua_init` is a JSON array of absolute container paths, loaded in order after
the bundled libraries. Mount custom scripts read-only or include them under
`config/` (available at `/opt/webzapret/config/`). `lua_opt` accepts native
arguments, including quoted inline `--lua-init` code and `--blob`. Lua is
executable code, not a safe data format: only import trusted strategies and
protect the panel with authentication. The current firewall intercepts only
outgoing traffic; scripts requiring incoming packets need additional rules.

## How the pieces fit together

- `src/wz-fw.sh` — `iptables` in `mangle/OUTPUT` (owned chain `WZFW`):
  guards loopback and nfqws re-injected packets, then either NFQUEUEs the
  access-uid traffic (direct) or redirects it into the exit layer (upstream),
  and desyncs the exit flows toward the upstream endpoint.
- `src/wz-svc.sh` — pidfile-based supervisor for `ss-server`, `sockd`,
  `nfqws`, and (in upstream modes) `redsocks`, `ss-local`, `wz-udprelay`.
- `src/wz-apply.sh` — transactional single-writer apply for strategy/mode.
- `src/wz-udprelay/wz-udprelay.c` — transparent UDP relay: reads UDP from a
  utun (policy-routed, `ip rule ... uidrange lookup 100`), performs SOCKS5 UDP
  ASSOCIATE to the exit endpoint, injects replies with spoofed source.
- `src/panel/panel.py` + `src/panel/index.html` — stdlib HTTP server + a
  single-file dark UI that polls `/api/*` and posts mutations.

## Isolation and utun0 (FAQ)

**What is utun0?** A virtual TUN interface that exists **only inside the
container's network namespace**. It is created on the fly by `wz-udprelay`
(`ioctl TUNSETIFF` on `/dev/net/tun`) in upstream modes and is the rendezvous
between the container's kernel and the userspace UDP relay: the kernel routes
scoped datagrams into it, the relay reads raw IP packets, forwards payloads to
the upstream via SOCKS5 UDP-ASSOCIATE, and injects replies back with the
spoofed source. In `direct` mode it is never created.

**Does it affect the guest system?** No. Docker containers run in their own
network namespace: `ip rule`, `ip route`, `iptables` and `ip link` executed
inside the container operate on the container's private routing/firewall
objects; `utun0` does not exist on the host. The compose sysctls
(`ip_forward`, `rp_filter`) apply to the container's netns only, and
`NET_ADMIN`/`NET_RAW` are capabilities confined to the container.

**What traffic goes into utun0?** Only datagrams that match the policy route
*twice* (`src/wz-fw.sh`):

```
ip rule add from all uidrange <uid-proxy>-<uid-proxy> ipproto udp lookup 100
ip route add default dev utun0 table 100
```

- `uidrange` — the packet must be **generated by uid `proxy`**, which is owned
  by exactly `ss-server` and `sockd`: i.e. only datagrams *decrypted from our
  clients' SS/SOCKS5 sessions*. The panel (root), `nfqws` (root),
  `redsocks` (root), `ss-local`/`wz-udprelay` (uid `exituser`) and all their
  DNS traffic have other UIDs and keep the normal routing table.
- `ipproto udp` — TCP is never policy-routed into the utun; in upstream modes
  TCP goes through the `nat/OUTPUT` REDIRECT into `redsocks`.

So utun0 carries only "the UDP traffic we sent via the proxy into our
container" — nothing from the host, nothing from other container processes.



```bash
make status           # curl /api/status
make strategy S=fake  # switch strategy via API
make exit M=socks5    # switch exit mode via API
make panel            # validate panel/state inside the container
make shell            # bash inside the container
```

Inside the container everything is scriptable, e.g.:

```bash
docker compose exec gateway wz-svc.sh status
docker compose exec gateway wz-fw.sh status
docker compose exec gateway wz-apply.sh status
docker compose exec gateway tail -n 50 /var/log/webzapret/nfqws.log
```

Logs: `/var/log/webzapret/{nfqws,ss-server,sockd,redsocks,ss-local,udprelay,panel}.log`

**Connection-level logging is enabled by default**: `ss-server`/`ss-local`
run with `-v`, Dante logs `connect`/`disconnect` events, `nfqws` runs with
`--debug=1`, and `wz-udprelay` logs each UDP session open/close (`--verbose`).

Export one merged file covering **all** modules:

```bash
curl -u "$PANEL_USER:$PANEL_PASSWORD" -OJ http://<host>:8080/api/logs/export
```

or click **export all logs (.log)** on the panel's Logs card.

## Troubleshooting

- **Container exits with firewall error**: host lacks NFQUEUE support or the
  container has no `NET_ADMIN`. On some Docker installs, temporarily try
  `privileged: true` (documented fallback); ensure the host has not stopped
  loading the `nfnetlink` module.
- **nfqws runs but nothing is desynced**: check `wz-fw.sh status` — the
  `WZFW` chain must contain NFQUEUE rules, and the access processes must run
  as uid `proxy` (`ps -o user,cmd -C ss-server`).
- **YouTube/Google pages never fully load while the rest of the internet
  works**: this is nfqws waiting to reassemble the whole TLS ClientHello and
  dropping every packet of the flow until it completes. In `nfqws.log` you see
  repeated `DELAY desync until reasm is complete (#N)` for the same connection.
  Multi-segment ClientHellos (large TLS 1.3/ECH hellos over low-MSS routes)
  can lose a segment, so reassembly never finishes and the connection hangs.
  Switch to a strategy with `"no_reasm": true` (both bundled YouTube
  strategies have it) or add it to the strategy entry in
  `config/strategies.json` — that renders `--reasm-disable=tls_client_hello`,
  which desyncs the first segment immediately instead of buffering the hello.
- **UDP relay not working**: verify the utun exists and the policy rule is
  installed (`ip rule show`, `ip route show table 100`), that
  `net.ipv4.conf.all.rp_filter=0` and `ip_forward=1` are set, and that
  `wz-udprelay --help` runs without error.
- **`/dev/net/tun` missing**: `mknod /dev/net/tun c 10 200` on the host, or
  use the compose `devices:` entry.
- **Panel shows services down after reboot**: state volume not mounted?
  `docker compose up -d` re-attaches the named volume `wz-state`.

## Security notes

- The container is an **open proxy** between your LAN and the internet —
  bind published ports to LAN interfaces and **set `PANEL_USER`/
  `PANEL_PASSWORD`**.
- Secrets are environment-only (`.env` is git-ignored) — nothing is baked
  into the image.
- Only the relay carries `CAP_NET_ADMIN`-class privilege (file capability);
  access/exit services run as unprivileged `proxy` / `exituser`.

## Roadmap

- Stage 2: hostlists/ipsets (`MODE_FILTER`), auto-hostlist, IPv6,
  per-strategy port sets, adaptive test pool, telemetry, TSPU dataset export,
  CI and multi-arch images.

## Credits

- [bol-van/zapret](https://github.com/bol-van/zapret) (GPLv3) — nfqws core,
  built from a pinned commit; containers follow the zapret shell/fw semantics.
- Debian packages `shadowsocks-libev`, `dante-server`, `redsocks`.
