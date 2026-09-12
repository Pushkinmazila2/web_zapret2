# web_zapret2

Stage 1 — an **isolated, containerized gateway** built on **zapre
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
- **DPI**: `nfqws` from current `bol-van/zapret` master (pinned commit),
  NFQUEUE 200/201, desync of the first N packets per flow (zapret semantics),
  `--dpi-desync-fwmark` loop protection, IPv4.
- **Exit** (switchable live, persists in a docker volume):
  - `direct` — everything leaves via the container default route, desynced.
  - `socks5` — TCP via `redsocks` (SO_ORIGINAL_DST), UDP via a bundled
    `wz-udprelay` (SOCKS5 UDP-ASSOCIATE) — full TCP+UDP through the upstream.
  - `ss` — TCP via `redsocks` -> local `ss-local`, UDP via `wz-udprelay` ->
    `ss-local`. The upstream tunnel itself is desynced by nfqws.
- **Panel** (`http://<host>:8080`): strategy picker (apply = write state +
  **restart nfqws**), exit-mode radio, service status, live logs, optional
  Basic auth.

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

`config/strategies.json` — each entry maps an id to the exact nfqws options
(`--filter-tcp=... --dpi-desync=... --new ...`). The active strategy id is
stored in `/opt/webzapret/state/strategy` (docker volume `wz-state` makes it
persistent). Changing it via the panel: writes the id, then **restarts nfqws**
with the new options (`/opt/webzapret/scripts/wz-apply.sh strategy <id>`).
`none` stops nfqws (pure passthrough, useful for diagnostics).

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

## Troubleshooting

- **Container exits with firewall error**: host lacks NFQUEUE support or the
  container has no `NET_ADMIN`. On some Docker installs, temporarily try
  `privileged: true` (documented fallback); ensure the host has not stopped
  loading the `nfnetlink` module.
- **nfqws runs but nothing is desynced**: check `wz-fw.sh status` — the
  `WZFW` chain must contain NFQUEUE rules, and the access processes must run
  as uid `proxy` (`ps -o user,cmd -C ss-server`).
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