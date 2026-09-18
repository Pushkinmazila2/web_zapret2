# syntax=docker/dockerfile:1.7
# =============================================================================
# web_zapret2 — Stage 1
# Isolated gateway: Shadowsocks + SOCKS5 in -> nfqws (zapret2) -> direct/upstream
# =============================================================================

# zapret upstream commit (bol-van/zapret master) pinned for reproducibility.
ARG ZAPRET_COMMIT=a1bca5a85e25ab138e9617a560c262fcf53e969a

# ------------- builder: zapret2 (nfqws) ---------------------------------------
FROM debian:bookworm-slim AS zapret-builder
ARG ZAPRET_COMMIT
ARG DEBIAN_FRONTEND=noninteractive
# DNS build-контейнерам выдаёт dockerd (см. daemon.json "dns").
# Писать в /etc/resolv.conf здесь нельзя: на LXC/VPS это read-only bind mount.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates pkg-config libluajit-5.1-dev \
        libnetfilter-queue-dev libnfnetlink-dev libpcap-dev \
        libmnl-dev zlib1g-dev libcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git init zapret \
 && cd zapret \
 && git remote add origin https://github.com/bol-van/zapret2.git \
 && git fetch --depth 1 origin "$ZAPRET_COMMIT" \
 && git checkout --detach FETCH_HEAD \
 && make -f Makefile

# ------------- builder: blockcheckw (pinned upstream + embedded corpus) -------
FROM rust:1.90-bookworm AS blockcheck-builder
ARG BLOCKCHECKW_COMMIT=0cc5cb530d2f78461bd6b92412d2fba0edcdaba1
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/blockcheckw
RUN git init . \
 && git remote add origin https://github.com/rcd27/blockcheckw.git \
 && git fetch --depth 1 origin "$BLOCKCHECKW_COMMIT" \
 && git checkout --detach FETCH_HEAD \
 && cargo build --locked --release --bin blockcheckw \
 && printf '%s\n' "$BLOCKCHECKW_COMMIT" > /build/blockcheckw.version


# ------------- builder: wz-udprelay (C, no deps) ------------------------------
FROM debian:bookworm-slim AS relay-builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY src/wz-udprelay/ /build/
RUN make -C /build all

# ------------- runtime ----------------------------------------------------------
FROM debian:bookworm-slim AS runtime
ARG DEBIAN_FRONTEND=noninteractive

# DNS build-контейнерам выдаёт dockerd; /etc/resolv.conf на LXC/VPS read-only.
# NOTE: user proxy is REQUIRED (dante user.unprivileged, ss-server runs as it).
RUN apt-get update && apt-get install -y --no-install-recommends \
        # services
        shadowsocks-libev \
        dante-server \
        redsocks \
        # networking / management
        iptables nftables iproute2 iputils-ping procps curl ca-certificates \
        util-linux tzdata libcap2-bin \
        # nfqws runtime deps (nfqws links -lmnl, -lz, -lnetfilter_queue, -lnfnetlink)
        libnetfilter-queue1 libnfnetlink0 libpcap0.8 libmnl0 zlib1g \
        python3 python3-pip libluajit-5.1-2 \
    && rm -rf /var/lib/apt/lists/* \
    # fail the build with a clear diagnostic if dante is missing/incomplete
    # (bookworm ships the binary as /usr/sbin/danted, older as sockd)
    && { command -v sockd >/dev/null 2>&1 || command -v danted >/dev/null 2>&1 || { \
             echo "ERROR: dante-server installed but neither sockd nor danted found:"; \
             dpkg -L dante-server; exit 1; }; } \
    && (id -u proxy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin proxy) \
    && (id -u exituser >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin exituser) \
    && (id -u testuser >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin testuser) \
    && mkdir -p /opt/webzapret/bin /var/log/webzapret /run/webzapret \
    && chown -R proxy:proxy /var/log/webzapret /run/webzapret

# yt-dlp — the probe tool for the strategy Test tab (pinned release for
# reproducibility; runs as the dedicated 'testuser' uid during a test).
RUN python3 -m pip install --break-system-packages --no-cache-dir --no-input "yt-dlp==2026.08.19" \
    && rm -rf /root/.cache/pip

# zapret2 binaries (nfqws, tpws, ipset, mdig)
COPY --from=zapret-builder /build/zapret/binaries/my/ /opt/webzapret/bin/
COPY --from=zapret-builder /build/zapret/lua/ /opt/webzapret/lua/
# udp -> socks5 relay for upstream UDP exit
COPY --from=relay-builder /build/wz-udprelay /opt/webzapret/bin/wz-udprelay
# config templates + scripts + panel
COPY config/ /opt/webzapret/config/
COPY src/entrypoint.sh src/wz-common.sh src/wz-fw.sh src/wz-svc.sh src/wz-apply.sh src/wz-test.sh src/wz-bcw.sh \
     /opt/webzapret/scripts/
COPY src/panel/ /opt/webzapret/panel/
COPY src/strategy.py src/blockcheck.py /opt/webzapret/scripts/
COPY --from=blockcheck-builder /build/blockcheckw/target/release/blockcheckw /opt/webzapret/bin/blockcheckw
COPY --from=blockcheck-builder /build/blockcheckw.version /opt/webzapret/config/blockcheckw.version
# Upstream blockcheckw expects this fixed zapret2 layout.
RUN mkdir -p /opt/zapret2/nfq2 \
 && ln -s /opt/webzapret/bin/nfqws2 /opt/zapret2/nfq2/nfqws2 \
 && ln -s /opt/webzapret/lua /opt/zapret2/lua \
 && test -x /opt/zapret2/nfq2/nfqws2 \
 && /opt/webzapret/bin/blockcheckw --version
COPY tests/ /opt/webzapret/tests/

# narrow-capability helper: relay needs NET_ADMIN only at TUN setup
RUN setcap cap_net_admin,cap_net_raw+ep /opt/webzapret/bin/wz-udprelay 2>/dev/null || true \
 && ln -sf /usr/local/bin/yt-dlp /opt/webzapret/bin/yt-dlp \
 && chmod +x /opt/webzapret/scripts/*.sh /opt/webzapret/panel/panel.py \
 && ln -sf /opt/webzapret/scripts/*.sh /usr/local/sbin/ \
 && mkdir -p /opt/webzapret/state

EXPOSE 8388/tcp 8388/udp 1080/tcp 1080/udp 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/webzapret/scripts/entrypoint.sh"]
