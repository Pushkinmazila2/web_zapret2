# syntax=docker/dockerfile:1.7
# =============================================================================
# web_zapret2 — Stage 1
# Isolated gateway: Shadowsocks + SOCKS5 in -> nfqws (zapret2) -> direct/upstream
# =============================================================================

# zapret upstream commit (bol-van/zapret master) pinned for reproducibility.
ARG ZAPRET_COMMIT=87e058624c72863db53bdaf7fb6f16576dddb6ab

# ------------- builder: zapret2 (nfqws) ---------------------------------------
FROM debian:bookworm-slim AS zapret-builder
ARG ZAPRET_COMMIT
ARG DEBIAN_FRONTEND=noninteractive
# Фикс DNS для сборщика:
RUN echo "nameserver 77.88.8.8" > /etc/resolv.conf && \
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf && \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates \
        libnetfilter-queue-dev libnfnetlink-dev libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git init zapret \
 && cd zapret \
 && git remote add origin https://github.com/bol-van/zapret.git \
 && git fetch --depth 1 origin "$ZAPRET_COMMIT" \
 && git checkout --detach FETCH_HEAD \
 && make -f Makefile

# ------------- builder: wz-udprelay (C, no deps) ------------------------------
FROM debian:bookworm-slim AS relay-builder
ARG DEBIAN_FRONTEND=noninteractive
# Фикс DNS для сборщика:
RUN echo "nameserver 77.88.8.8" > /etc/resolv.conf && \
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf && \
    apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY src/wz-udprelay/ /build/
RUN make -C /build all

# ------------- runtime ----------------------------------------------------------
FROM debian:bookworm-slim AS runtime
ARG DEBIAN_FRONTEND=noninteractive

# Фикс DNS для сборщика и безопасный useradd:
RUN echo "nameserver 77.88.8.8" > /etc/resolv.conf && \
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf && \
    apt-get update && apt-get install -y --no-install-recommends \
        # services
        shadowsocks-libev \
        dante-server \
        redsocks \
        # networking / management
        iptables iproute2 iputils-ping procps curl ca-certificates \
        util-linux tzdata libcap2-bin \
        # nfqws runtime deps
        libnetfilter-queue1 libnfnetlink0 libpcap0.8 \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && (id -u proxy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin proxy) \
    && (id -u exituser >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin exituser) \
    && mkdir -p /opt/webzapret/bin /var/log/webzapret /run/webzapret \
    && chown -R proxy:proxy /var/log/webzapret /run/webzapret

# zapret2 binaries (nfqws, tpws, ipset, mdig)
COPY --from=zapret-builder /build/zapret/binaries/my/ /opt/webzapret/bin/
# udp -> socks5 relay for upstream UDP exit
COPY --from=relay-builder /build/wz-udprelay /opt/webzapret/bin/wz-udprelay
# config templates + scripts + panel
COPY config/ /opt/webzapret/config/
COPY src/entrypoint.sh src/wz-common.sh src/wz-fw.sh src/wz-svc.sh src/wz-apply.sh \
     /opt/webzapret/scripts/
COPY src/panel/ /opt/webzapret/panel/
COPY tests/ /opt/webzapret/tests/

# narrow-capability helper: relay needs NET_ADMIN only at TUN setup
RUN setcap cap_net_admin,cap_net_raw+ep /opt/webzapret/bin/wz-udprelay 2>/dev/null || true \
 && chmod +x /opt/webzapret/scripts/*.sh /opt/webzapret/panel/panel.py \
 && ln -sf /opt/webzapret/scripts/*.sh /usr/local/sbin/ \
 && mkdir -p /opt/webzapret/state

EXPOSE 8388/tcp 8388/udp 1080/tcp 1080/udp 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/webzapret/scripts/entrypoint.sh"]
