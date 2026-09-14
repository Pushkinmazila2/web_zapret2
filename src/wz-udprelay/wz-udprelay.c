/* == wz-udprelay: transparent UDP relay for web_zapret2 upstream exits =====
 * The access layer (ss-server/sockd) produces plain UDP datagrams toward the
 * real targets. In upstream modes they are policy-routed into a utun device
 * (see wz-fw.sh) so this relay can read the ORIGINAL target from the IPv4
 * header - the one piece of info that REDIRECT/DNAT cannot expose for UDP.
 * Per (client,port)->(target,port) flow it: (1) SOCKS5 handshake + UDP
 * ASSOCIATE with the exit endpoint (remote SOCKS5 or local ss-local),
 * (2) forwards payloads with the SOCKS5 UDP framing, (3) reads replies,
 * strips the framing and injects them back into the TUN with the source
 * spoofed to the target; the kernel routes them to the waiting socket.
 * Needs: CAP_NET_ADMIN (TUN), /dev/net/tun, pthreads. IPv4 (Stage 1).
 * Build: gcc -O2 -Wall -o wz-udprelay wz-udprelay.c -lpthread
 * ========================================================================*/
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>

#define PROGNAME     "wz-udprelay"
#define IDLE_TIMEOUT 90
#define SESSION_MAX  512
#define QUEUE_MAX    256
#define CONNECT_MS   5000

static int tun_fd = -1;
static pthread_mutex_t tun_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    const char *tun_name, *socks_host, *user, *password;
    int socks_port;
    int verbose;
} Config;
static Config Cfg = { "utun0", NULL, "", "", 1080, 0 };

static void die(const char *m)
{ fprintf(stderr, "%s: %s: %s\n", PROGNAME, m, strerror(errno)); exit(1); }
static void usage(void)
{
    fprintf(stderr,
        "usage: %s --tun <name> --socks-host <ip> --socks-port <n> "
        "[--socks-user u --socks-password p] [--verbose]\n", PROGNAME);
    exit(0);
}

/* ---- connection-level logging (timestamped, to stderr, gated by --verbose) */
static void vlogf(const char *fmt, ...)
{
    va_list ap;
    char ts[32];
    time_t t = time(NULL);
    struct tm tmv;

    if (!Cfg.verbose) return;
    gmtime_r(&t, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    fprintf(stderr, "%s: [%s] ", PROGNAME, ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void fmt_addr(char *buf, size_t n, uint32_t ip, uint16_t port)
{
    snprintf(buf, n, "%u.%u.%u.%u:%u",
             (ip >> 24) & 0xff, (ip >> 16) & 0xff,
             (ip >> 8) & 0xff, ip & 0xff, port);
}

/* ---------------- TUN ---------------- */
static int tun_open(const char *name)
{
    struct ifreq ifr;
    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) die("open /dev/net/tun");
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (strlen(name) >= IFNAMSIZ) { errno = EINVAL; die("tun name too long"); }
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) die("TUNSETIFF");
    return fd;
}
static void tun_up(int fd, const char *name)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) return;
    ifr.ifr_flags |= IFF_UP;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
}

/* ---------------- checksums / packet build ---------------- */
static uint16_t v4_checksum(const void *data, int len)
{
    const uint8_t *b = (const uint8_t *)data;
    uint32_t sum = 0;
    int i;
    for (i = 0; i < len; i += 2) {
        uint16_t w = (uint16_t)((b[i] << 8) | (i + 1 < len ? b[i + 1] : 0));
        sum += w;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
static uint32_t read32be(const uint8_t *b)
{ return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | b[3]; }

static void tun_write(const uint8_t *pkt, int n)
{
    pthread_mutex_lock(&tun_mutex);
    write(tun_fd, pkt, n);
    pthread_mutex_unlock(&tun_mutex);
}

/* returns total length, 0 on error; builds IPv4+UDP src:sp -> dst:dp */
static int build_packet(uint8_t *pkt, const uint8_t *pl, int plen,
                        uint32_t src, uint16_t sp, uint32_t dst, uint16_t dp)
{
    int total = 28 + plen;
    uint32_t sum, s_net = htonl(src), d_net = htonl(dst);
    uint16_t cs;
    int i, c;

    if (total > 65535) return 0;
    memset(pkt, 0, total);
    pkt[0] = 0x45;
    pkt[2] = total >> 8; pkt[3] = total & 0xff;
    pkt[8] = 64; pkt[9] = IPPROTO_UDP;
    memcpy(pkt + 12, &s_net, 4);
    memcpy(pkt + 16, &d_net, 4);
    cs = v4_checksum(pkt, 20);
    pkt[10] = cs >> 8; pkt[11] = cs & 0xff;

    pkt[20] = sp >> 8; pkt[21] = sp & 0xff;
    pkt[22] = dp >> 8; pkt[23] = dp & 0xff;
    pkt[24] = (8 + plen) >> 8; pkt[25] = (8 + plen) & 0xff;

    sum = 0;
    sum += (src >> 16) & 0xffff; sum += src & 0xffff;
    sum += (dst >> 16) & 0xffff; sum += dst & 0xffff;
    sum += IPPROTO_UDP; sum += 8 + plen;
    sum += sp + (uint32_t)dp; sum += 8 + plen;
    for (i = 0; i < plen; i += 2) {
        c = pl[i] << 8;
        c |= (i + 1 < plen) ? pl[i + 1] : 0;
        sum += c;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    cs = (uint16_t)~sum;
    pkt[26] = cs >> 8; pkt[27] = cs & 0xff;
    memcpy(pkt + 28, pl, (size_t)plen);
    return total;
}

/* ---------------- SOCKS5 ---------------- */
static int recv_all(int fd, uint8_t *b, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(fd, b + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}
static int send_all(int fd, const uint8_t *b, int n)
{
    int sent = 0;
    while (sent < n) {
        int r = send(fd, b + sent, n - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return sent;
}
static int s5_handshake(int fd, const char *user, const char *password)
{
    uint8_t buf[300];
    int method;
    buf[0] = 5;
    if (user && *user) { buf[1] = 2; buf[2] = 0x00; buf[3] = 0x02; }
    else               { buf[1] = 1; buf[2] = 0x00; }
    if (send_all(fd, buf, 2 + buf[1]) < 0) return -1;
    if (recv_all(fd, buf, 2) < 0) return -1;
    if (buf[0] != 5) return -1;
    method = buf[1];
    if (method == 0x02) {
        if (strlen(user) > 255 || strlen(password) > 255) return -1;
        buf[0] = 0x01;
        buf[1] = (uint8_t)strlen(user);
        memcpy(buf + 2, user, strlen(user));
        buf[2 + strlen(user)] = (uint8_t)strlen(password);
        memcpy(buf + 3 + strlen(user), password, strlen(password));
        if (send_all(fd, buf, 3 + strlen(user) + strlen(password)) < 0) return -1;
        if (recv_all(fd, buf, 2) < 0) return -1;
        if (buf[0] != 1 || buf[1] != 0) return -1;
    } else if (method != 0x00) return -1;
    return 0;
}
/* 0 and fills *relay with the server's UDP relay endpoint */
static int s5_udp_associate(int fd, struct sockaddr_in *relay)
{
    uint8_t req[10] = { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 };
    uint8_t rsp[22];
    if (send_all(fd, req, 10) < 0) return -1;
    if (recv_all(fd, rsp, 4) < 0) return -1;
    if (rsp[0] != 5 || rsp[1] != 0 || rsp[2] != 0) return -1;
    if (rsp[3] == 1) {
        if (recv_all(fd, rsp + 4, 6) < 0) return -1;
        memset(relay, 0, sizeof(*relay));
        relay->sin_family = AF_INET;
        memcpy(&relay->sin_addr, rsp + 4, 4);
        relay->sin_port = (uint16_t)((rsp[8] << 8) | rsp[9]);
        return 0;
    }
    return -1; /* IPv6 relay out of scope (Stage 1) */
}
static int connect_socks(const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    struct sockaddr_in *sin;
    struct pollfd pfd;
    int fd, err, soerr = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    sin = (struct sockaddr_in *)res->ai_addr;
    sin->sin_port = htons((uint16_t)port);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    err = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (err != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    pfd.fd = fd; pfd.events = POLLOUT;
    if (poll(&pfd, 1, CONNECT_MS) <= 0 || !(pfd.revents & POLLOUT)) {
        close(fd); return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &(socklen_t){4}) < 0 ||
        soerr != 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, 0);
    return fd;
}

/* ---------------- session state ---------------- */
typedef struct payload { uint8_t *data; int len; struct payload *next; } Payload;
typedef struct session {
    uint32_t cip, tip;          /* client (access socket) / target */
    uint16_t cport, tport;
    int tcp_fd, udp_fd;
    struct sockaddr_in relay;
    time_t last;
    pthread_mutex_t qmutex;
    Payload *qhead, *qtail;
    int qlen;
    int closed;
    pthread_t tid;
    struct session *next;
} Session;

static Session *sessions = NULL;
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
static int session_count = 0;

static void session_close_fds(Session *s)
{
    if (s->tcp_fd >= 0) { close(s->tcp_fd); s->tcp_fd = -1; }
    if (s->udp_fd >= 0) { close(s->udp_fd); s->udp_fd = -1; }
}
static int session_enqueue(Session *s, const uint8_t *pkt, int n)
{
    Payload *p;
    pthread_mutex_lock(&s->qmutex);
    s->last = time(NULL);
    if (s->qlen >= QUEUE_MAX) {
        Payload *old = s->qhead;
        if (old) {
            s->qhead = old->next;
            if (!s->qhead) s->qtail = NULL;
            free(old->data); s->qlen--;
        }
    }
    p = calloc(1, sizeof(*p));
    if (!p) { pthread_mutex_unlock(&s->qmutex); return -1; }
    p->data = malloc((size_t)n);
    if (!p->data) { free(p); pthread_mutex_unlock(&s->qmutex); return -1; }
    memcpy(p->data, pkt, (size_t)n);
    p->len = n;
    if (s->qtail) s->qtail->next = p; else s->qhead = p;
    s->qtail = p;
    s->qlen++;
    pthread_mutex_unlock(&s->qmutex);
    return 0;
}
static int session_dequeue(Session *s, uint8_t **pkt, int *n)
{
    Payload *p; int r = 0;
    pthread_mutex_lock(&s->qmutex);
    p = s->qhead;
    if (p) {
        s->qhead = p->next;
        if (!s->qhead) s->qtail = NULL;
        *pkt = p->data; *n = p->len;
        s->qlen--;
        free(p);
        r = 1;
    }
    pthread_mutex_unlock(&s->qmutex);
    return r;
}

/* ---------------- session worker ---------------- */
static int relay_send(const Session *s, const uint8_t *payload, int plen)
{
    uint8_t frame[65535];
    uint32_t t_net = htonl(s->tip);
    int n = 10 + plen;
    if (n > 65535) return -1;
    frame[0] = 0; frame[1] = 0; frame[2] = 0; frame[3] = 1;
    memcpy(frame + 4, &t_net, 4);
    frame[8] = s->tport >> 8; frame[9] = s->tport & 0xff;
    memcpy(frame + 10, payload, (size_t)plen);
    return (sendto(s->udp_fd, frame, (size_t)n, 0,
                   (struct sockaddr *)&s->relay, sizeof(s->relay)) == n) ? 0 : -1;
}

/* inject reply: src spoofed to target, delivered to the client socket */
static void inject_reply(const Session *s, const uint8_t *payload, int plen,
                         uint32_t tip, uint16_t tport)
{
    uint8_t pkt[65535];
    int n = build_packet(pkt, payload, plen, tip, tport, s->cip, s->cport);
    if (n > 0) tun_write(pkt, n);
}

static void *session_thread(void *arg)
{
    Session *s = (Session *)arg;
    uint8_t buf[65535];
    struct pollfd pfd;

    pfd.fd = s->udp_fd;
    pfd.events = POLLIN;

    while (!s->closed) {
        uint8_t *pkt; int n;
        while (!s->closed && session_dequeue(s, &pkt, &n)) {
            if (relay_send(s, pkt, n) < 0) { free(pkt); s->closed = 1; break; }
            free(pkt);
        }
        if (s->closed) break;
        if (poll(&pfd, 1, 100) > 0 && (pfd.revents & (POLLIN | POLLERR))) {
            for (;;) {
                int r = (int)recv(s->udp_fd, buf, sizeof(buf), 0);
                if (r <= 0) break;
                if (r < 10 + 0 || buf[2] != 0) continue; /* RSV FRAG */
                if (buf[3] == 1 && r >= 10) { /* ATYP=IPv4 */
                    uint32_t tip = read32be(buf + 4);
                    uint16_t tport = (uint16_t)((buf[8] << 8) | buf[9]);
                    int plen = r - 10;
                    s->last = time(NULL);
                    inject_reply(s, buf + 10, plen, tip, tport);
                }
                /* ATYP=IPv6 replies ignored (Stage 1) */
            }
        }
    }
    session_close_fds(s);
    return NULL;
}

/* ---------------- session registry ---------------- */
static Session *session_find(uint32_t cip, uint16_t cport,
                             uint32_t tip, uint16_t tport)
{
    Session *s;
    for (s = sessions; s; s = s->next) {
        if (!s->closed && s->cip == cip && s->cport == cport &&
            s->tip == tip && s->tport == tport) {
            s->last = time(NULL);
            return s;
        }
    }
    return NULL;
}

static void session_evict_one(void)
{
    /* drop the session idle the longest (caller must hold list_mutex) */
    Session *s, *oldest = sessions, *prev = NULL;
    for (s = sessions; s; s = s->next)
        if (s->last <= oldest->last || oldest == NULL) oldest = s;
    if (oldest == sessions) { sessions = sessions->next; }
    else {
        for (s = sessions; s && s->next != oldest; s = s->next) ;
        if (s) { prev = s; prev->next = oldest->next; }
    }
    session_count--;
    oldest->closed = 1;
    if (Cfg.verbose) {
        char src[32], dst[32];
        fmt_addr(src, sizeof(src), oldest->cip, oldest->cport);
        fmt_addr(dst, sizeof(dst), oldest->tip, oldest->tport);
        vlogf("udp session closed: %s -> %s (evicted, max=%d)", src, dst, SESSION_MAX);
    }
    session_close_fds(oldest);
}

static int session_create(uint32_t cip, uint16_t cport,
                          uint32_t tip, uint16_t tport)
{
    Session *s;
    int fd;

    fd = connect_socks(Cfg.socks_host, Cfg.socks_port);
    if (fd < 0) return -1;
    if (s5_handshake(fd, Cfg.user, Cfg.password) < 0) { close(fd); return -1; }

    s = calloc(1, sizeof(*s));
    if (!s) { close(fd); return -1; }
    s->cip = cip; s->cport = cport;
    s->tip = tip; s->tport = tport;
    s->tcp_fd = fd;
    s->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    s->last = time(NULL);
    pthread_mutex_init(&s->qmutex, NULL);
    if (s->udp_fd < 0 ||
        s5_udp_associate(fd, &s->relay) < 0) {
        session_close_fds(s);
        free(s);
        return -1;
    }
    pthread_create(&s->tid, NULL, session_thread, s);

    pthread_mutex_lock(&list_mutex);
    if (session_count >= SESSION_MAX) session_evict_one();
    s->next = sessions;
    sessions = s;
    session_count++;
    pthread_mutex_unlock(&list_mutex);

    if (Cfg.verbose) {
        char src[32], dst[32];
        fmt_addr(src, sizeof(src), cip, cport);
        fmt_addr(dst, sizeof(dst), tip, tport);
        vlogf("udp session open: %s -> %s", src, dst);
    }
    return 0;
}

static Session *session_get(uint32_t cip, uint16_t cport,
                            uint32_t tip, uint16_t tport)
{
    Session *s;
    pthread_mutex_lock(&list_mutex);
    s = session_find(cip, cport, tip, tport);
    pthread_mutex_unlock(&list_mutex);
    if (s) return s;
    if (session_create(cip, cport, tip, tport) < 0) return NULL;
    pthread_mutex_lock(&list_mutex);
    s = session_find(cip, cport, tip, tport);
    pthread_mutex_unlock(&list_mutex);
    return s;
}

/* ---------------- TUN reader ---------------- */
static void *tun_reader(void *arg)
{
    uint8_t buf[65535];
    int n;

    (void)arg;
    for (;;) {
        n = (int)read(tun_fd, buf, sizeof(buf));
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n < 28) continue;
        if ((buf[0] >> 4) != 4) continue;      /* IPv4 only (Stage 1) */
        int ihl = (buf[0] & 0x0f) * 4;
        if (buf[9] != IPPROTO_UDP) continue;
        if (ihl < 20 || n < ihl + 8) continue;
        int total = (buf[2] << 8) | buf[3];
        if (total < ihl + 8 || total > n) continue;
        uint32_t cip = read32be(buf + 12);
        uint32_t tip = read32be(buf + 16);
        uint16_t cport = (uint16_t)((buf[ihl] << 8) | buf[ihl + 1]);
        uint16_t tport = (uint16_t)((buf[ihl + 2] << 8) | buf[ihl + 3]);
        int plen = total - ihl - 8;
        Session *s = session_get(cip, cport, tip, tport);
        if (s && !s->closed)
            session_enqueue(s, buf + ihl + 8, plen);
    }
    return NULL;
}

/* ---------------- idle reaper ---------------- */
static void *reaper(void *arg)
{
    (void)arg;
    for (;;) {
        sleep(15);
        pthread_mutex_lock(&list_mutex);
        Session *s = sessions, *prev = NULL;
        while (s) {
            Session *next = s->next;
            if (!s->closed && (time(NULL) - s->last) > IDLE_TIMEOUT) {
                if (prev) prev->next = next; else sessions = next;
                session_count--;
                s->closed = 1;
                if (Cfg.verbose) {
                    char src[32], dst[32];
                    fmt_addr(src, sizeof(src), s->cip, s->cport);
                    fmt_addr(dst, sizeof(dst), s->tip, s->tport);
                    vlogf("udp session closed: %s -> %s (idle timeout)", src, dst);
                }
                session_close_fds(s);
            } else {
                prev = s;
            }
            s = next;
        }
        pthread_mutex_unlock(&list_mutex);
    }
    return NULL;
}

/* ---------------- main ---------------- */
static void parse_args(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--tun") == 0 && i + 1 < argc)         Cfg.tun_name   = argv[++i];
        else if (strcmp(argv[i], "--socks-host") == 0 && i + 1 < argc)  Cfg.socks_host = argv[++i];
        else if (strcmp(argv[i], "--socks-port") == 0 && i + 1 < argc)  Cfg.socks_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--socks-user") == 0 && i + 1 < argc)  Cfg.user       = argv[++i];
        else if (strcmp(argv[i], "--socks-password") == 0 && i + 1 < argc) Cfg.password = argv[++i];
        else if (strcmp(argv[i], "--verbose") == 0) Cfg.verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) usage();
        else { fprintf(stderr, "unknown option: %s\n", argv[i]); usage(); }
    }
}

int main(int argc, char **argv)
{
    pthread_t reader, reap;

    parse_args(argc, argv);
    if (!Cfg.socks_host || Cfg.socks_port <= 0) usage();

    tun_fd = tun_open(Cfg.tun_name);
    tun_up(tun_fd, Cfg.tun_name);

    pthread_create(&reader, NULL, tun_reader, NULL);
    pthread_create(&reap,   NULL, reaper,    NULL);

    fprintf(stderr, "wz-udprelay: tun=%s socks=%s:%d udp-relay active\n",
            Cfg.tun_name, Cfg.socks_host, Cfg.socks_port);

    pthread_join(reader, NULL);  /* never returns on clean streams */
    return 0;
}